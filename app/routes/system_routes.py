"""系统信息、性能指标、电源操作、面板自升级。"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import shell
from ..auth import require_auth, require_internal
from ..config import MODE_INTERNAL, config
from ..metrics import basic_info, metrics, top_processes
from ..utils import is_root

router = APIRouter(prefix="/api/system", tags=["system"], dependencies=[Depends(require_auth)])

# 仓库根目录（app/ 的上级）
BASE_DIR = Path(__file__).resolve().parent.parent.parent


class PowerBody(BaseModel):
    action: str  # reboot | shutdown | cancel
    confirm: str = ""


class SelfUpdateBody(BaseModel):
    ref: str = ""  # 目标分支/标签/commit，空 = 默认 origin/main


@router.get("/info")
async def info():
    return basic_info()


@router.get("/metrics")
async def current_metrics():
    # 采样含 psutil 系统调用，PRoot 上单次可达数百毫秒，绝不能阻塞事件循环
    data = await asyncio.to_thread(metrics.sample)
    data["mode"] = config.mode  # 前端据此实时感知模式变化
    return data


@router.get("/history")
async def history():
    return {"points": metrics.history_list(), "interval": 2}


@router.get("/processes")
async def processes(limit: int = 15, sort: str = "cpu"):
    return top_processes(limit=max(1, min(limit, 100)), sort=sort)


@router.get("/network")
async def network():
    import psutil

    # Android / PRoot 会把内核的 PermissionError 直接抛出来（不是 psutil.Error）：
    # /proc/net/dev 读不到时，原来整个「网络」视图 500。这里逐项降级：
    # 计数/速率读不到就报 0，页面上仍能看到网卡与地址，并在 degraded 里说明原因。
    degraded: list[str] = []

    def safe(label, fn, default):
        try:
            return fn()
        except (psutil.Error, OSError) as exc:
            degraded.append(f"{label}: {exc}")
            return default

    counters = safe("net_io_counters", lambda: psutil.net_io_counters(pernic=True), {}) or {}
    stats = safe("net_if_stats", psutil.net_if_stats, {}) or {}
    addrs = safe("net_if_addrs", psutil.net_if_addrs, {}) or {}

    interfaces = []
    for name, addr_list in addrs.items():
        nic = counters.get(name)
        st = stats.get(name)
        interfaces.append({
            "name": name,
            "up": bool(st.isup) if st else False,
            "speed": st.speed if st else 0,
            "mtu": st.mtu if st else 0,
            "addresses": [
                {"family": str(a.family), "address": a.address, "netmask": a.netmask}
                for a in addr_list
            ],
            "bytes_sent": nic.bytes_sent if nic else 0,
            "bytes_recv": nic.bytes_recv if nic else 0,
            "packets_sent": nic.packets_sent if nic else 0,
            "packets_recv": nic.packets_recv if nic else 0,
        })
    return {"interfaces": interfaces, "degraded": degraded}


@router.get("/capabilities")
async def capabilities():
    """探测本机可用的系统工具，前端据此灰掉不支持的功能。"""
    return {
        # systemctl 存在不等于 systemd 在运行（容器里通常为 PID 1 之外）
        "systemd": os.path.isdir("/run/systemd/system")
        and shell.available("systemctl")
        and shell.available("journalctl"),
        "dmesg": shell.available("dmesg"),
        "lsblk": shell.available("lsblk"),
        "du": shell.available("du"),
        "mount": shell.available("mount"),
        "smartctl": shell.available("smartctl"),
        "is_root": is_root(),
        "mode": config.mode,
        "internal": config.mode == MODE_INTERNAL,
    }


@router.post("/power", dependencies=[Depends(require_internal)])
async def power(body: PowerBody):
    if body.confirm != "CONFIRM":
        raise HTTPException(400, "危险操作，需要确认参数 confirm=CONFIRM")
    if not os.path.isdir("/run/systemd/system") or not shell.available("systemctl"):
        raise HTTPException(400, "本机未运行 systemd，无法执行电源操作")
    mapping = {
        "reboot": (["systemctl", "reboot"], "系统正在重启"),
        "shutdown": (["systemctl", "poweroff"], "系统正在关机"),
        "cancel": (["systemctl", "cancel"], "已取消计划中的关机/重启"),
    }
    if body.action not in mapping:
        raise HTTPException(400, "不支持的操作")
    cmd, message = mapping[body.action]
    result = await shell.run(cmd, timeout=10)
    if not result.ok and body.action != "cancel":
        raise HTTPException(500, result.text or "执行失败")
    return {"ok": True, "message": message}


@router.post("/self-update", dependencies=[Depends(require_internal)])
async def self_update(body: SelfUpdateBody | None = None):
    """面板内一键升级。

    关键点：更新进程必须脱离本面板的进程组（setsid）——升级流程会重启面板，
    跟面板同组的进程会被一起带走，更新和其中的健康检查/回滚就都没了。
    更新过程（含失败原因）写入 panel.log，前端轮询 /healthz 观察版本变化。
    """
    update_cmd = [
        sys.executable, "-m", "app.main", "--update", "--app-dir", str(BASE_DIR),
    ]
    if body and body.ref:
        update_cmd += ["--update-ref", body.ref]

    log_path = BASE_DIR / "panel.log"
    log_fh = open(log_path, "ab")  # O_APPEND，多进程并发写安全
    try:
        subprocess.Popen(
            update_cmd,
            cwd=BASE_DIR,
            stdin=subprocess.DEVNULL,
            stdout=log_fh,
            stderr=log_fh,
            start_new_session=True,
        )
    finally:
        log_fh.close()  # 子进程持有自己的 fd 副本，父进程随即关闭

    return {
        "ok": True,
        "message": "升级已在后台启动：面板数秒内重启，登录态保持；"
                   "完成后版本号见 /healthz，失败自动回滚。详情见 panel.log。",
        "log": str(log_path),
    }
