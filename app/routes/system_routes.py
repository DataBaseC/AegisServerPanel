"""系统信息、性能指标、电源操作。"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import shell
from ..auth import require_auth, require_internal
from ..config import MODE_INTERNAL, config
from ..metrics import basic_info, metrics, top_processes
from ..utils import is_root

router = APIRouter(prefix="/api/system", tags=["system"], dependencies=[Depends(require_auth)])


class PowerBody(BaseModel):
    action: str  # reboot | shutdown | cancel
    confirm: str = ""


@router.get("/info")
async def info():
    return basic_info()


@router.get("/metrics")
async def current_metrics():
    data = metrics.sample()
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

    interfaces = []
    counters = psutil.net_io_counters(pernic=True)
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        nic = counters.get(name)
        st = stats.get(name)
        interfaces.append({
            "name": name,
            "up": bool(st.isup) if st else False,
            "speed": st.speed if st else 0,
            "mtu": st.mtu if st else 0,
            "addresses": [
                {"family": str(a.family), "address": a.address, "netmask": a.netmask}
                for a in addrs
            ],
            "bytes_sent": nic.bytes_sent if nic else 0,
            "bytes_recv": nic.bytes_recv if nic else 0,
            "packets_sent": nic.packets_sent if nic else 0,
            "packets_recv": nic.packets_recv if nic else 0,
        })
    return {"interfaces": interfaces}


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
