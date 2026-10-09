"""常驻应用 API：注册、启停、日志、试运行，以及面板自身的近期操作审计。

路径统一挂在 ``/api/panel/apps`` 下——``/api/apps`` 已被「应用与端口」发现占用
（那是只读的端口扫描，本模块是写操作的进程托管），前缀分开可以避免两套语义混淆。
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from collections import deque

import psutil
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..apps import AppError, a_name, normalize_definition, probe, supervisor
from ..auth import require_internal

router = APIRouter(prefix="/api/panel/apps", tags=["panel-apps"])

AUDIT_LIMIT = 40
_audit: deque[dict] = deque(maxlen=AUDIT_LIMIT)


class AppBody(BaseModel):
    name: str
    command: str
    description: str = ""
    cwd: str = ""
    env: dict[str, str] = {}
    autostart: bool = False
    restart: str = "on-failure"
    max_restarts: int = 5
    restart_delay: float = 2.0


class AppPatch(BaseModel):
    name: str | None = None
    command: str | None = None
    description: str | None = None
    cwd: str | None = None
    env: dict[str, str] | None = None
    autostart: bool | None = None
    restart: str | None = None
    max_restarts: int | None = None
    restart_delay: float | None = None


class ProbeBody(BaseModel):
    seconds: float = 5.0


def recent_audit() -> list[dict]:
    return list(_audit)


def record_audit(action: str, app_id: str, name: str, detail: str = "") -> None:
    _audit.appendleft({
        "time": int(time.time()),
        "kind": "panel",
        "action": action,
        "app_id": app_id,
        "app": name,
        "detail": detail[:300],
    })


def _guard(fn, *args, **kwargs):
    """把 AppError（用户输入问题）翻译成 400，而不是 500。"""
    try:
        return fn(*args, **kwargs)
    except AppError as exc:
        raise HTTPException(400, str(exc))


@router.get("")
async def list_apps(_session: dict = Depends(require_internal)):
    """常驻应用列表 + 面板自身运行信息（前端顶部说明用）。"""
    apps = supervisor.list()
    return {
        "total": len(apps),
        "apps": apps,
        "self": {
            "pid": os.getpid(),
            "registry": str(supervisor.registry.path),
            "log_dir": str(supervisor.log_dir),
            "systemd": os.path.isdir("/run/systemd/system"),
        },
        "audit": recent_audit(),
    }


@router.post("")
async def create_app(body: AppBody, _session: dict = Depends(require_internal)):
    """注册应用。默认不启动——先「试运行」确认配置，再正式保活。"""
    name = body.name.strip()
    if supervisor.registry.by_name(name):
        raise HTTPException(409, f"名称已存在：{name}（可直接编辑该应用）")
    definition = _guard(normalize_definition, body.model_dump())
    app = _guard(supervisor.registry.add, definition)
    record_audit("create", app["id"], a_name(app), app["command"])
    return {"ok": True, "app": supervisor.get(app["id"]),
            "message": f"已注册 {a_name(app)}（未启动，可先试运行再启动）"}


@router.get("/{app_id}")
async def app_detail(app_id: str, _session: dict = Depends(require_internal)):
    return _guard(supervisor.get, app_id)


@router.put("/{app_id}")
async def update_app(app_id: str, body: AppPatch, _session: dict = Depends(require_internal)):
    current = _guard(supervisor.registry.get, app_id)
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    merged = _guard(normalize_definition, patch, current)
    _guard(supervisor.registry.update, app_id, merged)
    record_audit("update", app_id, a_name(merged), merged["command"])
    running = supervisor.get(app_id)["runtime"]["status"] == "running"
    return {"ok": True, "app": supervisor.get(app_id),
            "message": "配置已更新" + ("，需重启应用后生效" if running else "")}


@router.delete("/{app_id}")
async def delete_app(app_id: str, _session: dict = Depends(require_internal)):
    app = _guard(supervisor.registry.get, app_id)
    status = supervisor.get(app_id)["runtime"]["status"]
    if status in ("running", "starting", "restarting"):
        raise HTTPException(400, "应用正在运行，请先停止再删除")
    _guard(supervisor.registry.remove, app_id)
    with contextlib.suppress(Exception):
        supervisor.runtimes.pop(app_id, None)
    record_audit("delete", app_id, a_name(app))
    return {"ok": True, "message": f"已删除 {a_name(app)}"}


@router.post("/{app_id}/start")
async def start_app(app_id: str, _session: dict = Depends(require_internal)):
    app = _guard(supervisor.registry.get, app_id)
    try:
        result = await supervisor.start(app_id)
    except AppError as exc:
        raise HTTPException(400, str(exc))
    record_audit("start", app_id, a_name(app))
    return {"ok": True, "app": result,
            "message": f"{a_name(app)} 已启动（PID {result['runtime']['pid']}）"}


@router.post("/{app_id}/stop")
async def stop_app(app_id: str, _session: dict = Depends(require_internal)):
    app = _guard(supervisor.registry.get, app_id)
    try:
        result = await supervisor.stop(app_id)
    except AppError as exc:
        raise HTTPException(400, str(exc))
    record_audit("stop", app_id, a_name(app))
    return {"ok": True, "app": result, "message": f"{a_name(app)} 已停止"}


@router.post("/{app_id}/restart")
async def restart_app(app_id: str, _session: dict = Depends(require_internal)):
    app = _guard(supervisor.registry.get, app_id)
    try:
        result = await supervisor.restart(app_id)
    except AppError as exc:
        raise HTTPException(400, str(exc))
    record_audit("restart", app_id, a_name(app))
    return {"ok": True, "app": result, "message": f"{a_name(app)} 已重启"}


@router.post("/{app_id}/probe")
async def probe_app(app_id: str, body: ProbeBody | None = None,
                    _session: dict = Depends(require_internal)):
    """试运行：跑几秒抓输出后结束，确认命令与工作目录是否正确。"""
    app = _guard(supervisor.registry.get, app_id)
    seconds = max(1.0, min((body.seconds if body else 5.0), 30.0))
    # probe 内部是阻塞的 communicate(timeout)，必须丢线程，否则会卡住整个事件循环
    result = await asyncio.to_thread(probe, app, seconds)
    record_audit("probe", app_id, a_name(app), result.get("message", ""))
    return {"ok": True, **result}


@router.get("/{app_id}/logs")
async def app_logs(app_id: str, offset: int = 0, limit: int = 262144, lines: int = 0,
                   _session: dict = Depends(require_internal)):
    return _guard(supervisor.log_of, app_id, offset, limit, lines)


@router.delete("/{app_id}/logs")
async def clear_app_logs(app_id: str, _session: dict = Depends(require_internal)):
    app = _guard(supervisor.registry.get, app_id)
    _guard(supervisor.clear_log, app_id)
    record_audit("clear-logs", app_id, a_name(app))
    return {"ok": True, "message": f"{a_name(app)} 的日志已清空"}


@router.get("/{app_id}/check-port")
async def check_port(app_id: str, port: int, _session: dict = Depends(require_internal)):
    """启动前的模糊提示：目标端口是否已被占用（只提示，不阻断启动）。"""
    app = _guard(supervisor.registry.get, app_id)
    occupied: list[dict] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != psutil.CONN_LISTEN or not conn.laddr or conn.laddr.port != port:
                continue
            row = {"pid": conn.pid, "name": "-", "user": "-"}
            if conn.pid:
                with contextlib.suppress(psutil.Error):
                    proc = psutil.Process(conn.pid)
                    row["name"] = proc.name()
                    row["user"] = proc.username()
            if row not in occupied:
                occupied.append(row)
    except (psutil.Error, OSError):
        # Android / PRoot 会屏蔽 /proc/net/tcp 并抛出裸 PermissionError（不是 psutil.Error）：
        # 枚举不到就当作"没有占用者"，只提示不阻断启动
        pass
    return {
        "port": port,
        "occupied": bool(occupied),
        "owners": occupied,
        "hint": (f"端口 {port} 已被占用" if occupied else f"端口 {port} 当前空闲"),
        "app": a_name(app),
    }
