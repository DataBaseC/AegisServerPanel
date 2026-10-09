"""systemd 服务管理：列表、启停、开机自启、日志。"""

from __future__ import annotations

import os
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import shell
from ..auth import require_auth, require_internal

router = APIRouter(prefix="/api/services", tags=["services"], dependencies=[Depends(require_auth)])

ACTIONS = {
    "start": "启动",
    "stop": "停止",
    "restart": "重启",
    "reload": "重载配置",
    "enable": "设置开机自启",
    "disable": "取消开机自启",
    "mask": "屏蔽",
    "unmask": "取消屏蔽",
}
UNIT_RE = re.compile(r"^[A-Za-z0-9@._:\-]+$")


class ActionBody(BaseModel):
    action: str


def _require_systemd() -> None:
    if not os.path.isdir("/run/systemd/system") or not shell.available("systemctl"):
        raise HTTPException(400, "本机未运行 systemd，无法管理服务")


def _validate_unit(name: str) -> str:
    if not UNIT_RE.match(name) or name.startswith("-"):
        raise HTTPException(400, "服务名不合法")
    return name if "." in name else f"{name}.service"


@router.get("")
async def list_services(q: str = "", state: str = "all"):
    _require_systemd()
    result = await shell.run(
        ["systemctl", "list-units", "--type=service", "--all", "--no-pager",
         "--no-legend", "--plain"], timeout=20
    )
    if not result.ok:
        raise HTTPException(500, result.text or "读取服务列表失败")

    enabled_map = {}
    files = await shell.run(
        ["systemctl", "list-unit-files", "--type=service", "--no-pager",
         "--no-legend", "--plain"], timeout=20
    )
    if files.ok:
        for line in files.out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                enabled_map[parts[0]] = parts[1]

    services = []
    for line in result.out.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit, load, active, sub = parts[0], parts[1], parts[2], parts[3]
        description = parts[4].strip() if len(parts) > 4 else ""
        if q and q.lower() not in unit.lower() and q.lower() not in description.lower():
            continue
        if state == "running" and active != "active":
            continue
        if state == "failed" and active != "failed":
            continue
        if state == "stopped" and active == "active":
            continue
        services.append({
            "unit": unit,
            "load": load,
            "active": active,
            "sub": sub,
            "description": description,
            "enabled": enabled_map.get(unit, "unknown"),
        })

    order = {"active": 0, "failed": 1, "inactive": 2}
    services.sort(key=lambda s: (order.get(s["active"], 3), s["unit"]))
    return {"total": len(services), "services": services}


@router.get("/{name}")
async def service_detail(name: str):
    _require_systemd()
    unit = _validate_unit(name)
    result = await shell.run(
        ["systemctl", "show", "--no-pager", unit, "--property=Id,Description,ActiveState,"
         "SubState,UnitFileState,MainPID,ExecMainPID,ExecStart,MemoryCurrent,CPUUsageNSec,"
         "ActiveEnterTimestamp,FragmentPath,LoadState"],
        timeout=15,
    )
    if not result.ok:
        raise HTTPException(404, result.text or "服务不存在")
    props = {}
    for line in result.out.splitlines():
        key, _, value = line.partition("=")
        props[key] = value
    return props


@router.post("/{name}/action", dependencies=[Depends(require_internal)])
async def service_action(name: str, body: ActionBody):
    _require_systemd()
    unit = _validate_unit(name)
    if body.action not in ACTIONS:
        raise HTTPException(400, f"不支持的操作，可选：{', '.join(ACTIONS)}")
    result = await shell.run(["systemctl", body.action, "--", unit], timeout=60)
    if not result.ok:
        detail = (result.err or result.out).strip().splitlines()
        raise HTTPException(500, detail[-1] if detail else "操作失败")
    return {"ok": True, "message": f"{unit} {ACTIONS[body.action]}成功"}


@router.get("/{name}/logs")
async def service_logs(name: str, lines: int = 200):
    _require_systemd()
    unit = _validate_unit(name)
    lines = max(1, min(lines, 2000))
    result = await shell.run(
        ["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "--output=short-iso"],
        timeout=25,
    )
    return {"unit": unit, "lines": result.out.splitlines(), "ok": result.ok,
            "error": None if result.ok else result.err.strip()}
