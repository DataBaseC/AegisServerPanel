"""应用市场（2.0 M4）：常见自托管应用的一键注册。

定位很明确——**只做提示与注册，不做下载安装**：

- 清单是仓库内的静态文件 ``app/market.json``，命令只能来自清单，
  不接受前端传入的任意命令（避免把这里变成"免确认的 root 命令执行"入口）；
- 注册走现有 ``supervisor.registry``，与「常驻应用」完全同构：不立即启动，
  用户可以先用「试运行」确认命令是否可用；
- 二进制是否已安装**不在这里拦**：命令装好之前就先把应用定义存下来是
  常见诉求（先写配置、再装包），启动时自然会报错并写入应用日志。
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..apps import NAME_RE, AppError, new_id, supervisor
from ..audit import AuditEvent, audit
from ..auth import client_ip, require_internal

router = APIRouter(prefix="/api/panel/market", tags=["market"])

MARKET_FILE = Path(__file__).resolve().parent.parent / "market.json"


class InstallBody(BaseModel):
    name: str | None = None


def catalog() -> list[dict]:
    """读取清单；文件缺失或损坏时返回空表（前端显示"暂无条目"而不是 500）。"""
    try:
        raw = json.loads(MARKET_FILE.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    items = raw.get("apps") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return []
    return [item for item in items
            if isinstance(item, dict) and item.get("id") and item.get("command")]


def _installed_entry(apps: list[dict], command: str) -> dict | None:
    """按命令前缀匹配已注册应用（清单命令与注册命令开头一致即视为同一应用）。"""
    needle = command.strip()
    if not needle:
        return None
    for app in apps:
        existing = str(app.get("command") or "").strip()
        if existing and (existing.startswith(needle) or needle.startswith(existing)):
            return app
    return None


@router.get("")
async def list_market(_session: dict = Depends(require_internal)):
    apps = supervisor.registry.all()
    items = []
    for entry in catalog():
        matched = _installed_entry(apps, entry.get("command", ""))
        items.append({
            **entry,
            "installed": matched is not None,
            "app_id": (matched or {}).get("id", ""),
            "app_name": (matched or {}).get("name", ""),
        })
    return {"apps": items, "total": len(items),
            "installed": len([i for i in items if i["installed"]])}


@router.post("/{market_id}/install")
async def install_app(market_id: str, request: Request,
                      body: InstallBody | None = None,
                      _session: dict = Depends(require_internal)):
    entry = next((item for item in catalog() if item.get("id") == market_id), None)
    if entry is None:
        raise HTTPException(404, f"市场里没有该应用：{market_id}")
    apps = supervisor.registry.all()
    if _installed_entry(apps, entry.get("command", "")) is not None:
        raise HTTPException(409, f"{entry.get('name')} 已在常驻应用中注册")
    name = str((body.name if body else "") or entry.get("name") or entry["id"]).strip()
    if not NAME_RE.match(name):
        raise AppError("名称只能用字母、数字、点、下划线、连字符，长度 1~48，且以字母或数字开头")
    if supervisor.registry.by_name(name):
        raise HTTPException(409, f"名称已存在：{name}")
    cwd = str(entry.get("cwd") or "")
    if not cwd or not Path(cwd).is_dir():
        cwd = str(Path.home()) if Path.home().is_dir() else "/"
    definition = {
        "id": new_id(),
        "name": name,
        "description": str(entry.get("description") or "")[:500],
        "command": str(entry.get("command") or "").strip(),
        "cwd": cwd,
        "env": {},
        "autostart": False,
        "restart": "on-failure",
        "max_restarts": 5,
        "restart_delay": 2.0,
        "created_at": int(time.time()),
        "updated_at": int(time.time()),
        "market_id": market_id,
    }
    try:
        app = supervisor.registry.add(definition)
    except AppError as exc:
        raise HTTPException(409, str(exc))
    audit.record(AuditEvent(action="market_install", target=market_id,
                            summary=f"{name} ← {definition['command'][:200]}",
                            source="web", ip=client_ip(request),
                            extra={"app_id": app["id"], "market_id": market_id}))
    return {"ok": True, "app": supervisor.get(app["id"]),
            "message": f"已注册 {name}（未启动）。确认依赖已安装后可在「常驻应用」里试运行"}
