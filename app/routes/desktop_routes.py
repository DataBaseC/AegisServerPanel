"""Web 桌面的状态接口（M0 原型）。

桌面布局是非关键数据：读失败回退默认布局，写失败最多丢一次窗口位置。
因此这里不做复杂迁移，只保证两点：

- 按用户名分文件，写入原子（临时文件 + ``os.replace``）且权限 0600；
- 只接受 JSON 对象并限制体积，避免变成任意文件写入通道。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import require_auth, session_username
from ..config import config

router = APIRouter(prefix="/api/desktop", tags=["desktop"])

# 同一进程内的并发写串行化（面板单进程 + 线程池）
_WRITE_LOCK = threading.Lock()
MAX_LAYOUT_BYTES = 512 * 1024
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class LayoutBody(BaseModel):
    layout: dict


def _dir():
    # 与主配置同目录，保持"一个部署一个目录"；不放 /var/lib 是为了让
    # 自定义 SERVERPANEL_CONFIG 的开发实例同样自包含。
    return config.path.parent / "desktop"


def _file(username: str):
    name = (username if _SAFE_NAME.match(username)
            else "u-" + hashlib.sha256(username.encode()).hexdigest()[:16])
    return _dir() / f"{name}.json"


def _default(username: str) -> dict:
    return {
        "version": 1,
        "username": username,
        "theme": {"accent": "#E95420", "dark": True, "wallpaper": "default"},
        "dock": ["terminal"],
        "windows": [],
        "updated_at": 0,
    }


def load_layout(username: str) -> dict:
    """读取用户布局；文件缺失/损坏时回退默认布局（不抛错）。"""
    try:
        data = json.loads(_file(username).read_text("utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return _default(username)
    if not isinstance(data, dict) or not isinstance(data.get("windows"), list):
        return _default(username)
    return data


def _save(username: str, layout: dict) -> None:
    payload = json.dumps(layout, ensure_ascii=False, indent=2)
    if len(payload.encode("utf-8")) > MAX_LAYOUT_BYTES:
        raise HTTPException(413, "桌面布局过大（上限 512KB）")
    path = _file(username)
    with _WRITE_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        tmp.write_text(payload, "utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)


@router.get("/bootstrap")
async def bootstrap(session: dict = Depends(require_auth)):
    """桌面首屏一次性拿齐：身份、角色、模式、布局。"""
    username = session_username(session)
    return {
        "ok": True,
        "username": username,
        "role": session.get("role"),
        "mode": config.mode,
        "mode_label": config.mode_label,
        "layout": load_layout(username),
    }


@router.get("/layout")
async def get_layout(session: dict = Depends(require_auth)):
    username = session_username(session)
    return {"ok": True, "layout": load_layout(username)}


@router.put("/layout")
async def put_layout(body: LayoutBody, session: dict = Depends(require_auth)):
    username = session_username(session)
    layout = dict(body.layout)
    # 用户名与时间戳由服务端决定，避免客户端伪造他人布局/时间
    layout["username"] = username
    layout["updated_at"] = int(time.time())
    _save(username, layout)
    return {"ok": True, "updated_at": layout["updated_at"]}
