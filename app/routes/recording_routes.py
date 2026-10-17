"""终端会话录制管理（2.0 M5）：列表 / 回放数据 / 删除。

录制本身在 ``app/recording.py`` 与终端 WS 中完成；这里只读文件，路径由
``recording.NAME_RE`` 严格约束，不允许穿越。
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request

from .. import recording
from ..audit import AuditEvent, audit
from ..auth import client_ip, require_internal
from ..prefs import prefs

router = APIRouter(prefix="/api/panel/recordings", tags=["recordings"],
                   dependencies=[Depends(require_internal)])


def _scan(directory) -> list[dict]:
    """枚举录制文件（同步 IO，调用方下线程池）。

    单个文件 stat 失败只跳过该条：原实现让 sorted(key=stat) 的异常被外层
    ``except OSError`` 吞掉，一个坏文件就会让整个列表变成「没有录制」。
    """
    found: list[tuple[float, dict]] = []
    try:
        paths = list(directory.glob("*.cast"))
    except OSError:
        return []
    for path in paths:
        if not recording.NAME_RE.fullmatch(path.name):
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        found.append((stat.st_mtime, {"name": path.name, "size": stat.st_size,
                                      "time": int(stat.st_mtime)}))
    found.sort(key=lambda item: item[0], reverse=True)
    return [item for _mtime, item in found]


@router.get("")
async def list_recordings():
    directory = recording.recordings_dir()
    items = await asyncio.to_thread(_scan, directory)
    return {"items": items, "enabled": bool(prefs.get("terminal.record_sessions")),
            "dir": str(directory)}


@router.get("/{name}")
async def get_recording(name: str):
    if not recording.NAME_RE.fullmatch(name):
        raise HTTPException(404, "录制不存在或格式不正确")
    path = recording.recordings_dir() / name
    try:
        size = path.stat().st_size
    except OSError:
        raise HTTPException(404, "录制不存在")
    if size > recording.MAX_REPLAY_BYTES:
        # 整份转成 JSON 事件数组会把内存放大数倍：超限时提示到服务器端回放
        raise HTTPException(
            413, f"录制文件过大（{size // (1024 * 1024)}MB），"
                 f"请在服务器上用 asciinema play 回放，或先分段导出")
    events = await asyncio.to_thread(recording.load_events, name)
    if events is None:
        raise HTTPException(404, "录制不存在或格式不正确")
    return {"name": name, "events": events}


@router.delete("/{name}")
async def delete_recording(name: str, request: Request):
    if not recording.NAME_RE.fullmatch(name):
        raise HTTPException(400, "录制文件名不合法")
    path = recording.recordings_dir() / name
    if not path.exists():
        raise HTTPException(404, "录制不存在")
    try:
        path.unlink()
    except OSError as exc:
        raise HTTPException(500, f"删除失败: {exc}")
    audit.record(AuditEvent(action="recording_delete", target=name,
                            source="web", ip=client_ip(request)))
    return {"ok": True, "message": f"已删除 {name}"}
