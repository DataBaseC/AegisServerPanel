"""常用操作 API：列出内置任务、一键执行、查看执行记录。

内置任务清单见 ``app/tasks.py``（声明式模板 + 参数正则校验）。任务整体要求内网模式，
与 ``/api/terminal/exec`` 同级——它本来就是"包装好的命令执行"，门禁不能比终端更松。
"""

from __future__ import annotations

import time
from collections import deque

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import shell
from ..auth import require_internal
from ..tasks import public_tasks, render, task_by_id

router = APIRouter(prefix="/api/panel/tasks", tags=["panel-tasks"])

RECORD_LIMIT = 30
_records: deque[dict] = deque(maxlen=RECORD_LIMIT)


class RunBody(BaseModel):
    params: dict[str, str] = {}


def recent_runs() -> list[dict]:
    return list(_records)


def _record(task_id: str, title: str, params: dict, code: int, duration: float,
            command: str) -> None:
    _records.appendleft({
        "time": int(time.time()),
        "task_id": task_id,
        "title": title,
        "params": params,
        "code": code,
        "duration": round(duration, 2),
        "command": command[:500],
    })


@router.get("")
async def list_tasks(_session: dict = Depends(require_internal)):
    return {"tasks": public_tasks(), "recent": recent_runs()}


@router.post("/{task_id}/run")
async def run_task(task_id: str, body: RunBody | None = None,
                   _session: dict = Depends(require_internal)):
    task = task_by_id(task_id)
    if task is None:
        raise HTTPException(404, "任务不存在")
    values = (body.params if body else {}) or {}
    missing = [p.label for p in task.params if not str(values.get(p.name) or p.default).strip()]
    if missing:
        raise HTTPException(400, f"缺少参数：{', '.join(missing)}")
    try:
        command = render(task, values)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    started = time.time()
    result = await shell.run(command, timeout=task.timeout, shell=True)
    duration = time.time() - started
    _record(task.id, task.title, values, result.code, duration, command)
    return {
        "ok": result.code == 0,
        "code": result.code,
        "stdout": result.out,
        "stderr": result.err,
        "command": command,
        "duration": round(duration, 2),
        "title": task.title,
    }


@router.get("/recent")
async def recent(_session: dict = Depends(require_internal)):
    return {"recent": recent_runs()}


@router.delete("/recent")
async def clear_recent(_session: dict = Depends(require_internal)):
    _records.clear()
    return {"ok": True, "message": "执行记录已清空"}
