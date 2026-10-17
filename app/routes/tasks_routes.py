"""常用操作 API：列出内置任务、一键执行、查看执行记录。

内置任务清单见 ``app/tasks.py``（声明式模板 + 参数正则校验）。任务整体要求内网模式，
与 ``/api/terminal/exec`` 同级——它本来就是"包装好的命令执行"，门禁不能比终端更松。

1.4.0 起执行记录改走统一审计管道（``app/audit.py``）：落盘、重启不丢、
可全类型追溯；本模块的 ``recent_runs`` 只是审计数据的任务视图。
"""

from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from .. import shell
from ..audit import AuditEvent, audit
from ..auth import client_ip, require_internal
from ..prefs import prefs
from ..tasks import public_tasks, render, task_by_id

router = APIRouter(prefix="/api/panel/tasks", tags=["panel-tasks"])


class RunBody(BaseModel):
    params: dict[str, str] = {}


def recent_runs(limit: int = 30) -> list[dict]:
    """最近任务执行记录（读审计管道）。

    事件里带 ``extra`` 兼容字段（task_id / title / params / command），
    面板「常用操作 → 最近执行记录」与任务卡片下的"上次执行"按这些字段渲染。
    """
    return audit.query(action="task_run", limit=max(1, min(limit, 100)))


def _record(task_id: str, title: str, params: dict, result, duration: float,
            command: str, ip: str) -> None:
    audit.record(AuditEvent(
        action="task_run",
        target=title or task_id,
        summary=f"id={task_id} params={params} cmd={command[:800]}",
        source="web",
        ip=ip,
        ok=result.code == 0,
        code=result.code,
        duration=duration,
        extra={"task_id": task_id, "title": title, "params": params,
               "command": command[:500]},
    ))


@router.get("")
async def list_tasks(_session: dict = Depends(require_internal)):
    return {"tasks": public_tasks(),
            "recent": await asyncio.to_thread(recent_runs)}


@router.post("/{task_id}/run")
async def run_task(task_id: str, request: Request, body: RunBody | None = None,
                   session: dict = Depends(require_internal)):
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
    _record(task.id, task.title, values, result, duration, command,
            client_ip(request))
    # 1.6.0 F1：任务失败主动通知（通知故障不影响接口返回，见 app/notify.py）
    if result.code != 0 and prefs.get("notify.on_task_fail"):
        from ..notify import notify

        await asyncio.to_thread(
            notify, "task_fail",
            f"任务「{task.title}」执行失败（退出码 {result.code}）",
        )
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
    return {"recent": await asyncio.to_thread(recent_runs)}


@router.delete("/recent")
async def clear_recent(_session: dict = Depends(require_internal)):
    # 审计记录不可删（可追溯性优先）：仅提示已归档
    return {"ok": True, "message": "执行记录已归档到审计日志（安全审计不可删除）"}
