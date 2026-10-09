"""进程管理：列表、详情、结束/暂停/继续、调整优先级。"""

from __future__ import annotations

import asyncio
import os
import signal as signal_module

import psutil
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import require_auth, require_internal
from ..config import MODE_INTERNAL, config

router = APIRouter(prefix="/api/processes", tags=["processes"], dependencies=[Depends(require_auth)])

# 信号表按平台可用性构建：POSIX 全量可用，Windows 等平台缺 SIGKILL/SIGSTOP 时自动剔除
SIGNALS = {
    name: getattr(signal_module, attr)
    for name, attr in (
        ("term", "SIGTERM"),
        ("kill", "SIGKILL"),
        ("int", "SIGINT"),
        ("hup", "SIGHUP"),
        ("stop", "SIGSTOP"),
        ("cont", "SIGCONT"),
    )
    if hasattr(signal_module, attr)
}


class SignalBody(BaseModel):
    signal: str = "term"


class NiceBody(BaseModel):
    nice: int


def _guard_pid(pid: int) -> None:
    """拒绝对面板自身与关键进程动手：杀掉自己/守护进程会让面板直接消失。"""
    if pid in (0, 1, os.getpid(), os.getppid()):
        raise HTTPException(400, f"拒绝操作面板自身与关键系统进程（PID {pid}）")


def _process_row(proc: psutil.Process) -> dict:
    with proc.oneshot():
        mem = proc.memory_info()
        try:
            create_time = int(proc.create_time())
        except psutil.Error:
            create_time = 0
        return {
            "pid": proc.pid,
            "ppid": proc.ppid(),
            "name": proc.name(),
            "user": proc.username(),
            "status": proc.status(),
            "cpu": round(proc.cpu_percent(interval=None), 1),
            "mem": round(proc.memory_percent(), 2),
            "rss": mem.rss,
            "vms": mem.vms,
            "threads": proc.num_threads(),
            "nice": proc.nice(),
            "create_time": create_time,
            "cmdline": " ".join(proc.cmdline()) or proc.name(),
        }


@router.get("")
async def list_processes(sort: str = "cpu", limit: int = 60, q: str = "", user: str = ""):
    def _collect() -> list[dict]:
        # 先触发一次 cpu_percent 采样，稍后读取才有效
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(interval=None)
            except psutil.Error:
                continue

        rows = []
        for proc in psutil.process_iter():
            try:
                row = _process_row(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if q and q.lower() not in row["cmdline"].lower() and q.lower() not in row["name"].lower():
                continue
            if user and row["user"] != user:
                continue
            rows.append(row)
        return rows

    # 全进程表两轮扫描 + 逐进程读 /proc，量大且不可预期，放线程池跑
    rows = await asyncio.to_thread(_collect)
    key = {"cpu": "cpu", "mem": "mem", "rss": "rss", "pid": "pid", "name": "name"}.get(sort, "cpu")
    rows.sort(key=lambda r: r[key], reverse=(key not in ("pid", "name")))
    return {"total": len(rows), "processes": rows[: max(1, min(limit, 500))]}


@router.get("/{pid}")
async def process_detail(pid: int):
    def _detail() -> dict:
        try:
            proc = psutil.Process(pid)
            detail = _process_row(proc)
            try:
                detail["cwd"] = proc.cwd()
            except psutil.Error:
                detail["cwd"] = None
            try:
                detail["exe"] = proc.exe()
            except psutil.Error:
                detail["exe"] = None
            try:
                detail["open_files"] = [f.path for f in proc.open_files()][:50]
            except psutil.Error:
                detail["open_files"] = []
            try:
                detail["connections"] = [
                    {"fd": c.fd, "family": str(c.family), "type": str(c.type),
                     "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                     "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                     "status": c.status}
                    for c in proc.net_connections()
                ][:50]
            except psutil.Error:
                detail["connections"] = []
            # 进程环境变量里常见 DATABASE_URL、API key 之类密钥：
            # 只在内网模式返回，公网只读模式登录用户看不到（防信息泄露）
            if config.mode == MODE_INTERNAL:
                try:
                    detail["environ"] = dict(list(proc.environ().items())[:40])
                except psutil.Error:
                    detail["environ"] = {}
            return detail
        except psutil.NoSuchProcess:
            raise HTTPException(404, "进程不存在")
        except psutil.AccessDenied:
            raise HTTPException(403, "权限不足，无法查看该进程")

    # net_connections / open_files 都是重调用，放线程池不阻塞事件循环
    return await asyncio.to_thread(_detail)


@router.post("/{pid}/signal", dependencies=[Depends(require_internal)])
async def send_signal(pid: int, body: SignalBody):
    if body.signal not in SIGNALS:
        raise HTTPException(400, f"不支持的信号，可选：{', '.join(SIGNALS)}")
    _guard_pid(pid)
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.send_signal(SIGNALS[body.signal])
    except psutil.NoSuchProcess:
        raise HTTPException(404, "进程不存在")
    except psutil.AccessDenied:
        raise HTTPException(403, "权限不足")
    return {"ok": True, "message": f"已向 {name}({pid}) 发送 {body.signal.upper()}"}


@router.post("/{pid}/nice", dependencies=[Depends(require_internal)])
async def set_nice(pid: int, body: NiceBody):
    if not -20 <= body.nice <= 19:
        raise HTTPException(400, "nice 值需在 -20 ~ 19 之间")
    _guard_pid(pid)  # 与 signal 一致：PID 0/1 与面板自身进程一律不碰
    try:
        proc = psutil.Process(pid)
        proc.nice(body.nice)
    except psutil.NoSuchProcess:
        raise HTTPException(404, "进程不存在")
    except psutil.AccessDenied:
        raise HTTPException(403, "权限不足（降低 nice 值需要 root）")
    return {"ok": True, "message": f"PID {pid} 优先级已设为 {body.nice}"}
