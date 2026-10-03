"""日志与控制台输出：journal、dmesg、/var/log 文件。"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException

from .. import shell
from ..auth import require_auth

router = APIRouter(prefix="/api/logs", tags=["logs"], dependencies=[Depends(require_auth)])

PRIORITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
LOG_DIRS = ["/var/log"]
TEXT_HINT = (".log", ".txt", ".out", ".err", ".conf", "syslog", "messages", "auth.log", "kern.log")


@router.get("/sources")
async def sources():
    """报告本机可用的日志来源。"""
    files = []
    for directory in LOG_DIRS:
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            if not (name.endswith(TEXT_HINT) or "." not in name and not name.endswith(".gz")):
                continue
            try:
                stat = os.stat(full)
            except OSError:
                continue
            files.append({"path": full, "name": name, "size": stat.st_size,
                          "mtime": int(stat.st_mtime)})
    return {
        "journal": shell.available("journalctl"),
        "dmesg": shell.available("dmesg"),
        "files": files,
    }


@router.get("/journal")
async def journal(lines: int = 200, unit: str = "", priority: str = "", since: str = "", boot: bool = False):
    if not shell.available("journalctl"):
        raise HTTPException(400, "本机缺少 journalctl，无法读取系统日志")
    lines = max(1, min(lines, 5000))
    cmd = ["journalctl", "--no-pager", "-n", str(lines), "--output=short-iso"]
    if boot:
        cmd.append("-b")
    if unit:
        cmd += ["-u", unit]
    if priority and priority in PRIORITIES:
        cmd += ["-p", priority]
    if since:
        cmd += ["--since", since]
    result = await shell.run(cmd, timeout=30)
    return {"lines": result.out.splitlines(), "ok": result.ok,
            "error": None if result.ok else (result.err or result.out).strip()[:2000]}


@router.get("/dmesg")
async def dmesg(lines: int = 200):
    if not shell.available("dmesg"):
        raise HTTPException(400, "本机缺少 dmesg，无法读取内核日志")
    lines = max(1, min(lines, 5000))
    result = await shell.run(["dmesg", "--time-format=iso"], timeout=20)
    if not result.ok:
        # 部分系统需要显式提升权限
        result = await shell.run(["dmesg"], timeout=20)
    if not result.ok:
        raise HTTPException(500, (result.err or result.out).strip()[:2000] or "读取内核日志失败")
    return {"lines": result.out.splitlines()[-lines:]}


@router.get("/tail")
async def tail(path: str, lines: int = 200):
    lines = max(1, min(lines, 5000))
    full = os.path.abspath(path)
    allowed = any(full == d or full.startswith(d.rstrip("/") + "/") for d in LOG_DIRS)
    if not allowed and os.geteuid() != 0:
        raise HTTPException(403, "仅允许读取 /var/log 下的日志文件")
    if not os.path.isfile(full):
        raise HTTPException(404, "日志文件不存在")
    result = await shell.run(["tail", "-n", str(lines), full], timeout=20)
    if not result.ok:
        raise HTTPException(500, result.text or "读取失败")
    return {"path": full, "lines": result.out.splitlines()}


@router.get("/file")
async def read_log(path: str, max_bytes: int = 256 * 1024):
    full = os.path.abspath(path)
    allowed = any(full == d or full.startswith(d.rstrip("/") + "/") for d in LOG_DIRS)
    if not allowed and os.geteuid() != 0:
        raise HTTPException(403, "仅允许读取 /var/log 下的日志文件")
    if not os.path.isfile(full):
        raise HTTPException(404, "日志文件不存在")
    size = os.path.getsize(full)
    limit = max(1024, min(max_bytes, 2 * 1024 * 1024))
    with open(full, "rb") as fh:
        if size > limit:
            fh.seek(-limit, os.SEEK_END)
        data = fh.read()
    return {
        "path": full,
        "size": size,
        "truncated": size > limit,
        "content": data.decode("utf-8", "replace"),
    }
