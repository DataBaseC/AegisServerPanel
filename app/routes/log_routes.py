"""日志与控制台输出：journal、dmesg、日志目录白名单内的文本文件。"""

from __future__ import annotations

import asyncio
import os

from fastapi import APIRouter, Depends, HTTPException

from .. import shell
from ..auth import require_auth
from ..config import config
from ..utils import log_dir_reason

router = APIRouter(prefix="/api/logs", tags=["logs"], dependencies=[Depends(require_auth)])

PRIORITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
TEXT_HINT = (".log", ".txt", ".out", ".err", ".conf", "syslog", "messages", "auth.log", "kern.log")


def _allowed_log_path(path: str) -> bool:
    """路径必须落在日志白名单目录内（realpath 解析，防 /var/log 符号链接指向别处）。

    与运行身份无关：root 也只允许读白名单。否则公网只读模式下，
    任何登录用户都能读取 /etc/shadow、面板配置等系统任意文件。
    """
    real = os.path.realpath(os.path.abspath(path))
    for d in config.log_dirs:
        if real == d or real.startswith(os.path.join(d, "")):  # join(d,"") 补全目录分隔符
            # 兜底再判一次白名单目录本身是否安全：白名单未必经面板写入
            # （配置导入会整体替换 config.data，也可能有人手工改了 config.json），
            # 只靠写入时校验会漏。敏感/隐藏目录一律不认。
            return log_dir_reason(d) is None
    return False


def _check_readable(path: str) -> str:
    full = os.path.abspath(path)
    if not _allowed_log_path(full):
        raise HTTPException(403, "仅允许读取日志目录白名单内的文件（默认 /var/log，"
                                 "可在配置文件中设置 log_dirs 扩展）")
    if not os.path.isfile(full):
        raise HTTPException(404, "日志文件不存在")
    return full


@router.get("/sources")
async def sources():
    """报告本机可用的日志来源。"""
    files = []
    for directory in config.log_dirs:
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
    full = _check_readable(path)
    before = os.stat(full)
    result = await shell.run(["tail", "-n", str(lines), full], timeout=20)
    # 前后 stat 比对（dev/ino）：校验到 tail 执行之间文件被换成白名单外的链接就作废
    after = os.stat(full)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise HTTPException(403, "文件在校验后被替换为白名单外的链接，已拒绝读取")
    if not result.ok:
        raise HTTPException(500, result.text or "读取失败")
    return {"path": full, "lines": result.out.splitlines()}


@router.get("/file")
async def read_log(path: str, max_bytes: int = 256 * 1024):
    full = _check_readable(path)
    size = os.path.getsize(full)
    limit = max(1024, min(max_bytes, 2 * 1024 * 1024))

    def _read() -> bytes:
        with open(full, "rb") as fh:
            # 打开后复核 fd 真实落点：白名单校验到打开之间若被换成指向名单外的
            # 符号链接（TOCTOU），此刻已跟随链接打开，这里能抓住并拒绝。
            fd_path = f"/proc/self/fd/{fh.fileno()}"
            if os.path.exists(fd_path) and not _allowed_log_path(os.path.realpath(fd_path)):
                raise HTTPException(403, "文件在校验后被替换为白名单外的链接，已拒绝读取")
            if size > limit:
                fh.seek(-limit, os.SEEK_END)
            return fh.read()

    data = await asyncio.to_thread(_read)  # 大日志读盘不阻塞事件循环
    return {
        "path": full,
        "size": size,
        "truncated": size > limit,
        "content": data.decode("utf-8", "replace"),
    }
