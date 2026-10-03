"""系统命令执行封装。

所有命令都在独立子进程中执行，附带超时保护与输出长度限制，
避免某条命令把服务拖死。
"""

from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass

MAX_OUTPUT = 512 * 1024  # 单次命令最多回传 512KB


@dataclass
class Result:
    code: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.code == 0

    @property
    def text(self) -> str:
        return self.out if self.out.strip() else self.err


def which(binary: str) -> str | None:
    return shutil.which(binary)


def available(binary: str) -> bool:
    return shutil.which(binary) is not None


async def run(
    cmd: str | list[str],
    timeout: float = 30,
    shell: bool = False,
    cwd: str | None = None,
    env: dict | None = None,
    stdin: bytes | None = None,
) -> Result:
    """执行命令并返回结果，超时返回 code=-1。"""
    if isinstance(cmd, str) and not shell:
        args: list[str] = shlex.split(cmd)
    elif isinstance(cmd, str):
        args = [cmd]
    else:
        args = list(cmd)

    if not shell and not args:
        return Result(-1, "", "空命令")
    if not shell and not shutil.which(args[0]) and not os.path.exists(args[0]):
        return Result(127, "", f"命令不存在: {args[0]}")

    kwargs = dict(stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    if cwd:
        kwargs["cwd"] = cwd
    if env:
        kwargs["env"] = {**os.environ, **env}

    try:
        if shell:
            proc = await asyncio.create_subprocess_shell(args[0], **kwargs)
        else:
            proc = await asyncio.create_subprocess_exec(*args, **kwargs)
    except (OSError, ValueError) as exc:
        return Result(-1, "", f"无法启动命令: {exc}")

    try:
        out, err = await asyncio.wait_for(proc.communicate(input=stdin), timeout=timeout)
    except asyncio.TimeoutError:
        # 超时与进程自行退出之间存在竞态：kill 可能撞上 ProcessLookupError
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()
        with contextlib.suppress(ProcessLookupError):
            await proc.wait()
        return Result(-1, "", f"命令执行超时（{timeout:g}s）")

    return Result(
        proc.returncode or 0,
        out.decode("utf-8", "replace")[:MAX_OUTPUT],
        err.decode("utf-8", "replace")[:MAX_OUTPUT],
    )


def run_sync(cmd: str | list[str], timeout: float = 30) -> Result:
    """同步版本，用于启动阶段等无法 await 的场景。"""
    args = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    if not args or not shutil.which(args[0]):
        return Result(127, "", f"命令不存在: {args[0] if args else ''}")
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Result(-1, "", str(exc))
    return Result(
        proc.returncode,
        proc.stdout.decode("utf-8", "replace")[:MAX_OUTPUT],
        proc.stderr.decode("utf-8", "replace")[:MAX_OUTPUT],
    )
