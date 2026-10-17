"""系统命令执行封装。

所有命令都在独立子进程中执行，附带超时保护与输出长度限制，
避免某条命令把服务拖死：

- **超时杀整组**：``shell=True`` 时命令经 sh 执行，管道会 fork 出孙进程；
  只 kill 直接子进程会让 ``find /`` / ``du`` 之类的重活继续在后台跑。
  因此 POSIX 下用独立会话启动，超时后 ``killpg`` 整组。
- **输出有上限**：超过 ``MAX_OUTPUT`` 的部分继续读出丢弃（不缓冲），
  而不是先 ``communicate()`` 全量进内存再切片——后者遇到 ``cat`` 大文件
  或 ``yes`` 会直接把面板 OOM 掉。
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shlex
import shutil
import signal
import subprocess
from dataclasses import dataclass

MAX_OUTPUT = 512 * 1024  # 单次命令最多回传 512KB
READ_CHUNK = 64 * 1024


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


def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    """强杀子进程及其进程组（POSIX）；失败/已退出时静默。"""
    with contextlib.suppress(ProcessLookupError, OSError):
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:  # pragma: no cover - 非 POSIX 平台没有进程组语义
            proc.kill()


async def _read_capped(stream: asyncio.StreamReader | None) -> bytes:
    """读取流并最多保留 ``MAX_OUTPUT`` 字节。

    超限后仍继续读取到 EOF，只是不再累积：不读会把子进程堵在写管道上，
    导致它无法退出，超时保护也就失去了意义。
    """
    if stream is None:
        return b""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(READ_CHUNK)
        if not chunk:
            break
        if total < MAX_OUTPUT:
            chunks.append(chunk[: MAX_OUTPUT - total])
        total += len(chunk)
    return b"".join(chunks)


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
    if os.name == "posix":
        # 独立会话 = 独立进程组，超时可以整组清理（含管道里的孙进程）
        kwargs["start_new_session"] = True
    if cwd:
        kwargs["cwd"] = cwd
    if env:
        kwargs["env"] = {**os.environ, **env}

    try:
        if shell:
            spawning = asyncio.create_subprocess_shell(args[0], **kwargs)
        else:
            spawning = asyncio.create_subprocess_exec(*args, **kwargs)
        # spawn 本身也可能挂住（多线程 fork 在 PRoot 上有持锁风险），
        # 必须一并纳入超时保护，否则 wait_for 的超时永远轮不到
        proc = await asyncio.wait_for(spawning, timeout=min(timeout, 15))
    except asyncio.TimeoutError:
        return Result(-1, "", "子进程创建超时")
    except (OSError, ValueError) as exc:
        return Result(-1, "", f"无法启动命令: {exc}")

    async def _collect() -> tuple[bytes, bytes]:
        if stdin is not None and proc.stdin is not None:
            with contextlib.suppress(BrokenPipeError, ConnectionResetError, OSError):
                proc.stdin.write(stdin)
                await proc.stdin.drain()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError, OSError):
                proc.stdin.close()
        out, err = await asyncio.gather(
            _read_capped(proc.stdout), _read_capped(proc.stderr))
        await proc.wait()
        return out, err

    try:
        out, err = await asyncio.wait_for(_collect(), timeout=timeout)
    except asyncio.TimeoutError:
        _kill_tree(proc)
        with contextlib.suppress(ProcessLookupError, OSError, asyncio.TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=3)
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
        # 同样用独立进程组 + 超时整组清理（subprocess.run 的超时只杀 sh 本身）
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=(os.name == "posix"))
    except (OSError, ValueError) as exc:
        return Result(-1, "", str(exc))
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        with contextlib.suppress(OSError, ValueError):
            out, err = proc.communicate(timeout=3)
        return Result(-1, "", f"命令执行超时（{timeout:g}s）")
    return Result(
        proc.returncode,
        out.decode("utf-8", "replace")[:MAX_OUTPUT],
        err.decode("utf-8", "replace")[:MAX_OUTPUT],
    )
