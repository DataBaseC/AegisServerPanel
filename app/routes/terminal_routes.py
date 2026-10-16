"""交互式终端：基于 PTY 的 WebSocket 会话，以及一次性命令执行接口。"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import time

from fastapi import APIRouter, Depends, HTTPException, WebSocket
from pydantic import BaseModel

from .. import shell
from ..audit import AuditEvent, audit
from ..auth import authenticate_ws, require_exec_auth, require_internal, sessions
from ..config import MODE_INTERNAL, config
from ..utils import is_root

# 终端拥有完整 root shell，仅在内网模式开放
router = APIRouter(tags=["terminal"])

# pty/fcntl/termios 仅存在于 POSIX 平台；缺失时保持可导入（服务管理等功能不受影响），
# 终端相关接口在运行时优雅报错，而不是整个进程起不来。
try:
    import fcntl
    import pty
    import struct
    import termios

    HAS_PTY = True
except ImportError:  # pragma: no cover - Windows 开发环境
    HAS_PTY = False


def recent_execs(limit: int = 40) -> list[dict]:
    """最近命令执行记录（面板「Agent 接入」页速览）。

    1.4.0 起改读统一审计管道：重启不丢、可追溯全类型操作。
    """
    return audit.query(action="exec", limit=max(1, min(limit, 100)))


class ExecBody(BaseModel):
    command: str
    cwd: str | None = None
    timeout: float = 60


def _pick_shell() -> str:
    override = os.environ.get("SERVERPANEL_SHELL")
    if override and os.path.exists(override):
        return override
    for candidate in ("/bin/bash", "/usr/bin/bash", "/bin/sh"):
        if os.path.exists(candidate):
            return candidate
    return os.environ.get("COMSPEC", "/bin/sh")  # 非 POSIX 平台的兜底


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except OSError:
        pass


def _child_setup() -> None:
    """让 PTY 成为子进程的控制终端，交互式 shell 才能正常工作。"""
    try:
        os.setsid()
    except OSError:
        pass
    try:
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    except OSError:
        pass


@router.get("/api/terminal/info")
async def terminal_info(_session: dict = Depends(require_internal)):
    if not HAS_PTY:
        raise HTTPException(501, "当前平台不支持 PTY 终端")
    return {
        "shell": _pick_shell(),
        "user": os.environ.get("USER") or "root",
        "cwd": os.path.expanduser("~"),
        "cwd_exists": os.path.isdir(os.path.expanduser("~")),
        "is_root": is_root(),
        "active_sessions": sessions.active_count(),
    }


@router.post("/api/terminal/exec")
async def exec_command(body: ExecBody, auth: dict = Depends(require_exec_auth)):
    """执行单条命令并返回输出。

    面板会话与 Agent 令牌都可以调用，用于非交互场景（脚本 / AI Agent 接管）。
    1.4.0 起 Agent 令牌按作用域校验命令（readonly / custom 前缀白名单），
    见 ``app/scopes.py``。
    """
    if not body.command.strip():
        raise HTTPException(400, "命令不能为空")
    if len(body.command) > 64 * 1024:
        raise HTTPException(400, "命令过长（上限 64KB）")
    # 链式比较连 NaN 一起拒：NaN 与任何值比较都是 False，
    # 而 body.timeout <= 0 or body.timeout > 600 这种写法会让 NaN 溜过去
    if not (1 <= body.timeout <= 600):
        raise HTTPException(400, "timeout 需在 1~600 秒之间")
    # 令牌作用域校验（面板会话不限制）
    if auth.get("kind") == "agent":
        from ..scopes import command_allowed

        if not command_allowed(auth.get("scope", "full"),
                               auth.get("prefixes") or [], body.command):
            audit.record(AuditEvent(
                action="exec_denied",
                target=body.command,
                summary=f"令牌 {auth.get('token_name', '')} 作用域不足",
                source="agent",
                ip=auth.get("ip", ""),
                ok=False,
            ))
            scope = auth.get("scope", "full")
            detail = ("该令牌为只读作用域，仅允许执行查询类命令"
                      if scope == "readonly"
                      else f"该令牌仅允许执行以指定前缀开头的命令（{', '.join(auth.get('prefixes') or [])}）")
            raise HTTPException(403, detail)
    started = time.time()
    result = await shell.run(
        body.command,
        timeout=body.timeout,
        shell=True,
        cwd=body.cwd if body.cwd and os.path.isdir(body.cwd) else None,
    )
    # 统一审计管道：落盘可追溯（面板会话与 Agent 令牌共用同一通道）
    kind = "agent" if auth.get("kind") == "agent" else "web"
    audit.record(AuditEvent(
        action="exec",
        target=body.command,  # AuditEvent 内部统一截断到 2000 字符
        summary=f"cwd={body.cwd or '-'} timeout={body.timeout:g}s",
        source=kind,
        ip=auth.get("ip", ""),
        actor=auth.get("token_name", ""),
        ok=result.code == 0,
        code=result.code,
        duration=time.time() - started,
        # 兼容字段：面板「Agent 接入 → 最近执行」按 kind/command 渲染
        # （1.4.0 换成审计事件后这两列曾经变成空白/错标）
        extra={"kind": kind, "command": body.command[:2000]},
    ))
    return {"code": result.code, "stdout": result.out, "stderr": result.err}


@router.websocket("/api/terminal/ws")
async def terminal_socket(websocket: WebSocket):
    if not HAS_PTY:
        await websocket.accept()
        await websocket.send_text("\x1b[31m当前平台不支持 PTY 终端\x1b[0m")
        await websocket.close(code=1011)
        return
    if not await authenticate_ws(websocket, internal_only=True):
        return
    await websocket.accept()

    shell_path = _pick_shell()
    env = os.environ.copy()
    env.update({
        "TERM": "xterm-256color",
        "COLORTERM": "truecolor",
        "LANG": env.get("LANG", "C.UTF-8"),
        "SERVERPANEL": "1",
    })
    home = os.path.expanduser("~")
    cwd = home if os.path.isdir(home) else "/"

    master, slave = pty.openpty()
    try:
        process = await asyncio.create_subprocess_exec(
            shell_path, "-l",
            stdin=slave, stdout=slave, stderr=slave,
            cwd=cwd, env=env, preexec_fn=_child_setup, close_fds=True,
        )
    except OSError as exc:
        os.close(master)
        os.close(slave)
        await websocket.send_text(f"\r\n\x1b[31m无法启动 shell: {exc}\x1b[0m\r\n")
        await websocket.close()
        return
    os.close(slave)
    os.set_blocking(master, False)

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[bytes | None] = asyncio.Queue()

    def on_readable() -> None:
        try:
            data = os.read(master, 65536)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        queue.put_nowait(data if data else None)

    loop.add_reader(master, on_readable)

    async def pump_output() -> None:
        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            await websocket.send_bytes(chunk)

    async def pump_input() -> None:
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break
            if message.get("bytes") is not None:
                os.write(master, message["bytes"])
                continue
            text = message.get("text")
            if text is None:
                continue
            # 控制消息为 JSON，其余按原样送入终端
            if text.startswith("{"):
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict) and payload.get("type") == "resize":
                    _set_winsize(
                        master,
                        int(payload.get("rows", 24)),
                        int(payload.get("cols", 80)),
                    )
                    continue
            os.write(master, text.encode())

    async def watch_mode() -> None:
        """内网模式被关闭后，立即终止已建立的终端会话。"""
        while config.mode == MODE_INTERNAL:
            await asyncio.sleep(2)
        try:
            await websocket.send_text("\r\n\x1b[33m内网模式已关闭，终端会话已终止。\x1b[0m\r\n")
        except Exception:
            pass

    output_task = asyncio.create_task(pump_output())
    input_task = asyncio.create_task(pump_input())
    mode_task = asyncio.create_task(watch_mode())

    try:
        await asyncio.wait(
            {output_task, input_task, mode_task}, return_when=asyncio.FIRST_COMPLETED
        )
    except Exception:
        pass
    finally:
        for task in (output_task, input_task, mode_task):
            task.cancel()
        try:
            loop.remove_reader(master)
        except (OSError, ValueError):
            pass
        try:
            os.close(master)
        except OSError:
            pass
        if process.returncode is None:
            try:
                # shell 已 setsid 成会话首进程：收尾要 TERM 整个进程组，
                # 否则用户在终端里跑的前台/后台程序会脱离管理继续存活。
                # killpg/getpgid 只在 POSIX 存在（同 apps.py / manage.py 的写法），
                # 缺了就退回单进程终止，别让 AttributeError 跳过下面的 websocket.close()
                if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                else:  # pragma: no cover - 非 POSIX 平台（PTY 门禁之外的双保险）
                    process.terminate()
                await asyncio.wait_for(process.wait(), timeout=3)
            except (ProcessLookupError, PermissionError, asyncio.TimeoutError, OSError):
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
        try:
            await websocket.close()
        except Exception:
            pass
