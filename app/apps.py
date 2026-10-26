"""常驻应用管理：把一条命令交给面板托管，长期运行且不随会话消失。

设计要点（与现有代码的既有约定保持一致）：

- **注册表与配置分离**：应用定义写在与 ``config.json`` 同目录的 ``apps.json``
  （0600，临时文件名带 pid + ``os.replace`` 原子替换，避免面板与 CLI 并发写互相踩）。
- **进程独立成组**：托管进程一律 ``start_new_session=True``，与面板进程组解耦，
  因此面板升级 / 守护重启不会连带杀死应用；反过来，停面板时会显式结束它们
  （见 ``manage.py`` 的 ``_panel_pids``）。
- **单一实现两处复用**：Web 路由与 ``serverpanel --apps`` 共用这里的注册表与
  同步控制函数，避免两套行为漂移。
- **异步驱动、同步兜底**：进程由 ``asyncio`` 子进程驱动（不阻塞事件循环），
  同时提供 ``run_sync`` 系列供 CLI / 测试等无事件循环场景使用。

托管命令通过 ``/bin/sh -c`` 执行，与 ``/api/terminal/exec`` 的语义一致——面板本身
就是 root shell 的等价物，这里不额外制造"更安全"的假象，而是把持久化与可观测性做对。
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .config import config
from .prefs import prefs

# ---------------------------------------------------------------- 常量与校验

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")
RESTART_POLICIES = ("never", "on-failure", "always")
DEFAULT_TIMEOUT = 10.0            # 注册时的试运行/停止等待上限
BOOT_DELAY = 2.0                  # 面板启动后延迟拉起自启应用，先让服务就绪
FAIL_WINDOW = 300.0               # 重启次数统计窗口（秒）
FAIL_LIMIT = 5                    # 窗口内重启超过此值 → failed（可被应用自身 max_restarts 覆盖）
TRUNCATE_LINE = 2000              # 单行日志截断长度，防一条超长行撑爆内存
MEM_LINES = 2000                  # 内存环形缓冲保留行数
LOG_MAX_BYTES = 4 * 1024 * 1024   # 日志上限的出厂默认值（实际以「快捷设置」里的 prefs 为准）
READ_CHUNK = 256 * 1024           # 单次日志读取上限

# 「升级 / 重启不杀托管应用」的交接协议：
# 重启前由 CLI 写一个带时间戳的标记文件，lifespan 退出时读到它就不结束应用；
# 新进程启动时按每个应用的 pidfile 接管仍在运行的那些（见 Supervisor.adopt_all）。
# 标记带 TTL：重启最终没发生（升级失败/命令被打断）时不会让后面的 --stop 漏杀。
PID_SUFFIX = ".pid"
SURVIVE_MARKER = ".apps-survive"
SURVIVE_TTL = 180.0

# 面板自身的启动特征：禁止把面板注册成"常驻应用"，
# 否则会出现「应用重启 → 面板重启 → 应用重启」的递归雪崩。
SELF_MARKERS = ("-m app.main", "app.main --host", "panel-supervisor.sh")


# 面板线上只跑 Linux；Windows 开发机上没有 SIGKILL/SIGKILL 语义，
# 统一用 getattr 兜底，避免"开发环境直接报 AttributeError"这种无意义阻塞。
SIG_TERM = getattr(signal, "SIGTERM", 15)
SIG_KILL = getattr(signal, "SIGKILL", SIG_TERM)


def shell_argv(command: str) -> list[str]:
    """构造 ``[shell, flag, command]``。

    面板线上只跑 Linux，但开发/测试会在 Windows 上进行，因此这里做平台适配，
    避免"托管应用"功能在开发机上直接不可用（Windows 用 ``cmd /c``，POSIX 用 ``sh -c``）。
    """
    if sys.platform == "win32":
        shell = os.environ.get("SERVERPANEL_SHELL") or os.environ.get("COMSPEC") or "cmd.exe"
        return [shell, "/c", command]
    override = os.environ.get("SERVERPANEL_SHELL")
    candidates = [override] if override else []
    candidates += ["/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh"]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return [candidate, "-c", command]
    return ["/bin/sh", "-c", command]


class AppError(ValueError):
    """应用定义不合法或操作不被允许。"""


# ---------------------------------------------------------------- 注册表

def default_registry_path() -> Path:
    """注册表固定与配置文件同目录（``SERVERPANEL_CONFIG`` 指向哪里就跟着去哪里）。

    ``SERVERPANEL_APPS_DIR`` 可显式覆盖目录，测试与本地冒烟用它把注册表和日志
    隔离到临时目录，避免污染真实部署。
    """
    override = os.environ.get("SERVERPANEL_APPS_DIR")
    if override:
        return Path(override) / "apps.json"
    return Path(config.path).parent / "apps.json"


class Registry:
    """``apps.json`` 的读写（原子替换 + 进程内锁）。"""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_registry_path()
        self._lock = threading.RLock()
        self._mtime = 0.0
        self._apps: list[dict] = []

    # ---- 读 ----
    def _load_unlocked(self) -> None:
        apps: list[dict] = []
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text("utf-8"))
                if isinstance(raw, dict):
                    raw = raw.get("apps")
                if isinstance(raw, list):
                    cleaned = [a for a in raw if isinstance(a, dict) and a.get("id")]
                    if raw and not cleaned:
                        # 非空但一条都认不出来：结构已被写坏，按读取失败处理
                        raise ValueError("注册表条目结构异常")
                    apps = cleaned
                else:
                    # 合法 JSON 但结构不对（"str" / {"other":1} / 被截断成 dict）：
                    # 一样当作读取失败处理，否则同样会把守护中的进程全变成孤儿
                    raise ValueError(f"注册表结构异常：{type(raw).__name__}")
            except (OSError, json.JSONDecodeError, ValueError):
                # 读失败/文件损坏时保留上一份注册表：置空会让正在运行的托管应用
                # 瞬间失去管理（Supervisor.list 会把不在注册表的 runtime 丢弃），
                # 一次瞬时 IO 失败就不该把守护中的进程全变成孤儿
                apps = list(self._apps)
        self._apps = apps
        self._mtime = self._mtime_now()

    def _mtime_now(self) -> float:
        try:
            return self.path.stat().st_mtime
        except OSError:
            return 0.0

    def reload_if_changed(self) -> bool:
        mtime = self._mtime_now()
        with self._lock:
            if mtime == self._mtime:
                return False
            self._load_unlocked()
        return True

    def load(self) -> None:
        """无条件重读注册表（测试与显式刷新用）。"""
        with self._lock:
            self._load_unlocked()

    def all(self) -> list[dict]:
        self.reload_if_changed()
        with self._lock:
            return [dict(a) for a in self._apps]

    def get(self, app_id: str) -> dict | None:
        self.reload_if_changed()
        with self._lock:
            for app in self._apps:
                if app["id"] == app_id:
                    return dict(app)
        return None

    def by_name(self, name: str) -> dict | None:
        self.reload_if_changed()
        with self._lock:
            for app in self._apps:
                if a_name(app) == name:
                    return dict(app)
        return None

    # ---- 写 ----
    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"version": 1, "apps": self._apps}
            tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
            tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), "utf-8")
            with contextlib.suppress(OSError):
                os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
            self._mtime = self._mtime_now()

    def add(self, app: dict) -> dict:
        self.reload_if_changed()
        with self._lock:
            if any(a["id"] == app["id"] for a in self._apps):
                raise AppError("应用 ID 冲突，请重试")
            if any(a_name(a) == a_name(app) for a in self._apps):
                raise AppError(f"名称已存在：{a_name(app)}")
            self._apps.append(app)
            self.save()
        return dict(app)

    def update(self, app_id: str, patch: dict) -> dict:
        self.reload_if_changed()
        with self._lock:
            for index, app in enumerate(self._apps):
                if app["id"] != app_id:
                    continue
                merged = {**app, **patch, "id": app["id"], "created_at": app.get("created_at", 0)}
                if any(a_name(a) == a_name(merged) for i, a in enumerate(self._apps) if i != index):
                    raise AppError(f"名称已存在：{a_name(merged)}")
                merged["updated_at"] = int(time.time())
                self._apps[index] = merged
                self.save()
                return dict(merged)
        raise AppError("应用不存在")

    def remove(self, app_id: str) -> dict:
        self.reload_if_changed()
        with self._lock:
            for index, app in enumerate(self._apps):
                if app["id"] == app_id:
                    self._apps.pop(index)
                    self.save()
                    return dict(app)
        raise AppError("应用不存在")


def a_name(app: dict) -> str:
    return str(app.get("name") or app.get("id") or "")


def new_id() -> str:
    return secrets.token_hex(4)


# ---------------------------------------------------------------- 定义校验

def normalize_definition(payload: dict, existing: dict | None = None) -> dict:
    """校验并归一化应用定义，非法输入直接抛 ``AppError``。"""
    base = existing or {}
    name = str(payload.get("name", base.get("name", ""))).strip()
    if not NAME_RE.match(name):
        raise AppError("名称只能用字母、数字、点、下划线、连字符，长度 1~48，且以字母或数字开头")

    command = str(payload.get("command", base.get("command", ""))).strip()
    if not command:
        raise AppError("命令不能为空")
    if len(command) > 4096:
        raise AppError("命令过长（上限 4096 字符）")
    lowered = command.lower()
    for marker in SELF_MARKERS:
        if marker in lowered:
            raise AppError("不能把面板自身注册为常驻应用（会导致重启递归）")
    # 命令是否真实存在交由 shell 判断：这里只做"打不开的空洞"提示
    binary = ""
    with contextlib.suppress(ValueError):
        parts = shlex.split(command)
        binary = parts[0] if parts else ""
    if binary and "/" not in binary and shutil.which(binary) is None:
        raise AppError(f"命令不存在：{binary}")

    cwd = str(payload.get("cwd", base.get("cwd", "")) or "").strip()
    if cwd:
        if not os.path.isabs(cwd):
            raise AppError("工作目录必须是绝对路径")
        if not os.path.isdir(cwd):
            # 与文件管理接口的"目录不存在就回退"不同：托管应用的目录写错必须报错，
            # 否则用户以为跑起来了，其实在一个意外目录里。
            raise AppError(f"工作目录不存在：{cwd}")
    else:
        cwd = str(base.get("cwd") or (os.path.expanduser("~") if os.path.isdir(os.path.expanduser("~")) else "/"))

    env_in = payload.get("env", base.get("env", {})) or {}
    if not isinstance(env_in, dict):
        raise AppError("env 必须是对象")
    env: dict[str, str] = {}
    for key, value in list(env_in.items())[:64]:
        key = str(key).strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            raise AppError(f"环境变量名不合法：{key}")
        env[key] = str(value)[:4096]

    restart = str(payload.get("restart", base.get("restart", "on-failure")) or "on-failure")
    if restart not in RESTART_POLICIES:
        raise AppError(f"重启策略只能是：{', '.join(RESTART_POLICIES)}")

    try:
        max_restarts = int(payload.get("max_restarts", base.get("max_restarts", FAIL_LIMIT)))
    except (TypeError, ValueError):
        raise AppError("max_restarts 必须是整数")
    if not 0 <= max_restarts <= 100:
        raise AppError("max_restarts 需在 0~100 之间")

    try:
        restart_delay = float(payload.get("restart_delay", base.get("restart_delay", 2)))
    except (TypeError, ValueError):
        raise AppError("restart_delay 必须是数字")
    if not 0.5 <= restart_delay <= 300:
        raise AppError("restart_delay 需在 0.5~300 秒之间")

    now = int(time.time())
    return {
        "id": base.get("id") or new_id(),
        "name": name,
        "description": str(payload.get("description", base.get("description", "")))[:500],
        "command": command,
        "cwd": cwd,
        "env": env,
        "autostart": bool(payload.get("autostart", base.get("autostart", False))),
        "restart": restart,
        "max_restarts": max_restarts,
        "restart_delay": restart_delay,
        "created_at": base.get("created_at") or now,
        "updated_at": now,
    }


# ---------------------------------------------------------------- 日志


class AppLog:
    """应用日志：stdout/stderr 合流落盘 + 内存环形缓冲。

    文件按字节偏移读取（前端轮询 ``offset`` 增量跟随）；内存缓冲用于面板重启后
    （新进程里 offset 归零也没关系）仍能立刻回看最近输出。

    ``max_bytes=None`` 时每次写入都从「快捷设置」读当前上限（热加载），
    因此在界面把上限调小后无需重启、也无需重建已有实例即可生效。
    """

    def __init__(self, path: Path, max_bytes: int | None = None,
                 rotate: bool = True) -> None:
        self.path = Path(path)
        self._fixed_max = max_bytes
        # 托管应用的输出由**子进程自己 append 到这个文件**（见 Supervisor._spawn），
        # rename 轮转会让子进程继续写旧 inode、新 .log 只剩面板提示行。因此这类实例
        # 用就地截断（rotate=False）；其他调用方（CLI/测试）保持 rename 语义。
        self._rotate_by_rename = rotate
        self._buffer: deque[str] = deque(maxlen=MEM_LINES)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def max_bytes(self) -> int:
        if self._fixed_max is not None:
            return self._fixed_max
        return prefs.app_log_limit()

    def append(self, text: str) -> None:
        if not text:
            return
        with self._lock:
            self._rotate_if_needed()
            try:
                with open(self.path, "ab") as fh:
                    fh.write(text.encode("utf-8", "replace"))
            except OSError:
                pass
            for line in text.splitlines():
                self._buffer.append(line[:TRUNCATE_LINE])

    def clear_memory(self) -> None:
        """清空内存环形缓冲（日志清理用；已落盘文件由调用方另行截断）。"""
        with self._lock:
            self._buffer.clear()

    def _rotate_if_needed(self) -> None:
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        limit = self.max_bytes
        if size <= limit:
            return
        if self._rotate_by_rename:
            with contextlib.suppress(OSError):
                os.replace(self.path, self.path.with_suffix(self.path.suffix + ".1"))
            return
        # 就地截断：保留尾部 1/4（至少 64KB）。托管进程持有 O_APPEND 的 fd，截断后
        # 它的下一次写入直接落在新 EOF 上，不需要重开文件。代价是截断瞬间的在途
        # 写入可能丢几行——与 logrotate 的 copytruncate 同样的取舍。
        keep = max(64 * 1024, limit // 4)
        with contextlib.suppress(OSError):
            with open(self.path, "rb") as fh:
                fh.seek(max(0, size - keep))
                tail = fh.read()
            with open(self.path, "wb") as fh:
                fh.write(tail)
            self._buffer.clear()

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
            # 托管进程持有这个文件的 fd（输出直接 append 落盘）：unlink 在 Linux 上
            # 会让它继续写一个已删除的 inode——磁盘白占、日志从界面上"消失"；
            # Windows 上则直接删不掉。截断才既能清空又能让后续输出继续可见。
            try:
                with open(self.path, "wb"):
                    pass
            except OSError:
                with contextlib.suppress(OSError):
                    self.path.unlink()

    @property
    def size(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def memory_lines(self, limit: int = 200) -> list[str]:
        with self._lock:
            items = list(self._buffer)
        return items[-max(1, min(limit, MEM_LINES)):]

    def read(self, offset: int = 0, limit: int = READ_CHUNK, tail_lines: int = 0) -> dict:
        """读取日志。

        - ``tail_lines > 0``：返回文件末尾 N 行，``next_offset`` 指向文件末尾；
        - 否则从 ``offset`` 开始读取至多 ``limit`` 字节，``next_offset`` 供下次轮询。
        """
        size = self.size
        start = offset
        if tail_lines > 0:
            start = max(0, size - max(64 * 1024, tail_lines * 512))
        elif start < 0 or start > size:
            start = 0  # 文件被轮转/清空：从头开始，避免返回空内容让前端卡住

        try:
            with open(self.path, "rb") as fh:
                fh.seek(start)
                data = fh.read(max(1024, min(limit, READ_CHUNK)))
        except OSError:
            data = b""
        text = data.decode("utf-8", "replace")
        if tail_lines > 0:
            text = "\n".join(text.splitlines()[-tail_lines:])
        return {
            "content": text,
            "offset": start,
            "next_offset": start + len(data),
            "size": size,
            "truncated": start + len(data) < size,
        }


# ---------------------------------------------------------------- 进程托管


@dataclass
class ManagedRuntime:
    app_id: str
    proc: asyncio.subprocess.Process | None = None
    status: str = "stopped"          # stopped | starting | running | restarting | failed
    started_at: float = 0.0
    exited_at: float = 0.0
    last_code: int | None = None
    restart_count: int = 0           # 累计重启次数
    fails: deque[float] = field(default_factory=deque)   # 窗口内失败/重启时间戳
    log: AppLog | None = None
    desired: str = "stopped"         # 用户意图：running | stopped
    pid: int | None = None           # 进程 PID（接管的进程没有 asyncio.Process 对象）
    adopted: bool = False            # True = 上个面板实例拉起、由本实例按 pidfile 接管
    _lock: asyncio.Lock | None = None   # start/stop 串行化（见 Supervisor._app_lock）
    _monitor: asyncio.Task | None = None
    _stop_timer: asyncio.Task | None = None

    def live_pid(self) -> int | None:
        """当前仍在运行的 PID；None 表示没有活着的进程。"""
        if self.proc is not None and self.proc.returncode is None:
            return self.proc.pid
        if self.adopted and self.pid:
            return self.pid
        return None

    def snapshot(self, app: dict) -> dict:
        """给前端/CLI 的运行时视图。"""
        pid = self.live_pid()
        rss, cpu = 0, 0.0
        if pid:
            try:
                import psutil
                proc = psutil.Process(pid)
                rss = proc.memory_info().rss
                cpu = round(proc.cpu_percent(interval=None), 1)
            except Exception:
                pass
        return {
            "status": self.status,
            "pid": pid,
            "started_at": int(self.started_at),
            "uptime": int(time.time() - self.started_at) if pid and self.started_at else 0,
            "last_code": self.last_code,
            "exited_at": int(self.exited_at),
            "restart_count": self.restart_count,
            "memory_rss": rss,
            "cpu": cpu,
            "log_size": self.log.size if self.log else 0,
            "autostart": bool(app.get("autostart")),
        }


class Supervisor:
    """常驻应用的进程守护：拉起、守护、重启、日志收集。"""

    def __init__(self, registry: Registry | None = None, log_dir: Path | None = None) -> None:
        self.registry = registry or Registry()
        self.log_dir = Path(log_dir) if log_dir else self.registry.path.parent / "logs" / "apps"
        self.runtimes: dict[str, ManagedRuntime] = {}
        self._tick: asyncio.Task | None = None
        self._boot: asyncio.Task | None = None
        self._lock = threading.RLock()

    # ---- 生命周期 ----
    def _log_path(self, app: dict) -> Path:
        return self.log_dir / f"{a_name(app)}.log"

    def _pid_path(self, app: dict) -> Path:
        return self.log_dir / f"{a_name(app)}{PID_SUFFIX}"

    def _write_pidfile(self, app: dict, pid: int) -> None:
        """记录托管进程 PID（原子替换），供下一个面板实例接管。"""
        path = self._pid_path(app)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps({"pid": pid, "started_at": time.time()}), "utf-8")
            os.replace(tmp, path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)

    def _read_pidfile(self, app: dict) -> dict:
        try:
            data = json.loads(self._pid_path(app).read_text("utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _clear_pidfile(self, app: dict | None) -> None:
        if app is None:
            return
        with contextlib.suppress(OSError):
            self._pid_path(app).unlink(missing_ok=True)

    @staticmethod
    def _pid_alive(pid: int | None) -> bool:
        """PID 是否还活着。

        用 psutil 而不是 ``os.kill(pid, 0)``：Windows 上的 ``os.kill`` 除
        CTRL_C_EVENT/CTRL_BREAK_EVENT 外会直接 TerminateProcess——传 0 等于杀人。
        """
        if not pid:
            return False
        try:
            import psutil
            return bool(psutil.pid_exists(int(pid)))
        except Exception:
            return False

    @staticmethod
    def _process_argv(pid: int) -> list[str]:
        try:
            import psutil
            return list(psutil.Process(int(pid)).cmdline())
        except Exception:
            return []

    @staticmethod
    def _command_matches(app: dict, argv: list[str]) -> bool:
        """PID 复用防护：命令行里必须还能看到该应用的命令，才认这个进程是我们拉起的。"""
        command = str(app.get("command") or "")
        if not command:
            return False
        joined = " ".join(argv)
        return command in joined or joined.endswith(command)

    def adopt_all(self) -> int:
        """接管上个面板实例拉起的托管进程，返回接管数量。

        升级/重启时面板进程会退出，但托管进程在独立会话里继续跑（输出已直接落盘，
        不再经过面板的管道——管道读端随面板消失会让应用下一次写日志就 EPIPE 被杀）。
        新实例启动时按 pidfile 认领它们：既能避免"重启后同一个应用被拉起两份"，
        也不再把它们变成没人管的孤儿。
        """
        adopted = 0
        for app in self.registry.all():
            runtime = self._runtime(app)
            if runtime.proc is not None and runtime.proc.returncode is None:
                continue
            record = self._read_pidfile(app)
            pid = int(record.get("pid") or 0)
            if not pid or not self._pid_alive(pid):
                self._clear_pidfile(app)   # pidfile 陈旧
                continue
            argv = self._process_argv(pid)
            if not argv or not self._command_matches(app, argv):
                # PID 已被内核回收给别的进程：绝不能把别人的进程当自己的管
                self._clear_pidfile(app)
                continue
            runtime.adopted = True
            runtime.pid = pid
            runtime.status = "running"
            runtime.desired = "running"
            runtime.started_at = float(record.get("started_at") or 0) or time.time()
            self._note(runtime, app, f"接管上个面板实例的进程（PID {pid}）")
            adopted += 1
        return adopted

    async def serve(self) -> None:
        """面板启动时调用：接管遗留进程、进入守护循环并拉起 autostart 应用。"""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.adopt_all()
        self._tick = asyncio.create_task(self._tick_loop())
        self._boot = asyncio.create_task(self._boot_autostart())

    async def shutdown(self, keep_apps: bool = False) -> None:
        """面板退出：默认终止所有托管进程，避免留下无人认领的孤儿。

        ``keep_apps=True`` 用于**升级 / 重启**（由 CLI 写交接标记触发）：应用继续
        在独立会话里运行，进程与 pidfile 都留着，下一个面板实例 ``adopt_all()``
        接管。``--stop`` 永远是 False（停面板 = 停应用）。
        """
        for task in (self._boot, self._tick):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        for runtime in list(self.runtimes.values()):
            if runtime._stop_timer:
                runtime._stop_timer.cancel()
                runtime._stop_timer = None
        if keep_apps:
            # 不 stop、不清 pidfile：交接给下一个实例（不清 runtimes 是为了让
            # 进程对象在退出阶段被回收时不再触发 transport 清理）
            self.runtimes.clear()
            gc.collect()
            return
        for app_id in list(self.runtimes):
            with contextlib.suppress(Exception):
                await self.stop(app_id, timeout=3)
        # 回收已无引用的子进程对象，避免解释器退出时刷 "unclosed transport" 噪音
        gc.collect()

    async def _boot_autostart(self) -> None:
        await asyncio.sleep(BOOT_DELAY)
        if not prefs.apps_autostart_enabled():
            return  # 全局开关关闭时一律不自启；显式 start 仍照常生效
        for app in self.registry.all():
            if not app.get("autostart"):
                continue
            runtime = self._runtime(app)
            if runtime.live_pid():
                continue  # 已被 adopt_all 接管：绝不重复拉起第二份
            with contextlib.suppress(AppError):
                await self.start(app["id"], autostart=True)

    async def _tick_loop(self) -> None:
        while True:
            try:
                await self._reap()
            except Exception:  # 守护循环不允许因单次异常退出
                pass
            await asyncio.sleep(1.5)

    async def _reap(self) -> None:
        """回收已退出的进程并按策略决定是否重启。"""
        for runtime in list(self.runtimes.values()):
            if runtime.adopted:
                await self._reap_adopted(runtime)
                continue
            proc = runtime.proc
            if proc is None or proc.returncode is None:
                continue
            app = self.registry.get(runtime.app_id)
            if app is None:  # 定义已被删除
                self.runtimes.pop(runtime.app_id, None)
                continue
            code = proc.returncode
            # 输出直接落盘（没有管道可排空），只需释放 transport 与 pidfile
            self._close_pipe(proc)
            self._clear_pidfile(app)
            runtime.proc = None
            runtime.pid = None
            runtime.last_code = code
            runtime.exited_at = time.time()
            runtime._monitor = None
            if runtime.desired == "stopped":
                runtime.status = "stopped"
                self._note(runtime, app, f"已停止（退出码 {code}）")
                continue
            self._note(runtime, app, f"进程退出（退出码 {code}）")
            if self._should_restart(runtime, app, code):
                # 失败时间戳必须在这里落账：_delayed_start 只负责"稍后重新拉起"，
                # 若把计数写在拉起处，崩溃循环就永远不会触顶（重启上限形同虚设）。
                runtime.fails.append(time.time())
                runtime.restart_count += 1
                runtime.status = "restarting"
                delay = float(app.get("restart_delay", 2))
                runtime._stop_timer = asyncio.create_task(self._delayed_start(app["id"], delay))
            else:
                runtime.status = "failed"
                runtime.desired = "stopped"
                self._note(runtime, app, "达到重启上限或策略为 never，已放弃自动拉起（可手动启动）")

    async def _reap_adopted(self, runtime: ManagedRuntime) -> None:
        """接管进程的回收：没有 asyncio.Process 句柄，只能按 PID 存活判断。"""
        app = self.registry.get(runtime.app_id)
        if app is None:
            self.runtimes.pop(runtime.app_id, None)
            return
        if self._pid_alive(runtime.pid):
            return
        self._clear_pidfile(app)
        runtime.adopted = False
        runtime.pid = None
        runtime.exited_at = time.time()
        if runtime.desired == "stopped":
            runtime.status = "stopped"
            self._note(runtime, app, "已停止")
            return
        # 接管期间拿不到退出码：按失败处理（-1），让策略决定是否重拉
        code = -1
        runtime.last_code = code
        self._note(runtime, app, "接管的进程已退出（退出码未知，按失败计）")
        if self._should_restart(runtime, app, code):
            runtime.fails.append(time.time())
            runtime.restart_count += 1
            runtime.status = "restarting"
            delay = float(app.get("restart_delay", 2))
            runtime._stop_timer = asyncio.create_task(self._delayed_start(app["id"], delay))
        else:
            runtime.status = "failed"
            runtime.desired = "stopped"
            self._note(runtime, app, "达到重启上限或策略为 never，已放弃自动拉起（可手动启动）")

    def _should_restart(self, runtime: ManagedRuntime, app: dict, code: int) -> bool:
        policy = app.get("restart", "on-failure")
        if policy == "never":
            return False
        if policy == "on-failure" and code == 0:
            return False
        # 稳定运行超过窗口一半视为恢复，清空失败计数
        if runtime.started_at and time.time() - runtime.started_at > FAIL_WINDOW / 2:
            runtime.fails.clear()
        # 只统计窗口内的重启，避免"跑几天崩一次"被历史计数误判为崩溃循环
        cutoff = time.time() - FAIL_WINDOW
        while runtime.fails and runtime.fails[0] < cutoff:
            runtime.fails.popleft()
        limit = int(app.get("max_restarts", FAIL_LIMIT))
        return len(runtime.fails) < limit

    async def _delayed_start(self, app_id: str, delay: float) -> None:
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.sleep(delay)
            app = self.registry.get(app_id)
            if app is None:
                return
            runtime = self.runtimes.get(app_id)
            if runtime is None or runtime.desired != "running":
                return
            async with self._app_lock(runtime):
                if runtime.live_pid():
                    return  # 已被手动启动/已接管，避免重复拉起
                with contextlib.suppress(AppError):
                    await self._spawn(runtime, app)

    # ---- 操作 ----
    @staticmethod
    def _app_lock(runtime: ManagedRuntime) -> asyncio.Lock:
        """每个应用一把异步锁：start / stop / 延迟重启必须串行。

        原实现只检查 ``runtime.proc`` 就 ``await _spawn()``，而赋值发生在
        ``await`` 之后：双击启动、客户端超时重试、自启与手动启动并发时都会
        真的拉出两个进程，其中一个失去跟踪（审查 P1-4 实测：shutdown 后残留孤儿）。
        """
        if runtime._lock is None:
            runtime._lock = asyncio.Lock()
        return runtime._lock

    def _runtime(self, app: dict) -> ManagedRuntime:
        runtime = self.runtimes.get(app["id"])
        if runtime is None:
            runtime = ManagedRuntime(app_id=app["id"])
            runtime.log = AppLog(self.log_dir / f"{a_name(app)}.log", rotate=False)
            self.runtimes[app["id"]] = runtime
        return runtime

    def _note(self, runtime: ManagedRuntime, app: dict, message: str) -> None:
        if runtime.log:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            runtime.log.append(f"[{stamp}] [面板] {message}\n")

    async def start(self, app_id: str, autostart: bool = False) -> dict:
        app = self.registry.get(app_id)
        if app is None:
            raise AppError("应用不存在")
        runtime = self._runtime(app)
        async with self._app_lock(runtime):
            if runtime.live_pid():
                return self.snapshot(app)
            if runtime._stop_timer:
                runtime._stop_timer.cancel()
                runtime._stop_timer = None
            runtime.desired = "running"
            runtime.fails.clear()
            runtime.status = "starting"
            if not autostart:
                self._note(runtime, app, "启动")
            await self._spawn(runtime, app)
            return self.snapshot(app)

    async def _spawn(self, runtime: ManagedRuntime, app: dict) -> None:
        env = {**os.environ, "SERVERPANEL_APP": a_name(app)}
        env.update({str(k): str(v) for k, v in (app.get("env") or {}).items()})
        args = shell_argv(app["command"])
        log_path = self._log_path(app)
        # 输出**直接追加到日志文件**，不经过面板的管道：管道读端随面板进程一起
        # 消失，应用下一次写日志就会 EPIPE/SIGPIPE 被杀——那样"面板升级不中断
        # 托管应用"就是空话。落盘后前端仍按字节偏移增量跟随（AppLog.read）。
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        except OSError as exc:
            runtime.status = "failed"
            runtime.desired = "stopped"
            self._note(runtime, app, f"打开日志文件失败：{exc}")
            raise AppError(f"打开日志文件失败：{exc}")
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                cwd=app.get("cwd") or None,
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=log_fd,            # 子进程直接写文件（继承这个 fd）
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,   # 脱离面板进程组，面板升级不连带杀死应用
            )
        except (OSError, ValueError) as exc:
            runtime.status = "failed"
            runtime.desired = "stopped"
            self._note(runtime, app, f"启动失败：{exc}")
            raise AppError(f"启动失败：{exc}")
        finally:
            # 子进程已继承该 fd；父进程这份必须关掉，否则文件永远被占着
            with contextlib.suppress(OSError):
                os.close(log_fd)
        runtime.proc = proc
        runtime.pid = proc.pid
        runtime.adopted = False
        runtime.status = "running"
        runtime.started_at = time.time()
        runtime.last_code = None
        # pidfile 是"跨面板实例交接"的唯一凭据：升级后新实例靠它认领进程
        self._write_pidfile(app, proc.pid)
        self._note(runtime, app, f"已启动（PID {proc.pid}）")

    async def stop(self, app_id: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
        app = self.registry.get(app_id)
        if app is None:
            raise AppError("应用不存在")
        runtime = self._runtime(app)
        # 与 start 共用同一把锁：否则「启动中收到停止」会先看到 proc=None 就返回，
        # 随后启动流程把进程拉起来，用户看到的状态却是 stopped
        async with self._app_lock(runtime):
            return await self._stop_locked(runtime, app, timeout)

    async def _stop_locked(self, runtime: ManagedRuntime, app: dict,
                           timeout: float) -> dict:
        runtime.desired = "stopped"
        if runtime._stop_timer:
            runtime._stop_timer.cancel()
            runtime._stop_timer = None
        if runtime.adopted:
            # 接管的进程没有 asyncio.Process：按 PID 发信号并轮询存活
            pid = runtime.pid
            runtime.adopted = False
            runtime.pid = None
            if pid and self._pid_alive(pid):
                self._signal_group(pid, SIG_TERM)
                deadline = time.time() + timeout
                while time.time() < deadline and self._pid_alive(pid):
                    await asyncio.sleep(0.2)
                if self._pid_alive(pid):
                    self._signal_group(pid, SIG_KILL)
                    await asyncio.sleep(0.3)
            self._clear_pidfile(app)
            runtime.status = "stopped"
            runtime.exited_at = time.time()
            self._note(runtime, app, "已停止（接管的进程）")
            return self.snapshot(app)
        proc = runtime.proc
        if proc is None or proc.returncode is not None:
            runtime.proc = None
            runtime.pid = None
            runtime.status = "stopped"
            self._clear_pidfile(app)
            return self.snapshot(app)
        # 向整个进程组发送 TERM：应用自己 fork 的子进程也要一起收走
        self._signal_group(proc.pid, SIG_TERM)
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            self._signal_group(proc.pid, SIG_KILL)
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(proc.wait(), timeout=3)
        runtime.proc = None
        runtime.pid = None
        runtime.last_code = proc.returncode
        runtime.exited_at = time.time()
        runtime.status = "stopped"
        self._close_pipe(proc)
        self._clear_pidfile(app)
        self._note(runtime, app, "已停止")
        return self.snapshot(app)

    async def restart(self, app_id: str) -> dict:
        with contextlib.suppress(AppError):
            await self.stop(app_id, timeout=5)
        return await self.start(app_id)

    @staticmethod
    def _close_pipe(proc) -> None:
        """关闭输出管道与子进程 transport。

        asyncio 子进程的 transport 不显式关闭，退出时会刷一堆 "unclosed transport"
        噪音（Windows 上尤其吵）并占着 fd；这里在进程回收时一并收尾。
        """
        stream = getattr(proc, "stdout", None)
        if stream is not None:
            with contextlib.suppress(Exception):
                stream.close()
        transport = getattr(proc, "_transport", None)
        if transport is not None:
            with contextlib.suppress(Exception):
                transport.close()

    @staticmethod
    def _signal_group(pid: int, sig: int) -> None:
        if hasattr(os, "killpg"):
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.killpg(pid, sig)
                return
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.kill(pid, sig)

    # ---- 查询 ----
    def snapshot(self, app: dict) -> dict:
        runtime = self.runtimes.get(app["id"])
        app_id = app["id"]
        base = {
            "status": "stopped", "pid": None, "started_at": 0, "uptime": 0,
            "last_code": None, "exited_at": 0, "restart_count": 0,
            "memory_rss": 0, "cpu": 0.0, "log_size": 0,
        }
        if runtime is None:
            runtime = ManagedRuntime(app_id=app_id)
            runtime.log = AppLog(self.log_dir / f"{a_name(app)}.log", rotate=False)
            self.runtimes[app_id] = runtime
        base.update(runtime.snapshot(app))
        return {**app, "runtime": base}

    def list(self) -> list[dict]:
        apps = self.registry.all()
        for app in apps:
            self._runtime(app)
        known = {a["id"] for a in apps}
        for app_id in list(self.runtimes):
            if app_id not in known:
                self.runtimes.pop(app_id, None)
        return [self.snapshot(app) for app in apps]

    def get(self, app_id: str) -> dict:
        app = self.registry.get(app_id)
        if app is None:
            raise AppError("应用不存在")
        return self.snapshot(app)

    def log_of(self, app_id: str, offset: int = 0, limit: int = READ_CHUNK,
               tail_lines: int = 0) -> dict:
        app = self.registry.get(app_id)
        if app is None:
            raise AppError("应用不存在")
        runtime = self._runtime(app)
        assert runtime.log is not None
        data = runtime.log.read(offset=offset, limit=limit, tail_lines=tail_lines)
        memory = runtime.log.memory_lines(200)
        if not memory:
            # 输出由子进程直接落盘（不再经过面板管道），内存环里可能没有内容
            # （面板刚重启完就是这种情况）：用文件尾部回填，别让界面显示空白
            tail = runtime.log.read(tail_lines=200)
            memory = (tail.get("content") or "").splitlines()
        data["memory"] = memory
        return data

    def clear_log(self, app_id: str) -> dict:
        app = self.registry.get(app_id)
        if app is None:
            raise AppError("应用不存在")
        runtime = self._runtime(app)
        if runtime.log:
            runtime.log.clear()
        return {"ok": True, "app": a_name(app)}


# ---------------------------------------------------------------- 全局单例

supervisor = Supervisor()


# ---------------------------------------------------------------- 跨实例交接标记
#
# 语义：CLI 在"要让面板重启但不想打断托管应用"时写标记；面板 lifespan 退出读到
# 标记就跳过 shutdown（应用与 pidfile 都留着），新实例启动时 adopt_all() 认领。
# 标记带 TTL：重启最终没发生（升级失败/命令被打断/有人 Ctrl-C）时不会让之后
# 的 `--stop` 误以为"这次也该留着应用"。


def survive_marker_path() -> Path:
    return supervisor.registry.path.parent / SURVIVE_MARKER


def mark_survive(ttl: float = SURVIVE_TTL) -> None:
    """升级 / 重启前调用：告诉即将退出的面板"别杀托管应用"。"""
    path = survive_marker_path()
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps({"ts": time.time(), "ttl": ttl}), "utf-8")
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)


def consume_survive() -> bool:
    """读取并删除交接标记（一次性）。过期视为不存在。"""
    path = survive_marker_path()
    try:
        data = json.loads(path.read_text("utf-8"))
        path.unlink(missing_ok=True)
    except (OSError, json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    try:
        ts = float(data.get("ts") or 0)
        ttl = float(data.get("ttl") or SURVIVE_TTL)
    except (TypeError, ValueError):
        return False
    return ts > 0 and time.time() - ts <= ttl


def clear_survive() -> None:
    with contextlib.suppress(OSError):
        survive_marker_path().unlink(missing_ok=True)


def reload_registry() -> None:
    """外部（CLI / 手工编辑 apps.json）改动后由服务端感知。"""
    supervisor.registry.reload_if_changed()


# ---------------------------------------------------------------- 同步工具（CLI / 测试）

def probe(app: dict, seconds: float = 5.0) -> dict:
    """试运行：跑一小段时间抓输出后结束，用于确认配置是否正确。

    输出重定向到临时文件而不是管道：进程被强杀时管道里未读走的数据会随着
    句柄一起消失（实测 ``communicate`` 超时后第二次调用可能拿不到任何输出），
    落盘则不受影响，观察期内写到多少就保留多少。
    """
    env = {**os.environ, "SERVERPANEL_APP": a_name(app)}
    env.update({str(k): str(v) for k, v in (app.get("env") or {}).items()})
    with tempfile.TemporaryFile() as sink:
        try:
            proc = subprocess.Popen(
                shell_argv(app["command"]),
                cwd=app.get("cwd") or None,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=sink,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            return {"ok": False, "code": None, "output": f"启动失败：{exc}", "survived": False}
        survived = True
        try:
            proc.wait(timeout=seconds)
            survived = False
        except subprocess.TimeoutExpired:
            Supervisor._signal_group(proc.pid, SIG_TERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                Supervisor._signal_group(proc.pid, SIG_KILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=5)
        code = proc.returncode
        # 只读尾部 16KB：探针最长观察 30 秒，命令若狂刷输出（yes / tail -f）
        # 临时文件可能涨到 GB 级，整体 read() 会把内存打满
        size = sink.tell()
        sink.seek(max(0, size - 16_000))
        raw = sink.read(16_000)
    text = (raw or b"").decode("utf-8", "replace")
    return {
        "ok": True,
        "code": code,
        "survived": survived,
        "output": text[-16_000:],
        "message": ("进程在观察期内持续运行，配置看起来正常" if survived
                    else f"进程在 {seconds:g} 秒内退出（退出码 {code}），请检查命令"),
    }


def read_log_lines(app: dict, lines: int = 200) -> list[str]:
    path = supervisor.log_dir / f"{a_name(app)}.log"
    log = AppLog(path)
    data = log.read(tail_lines=lines)
    content = data["content"]
    if not content.strip():
        content = "\n".join(log.memory_lines(lines))
    return content.splitlines()[-lines:]


def panel_pids_guard() -> set[int]:
    """当前所有托管应用的 PID 集合（面板自身进程内已知的那部分）。"""
    pids: set[int] = set()
    for runtime in supervisor.runtimes.values():
        proc = runtime.proc
        if proc is not None and proc.returncode is None:
            pids.add(proc.pid)
    return pids


def apps_group_pids(registry: Registry | None = None) -> set[int]:
    """反查托管应用的进程组 ID（面板重启后内存状态会丢，只能按注册表找）。

    面板/守护的停止流程用它排除"正在被面板托管的应用"，避免整组 TERM 时
    把用户的服务一起带走。
    """
    pids = set(panel_pids_guard())
    if not hasattr(os, "getpgid"):
        return pids
    reg = registry or supervisor.registry
    commands = [a["command"] for a in reg.all() if a.get("command")]
    if not commands:
        return pids
    try:
        import psutil
    except ImportError:
        return pids
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmdline = " ".join(proc.info.get("cmdline") or [])
            pid = proc.info["pid"]
        except psutil.Error:
            continue
        if not cmdline or not any(cmd in cmdline for cmd in commands):
            continue
        with contextlib.suppress(OSError):
            pids.add(os.getpgid(pid))
    return pids
