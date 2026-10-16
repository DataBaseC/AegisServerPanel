"""Agent 令牌作用域：把「一条 HTTP 请求执行一条命令」的能力关进笼子。

三种作用域：

- ``full``：不限制（等价旧版单令牌，默认）
- ``readonly``：只允许匹配内置只读命令模式（``systemctl status``、
  ``journalctl``、``df``、``ps``……见 :data:`READONLY_PATTERNS`）
- ``custom``：只允许以用户指定前缀开头的命令（前缀白名单）

校验方式：把 shell 命令按 ``&&`` / ``||`` / ``;`` / ``|`` 拆成段，
**每一段**都必须通过——防止 ``df -h && rm -rf /`` 这类尾挂恶意命令。

注意：这是"减小令牌爆炸半径"的纵深防御，不是沙箱。full 作用域令牌
依然等于 root shell，请按需签发、定期轮换。
"""

from __future__ import annotations

import re
import shlex

# (可执行文件, 可选子命令) 二元组；子命令为 None 表示不限子命令。
# 只收"输出信息、不改变系统状态"的命令。
READONLY_PATTERNS: tuple[tuple[str, str | None], ...] = (
    # systemd 只读面
    ("systemctl", "status"), ("systemctl", "is-active"), ("systemctl", "is-enabled"),
    ("systemctl", "is-failed"), ("systemctl", "list-units"), ("systemctl", "list-unit-files"),
    ("systemctl", "list-timers"), ("systemctl", "show"), ("systemctl", "cat"),
    ("journalctl", None), ("systemd-analyze", None),
    # 资源与进程
    ("ps", None), ("top", "-b"), ("vmstat", None), ("iostat", None),
    ("mpstat", None), ("sar", None), ("free", None), ("uptime", None),
    ("df", None), ("du", None), ("lsblk", None), ("findmnt", None),
    ("mount", None),  # 无参 mount = 列表
    # 网络只读
    ("ss", None), ("netstat", None), ("ip", "addr"), ("ip", "route"),
    ("ip", "link"), ("ip", "-s"), ("ifconfig", None), ("ping", "-c"),
    ("dig", None), ("nslookup", None), ("host", None), ("traceroute", None),
    ("tracepath", None), ("mtr", None), ("lsof", "-i"),
    # 内核与硬件信息
    ("dmesg", None), ("uname", None), ("hostname", None), ("hostnamectl", None),
    ("lsmod", None), ("lscpu", None), ("lsmem", None), ("lsusb", None),
    ("lspci", None), ("sensors", None), ("smartctl", "-i"), ("smartctl", "-a"),
    ("timedatectl", "status"), ("localectl", "status"),
    # 目录与文件内容（cat 只允许 /proc、/sys 下的虚拟文件）
    ("ls", None), ("stat", None), ("file", None), ("wc", None),
    ("cat", "/proc"), ("cat", "/sys"),
    # 身份与时间
    ("whoami", None), ("id", None), ("date", None), ("w", None), ("last", None),
)

_SEGMENT_RE = re.compile(r"&&|\|\||[;|]")


def _split_segments(command: str) -> list[list[str]]:
    """把 shell 命令拆成段，每段 shlex 解析成 argv；解析失败的段整体拒绝。"""
    segments: list[list[str]] = []
    for chunk in _SEGMENT_RE.split(command):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            argv = shlex.split(chunk)
        except ValueError:
            return []  # 引号不闭合：无法静态分析，直接拒
        if argv:
            segments.append(argv)
    return segments


def _matches(argv: list[str], patterns: tuple[tuple[str, str | None], ...]) -> bool:
    exe = argv[0]
    sub = argv[1] if len(argv) > 1 else None
    for pattern_exe, pattern_sub in patterns:
        if exe != pattern_exe:
            continue
        if pattern_sub is None:
            return True
        if sub == pattern_sub:
            return True
        # 形如 ("ip", "-s")：允许 -s link 这类"选项+子命令"组合
        if sub and sub.startswith("-") and pattern_sub.startswith("-") and len(argv) > 2 \
                and argv[2] == pattern_sub:
            return True
    return False


def command_allowed(scope: str, prefixes: list[str], command: str) -> bool:
    """整条命令是否在作用域允许范围内。"""
    if scope == "full":
        return True
    segments = _split_segments(command)
    if not segments:
        return False  # 空命令或不可解析：不给过
    if scope == "readonly":
        return all(_matches(argv, READONLY_PATTERNS) for argv in segments)
    if scope == "custom":
        allowed = tuple(p for p in prefixes if p)
        if not allowed:
            return False
        for argv in segments:
            joined = " ".join(argv)
            if not any(joined == p or joined.startswith(p + " ") or argv[0] == p
                       for p in allowed):
                return False
        return True
    return False
