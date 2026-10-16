"""Agent 令牌作用域：把「一条 HTTP 请求执行一条命令」的能力关进笼子。

三种作用域：

- ``full``：不限制（等价旧版单令牌，默认）
- ``readonly``：只允许内置的只读命令（见 :data:`READONLY_COMMANDS`）
- ``custom``：只允许以用户指定前缀开头的命令（前缀白名单）

校验分三层，任何一层不过就拒：

1. **元字符白名单**：命令里出现 ``&``、换行、反引号、``$``、``(``、``>``、
   ``*`` 等 shell 元字符一律拒绝——它们在 ``sh -c`` 下会改变命令结构，
   静态拆段分析不出真实语义（``ls & rm -rf /``、``ls $(id)``、
   ``ls`` 后接换行再跟一条命令，都属于这一类）；
2. **按 ``&&`` / ``||`` / ``;`` / ``|`` 拆段**，每段必须独立通过校验；
3. **逐段判定**：段首可执行文件必须在表内，且子命令/选项受逐命令规则约束
   （例如 ``ip`` 只认 show/list 形式）。

注意：这是"减小令牌爆炸半径"的纵深防御，不是沙箱。full 作用域令牌
依然等于 root shell，请按需签发、定期轮换。

1.4.1 起收紧：原实现只按分隔符拆段、只看段首 token，导致
``ls & rm -rf /``、``ls $(...)``、换行拼接、``df -h > /etc/x``
全部被放行（等价于只读令牌可执行任意命令）；同时把 ``mount``、
``hostname`` 改名、``ifconfig``、``ip addr/route/link`` 的非 show 形式、
``dmesg -C``、``journalctl --vacuum-*`` 等会改变系统状态的命令
移出只读白名单。
"""

from __future__ import annotations

import posixpath
import re
import shlex

# shell 元字符：出现即拒（fail-closed）。
# 说明：``&&`` / ``||`` / ``;`` / ``|`` 不在其中——它们由第 2 层拆段后逐段校验；
# 单个 ``&``（后台/顺序分隔，``ls & rm -rf /`` 就是它）由 _BARE_AMP_RE 单独拒，
# 这样 ``df -h && id`` 与 ``df -h; id`` 的行为一致（都是"每段都得是只读命令"）。
_FORBIDDEN_CHARS = "\n\r`$(){}<>*?[]~!#\\"
_BARE_AMP_RE = re.compile(r"(?<!&)&(?!&)")

# 只读命令表：exe -> None（不限制子命令/选项）或允许出现的子命令/选项集合。
# 只收"输出信息、不改变系统状态"的命令。
READONLY_COMMANDS: dict[str, frozenset[str] | None] = {
    # systemd 只读面
    "systemctl": frozenset({
        "status", "is-active", "is-enabled", "is-failed", "is-system-running",
        "list-units", "list-unit-files", "list-timers", "list-sockets",
        "list-jobs", "list-dependencies", "show", "cat", "get-default",
    }),
    "journalctl": None,
    "systemd-analyze": None,
    # 资源与进程
    "ps": None, "vmstat": None, "iostat": None, "mpstat": None, "sar": None,
    "free": None, "uptime": None, "df": None, "du": None, "lsblk": None,
    "findmnt": None, "top": frozenset({"-b"}),
    # 网络只读
    "ss": None, "netstat": None, "dig": None, "nslookup": None, "host": None,
    "traceroute": None, "tracepath": None, "mtr": None, "ping": frozenset({"-c"}),
    "lsof": frozenset({"-i"}),
    # 内核与硬件信息
    "dmesg": None, "uname": None, "lsmod": None, "lscpu": None, "lsmem": None,
    "lsusb": None, "lspci": None, "sensors": None,
    "smartctl": frozenset({"-i", "-a"}),
    "timedatectl": frozenset({"status"}), "localectl": frozenset({"status"}),
    # 目录与文件内容（cat 只允许 /proc、/sys 下的虚拟文件，见 _cat_ok）
    "ls": None, "stat": None, "file": None, "wc": None,
    # 身份与时间
    "whoami": None, "id": None, "w": None, "last": None,
}

# 逐命令选项黑名单（这些选项会改状态：清内核环、轮转日志…）
_DENY_OPTS: dict[str, frozenset[str]] = {
    "dmesg": frozenset({"-C", "-c", "-D", "-E", "-n", "--clear", "--read-clear",
                        "--console-off", "--console-on", "--console-level"}),
    "journalctl": frozenset({"--vacuum-time", "--vacuum-size", "--vacuum-files",
                             "--rotate", "--flush", "--sync", "--relinquish-var",
                             "--setup-keys", "--update-catalog", "--verify-key"}),
}

# hostname：只允许"查看"类选项（都不带参数，因此不会改名）
_HOSTNAME_OPTS = frozenset({"-f", "-s", "-d", "-i", "-I", "-A", "--fqdn", "--short",
                            "--domain", "--ip-address", "--all-fqdns"})

_IP_OBJECTS = frozenset({"addr", "address", "route", "link", "neigh", "rule",
                         "netns", "maddress", "tunnel"})
_IP_ACTIONS = frozenset({"show", "list", "ls", "sh", "get"})

# 敏感虚拟文件：按 basename 精确匹配（不能用子串，否则 /proc/meminfo 会被
# "/mem" 误伤），外加两个按路径片段匹配的目录。
_CAT_DENY_NAMES = frozenset({"kcore", "mem", "environ", "keys", "kmsg"})
_CAT_DENY_SUBSTR = ("/sysrq-trigger", "/self/fd/")

_SEGMENT_RE = re.compile(r"&&|\|\||[;|]")


def _opt(argv: list[str]) -> list[str]:
    """去掉选项，只留位置参数（``-x`` / ``--long`` 都算选项）。"""
    return [a for a in argv if not a.startswith("-")]


def _cat_ok(argv: list[str]) -> bool:
    """cat 只允许读 /proc、/sys 下的虚拟文件，且排除几个敏感虚拟文件。

    路径一律按 POSIX 语义处理（``posixpath``）：面板跑在 Linux 上，
    而且这样在 Windows 开发机上跑测试时结果也一致。
    """
    paths = _opt(argv[1:])
    if not paths:
        return False
    for raw in paths:
        path = posixpath.normpath(raw)
        if not (path.startswith("/proc/") or path.startswith("/sys/")):
            return False
        if posixpath.basename(path) in _CAT_DENY_NAMES:
            return False
        if any(bad in path for bad in _CAT_DENY_SUBSTR):
            return False
    return True


def _ip_ok(argv: list[str]) -> bool:
    """ip 只允许 show/list 形式（``ip addr add`` / ``ip link set`` 会改网络）。"""
    rest = _opt(argv[1:])
    if not rest:
        return True                      # 裸 ip = 用法提示，无副作用
    if rest[0] not in _IP_OBJECTS:
        return False
    if len(rest) == 1:
        return True                      # ip addr 等价于 ip addr show
    return all(token in _IP_ACTIONS for token in rest[1:])


def _hostname_ok(argv: list[str]) -> bool:
    return all(a in _HOSTNAME_OPTS for a in argv[1:])


def _date_ok(argv: list[str]) -> bool:
    """只允许查看时间：无参数、-u/--utc/-R、以及 +格式串；-s/--set 会改时间。"""
    for arg in argv[1:]:
        if arg in ("-u", "--utc", "-R", "--rfc-2822", "--rfc-3339=seconds"):
            continue
        if arg.startswith("+"):
            continue
        return False
    return True


def _has_denied_opt(argv: list[str], deny: frozenset[str]) -> bool:
    """选项黑名单匹配：``--vacuum-time`` 同时覆盖 ``--vacuum-time=1s`` 写法。"""
    for arg in argv[1:]:
        if arg in deny:
            return True
        if arg.startswith("--") and "=" in arg and arg.split("=", 1)[0] in deny:
            return True
    return False


def _matches(argv: list[str]) -> bool:
    """单个命令段是否属于只读范围。"""
    if not argv:
        return False
    exe = argv[0]
    if exe == "cat":
        return _cat_ok(argv)
    if exe == "ip":
        return _ip_ok(argv)
    if exe == "hostname":
        return _hostname_ok(argv)
    if exe == "date":
        return _date_ok(argv)
    if exe not in READONLY_COMMANDS:
        return False
    allowed = READONLY_COMMANDS[exe]
    deny = _DENY_OPTS.get(exe)
    if deny is not None and _has_denied_opt(argv, deny):
        return False
    if allowed is None:
        return True
    sub = argv[1] if len(argv) > 1 else None
    return sub is not None and sub in allowed


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


def command_allowed(scope: str, prefixes: list[str], command: str) -> bool:
    """整条命令是否在作用域允许范围内。"""
    if scope == "full":
        return True
    command = command or ""
    # 第 1 层：shell 元字符（换行、反引号、$()、重定向、通配符、单个 &…）
    if any(ch in command for ch in _FORBIDDEN_CHARS) or _BARE_AMP_RE.search(command):
        return False
    segments = _split_segments(command)
    if not segments:
        return False  # 空命令或不可解析：不给过
    if scope == "readonly":
        # 第 2/3 层：逐段通过（&& / || / ; / | 尾挂命令也在这里被拦）
        return all(_matches(argv) for argv in segments)
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
