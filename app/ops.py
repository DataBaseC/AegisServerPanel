"""运维扩展的纯逻辑层（2.0 M3）：解析器与输入校验。

设计要点：

- **只放可以离线单测的逻辑**：crontab 行、apt 可升级列表、docker 的 JSON 行、
  ufw / iptables 输出、authorized_keys、备份文件名、网络工具目标。
  "探测本机命令、拼参数列表、写审计" 一律留在 ``routes`` 层。
- **用户输入只走白名单**：任何最终会进命令行的输入都必须先过这里的正则，
  非法立刻抛 :class:`OpsError`（路由层翻成 HTTP 400），绝不把原始输入
  直接拼进命令行——参数一律以列表形式交给 ``shell.run``。
- 解析失败**不抛异常**（外部命令输出格式会随版本漂移），只跳过看不懂的行，
  让端点始终能返回结构化的空列表，面板不会因为解析出错而 500。
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

# ---------------------------------------------------------------- 通用


class OpsError(ValueError):
    """用户输入不合法（路由层翻成 HTTP 400）。"""


# crontab 字段：数字与特殊字符（分 时 日 月 周），字母只允许 JAN/MON 这类缩写。
# 不能以 / 或 . 开头，否则 "/usr/bin/foo" 这种命令会被误判成字段。
CRON_FIELD_RE = re.compile(r"^(?![./])[0-9*/,\-?#]{1,32}$")
# crontab 的环境变量行（PATH=/usr/local/bin、MAILTO=root、SHELL=/bin/bash）。
# 它们不是任务，但必须原样保留：crontab - 是整份覆盖，丢了会改变任务运行环境。
CRON_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
CRON_NAME_RE = re.compile(
    r"^(?i:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC|SUN|MON|TUE|WED|THU|FRI|SAT)"
    r"(?:-(?i:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC|SUN|MON|TUE|WED|THU|FRI|SAT))?"
    r"(?:/\d{1,2})?$"
)
CRON_MACROS = frozenset({"@reboot", "@yearly", "@annually", "@monthly", "@weekly",
                         "@daily", "@midnight", "@hourly"})

# 容器 id / 名称：docker 允许字母数字开头，后续允许 _ . -
CONTAINER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")

# 数据库标识符（库名 / 用户 / 备份名的一段）
IDENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

# 主机：IPv4 / IPv6 字面量或主机名，禁止空格与 shell 元字符
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251})?$|^\[[0-9A-Fa-f:]{2,45}\]$")

# 网络工具目标：域名 / IP / IPv6（方括号），禁止空格、分号、管道、重定向
TARGET_RE = re.compile(r"^[A-Za-z0-9.:\-\[\]]{1,253}$")

# 公钥行（spec 要求的四类前缀；body 必须是 base64 段）
PUBKEY_RE = re.compile(
    r"^(?P<type>(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-\S+|sk-\S+))"
    r"(?P<gap>\s+)(?P<body>[A-Za-z0-9+/]{16,}={0,3})(?:\s+(?P<comment>.*))?$"
)

# 备份文件名：不以 . 或 - 开头，不含路径分隔符
BACKUP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
BACKUP_SUFFIXES = (".tar.gz", ".tgz", ".tar")
BACKUP_SUFFIX = ".tar.gz"

# rclone 远程：name:path（path 允许字母数字与少量分隔符）
REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}:[A-Za-z0-9._\-/ ]{0,240}$")

# apt 包名（含 :arch 后缀、+ 与 . 的合法名）
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]{0,79}(:[a-z0-9\-]{1,16})?$")

UFW_LINE_RE = re.compile(
    r"^\[\s*(?P<index>\d+)\]\s+(?P<spec>\S.*?)"
    r"\s+(?P<action>ALLOW(?: IN| OUT| FWD)?|DENY(?: IN| OUT)?|REJECT|LIMIT)"
    r"\s+(?P<from>.+)$"
)
ANYWHERE = frozenset({"anywhere", "0.0.0.0/0", "::/0", "anywhere (v6)"})


# ---------------------------------------------------------------- crontab


def _is_field(token: str) -> bool:
    """判断一个 token 是否可能是 cron 时间字段（而不是命令的一部分）。"""
    return bool(CRON_FIELD_RE.match(token) or CRON_NAME_RE.match(token))


def _split_schedule(text: str) -> tuple[str, str]:
    """把一行任务切成 ``(schedule, command)``；不合法抛 :class:`OpsError`。"""
    parts = text.split()
    if not parts:
        raise OpsError("空行不能写入 crontab")
    if parts[0].lower() in CRON_MACROS:
        if len(parts) < 2:
            raise OpsError(f"{parts[0]} 后面缺少要执行的命令")
        return parts[0].lower(), text[len(parts[0]):].strip()
    if parts[0].startswith("@"):
        raise OpsError(f"不支持的定时宏：{parts[0]}")
    count = 0
    while count < len(parts) and count < 6 and _is_field(parts[count]):
        count += 1
    if count == 6 and len(parts) == 6:
        raise OpsError("定时表达式后面缺少要执行的命令")
    if count < 5:
        raise OpsError("定时表达式至少需要 5 段字段（分 时 日 月 周）")
    if len(parts) <= count:
        raise OpsError("定时表达式后面缺少要执行的命令")
    return " ".join(parts[:count]), " ".join(parts[count:])


def parse_cron_line(raw: str, index: int = 0) -> dict:
    """解析单行 crontab。

    ``#`` 开头的行视为**停用**（面板的启停就是加/去注释），但内容仍尝试解析，
    这样前端能显示"如果启用会跑什么"。
    """
    text = (raw or "").rstrip("\r\n")
    stripped = text.strip()
    enabled = not stripped.startswith("#")
    body = stripped if enabled else stripped.lstrip("#").strip()
    item = {"index": index, "raw": text, "enabled": enabled,
            "schedule": "", "command": "", "comment": "", "error": ""}
    if not body:
        item["comment"] = stripped
        return item
    if body.startswith("#"):
        item["comment"] = body
        return item
    if CRON_ENV_RE.match(body):
        # 环境变量行：前端按「命令」列展示，保存时原样写回
        item["command"] = body
        item["comment"] = "环境变量"
        return item
    try:
        schedule, command = _split_schedule(body)
    except OpsError as exc:
        # 注释内容本来就不是任务（如 "# 由 serverpanel 管理"），不算错误
        if enabled:
            item["error"] = str(exc)
        else:
            item["comment"] = body
        return item
    item["schedule"] = schedule
    item["command"] = command
    return item


def parse_crontab(text: str) -> list[dict]:
    """把 ``crontab -l`` 的整段输出切成结构化行列表（空行丢弃）。"""
    return [parse_cron_line(line, index)
            for index, line in enumerate((text or "").splitlines()) if line.strip()]


def validate_cron_line(line: str) -> str:
    """校验用户提交的**一行**任务，返回清洗后的文本；不合法抛 OpsError。

    换行注入在多行合并写入时最危险（一条"命令"里塞进第二条任务，
    或塞进 ``MAILTO`` / 覆盖式重定向），因此这里显式拒绝内嵌换行。
    """
    text = (line or "")
    if "\n" in text or "\r" in text:
        raise OpsError("一行只能包含一条任务（禁止换行注入）")
    stripped = text.strip()
    if not stripped:
        raise OpsError("空行不能写入 crontab")
    enabled = not stripped.startswith("#")
    body = stripped if enabled else stripped.lstrip("#").strip()
    if not body:
        return stripped  # 纯注释行（如 "# 由 serverpanel 管理"）原样保留
    if CRON_ENV_RE.match(body):
        # PATH=/usr/local/bin 之类：合法且必须保留，不能当成\"字段不足\"
        return stripped
    if not enabled:
        try:  # 停用行允许是任意注释文本；只有"想启用"的行必须语法正确
            _split_schedule(body)
        except OpsError:
            pass
        return stripped
    _split_schedule(body)
    return stripped


def render_crontab(lines: list[str]) -> str:
    """把行列表拼回 crontab 文本（末尾单换行，空行丢弃）。"""
    kept = [line.strip() for line in lines if line and line.strip()]
    return "\n".join(kept) + ("\n" if kept else "")


def normalize_crontab(text: str) -> list[str]:
    """写入后读回校验用：忽略空行与行尾空白，只比较有效行。"""
    return [line.rstrip() for line in (text or "").splitlines() if line.strip()]


# ---------------------------------------------------------------- apt


def parse_apt_upgradable(text: str) -> list[dict]:
    """解析 ``apt list --upgradable``。

    典型行：``nodejs/jammy-security 18.19.1+dfsg-6ubuntu5 amd64 [upgradable from: ...]``
    来源里带 ``-security`` 视为安全更新。
    """
    packages = []
    seen = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("Listing") or line.startswith("WARNING"):
            continue
        parts = line.split()
        if len(parts) < 2 or "/" not in parts[0]:
            continue
        name, _, repo = parts[0].partition("/")
        if not name or name in seen:
            continue
        seen.add(name)
        arch = parts[2] if len(parts) > 2 and not parts[2].startswith("[") else ""
        packages.append({
            "name": name,
            "version": parts[1],
            "repo": repo,
            "arch": arch,
            "security": "-security" in repo,
        })
    packages.sort(key=lambda item: (not item["security"], item["name"]))
    return packages


def check_package_name(name: str) -> str:
    text = (name or "").strip()
    if not PACKAGE_RE.match(text):
        raise OpsError(f"包名不合法：{text[:40]}")
    return text


# ---------------------------------------------------------------- docker


def parse_docker_json(text: str) -> list[dict]:
    """解析 ``--format '{{json .}}'`` 的逐行 JSON 输出。

    键统一转小写去空格，方便路由层直接取 ``item["id"]`` 这类字段；
    看不懂的行直接跳过（docker 版本差异不该让列表 500）。
    """
    items = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        items.append({
            str(key).strip().lower(): (value.strip() if isinstance(value, str) else value)
            for key, value in data.items()
        })
    return items


def check_container_id(value: str) -> str:
    """容器 id / 名称白名单校验（后续作为独立 argv 传入，绝不拼接）。"""
    text = (value or "").strip()
    if not CONTAINER_RE.match(text):
        raise OpsError("容器 id 不合法")
    return text


# ---------------------------------------------------------------- 防火墙


def _split_port_proto(spec: str) -> tuple[str, str]:
    """``"22/tcp"`` → ``("22", "tcp")``；应用名（如 ``Apache Full``）原样返回。"""
    text = spec.strip()
    if "/" in text:
        port, _, proto = text.partition("/")
        return port.strip(), proto.strip().lower()
    return text, ""


def _is_risky(action: str, port: str, source: str, watch_ports: set[str]) -> bool:
    """任意来源全放行 22 / 面板端口 → 危险规则。"""
    # action 可能是 "ALLOW IN" / "ALLOW" / "ACCEPT"，只看第一段
    if action.upper().split()[0] not in ("ALLOW", "ACCEPT"):
        return False
    if source.strip().lower() not in ANYWHERE:
        return False
    return bool(port) and port in watch_ports


def parse_ufw_status(text: str, watch_ports: set[str] | frozenset[str] = frozenset()) -> list[dict]:
    """解析 ``ufw status numbered``。"""
    rules = []
    for line in (text or "").splitlines():
        match = UFW_LINE_RE.match(line.strip())
        if not match:
            continue
        raw_spec = match.group("spec").strip()
        spec = raw_spec.replace("(v6)", "").strip()
        port, proto = _split_port_proto(spec)
        source = match.group("from").strip()
        rules.append({
            "index": int(match.group("index")),
            "port": port,
            "proto": proto,
            "action": match.group("action").strip(),
            "from": source,
            "v6": "(v6)" in raw_spec,
            "raw": line.strip(),
            "risky": _is_risky(match.group("action"), port, source, set(watch_ports)),
        })
    return rules


IPTABLES_DPORT_RE = re.compile(r"--dports?\s+([0-9,:]+)")
IPTABLES_PROTO_RE = re.compile(r"-p\s+([A-Za-z0-9]+)")
IPTABLES_SRC_RE = re.compile(r"-s\s+([0-9A-Fa-f.:/]+)")
IPTABLES_JUMP_RE = re.compile(r"-j\s+([A-Za-z0-9_-]+)")


def parse_iptables(text: str, watch_ports: set[str] | frozenset[str] = frozenset()) -> list[dict]:
    """解析 ``iptables -S``（只读展示）。没有头部/统计行，逐行是规则。"""
    rules = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("-A "):
            continue
        chain = line.split()[1] if len(line.split()) > 1 else ""
        dport = IPTABLES_DPORT_RE.search(line)
        proto = IPTABLES_PROTO_RE.search(line)
        source = IPTABLES_SRC_RE.search(line)
        jump = IPTABLES_JUMP_RE.search(line)
        port = dport.group(1).split(",")[0] if dport else ""
        origin = source.group(1) if source else "0.0.0.0/0"
        action = jump.group(1) if jump else ""
        rules.append({
            "index": len(rules) + 1,
            "chain": chain,
            "port": port,
            "proto": proto.group(1) if proto else "all",
            "action": action,
            "from": origin,
            "v6": ":" in origin,
            "raw": line,
            "risky": _is_risky(action, port, origin, set(watch_ports)),
        })
    return rules


def check_port(value) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise OpsError("端口必须是整数")
    if not 1 <= port <= 65535:
        raise OpsError("端口需要在 1 ~ 65535 之间")
    return port


def check_proto(value: str) -> str:
    text = (value or "").strip().lower()
    if text not in ("tcp", "udp"):
        raise OpsError("协议只能是 tcp 或 udp")
    return text


# ---------------------------------------------------------------- 反代 / 证书


def parse_nginx_sites(names: list[str]) -> list[str]:
    return sorted(name for name in names if name and not name.startswith("."))


def parse_not_after(text: str) -> dict:
    """解析 ``openssl x509 -enddate -noout`` 的 ``notAfter=...``。

    返回 ``{"not_after": iso 字符串, "days_left": 整数}``；解析失败返回空 dict。
    """
    line = (text or "").strip()
    if line.lower().startswith("notafter="):
        line = line.split("=", 1)[1]
    line = " ".join(line.split())  # "Jun  1 12:00:00 2026 GMT" → 单空格
    try:
        stamp = datetime.strptime(line, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return {}
    delta = stamp.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)
    return {"not_after": stamp.strftime("%Y-%m-%d %H:%M:%S"),
            "days_left": int(delta.total_seconds() // 86400)}


# ---------------------------------------------------------------- SSH 公钥


def parse_key_line(line: str) -> dict:
    """解析 authorized_keys 的一行（不做合法性判定，非法返回 ``valid: False``）。"""
    text = (line or "").strip()
    match = PUBKEY_RE.match(text)
    if not match:
        return {"line": text, "type": "", "comment": "", "valid": False}
    return {
        "line": text,
        "type": match.group("type"),
        "comment": (match.group("comment") or "").strip(),
        "valid": True,
    }


def validate_public_key(line: str) -> str:
    """校验用户提交的公钥行；不合法抛 OpsError，合法返回清洗后的行。"""
    text = (line or "")
    if "\n" in text or "\r" in text:
        raise OpsError("公钥只能是一行（禁止换行注入）")
    text = text.strip()
    if not text:
        raise OpsError("公钥不能为空")
    match = PUBKEY_RE.match(text)
    if not match:
        raise OpsError("不是合法的 SSH 公钥（应以 ssh-rsa / ssh-ed25519 / ecdsa-sha2- / sk- 开头）")
    return text


def parse_fingerprint(text: str) -> str:
    """从 ``ssh-keygen -lf -`` 的输出里取指纹（``2048 SHA256:xxx comment (RSA)``）。"""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and (parts[1].startswith("SHA256:") or parts[1].startswith("MD5:")):
            return parts[1]
    return ""


# ---------------------------------------------------------------- 网络工具

NET_TOOLS = ("ping", "traceroute", "mtr", "curl")


def check_target(value: str) -> str:
    """网络工具目标校验：只允许域名 / IP / IPv6，禁掉一切 shell 元字符。"""
    text = (value or "").strip()
    if not text:
        raise OpsError("目标不能为空")
    if not TARGET_RE.match(text):
        raise OpsError("目标不合法（只能包含字母、数字、点、冒号、连字符与方括号）")
    if ".." in text:
        raise OpsError("目标不合法（不允许连续的点）")
    return text


def check_net_tool(value: str) -> str:
    text = (value or "").strip().lower()
    if text not in NET_TOOLS:
        raise OpsError(f"不支持的工具，可选：{', '.join(NET_TOOLS)}")
    return text


# ---------------------------------------------------------------- 备份


def check_backup_name(name: str) -> str:
    """备份文件名白名单：不含路径分隔符、不以点开头、后缀必须是归档后缀。"""
    text = (name or "").strip()
    if not text or not BACKUP_NAME_RE.match(text):
        raise OpsError("备份名不合法（只允许字母数字与 . _ -）")
    if ".." in text:
        raise OpsError("备份名不合法（不允许 ..）")
    if not text.endswith(BACKUP_SUFFIXES):
        raise OpsError(f"备份名必须以 {' / '.join(BACKUP_SUFFIXES)} 结尾")
    return text


def default_backup_name(now: datetime | None = None) -> str:
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    return f"backup-{stamp}{BACKUP_SUFFIX}"


def check_backup_source(path: str, protected: frozenset[str] | set[str] = frozenset()) -> str:
    """备份源路径校验：必须存在，且不能是文件系统根或 PROTECTED 目录本身。"""
    text = (path or "").strip()
    if not text:
        raise OpsError("备份路径不能为空")
    if "\x00" in text:
        raise OpsError("路径包含非法字符")
    full = os.path.realpath(os.path.abspath(text))
    if full == os.path.dirname(full):
        raise OpsError("不能备份文件系统根目录")
    if full in protected:
        raise OpsError(f"受保护的系统目录，禁止备份：{full}")
    if not os.path.exists(full):
        raise OpsError(f"路径不存在：{full}")
    return full


def tree_size(paths: list[str], limit: int) -> int:
    """统计待备份内容的总体积，超过 ``limit`` 立刻抛 OpsError。

    不跟随符号链接（``followlinks=False``）：备份 / 统计都不该越过链接目标，
    否则一个 ``ln -s / /data/link`` 就能让体积统计变成整盘扫描。
    """
    total = 0
    for path in paths:
        if os.path.isfile(path) and not os.path.islink(path):
            total += os.path.getsize(path)
        else:
            for base, _dirs, files in os.walk(path, followlinks=False):
                for name in files:
                    full = os.path.join(base, name)
                    try:
                        stat = os.lstat(full)
                    except OSError:
                        continue
                    total += stat.st_size
                    if total > limit:
                        raise OpsError(f"备份内容超过上限（{limit // (1024 ** 3)} GiB）")
                if total > limit:
                    raise OpsError(f"备份内容超过上限（{limit // (1024 ** 3)} GiB）")
        if total > limit:
            raise OpsError(f"备份内容超过上限（{limit // (1024 ** 3)} GiB）")
    return total


def check_remote(value: str) -> str:
    """rclone 远程路径校验：``name:path``。"""
    text = (value or "").strip()
    if not REMOTE_RE.match(text):
        raise OpsError("远程路径不合法（形如 gdrive:backups）")
    if ".." in text:
        raise OpsError("远程路径不合法（不允许 ..）")
    return text


def parse_rclone_remotes(text: str) -> list[dict]:
    """解析 ``rclone listremotes``（每行一个 ``name:``）。"""
    remotes = []
    for line in (text or "").splitlines():
        name = line.strip()
        if not name.endswith(":") or len(name) < 2:
            continue
        remotes.append({"name": name, "label": name[:-1]})
    return remotes


# ---------------------------------------------------------------- 数据库


def check_db_host(value: str) -> str:
    text = (value or "").strip() or "127.0.0.1"
    if not HOST_RE.match(text):
        raise OpsError("主机不合法（只允许 IP 或主机名）")
    return text


def check_ident(value: str, label: str) -> str:
    text = (value or "").strip()
    if not text:
        raise OpsError(f"{label} 不能为空")
    if not IDENT_RE.match(text):
        raise OpsError(f"{label} 不合法（只允许字母数字与 . _ -，最长 64）")
    return text
