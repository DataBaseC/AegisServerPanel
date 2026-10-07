"""快捷设置：统一的可调参数模型（读写 ``config.json`` 的 ``prefs`` 命名空间）。

设计要点：

- **单一真相源**：所有可调参数在这里定义一次（默认值、范围、生效方式），
  消费方（``auth`` / ``apps`` / ``manage`` / 路由）通过 ``prefs.get()`` 读取，
  不在各自模块里散落常量。
- **与既有顶层键双向兼容**：``trust_proxy`` / ``allowed_origins`` / ``log_dirs``
  历史上是顶层键（``config.py`` 有对应 property，``log_routes`` / ``auth`` 直接读），
  这里读写时同步维护，避免出现"两套真相"。
- **热加载**：每次读取都走 ``config.reload_if_changed()``（mtime 判定），
  外部命令或界面改完立即生效，无需重启面板。
- **越界即拒绝**：非法值抛 ``PrefsError``（调用方翻成 HTTP 400），不做静默兜底。
"""

from __future__ import annotations

import ipaddress
import os
import re
import time
from typing import Any, Callable

from .config import config

# ---------------------------------------------------------------- 参数定义

# 生效方式：immediate 立即 / new-session 仅对新会话 / restart 需重启面板
EFFECT_IMMEDIATE = "immediate"
EFFECT_NEW_SESSION = "new-session"
EFFECT_RESTART = "restart"

ORIGIN_RE = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?$")
LOG_EXT_HINT = (".log", ".txt", ".out", ".err")

MIN_LOG_BYTES = 256 * 1024
MAX_LOG_BYTES = 256 * 1024 * 1024


class PrefsError(ValueError):
    """参数不合法或不被允许。"""


def _int_range(low: int, high: int, unit: str = "") -> Callable[[Any], int]:
    def check(value: Any) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise PrefsError(f"必须是整数{'（单位：' + unit + '）' if unit else ''}")
        if not low <= number <= high:
            raise PrefsError(f"需要在 {low} ~ {high} 之间{'（单位：' + unit + '）' if unit else ''}")
        return number

    return check


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("1", "true", "yes", "on", "是"):
            return True
        if lowered in ("0", "false", "no", "off", "否"):
            return False
    raise PrefsError("需要是 true / false")


def _origins(value: Any) -> list[str]:
    if isinstance(value, str):
        items = [line.strip() for line in value.splitlines() if line.strip()]
    elif isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
    else:
        raise PrefsError("需要是 origin 列表")
    result = []
    for item in items:
        normalized = item.rstrip("/")
        if not ORIGIN_RE.match(normalized):
            raise PrefsError(f"不是合法来源（形如 http://host:port）：{item}")
        if normalized not in result:
            result.append(normalized)
    if len(result) > 20:
        raise PrefsError("来源最多 20 条")
    return result


def _log_dirs(value: Any) -> list[str]:
    if isinstance(value, str):
        items = [line.strip() for line in value.splitlines() if line.strip()]
    elif isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
    else:
        raise PrefsError("需要是目录列表")
    result = []
    for item in items:
        if not item.startswith("/") and not os.path.isabs(item):
            raise PrefsError(f"必须是绝对路径：{item}")
        normalized = os.path.realpath(os.path.abspath(item))
        if normalized == os.path.dirname(normalized):  # 文件系统根
            raise PrefsError("不能把文件系统根目录加入日志白名单")
        if not os.path.isdir(normalized):
            # 也覆盖 /etc/shadow 这类"存在但是文件"的输入，错误信息比"目录不存在"更准确
            raise PrefsError(f"不是已存在的目录：{item}")
        if normalized not in result:
            result.append(normalized)
    if not result:
        raise PrefsError("至少保留一个日志目录")
    if len(result) > 20:
        raise PrefsError("日志目录最多 20 条")
    return result


def _host(value: Any) -> str:
    text = str(value or "").strip()
    if text in ("0.0.0.0", "::"):
        return text
    try:
        ipaddress.ip_address(text)
    except ValueError:
        raise PrefsError(f"不是合法 IP 地址：{text}（不支持域名，避免启动时解析失败）")
    return text


# key -> (默认值, 校验器, 生效方式, 说明)
FIELDS: dict[str, tuple[Any, Callable[[Any], Any], str, str]] = {
    "autostart.apps_enabled": (
        True, _bool, EFFECT_IMMEDIATE,
        "面板启动时是否自动拉起标记了自启的常驻应用",
    ),
    "logs.app_max_bytes": (
        4 * 1024 * 1024, _int_range(MIN_LOG_BYTES, MAX_LOG_BYTES, "字节"),
        EFFECT_IMMEDIATE, "单个常驻应用日志文件的上限，超过后轮转为 .1",
    ),
    "logs.panel_max_bytes": (
        10 * 1024 * 1024, _int_range(MIN_LOG_BYTES, MAX_LOG_BYTES, "字节"),
        EFFECT_IMMEDIATE, "面板自身日志 panel.log 的上限，超过后轮转为 .1",
    ),
    "session.ttl_hours": (
        12, _int_range(1, 168, "小时"), EFFECT_NEW_SESSION,
        "登录会话有效期（滑动续期）；已签发的会话保留原到期时间",
    ),
    "security.max_failures": (
        5, _int_range(3, 20, "次"), EFFECT_IMMEDIATE,
        "同一来源 IP 连续失败多少次后锁定",
    ),
    "security.lockout_seconds": (
        60, _int_range(10, 3600, "秒"), EFFECT_IMMEDIATE,
        "锁定时长",
    ),
    "security.trust_proxy": (
        False, _bool, EFFECT_IMMEDIATE,
        "位于可信反向代理之后时开启（开启后按 X-Forwarded-For 最后一跳判定来源）",
    ),
    "security.allowed_origins": (
        [], _origins, EFFECT_IMMEDIATE,
        "反向代理换了域名时的 WebSocket 握手放行来源",
    ),
    "security.log_dirs": (
        ["/var/log"], _log_dirs, EFFECT_IMMEDIATE,
        "日志接口允许读取的目录白名单",
    ),
    "listen.host": (
        "0.0.0.0", _host, EFFECT_RESTART,
        "面板监听地址（重启生效）",
    ),
    "listen.port": (
        8787, _int_range(1024, 65535, "端口"), EFFECT_RESTART,
        "面板监听端口（重启生效）",
    ),
}

# prefs 键 -> config.json 顶层键（历史上存在、且被其它模块直接读取）
LEGACY_KEYS = {
    "security.trust_proxy": "trust_proxy",
    "security.allowed_origins": "allowed_origins",
    "security.log_dirs": "log_dirs",
}


def _defaults() -> dict:
    return {key: (list(value) if isinstance(value, list) else value)
            for key, (value, *_rest) in FIELDS.items()}


def _dig(data: dict, key: str, default: Any) -> Any:
    node: Any = data
    for part in key.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _plant(data: dict, key: str, value: Any) -> None:
    parts = key.split(".")
    node = data
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = value


class Prefs:
    """``config.json`` 中 ``prefs`` 命名空间的读写与校验。"""

    def __init__(self) -> None:
        self._cache: dict[str, Any] | None = None
        self._cache_stamp: tuple[float, int] | None = None

    # ---- 读 ----
    def _stamp(self) -> tuple[float, int]:
        try:
            stat = config.path.stat()
            return (stat.st_mtime, stat.st_size)
        except OSError:
            return (0.0, 0)

    def all(self) -> dict[str, Any]:
        """当前生效值。兼容三种来源：prefs 命名空间 > 顶层 legacy 键 > 默认值。"""
        config.reload_if_changed()
        stamp = self._stamp()
        if stamp == self._cache_stamp and self._cache is not None:
            return dict(self._cache)
        data = config.data if isinstance(config.data, dict) else {}
        node = data.get("prefs") if isinstance(data.get("prefs"), dict) else {}
        values = _defaults()
        for key in FIELDS:
            found = None
            # 取值优先级：扁平顶层键（手工配置/测试更直观）> prefs 命名空间 > legacy 顶层键
            if key in data:
                found = data[key]
            if found is None:
                found = _dig(node, key, None)
            legacy = LEGACY_KEYS.get(key)
            if found is None and legacy and legacy in data:
                found = data[legacy]
            if found is None:
                continue
            check = FIELDS[key][1]
            try:
                values[key] = check(found)
            except PrefsError:
                values[key] = _defaults()[key]  # 配置被手工改坏时回落到默认值，不让面板起不来
        self._cache = values
        self._cache_stamp = stamp
        return dict(values)

    def _invalidate(self) -> None:
        """强制下次读取重新解析。

        ``config.save()`` 在多数场景下 mtime 的秒级精度不足以区分连续两次写入，
        只把缓存戳置空会被 ``stamp == self._cache_stamp`` 短路掉（实测踩过），
        因此这里显式作废缓存。
        """
        self._cache = None  # type: ignore[assignment]
        self._cache_stamp = None

    def get(self, key: str, default: Any = None) -> Any:
        if key not in FIELDS:
            raise KeyError(key)
        return self.all().get(key, default)

    def effect(self, key: str) -> str:
        return FIELDS[key][2]

    def describe(self) -> list[dict]:
        """给前端渲染用的字段说明（含范围与生效方式）。"""
        values = self.all()
        described = []
        for key, (default, _check, effect, note) in FIELDS.items():
            described.append({
                "key": key,
                "value": values[key],
                "default": default,
                "effect": effect,
                "note": note,
            })
        return described

    # ---- 写 ----
    def update(self, patch: dict[str, Any]) -> dict:
        """校验并写入。返回 ``{"changed": {...}, "pending_restart": bool, "values": {...}}``。"""
        if not isinstance(patch, dict) or not patch:
            raise PrefsError("没有需要修改的项")
        unknown = [k for k in patch if k not in FIELDS]
        if unknown:
            raise PrefsError(f"未知设置项：{', '.join(sorted(unknown))}")

        current = self.all()
        changed: dict[str, Any] = {}
        for key, raw in patch.items():
            check = FIELDS[key][1]
            try:
                value = check(raw)
            except PrefsError as exc:
                raise PrefsError(f"{key}: {exc}")
            if value != current[key]:
                changed[key] = value

        if not changed:
            return {"changed": {}, "pending_restart": False, "values": current,
                    "message": "没有变化"}

        config.reload_if_changed()
        data = config.data if isinstance(config.data, dict) else {}
        prefs_node = data.get("prefs")
        if not isinstance(prefs_node, dict):
            prefs_node = {}
            data["prefs"] = prefs_node
        for key, value in changed.items():
            _plant(prefs_node, key, value)
            legacy = LEGACY_KEYS.get(key)
            if legacy:
                data[legacy] = value  # 同步顶层键，保证旧读取路径立即看到新值
        prefs_node["updated_at"] = int(time.time())
        config.data = data
        config.save()
        self._invalidate()
        values = self.all()
        pending = any(FIELDS[key][2] == EFFECT_RESTART for key in changed)
        return {
            "changed": changed,
            "pending_restart": pending,
            "values": values,
            "message": "配置已更新" + ("，部分项需重启面板后生效" if pending else "（立即生效）"),
        }

    # ---- 便捷读取（消费方用，避免到处写 get 的字符串键） ----
    def app_log_limit(self) -> int:
        return int(self.get("logs.app_max_bytes"))

    def panel_log_limit(self) -> int:
        return int(self.get("logs.panel_max_bytes"))

    def session_ttl_seconds(self) -> int:
        return int(self.get("session.ttl_hours")) * 3600

    def max_failures(self) -> int:
        return int(self.get("security.max_failures"))

    def lockout_seconds(self) -> int:
        return int(self.get("security.lockout_seconds"))

    def apps_autostart_enabled(self) -> bool:
        return bool(self.get("autostart.apps_enabled"))


prefs = Prefs()
