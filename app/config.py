"""配置持久化与面板密码管理。

密码使用 PBKDF2-HMAC-SHA256 加盐哈希后保存在本地配置文件中，
配置文件权限固定为 0600，只允许服务运行用户读取。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

PBKDF2_ITERATIONS = 260_000
SESSION_TTL = 12 * 3600
COOKIE_NAME = "sp_session"

# 运行模式：公网模式只读监控，内网模式解锁全部控制能力。
# 模式只能通过在服务器本机执行命令切换，面板自身不提供切换接口。
MODE_PUBLIC = "public"
MODE_INTERNAL = "internal"
MODE_LABELS = {
    MODE_PUBLIC: "公网模式（只读）",
    MODE_INTERNAL: "内网模式（完全控制）",
}


def default_config_path() -> Path:
    env = os.environ.get("SERVERPANEL_CONFIG")
    if env:
        return Path(env)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/etc/serverpanel/config.json")
    return Path.home() / ".config" / "serverpanel" / "config.json"


class Config:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_config_path()
        self._lock = threading.RLock()
        self._mtime = 0.0
        self.data: dict = {}
        self.load()

    def _stat_mtime(self) -> float:
        try:
            return self.path.stat().st_mtime
        except OSError:
            return 0.0

    def load(self) -> None:
        with self._lock:
            self._load_unlocked()

    def _load_unlocked(self) -> None:
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text("utf-8"))
            except (OSError, json.JSONDecodeError):
                self.data = {}
        self._mtime = self._stat_mtime()

    def reload_if_changed(self) -> bool:
        """配置文件被外部命令（如 serverpanel --enable-internal）修改后热加载。"""
        mtime = self._stat_mtime()
        with self._lock:
            if mtime == self._mtime:
                return False
            self._load_unlocked()
        return True

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # 临时文件名带上 pid：服务进程与本机 CLI 命令（serverpanel --enable-internal 等）
            # 可能并发写同一配置，避免互相覆盖对方的临时文件（os.replace 保证单文件原子性）。
            tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
            tmp.write_text(json.dumps(self.data, indent=2), "utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
            self._mtime = self._stat_mtime()

    # ---- 运行模式 ----
    @property
    def mode(self) -> str:
        self.reload_if_changed()
        return self.data.get("mode", MODE_PUBLIC)

    @property
    def mode_label(self) -> str:
        return MODE_LABELS.get(self.mode, self.mode)

    @property
    def mode_updated_at(self) -> int:
        return int(self.data.get("mode_updated_at") or 0)

    def set_mode(self, mode: str) -> None:
        if mode not in MODE_LABELS:
            raise ValueError(f"未知模式: {mode}")
        with self._lock:
            self.data["mode"] = mode
            self.data["mode_updated_at"] = int(time.time())
            self.save()

    # ---- Agent 接入令牌 ----
    # 供本地脚本 / AI Agent 通过 HTTP 直接执行命令，仅在内网模式下生效。
    @property
    def agent_token(self) -> str:
        self.reload_if_changed()
        return self.data.get("agent_token") or ""

    @property
    def agent_token_updated_at(self) -> int:
        return int(self.data.get("agent_token_updated_at") or 0)

    def issue_agent_token(self, token: str | None = None) -> str:
        token = token or secrets.token_urlsafe(32)
        with self._lock:
            self.data["agent_token"] = token
            self.data["agent_token_updated_at"] = int(time.time())
            self.save()
        return token

    def revoke_agent_token(self) -> None:
        with self._lock:
            self.data.pop("agent_token", None)
            self.data.pop("agent_token_updated_at", None)
            self.save()

    # ---- 安全相关可配置项 ----
    # 日志接口允许读取的目录白名单（realpath 解析后仍须落在白名单内）。
    # 无论服务是否以 root 运行，白名单之外一律拒绝——不能因为 root 就放开全盘读取，
    # 否则公网只读模式下登录用户可以读到 /etc/shadow、面板自身配置等任意文件。
    @property
    def log_dirs(self) -> list[str]:
        dirs = self.data.get("log_dirs")
        if (
            isinstance(dirs, list)
            and dirs
            and all(isinstance(d, str) and os.path.isabs(d) for d in dirs)
        ):
            return [os.path.realpath(os.path.abspath(d)) for d in dirs]
        return ["/var/log"]

    # 仅当面板部署在可信反向代理之后时才开启。开启后 client_ip 取
    # X-Forwarded-For 的最后一跳（由可信代理写入），否则直接取 TCP 对端地址，
    # 避免攻击者伪造 XFF 绕过登录失败锁定。
    @property
    def trust_proxy(self) -> bool:
        return bool(self.data.get("trust_proxy", False))

    # 跨站 WebSocket 握手的额外放行来源（反向代理换了域名时配置）。
    # 同源（Origin 与 Host 一致）永远放行。
    @property
    def allowed_origins(self) -> list[str]:
        origins = self.data.get("allowed_origins")
        if isinstance(origins, list):
            return [o for o in origins if isinstance(o, str) and o]
        return []

    @property
    def initialized(self) -> bool:
        return bool(self.data.get("password_hash"))

    @property
    def hostname_label(self) -> str:
        return self.data.get("label") or "ServerPanel"

    def set_password(self, password: str) -> None:
        if len(password) < 8:
            raise ValueError("密码长度至少 8 位")
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
        self.data["password_hash"] = (
            f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"
        )
        self.data["updated_at"] = int(time.time())
        self.save()

    def verify_password(self, password: str) -> bool:
        stored = self.data.get("password_hash")
        if not stored:
            return False
        try:
            _algo, iterations, salt_hex, hash_hex = stored.split("$")
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
            )
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(digest.hex(), hash_hex)


config = Config()
