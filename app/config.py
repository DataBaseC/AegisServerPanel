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
    if os.geteuid() == 0:
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
        # secret 用于签名下载链接等短时凭据
        if not self.data.get("secret"):
            self.data["secret"] = secrets.token_hex(32)
            self.save()
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
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(self.data, indent=2), "utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
            os.chmod(self.path, 0o600)
            self._mtime = self._stat_mtime()

    @property
    def secret(self) -> bytes:
        return bytes.fromhex(self.data["secret"])

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

    def sign(self, payload: str) -> str:
        return hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()

    def make_short_token(self, ttl: int = 300) -> str:
        expires = int(time.time()) + ttl
        return f"{expires}.{self.sign(str(expires))}"

    def check_short_token(self, token: str) -> bool:
        try:
            expires_s, signature = token.split(".", 1)
            expires = int(expires_s)
        except (ValueError, AttributeError):
            return False
        if expires < time.time():
            return False
        return hmac.compare_digest(self.sign(expires_s), signature)


config = Config()
