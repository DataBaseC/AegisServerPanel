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

PBKDF2_ITERATIONS = 600_000  # OWASP 2023 对 PBKDF2-HMAC-SHA256 的推荐值
SESSION_TTL = 12 * 3600
COOKIE_NAME = "sp_session"

# 密码强度策略（1.4.0 起）：最低 12 位 + 常见弱口令/键盘模式黑名单。
# 面板密码 = root shell，8 位纯小写在现代算力下不够看。
PASSWORD_MIN_LENGTH = 12
WEAK_PASSWORDS = frozenset({
    "password", "password1", "password12", "password123", "passw0rd",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "qwertyuiop", "abc123", "abc123456",
    "111111", "000000", "iloveyou", "admin", "admin123", "administrator",
    "root", "toor", "letmein", "welcome", "monkey", "dragon",
    "serverpanel", "serverpanel1", "server", "panel", "ubuntu", "debian",
    "changeme", "test123", "666666", "888888", "aaaaaaaa", "qwerty12",
})


def _validate_password_strength(password: str) -> None:
    """密码强度校验：长度 + 弱口令黑名单 + 键盘/重复模式。"""
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"密码长度至少 {PASSWORD_MIN_LENGTH} 位")
    lowered = password.lower()
    if lowered in WEAK_PASSWORDS:
        raise ValueError("这是常见的弱口令，请换一个")
    # 单一字符重复（aaaaaaaaaaaa）或顺序键盘行（qwertyuiop…）
    if len(set(lowered)) <= 3:
        raise ValueError("密码字符种类太少")
    for row in ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"):
        if row[:6] in lowered or row[::-1][:6] in lowered:
            raise ValueError("密码包含连续键盘序列，请换一个")


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
        self._fingerprint: tuple[int, int, int] = (0, 0, 0)
        self.data: dict = {}
        self.load()

    def _stat_fingerprint(self) -> tuple[int, int, int]:
        """配置文件指纹 (mtime_ns, size, ino)。

        只比 st_mtime 秒级浮点更可靠：PRoot/容器文件系统 mtime 可能只有秒级
        精度，同秒内的外部修改（--disable-internal / --revoke-agent-token）
        会被误判为「没变」，导致模式降级或令牌吊销迟迟不生效。三元组里任一
        变化都触发重载。
        """
        try:
            st = self.path.stat()
            return (st.st_mtime_ns, st.st_size, st.st_ino)
        except OSError:
            return (0, 0, 0)

    def load(self) -> None:
        with self._lock:
            self._load_unlocked()

    def _load_unlocked(self) -> None:
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text("utf-8"))
            except (OSError, json.JSONDecodeError):
                self.data = {}
        self._fingerprint = self._stat_fingerprint()

    def reload_if_changed(self) -> bool:
        """配置文件被外部命令（如 serverpanel --enable-internal）修改后热加载。"""
        fingerprint = self._stat_fingerprint()
        with self._lock:
            if fingerprint == self._fingerprint:
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
            self._fingerprint = self._stat_fingerprint()

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
    # 1.4.0 起支持多令牌：每个令牌有名称、作用域、过期时间；
    # 磁盘上只存 SHA-256 哈希。旧版单令牌（agent_token 明文字段）在首次
    # 访问时自动迁移为一条 full 作用域的「默认令牌」。
    @property
    def agent_tokens(self) -> list[dict]:
        self.reload_if_changed()
        # 先做旧版迁移：任何读取者（列表、鉴权门、CLI）都会顺带把
        # agent_token 明文字段哈希化，避免"迁移只挂在某一条路径上"。
        self._migrate_legacy_token()
        tokens = self.data.get("agent_tokens")
        if not isinstance(tokens, list):
            return []
        return [t for t in tokens if isinstance(t, dict) and t.get("hash")]

    @property
    def agent_token_updated_at(self) -> int:
        tokens = self.agent_tokens
        return max((int(t.get("created_at", 0)) for t in tokens), default=0)

    def _migrate_legacy_token(self) -> bool:
        """把旧版 agent_token 明文迁移进多令牌列表（哈希化）。"""
        self.reload_if_changed()  # 先吸收外部改动，避免用陈旧内存覆盖别人刚写的配置
        legacy = self.data.get("agent_token")
        if not legacy or not isinstance(legacy, str):
            return False
        with self._lock:
            if self.data.get("agent_token") != legacy:
                return False  # 已被其他进程迁移
            tokens = list(self.data.get("agent_tokens") or [])
            digest = hashlib.sha256(legacy.encode("utf-8")).hexdigest()
            if not any(t.get("hash") == digest for t in tokens if isinstance(t, dict)):
                tokens.append({
                    "id": secrets.token_hex(4),
                    "name": "默认令牌（迁移自旧版）",
                    "hash": digest,
                    "scope": "full",
                    "prefixes": [],
                    "expires_at": 0,
                    "created_at": int(self.data.get("agent_token_updated_at") or time.time()),
                    "last_used_at": 0,
                    "note": "",
                })
            self.data.pop("agent_token", None)
            self.data.pop("agent_token_updated_at", None)
            self.data["agent_tokens"] = tokens
            self.save()
            return True

    def find_agent_token(self, token: str) -> dict | None:
        """按明文令牌查找（比对哈希，常量时间）；顺带完成旧版迁移。"""
        self._migrate_legacy_token()
        digest = hashlib.sha256((token or "").encode("utf-8")).hexdigest()
        now = time.time()
        for item in self.agent_tokens:
            stored = str(item.get("hash") or "")
            # 常量时间比较：消除时序侧信道
            if stored and hmac.compare_digest(digest, stored):
                expires = item.get("expires_at") or 0
                if expires and now > float(expires):
                    return None  # 过期令牌视同不存在
                return item
        return None

    def touch_agent_token(self, token_id: str) -> None:
        """记录令牌最近使用时间（节流落盘）。"""
        now = time.time()
        with self._lock:
            changed = False
            for item in self.data.get("agent_tokens") or []:
                if isinstance(item, dict) and item.get("id") == token_id:
                    if now - float(item.get("last_used_at") or 0) > 60:
                        item["last_used_at"] = int(now)
                        changed = True
            if changed:
                self.save()

    def create_agent_token(self, name: str, scope: str = "full",
                           prefixes: list[str] | None = None,
                           expires_days: int = 0, note: str = "") -> str:
        """创建令牌，返回明文（仅此一次）。"""
        if scope not in ("full", "readonly", "custom"):
            raise ValueError(f"不支持的作用域: {scope}")
        if scope == "custom" and not prefixes:
            raise ValueError("custom 作用域必须提供命令前缀白名单")
        token = secrets.token_urlsafe(32)
        record = {
            "id": secrets.token_hex(4),
            "name": (name or "未命名令牌").strip()[:60],
            "hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "scope": scope,
            "prefixes": [p.strip() for p in (prefixes or []) if p.strip()][:50],
            "expires_at": int(time.time() + expires_days * 86400) if expires_days else 0,
            "created_at": int(time.time()),
            "last_used_at": 0,
            "note": (note or "").strip()[:200],
        }
        with self._lock:
            self._migrate_legacy_token()
            tokens = list(self.data.get("agent_tokens") or [])
            tokens.append(record)
            self.data["agent_tokens"] = tokens
            self.save()
        return token

    def revoke_agent_token(self, token_id: str) -> bool:
        with self._lock:
            tokens = [t for t in (self.data.get("agent_tokens") or [])
                      if not (isinstance(t, dict) and t.get("id") == token_id)]
            if len(tokens) == len(self.data.get("agent_tokens") or []):
                return False
            self.data["agent_tokens"] = tokens
            self.save()
            return True

    def revoke_all_agent_tokens(self) -> int:
        with self._lock:
            count = len(self.data.get("agent_tokens") or [])
            self.data.pop("agent_tokens", None)
            self.data.pop("agent_token", None)
            self.data.pop("agent_token_updated_at", None)
            self.save()
            return count

    def issue_agent_token(self, token: str | None = None) -> str:
        """旧 CLI 入口兼容：创建一条 full 作用域令牌。"""
        if token:
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            record = {
                "id": secrets.token_hex(4),
                "name": "CLI 自定义令牌",
                "hash": digest,
                "scope": "full",
                "prefixes": [],
                "expires_at": 0,
                "created_at": int(time.time()),
                "last_used_at": 0,
                "note": "",
            }
            with self._lock:
                self._migrate_legacy_token()
                tokens = list(self.data.get("agent_tokens") or [])
                tokens.append(record)
                self.data["agent_tokens"] = tokens
                self.save()
            return token
        return self.create_agent_token(name="CLI 生成令牌", scope="full")

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

    # 远程拉取（/api/files/fetch）是否允许访问内网/回环/链路本地地址。
    # 默认 False：面板以 root 运行， unrestricted fetch 可被用作探测/读取
    # 内网服务（含云元数据 169.254.169.254）的跳板，且响应会落盘成文件
    # 可被读回（带回显的 SSRF）。内网运维场景可在配置中显式放行。
    @property
    def fetch_allow_private(self) -> bool:
        return bool(self.data.get("fetch_allow_private", False))

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

    # ---- TOTP 二次认证（1.4.0）----
    @property
    def totp_secret(self) -> str:
        return self.data.get("totp_secret") or ""

    @property
    def totp_enabled(self) -> bool:
        return bool(self.data.get("totp_enabled"))

    @property
    def totp_recovery_hashes(self) -> list[str]:
        hashes = self.data.get("totp_recovery_hashes")
        if isinstance(hashes, list):
            return [h for h in hashes if isinstance(h, str)]
        return []

    def set_totp_secret(self, secret: str) -> None:
        """保存 secret（setup 阶段）。

        1.4.1 起**不再**顺手把 ``totp_enabled`` 置回 False：那等于给
        「仅凭会话调 /totp/setup」留了一键关闭二次认证的后门。
        关闭 2FA 只能走 :meth:`disable_totp`（接口层要求验证密码）。
        """
        with self._lock:
            self.data["totp_secret"] = secret
            self.save()

    def enable_totp(self, recovery_hashes: list[str]) -> None:
        with self._lock:
            self.reload_if_changed()
            self.data["totp_enabled"] = True
            self.data["totp_recovery_hashes"] = recovery_hashes
            self.data["totp_enabled_at"] = int(time.time())
            self.save()

    def disable_totp(self) -> None:
        with self._lock:
            self.reload_if_changed()
            self.data.pop("totp_secret", None)
            self.data.pop("totp_enabled", None)
            self.data.pop("totp_recovery_hashes", None)
            self.data.pop("totp_enabled_at", None)
            self.save()

    def consume_recovery_code(self, code: str) -> bool:
        """核销一个恢复码（用后即焚）。命中返回 True。"""
        from . import totp as totp_mod

        hashes = self.totp_recovery_hashes
        index = totp_mod.consume_recovery(code, hashes)
        if index is None:
            return False
        with self._lock:
            hashes = list(self.data.get("totp_recovery_hashes") or [])
            if index < len(hashes):
                hashes.pop(index)
            self.data["totp_recovery_hashes"] = hashes
            self.save()
        return True

    def set_password(self, password: str, only_if_uninitialized: bool = False) -> None:
        # 长度下限与弱口令黑名单见 _validate_password_strength（1.4.0 起强化）
        _validate_password_strength(password)
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
        with self._lock:
            self.reload_if_changed()  # 外部命令改过配置时以磁盘为准，防止旧内存态覆盖
            if only_if_uninitialized and self.data.get("password_hash"):
                raise ValueError("面板已初始化")
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
