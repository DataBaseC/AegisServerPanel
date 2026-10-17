"""配置持久化与面板密码管理。

密码使用 PBKDF2-HMAC-SHA256 加盐哈希后保存在本地配置文件中，
配置文件权限固定为 0600，只允许服务运行用户读取。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

from .utils import password_is_weak

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


def hash_password(password: str) -> str:
    """生成密码哈希串（PBKDF2-HMAC-SHA256 + 随机盐）。

    2.0 M4 起多用户与单密码共用同一种哈希格式，便于把既有
    ``password_hash`` 原样迁移成 ``username=admin`` 的用户记录。
    """
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password_hash(stored: str, password: str) -> bool:
    """校验密码与哈希串是否匹配（常量时间比较）。"""
    if not stored:
        return False
    try:
        _algo, iterations, salt_hex, hash_hex = str(stored).split("$")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), hash_hex)


# 多用户 / RBAC（2.0 M4）
# 用户名只允许字母数字与 _ . -，长度 3~32：既方便 URL/日志里辨认，也避免
# 与 shell、文件名构造冲突。角色是三档固定枚举，顺序即权限高低。
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
ROLE_VIEWER = "viewer"
ROLE_OPERATOR = "operator"
ROLE_ADMIN = "admin"
ROLES = (ROLE_VIEWER, ROLE_OPERATOR, ROLE_ADMIN)
LEGACY_ADMIN_NAME = "admin"


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
        # 最近一次加载失败的原因（None = 正常）。用于区分「从未初始化」与
        # 「配置文件坏了」——前者允许首次设密码，后者必须拒绝。
        self.load_error: str | None = None
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
        """从磁盘加载配置。

        读取失败或 JSON 损坏时**保留内存里的旧数据**，只记录 ``load_error``：
        如果把 ``data`` 清空，下一个请求会把面板当成「未初始化」（``/api/auth/setup``
        无需鉴权即可设置新密码），随后任意一次 ``save()`` 还会把空配置写回磁盘，
        永久抹掉密码哈希与 Agent 令牌。指纹照常更新，避免每个请求都重复读坏文件；
        文件被修好后指纹变化会自然重试。
        """
        if not self.path.exists():
            # 已经初始化过的部署，配置文件突然消失（误删、挂载点抖动、NFS 短暂
            # 不可见）不能当成「首次安装」：否则任何人打开页面都能重新设密码接管。
            if self.data.get("password_hash") or self.data.get("users"):
                self.load_error = "配置文件不存在（内存中保留已初始化的配置）"
                self._fingerprint = self._stat_fingerprint()
                return
            self.data = {}
            self.load_error = None
            self._fingerprint = self._stat_fingerprint()
            return
        try:
            data = json.loads(self.path.read_text("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("配置文件顶层必须是 JSON 对象")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            # 首次安装时 data 为空但 load_error 有值：此时的「未初始化」不可信，
            # set_password 会拒绝重新初始化，用户修好文件后即可恢复。
            self.load_error = f"{type(exc).__name__}: {exc}"
            self._fingerprint = self._stat_fingerprint()
            return
        self.data = data
        self.load_error = None
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
                           expires_days: int = 0, note: str = "",
                           token: str | None = None) -> str:
        """创建令牌，返回明文（仅此一次）。

        ``token`` 允许调用方指定自定义令牌（面板「自定义令牌」入口）；
        为 None/空时生成随机令牌。磁盘上只存哈希。
        """
        if scope not in ("full", "readonly", "custom"):
            raise ValueError(f"不支持的作用域: {scope}")
        if scope == "custom" and not prefixes:
            raise ValueError("custom 作用域必须提供命令前缀白名单")
        secret = (token or "").strip() or secrets.token_urlsafe(32)
        record = {
            "id": secrets.token_hex(4),
            "name": (name or "未命名令牌").strip()[:60],
            "hash": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
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
        return secret

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
    def password_weak(self) -> bool:
        """当前密码是否被判为弱（1.6.0 U1）。

        旧配置没有该字段时按 False 处理；下次登录验证成功会补记（见
        :meth:`verify_password`），无需用户重新设置密码。
        """
        return bool(self.data.get("password_weak"))

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
        with self._lock:
            self.reload_if_changed()  # 外部命令改过配置时以磁盘为准，防止旧内存态覆盖
            if only_if_uninitialized and self.load_error:
                # 配置文件存在但读不出来：不能把它当成「首次安装」而允许重新设密码，
                # 否则坏文件 = 一键接管面板。
                raise ValueError("配置文件无法读取或解析，请先修复配置文件再初始化")
            if only_if_uninitialized and self.data.get("password_hash"):
                raise ValueError("面板已初始化")
            self.data["password_hash"] = hash_password(password)
            # 只存派生出的布尔标记（非敏感），供安全巡检判断"密码强度偏弱"
            self.data["password_weak"] = password_is_weak(password)
            self.data["updated_at"] = int(time.time())
            self._sync_admin_user_unlocked(password)
            self.save()

    def verify_password(self, password: str) -> bool:
        stored = self.data.get("password_hash")
        if not verify_password_hash(stored, password):
            return False
        if "password_weak" not in self.data:
            # 旧配置升级：登录时能拿到明文，顺手补记强度，避免巡检永远看不到这一项
            self.data["password_weak"] = password_is_weak(password)
            self.save()
        return True

    # ---- 多用户与 RBAC（2.0 M4）----
    # ``users`` 是可选列表：不存在/为空时面板完全走原有的单密码逻辑
    # （单密码视为 admin），所有既有部署与测试行为不变。一旦通过
    # POST /api/panel/users 创建第一个用户，历史单密码会被迁移成
    # ``username=admin`` 的一条记录，仍可用原密码登录。
    @property
    def users(self) -> list[dict]:
        self.reload_if_changed()
        users = self.data.get("users")
        if not isinstance(users, list):
            return []
        return [u for u in users if isinstance(u, dict) and u.get("username")]

    @property
    def has_users(self) -> bool:
        """是否已进入多用户模式（RBAC 只在为真时生效）。"""
        return bool(self.users)

    def find_user(self, username: str) -> dict | None:
        target = str(username or "").strip()
        if not target:
            return None
        for user in self.users:
            if user.get("username") == target:
                return dict(user)
        return None

    def user_by_id(self, user_id: str) -> dict | None:
        for user in self.users:
            if user.get("id") == user_id:
                return dict(user)
        return None

    def admin_count(self) -> int:
        return len([u for u in self.users if u.get("role") == ROLE_ADMIN and not u.get("disabled")])

    def create_user(self, username: str, password: str, role: str = ROLE_VIEWER) -> dict:
        """创建用户；首个用户创建前把历史单密码迁移成 admin 记录。"""
        name = str(username or "").strip()
        if not USERNAME_RE.match(name):
            raise ValueError("用户名只能用字母、数字、下划线、点、连字符，长度 3~32")
        if role not in ROLES:
            raise ValueError(f"角色只能是：{', '.join(ROLES)}")
        _validate_password_strength(password)
        with self._lock:
            self.reload_if_changed()
            users = list(self.data.get("users") or [])
            self._seed_admin_unlocked(users)
            if any(u.get("username") == name for u in users if isinstance(u, dict)):
                raise ValueError(f"用户名已存在：{name}")
            now = int(time.time())
            record = {
                "id": secrets.token_hex(8),
                "username": name,
                "role": role,
                "password_hash": hash_password(password),
                "totp_secret": "",
                "totp_enabled": False,
                "recovery_hashes": [],
                "created_at": now,
                "disabled": False,
            }
            users.append(record)
            self.data["users"] = users
            self.save()
            return dict(record)

    def update_user(self, user_id: str, patch: dict) -> dict:
        """修改角色 / 禁用状态 / 重置密码；不允许把最后一个管理员降级或禁用。"""
        with self._lock:
            self.reload_if_changed()
            users = list(self.data.get("users") or [])
            index = next((i for i, u in enumerate(users)
                          if isinstance(u, dict) and u.get("id") == user_id), None)
            if index is None:
                raise ValueError("用户不存在")
            user = dict(users[index])
            role = patch.get("role")
            if role is not None:
                if role not in ROLES:
                    raise ValueError(f"角色只能是：{', '.join(ROLES)}")
                user["role"] = role
            if patch.get("disabled") is not None:
                user["disabled"] = bool(patch["disabled"])
            password = patch.get("password")
            if password:
                _validate_password_strength(password)
                user["password_hash"] = hash_password(password)
            if self._would_drop_last_admin(users, user):
                raise ValueError("不能移除最后一个管理员：请先把其他用户提升为 admin")
            users[index] = user
            self.data["users"] = users
            self.save()
            return dict(user)

    def delete_user(self, user_id: str) -> dict:
        with self._lock:
            self.reload_if_changed()
            users = list(self.data.get("users") or [])
            target = next((u for u in users
                           if isinstance(u, dict) and u.get("id") == user_id), None)
            if target is None:
                raise ValueError("用户不存在")
            if self._would_drop_last_admin(users, None, removed_id=user_id):
                raise ValueError("不能删除最后一个管理员")
            self.data["users"] = [u for u in users
                                  if not (isinstance(u, dict) and u.get("id") == user_id)]
            self.save()
            return dict(target)

    def verify_user_password(self, user: dict, password: str) -> bool:
        return verify_password_hash(str((user or {}).get("password_hash") or ""), password)

    def set_user_password(self, user_id: str, password: str) -> None:
        self.update_user(user_id, {"password": password})

    def consume_user_recovery_code(self, user_id: str, code: str) -> bool:
        """核销某个用户的一次性恢复码（用后即焚）。"""
        from . import totp as totp_mod

        with self._lock:
            self.reload_if_changed()
            users = list(self.data.get("users") or [])
            index = next((i for i, u in enumerate(users)
                          if isinstance(u, dict) and u.get("id") == user_id), None)
            if index is None:
                return False
            hashes = [h for h in (users[index].get("recovery_hashes") or []) if isinstance(h, str)]
            hit = totp_mod.consume_recovery(code, hashes)
            if hit is None:
                return False
            hashes.pop(hit)
            users[index]["recovery_hashes"] = hashes
            self.data["users"] = users
            self.save()
            return True

    def set_user_totp(self, user_id: str, **patch) -> dict:
        """更新某个用户的 TOTP 字段（secret / enabled / recovery_hashes）。"""
        with self._lock:
            self.reload_if_changed()
            users = list(self.data.get("users") or [])
            index = next((i for i, u in enumerate(users)
                          if isinstance(u, dict) and u.get("id") == user_id), None)
            if index is None:
                raise ValueError("用户不存在")
            users[index] = {**users[index], **patch}
            self.data["users"] = users
            self.save()
            return dict(users[index])

    def _would_drop_last_admin(self, users: list[dict], candidate: dict | None = None,
                               removed_id: str = "") -> bool:
        """改完/删完之后是否一个可用管理员都不剩。"""
        admins = 0
        for user in users:
            if not isinstance(user, dict):
                continue
            if removed_id and user.get("id") == removed_id:
                continue
            effective = candidate if (candidate and user.get("id") == candidate.get("id")) else user
            if effective.get("role") == ROLE_ADMIN and not effective.get("disabled"):
                admins += 1
        return admins == 0

    def _seed_admin_unlocked(self, users: list[dict]) -> None:
        """把历史单密码迁移成 admin 用户（仅在列表里还没有任何用户时）。"""
        if any(isinstance(u, dict) and u.get("username") for u in users):
            return
        stored = self.data.get("password_hash")
        if not stored:
            return
        users.append({
            "id": secrets.token_hex(8),
            "username": LEGACY_ADMIN_NAME,
            "role": ROLE_ADMIN,
            "password_hash": stored,
            "totp_secret": self.data.get("totp_secret") or "",
            "totp_enabled": bool(self.data.get("totp_enabled")),
            "recovery_hashes": list(self.data.get("totp_recovery_hashes") or []),
            "created_at": int(self.data.get("updated_at") or time.time()),
            "disabled": False,
            "note": "迁移自单密码模式",
        })

    def _sync_admin_user_unlocked(self, password: str) -> None:
        """单密码被 CLI / 改密接口更新时，同步 admin 用户（保住救援通道）。"""
        users = self.data.get("users")
        if not isinstance(users, list) or not users:
            return
        for user in users:
            if isinstance(user, dict) and user.get("username") == LEGACY_ADMIN_NAME:
                user["password_hash"] = hash_password(password)
                return


config = Config()
