"""会话管理：登录令牌签发、校验、失败锁定。

会话写穿到 sessions.json（0600，与配置文件同目录）：
重启后面板登录态不丢。

1.4.0 起：

- **会话令牌磁盘哈希化**：sessions.json 里存的是令牌的 SHA-256，
  配置文件泄露也无法直接冒用会话。注意：从 1.3.1 及更早版本升级时，
  磁盘上是明文令牌、无法反推哈希，**旧会话一律失效（需要重新登录）**，
  加载时会把明文键直接清出文件。
- **失败锁定指数退避 + 持久化**：失败计数落盘（重启不清零），
  按累计失败次数升级锁定时长；IP 与全局双维度计数，防分布式慢速尝试。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

from fastapi import HTTPException, Request, WebSocket, status

from .config import COOKIE_NAME, MODE_INTERNAL, config
from .prefs import prefs

INTERNAL_HINT = "该功能仅在内网模式可用，请在服务器上执行 serverpanel --enable-internal 激活"

# 会话键的合法形态：令牌的 SHA-256 十六进制摘要（旧版明文键不符合）
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")

# 下面是出厂默认值；实际取值走 prefs（可在「设置 → 快捷设置」里改，立即生效）。
# 保留常量是为了兼容既有测试与外部引用。
MAX_FAILURES = 5
LOCKOUT_SECONDS = 60
SESSIONS_FILE = "sessions.json"
FAILURES_FILE = "failures.json"
PERSIST_MIN_INTERVAL = 60.0  # 滑动续期的落盘节流（秒）

# 锁定升级阶梯：(累计失败次数阈值, 锁定时长秒)。
# 第一档阈值可被 prefs.max_failures 覆盖（小于 5 时）；后续档位固定，
# 防止"每个 IP 只试一两次"的分布式慢速爆破靠重启计数清零绕过。
ESCALATION_TIERS = (
    (5, 60),        # 5 次 → 锁 1 分钟
    (10, 3600),     # 10 次 → 锁 1 小时
    (20, 86400),    # 20 次 → 锁 24 小时
)
# 失败计数的保留窗口：至少覆盖最长锁定档，否则升级永远攒不起来
FAILURE_WINDOW = 86400


def token_digest(token: str) -> str:
    """会话令牌的磁盘存储形式（SHA-256 十六进制）。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class FailureTracker:
    """登录失败计数：持久化 + 指数退避 + IP/全局双维度。

    - ``ips``：按来源 IP 计数（防单 IP 快速爆破）
    - ``global``：全局计数（防分布式慢速尝试）
    成功登录清除对应 IP 与全局计数；重启不再清零（计数落盘）。

    1.4.1 起锁定时长从**跨过档位阈值的那一刻**起算（``locked_until``），
    而不是"档位时长 − 最早一次失败的年龄"。原实现按后者计算：10 次失败
    若散布在 1 小时以上，剩余时长算出来是负数 → 直接不锁，慢速爆破反而
    永远不会被锁（实测 5 次/10 分钟、10 次/2 小时都是 0 秒）。
    """

    def __init__(self) -> None:
        self._ips: dict[str, list[float]] = {}
        self._global: list[float] = []
        # ip -> 锁定截止时间戳；global 维度单独一个
        self._locked_until: dict[str, float] = {}
        self._global_locked_until: float = 0.0
        self._lock = threading.RLock()  # status() 会在持锁状态下调用 locked_for
        self._load()

    def _file(self) -> Path:
        return Path(config.path).parent / FAILURES_FILE

    def _load(self) -> None:
        try:
            data = json.loads(self._file().read_text("utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return
        if not isinstance(data, dict):
            return
        now = time.time()
        ips = data.get("ips")
        if isinstance(ips, dict):
            for ip, attempts in ips.items():
                if isinstance(ip, str) and isinstance(attempts, list):
                    kept = [float(t) for t in attempts
                            if isinstance(t, (int, float)) and now - float(t) < FAILURE_WINDOW]
                    if kept:
                        self._ips[ip] = kept
        glob = data.get("global")
        if isinstance(glob, list):
            self._global = [float(t) for t in glob
                            if isinstance(t, (int, float)) and now - float(t) < FAILURE_WINDOW]
        locked = data.get("locked_until")
        if isinstance(locked, dict):
            for ip, until in locked.items():
                if isinstance(ip, str) and isinstance(until, (int, float)) and float(until) > now:
                    self._locked_until[ip] = float(until)
        gun = data.get("global_locked_until")
        if isinstance(gun, (int, float)) and float(gun) > now:
            self._global_locked_until = float(gun)

    def _save(self) -> None:
        path = self._file()
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps({
                "ips": self._ips,
                "global": self._global,
                "locked_until": self._locked_until,
                "global_locked_until": self._global_locked_until,
            }), "utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError:
            # 落盘失败只影响"重启不清零"，内存计数照常工作
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def _prune(self) -> None:
        now = time.time()
        for ip in [k for k, v in self._ips.items()
                   if not any(now - t < FAILURE_WINDOW for t in v)]:
            self._ips.pop(ip, None)
        self._global = [t for t in self._global if now - t < FAILURE_WINDOW]
        for ip in [k for k, until in self._locked_until.items() if until <= now]:
            self._locked_until.pop(ip, None)
        if self._global_locked_until <= now:
            self._global_locked_until = 0.0

    @staticmethod
    def _tier(attempts: list[float], base_limit: int) -> int:
        """达到第几档锁定；0 = 未锁定。"""
        tier = 0
        for index, (threshold, _seconds) in enumerate(ESCALATION_TIERS):
            # 第一档阈值跟随 prefs（可调）；后续档位在可调值上翻倍累进
            if index == 0:
                effective = max(1, base_limit)
            else:
                effective = threshold
            if len(attempts) >= effective:
                tier += 1
        return tier

    def _tier_seconds(self, tier: int, base_limit: int) -> int:
        """第 tier 档的锁定时长（第一档跟随 prefs）。"""
        if tier <= 0:
            return 0
        if tier == 1:
            return max(prefs.lockout_seconds(), 1)
        index = min(tier, len(ESCALATION_TIERS)) - 1
        return ESCALATION_TIERS[index][1]

    def locked_for(self, ip: str) -> int:
        """返回剩余锁定秒数；0 = 未锁定。

        两个维度：

        - **IP 维度**：本 IP 的累计失败达到档位时，从跨档那一刻起锁
          ``ESCALATION_TIERS`` 对应时长（第一档时长跟 prefs，可调）；
        - **全局维度**：窗口内全局失败达到第三档阈值时，对所有来源
          限流 60 秒——防"每个 IP 只试一两次"的分布式慢速爆破。
          正常使用下全局失败很难攒到这个量级，误伤可控。
        """
        self._prune()
        now = time.time()
        with self._lock:
            self._prune()
            deadline = max(self._locked_until.get(ip, 0.0), self._global_locked_until)
            if deadline <= now:
                return 0
            remaining = deadline - now
        return int(remaining) + (1 if remaining > int(remaining) else 0)

    def record_failure(self, ip: str) -> None:
        now = time.time()
        with self._lock:
            self._ips.setdefault(ip, []).append(now)
            self._global.append(now)
            self._prune()
            # 跨档即起算锁定时长（同一档不重复续期，避免攻击者靠持续
            # 失败把"1 小时"无限延长；要升级需要攒到下一档）
            tier = self._tier(self._ips.get(ip, []), prefs.max_failures())
            if tier > 0 and now >= self._locked_until.get(ip, 0.0):
                self._locked_until[ip] = now + self._tier_seconds(tier, prefs.max_failures())
            if (len(self._global) >= ESCALATION_TIERS[-1][0]
                    and now >= self._global_locked_until):
                self._global_locked_until = now + 60
            self._save()

    def clear_failures(self, ip: str) -> None:
        with self._lock:
            self._ips.pop(ip, None)
            self._locked_until.pop(ip, None)
            self._global = []
            self._global_locked_until = 0.0
            self._save()

    def status(self, ip: str) -> dict:
        """面板「安全中心」展示：当前 IP 与全局的失败计数、锁定状态。"""
        with self._lock:
            self._prune()
            now = time.time()
            return {
                "ip": ip,
                "ip_failures": len([t for t in self._ips.get(ip, [])
                                    if now - t < FAILURE_WINDOW]),
                "global_failures": len(self._global),
                "locked_seconds": self.locked_for(ip),
                "tiers": [{"attempts": t, "lock_seconds": s} for t, s in ESCALATION_TIERS],
            }


failures = FailureTracker()


class SessionStore:
    def __init__(self, ttl: int | None = None) -> None:
        # ttl=None 时动态读取 prefs：改会话时长后新签发的会话立即生效，
        # 已存在的会话保留各自的 expires（不会把正在使用的人踢下线）。
        self._fixed_ttl = ttl
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._last_persist = 0.0
        self._load()

    @property
    def ttl(self) -> int:
        return self._fixed_ttl if self._fixed_ttl is not None else prefs.session_ttl_seconds()

    def _file(self) -> Path:
        return Path(config.path).parent / SESSIONS_FILE

    def _load(self) -> None:
        try:
            data = json.loads(self._file().read_text("utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return
        if not isinstance(data, dict):
            return
        now = time.time()
        dropped = 0
        for key, session in data.items():
            if not isinstance(session, dict):
                continue
            if session.get("expires", 0) < now:
                continue
            # 键就是令牌的 SHA-256（64 位十六进制）。1.4.0 之前的旧格式
            # 存的是明文令牌，无法反推哈希 → 直接丢弃并重写文件，
            # 否则明文会一直留在 sessions.json 里（与"磁盘只存哈希"矛盾，
            # 也会被 list_active 当成 id 前 12 位展示出来）。
            if not _DIGEST_RE.fullmatch(str(key)):
                dropped += 1
                continue
            self._sessions[key] = session
        if dropped:
            # 升级后所有浏览器会话失效（需重新登录），把明文键清出磁盘
            self._persist(force=True)

    def _persist(self, force: bool = False) -> None:
        """落盘。create/revoke 立即写；滑动续期按 PERSIST_MIN_INTERVAL 节流。"""
        now = time.time()
        if not force and now - self._last_persist < PERSIST_MIN_INTERVAL:
            return
        self._last_persist = now
        path = self._file()
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(self._sessions), "utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError:
            # 落盘失败只影响"重启不掉线"，内存会话照常工作
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def create(self, ip: str, label: str = "") -> str:
        """签发会话。返回明文令牌（只此一次），磁盘上只存哈希。"""
        token = secrets.token_urlsafe(32)
        digest = token_digest(token)
        now = time.time()
        with self._lock:
            self._sessions[digest] = {"ip": ip, "created": now, "expires": now + self.ttl,
                                      "label": label}
            self._prune()
            self._persist(force=True)
        return token

    def validate(self, token: str | None, renew: bool = True) -> dict | None:
        """校验会话。renew=False 时只查不续期（状态查询类接口用）。"""
        if not token:
            return None
        digest = token_digest(token)
        with self._lock:
            session = self._sessions.get(digest)
            if session is None:
                return None
            if session["expires"] < time.time():
                self._sessions.pop(digest, None)
                self._persist()
                return None
            if renew:
                session["expires"] = time.time() + self.ttl  # 滑动续期
                self._persist()
            return dict(session)

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        digest = token_digest(token)
        with self._lock:
            if self._sessions.pop(digest, None) is not None:
                self._persist(force=True)

    def revoke_digest(self, digest: str) -> bool:
        """按哈希吊销（安全中心「踢出会话」用）。"""
        with self._lock:
            if self._sessions.pop(digest, None) is not None:
                self._persist(force=True)
                return True
            return False

    def revoke_all(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._persist(force=True)

    def active_count(self) -> int:
        with self._lock:
            self._prune()
            return len(self._sessions)

    def list_active(self) -> list[dict]:
        """活跃会话列表（安全中心用）：哈希前缀、IP、创建/过期时间。"""
        with self._lock:
            self._prune()
            return [
                {
                    "id": digest[:12],       # 列表展示用短标识，踢出时传全量
                    "ip": s.get("ip", ""),
                    "label": s.get("label", ""),
                    "created": int(s.get("created", 0)),
                    "expires": int(s.get("expires", 0)),
                    "current": False,        # 由调用方标注当前会话
                }
                for digest, s in self._sessions.items()
            ]

    def _prune(self) -> None:
        now = time.time()
        for key in [k for k, s in self._sessions.items() if s["expires"] < now]:
            self._sessions.pop(key, None)

    # ---- 登录失败锁定（委托给持久化失败跟踪器）----
    def locked_for(self, ip: str) -> int:
        return failures.locked_for(ip)

    def record_failure(self, ip: str) -> None:
        failures.record_failure(ip)

    def clear_failures(self, ip: str) -> None:
        failures.clear_failures(ip)


sessions = SessionStore()


def client_ip(request: Request | WebSocket) -> str:
    """客户端真实 IP。

    仅当配置 trust_proxy=true（面板部署在可信反向代理之后）才读取
    X-Forwarded-For，且取最后一跳——最左侧的值由客户端任意填写，
    直连部署时信任它会绕过登录失败锁定。默认取 TCP 对端地址。
    """
    if config.trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def extract_token(request: Request | WebSocket) -> str | None:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        return token
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    # query 参数仅放行 WebSocket（浏览器 WS 无法自定义头，前端必须借道）；
    # HTTP 接口一律走 Cookie / Authorization 头，避免令牌进日志与历史记录。
    if isinstance(request, WebSocket):
        return request.query_params.get("token")
    return None


def extract_agent_token(request: Request) -> str | None:
    """Agent 令牌取值顺序：X-Agent-Token 头 → Bearer 头。

    1.4.0 起不再接受 token 查询参数（与面板会话一致，防泄漏进访问日志）。
    """
    token = request.headers.get("x-agent-token")
    if token:
        return token.strip()
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


async def require_auth(request: Request) -> dict:
    """FastAPI 依赖：要求已登录，否则 401。"""
    session = sessions.validate(extract_token(request))
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "未登录或会话已过期")
    return session


def is_internal() -> bool:
    return config.mode == MODE_INTERNAL


async def require_internal(request: Request) -> dict:
    """FastAPI 依赖：要求已登录，且当前处于内网模式。"""
    session = sessions.validate(extract_token(request))
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "未登录或会话已过期")
    if config.mode != MODE_INTERNAL:
        raise HTTPException(status.HTTP_403_FORBIDDEN, INTERNAL_HINT)
    return session


async def require_exec_auth(request: Request) -> dict:
    """命令执行鉴权：面板会话或 Agent 令牌均可，且必须处于内网模式。

    Agent 令牌只在内网模式下有效，管理员关闭内网模式后立即失效。
    1.4.0 起返回令牌的作用域信息（scope / prefixes / token_id），
    由调用方按作用域校验具体命令（见 app/scopes.py）。

    1.4.1 修：这里**无条件**调用 :meth:`Config.find_agent_token`。
    原实现先判断 ``config.agent_token`` 是否为真，而该属性在"只有旧版
    明文字段"的配置上返回空串（迁移恰恰发生在 find_agent_token 内部），
    于是旧令牌第一次调用就被 401，自动迁移永远跑不到——升级即断所有
    既有令牌。现在由 find_agent_token/agent_tokens 负责触发迁移。
    """
    if config.mode != MODE_INTERNAL:
        raise HTTPException(status.HTTP_403_FORBIDDEN, INTERNAL_HINT)
    session = sessions.validate(extract_token(request))
    if session is not None:
        return {"kind": "session", "ip": client_ip(request)}
    provided = extract_agent_token(request)
    if provided:
        record = config.find_agent_token(provided)
        if record is not None:
            config.touch_agent_token(str(record.get("id", "")))
            return {
                "kind": "agent",
                "ip": client_ip(request),
                "scope": record.get("scope", "full"),
                "prefixes": record.get("prefixes") or [],
                "token_id": record.get("id", ""),
                "token_name": record.get("name", ""),
            }
        # 令牌存在配置中但校验未过：区分「无效」与「过期」意义不大，统一 401
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Agent 令牌无效")
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "未登录或会话已过期")


def origin_allowed(request: Request | WebSocket) -> bool:
    """跨站 WebSocket 握手防护。

    浏览器发起的 WebSocket 一定携带 Origin 头：与 Host 同源，或位于配置的
    allowed_origins 白名单内才放行。非浏览器客户端（无 Origin 头）本来就要
    通过令牌/会话鉴权，直接放行。
    """
    origin = request.headers.get("origin")
    if not origin:
        return True
    host = request.headers.get("host")
    if host and origin in (f"http://{host}", f"https://{host}"):
        return True
    return origin in config.allowed_origins


async def authenticate_ws(websocket: WebSocket, internal_only: bool = False) -> bool:
    """WebSocket 握手鉴权，失败时关闭连接。internal_only 要求内网模式。"""
    if not origin_allowed(websocket):
        await websocket.close(code=1008, reason="Origin 不被允许")
        return False
    if sessions.validate(extract_token(websocket)) is None:
        await websocket.close(code=4401, reason="未登录")
        return False
    if internal_only and config.mode != MODE_INTERNAL:
        await websocket.close(code=4403, reason="内网模式未激活")
        return False
    return True
