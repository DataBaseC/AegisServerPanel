"""会话管理：登录令牌签发、校验、失败锁定。"""

from __future__ import annotations

import secrets
import threading
import time

from fastapi import HTTPException, Request, WebSocket, status

from .config import COOKIE_NAME, MODE_INTERNAL, SESSION_TTL, config

INTERNAL_HINT = "该功能仅在内网模式可用，请在服务器上执行 serverpanel --enable-internal 激活"

MAX_FAILURES = 5
LOCKOUT_SECONDS = 60


class SessionStore:
    def __init__(self, ttl: int = SESSION_TTL) -> None:
        self.ttl = ttl
        self._sessions: dict[str, dict] = {}
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def create(self, ip: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._sessions[token] = {"ip": ip, "created": now, "expires": now + self.ttl}
            self._prune()
        return token

    def validate(self, token: str | None) -> dict | None:
        if not token:
            return None
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if session["expires"] < time.time():
                self._sessions.pop(token, None)
                return None
            session["expires"] = time.time() + self.ttl  # 滑动续期
            return dict(session)

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def revoke_all(self) -> None:
        with self._lock:
            self._sessions.clear()

    def active_count(self) -> int:
        with self._lock:
            self._prune()
            return len(self._sessions)

    def _prune(self) -> None:
        now = time.time()
        for token in [t for t, s in self._sessions.items() if s["expires"] < now]:
            self._sessions.pop(token, None)

    # ---- 登录失败锁定 ----
    def locked_for(self, ip: str) -> int:
        with self._lock:
            attempts = [t for t in self._failures.get(ip, []) if time.time() - t < LOCKOUT_SECONDS]
            self._failures[ip] = attempts
            if len(attempts) >= MAX_FAILURES:
                return int(LOCKOUT_SECONDS - (time.time() - attempts[0])) + 1
            return 0

    def record_failure(self, ip: str) -> None:
        with self._lock:
            self._failures.setdefault(ip, []).append(time.time())

    def clear_failures(self, ip: str) -> None:
        with self._lock:
            self._failures.pop(ip, None)


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
    return request.query_params.get("token")


def extract_agent_token(request: Request) -> str | None:
    """Agent 令牌取值顺序：X-Agent-Token 头 → Bearer 头 → token 查询参数。"""
    token = request.headers.get("x-agent-token")
    if token:
        return token.strip()
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.query_params.get("token")


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
    """
    if config.mode != MODE_INTERNAL:
        raise HTTPException(status.HTTP_403_FORBIDDEN, INTERNAL_HINT)
    session = sessions.validate(extract_token(request))
    if session is not None:
        return {"kind": "session", "ip": client_ip(request)}
    expected = config.agent_token
    provided = extract_agent_token(request)
    if expected and provided and secrets.compare_digest(provided, expected):
        return {"kind": "agent", "ip": client_ip(request)}
    if provided:
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
