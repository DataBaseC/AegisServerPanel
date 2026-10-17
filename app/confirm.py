"""高危操作的服务端确认令牌（2.0 M1）。

前端在确认对话框之后向 ``POST /api/panel/confirm`` 申请一次性令牌（2 分钟、
绑定动作与会话），高危端点由中间件校验 ``X-Confirm-Token`` 后才执行。

这样"确认"不再只是前端装饰：任何脚本/Agent 直接调高风险接口，也必须先
经过一次显式的确认申请。令牌签名密钥在进程启动时随机生成，重启即失效
（不需要落盘，也不引入新配置）。

2.0 审查后收紧：
- payload 里带一次性 nonce，``verify`` 成功即作废——同一令牌不能重放 120 秒；
- 绑定申请者会话（cookie 或 Bearer），A 用户签发的令牌不能被 B 用户使用。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time

from fastapi import HTTPException

TTL_SECONDS = 120
ACTIONS = frozenset({"power", "update", "service", "tokens", "apps", "config",
                     "docker", "firewall", "proxy"})

# 进程级随机密钥：重启后旧令牌自动失效
_SECRET = secrets.token_bytes(32)

# 已消费的 nonce → 过期时间。只保留到令牌过期为止，容量有硬上限。
_USED: dict[str, int] = {}
_USED_LOCK = threading.Lock()
_USED_MAX = 4096

_SERVICE_ACTION_RE = re.compile(r"^/api/services/[^/]+/action$")
_APP_DELETE_RE = re.compile(r"^/api/panel/apps/[^/]+$")
# 2.0 M3：容器删除、防火墙放行/拒绝、nginx 重载只在路径上能判定（中间件读不到 body）
_DOCKER_DELETE_RE = re.compile(r"^/api/panel/infra/docker/containers/[^/]+$")
_FIREWALL_RE = re.compile(r"^/api/panel/infra/firewall/(?:allow|deny)$")

# 精确匹配的路径 → 动作
_EXACT_ACTIONS = {
    ("POST", "/api/system/power"): "power",
    ("POST", "/api/system/self-update"): "update",
    ("DELETE", "/api/agent/tokens"): "tokens",
    ("POST", "/api/panel/config/import"): "config",
    ("POST", "/api/panel/maintenance/updates/apply"): "update",
    ("POST", "/api/panel/infra/proxy/reload"): "proxy",
}
# 带 id 的路径 → 动作（(正则, 方法, 动作)）
_PATTERN_ACTIONS = (
    (_SERVICE_ACTION_RE, "POST", "service"),
    (_APP_DELETE_RE, "DELETE", "apps"),
    (_DOCKER_DELETE_RE, "DELETE", "docker"),
    (_FIREWALL_RE, "POST", "firewall"),
)


def action_for(method: str, path: str) -> str | None:
    """路径 → 确认动作；返回 None 表示不需要确认。

    ``/api/services/*/action`` 一律要求确认（停止/重启/禁用都可能打断线上服务）。
    2.0 M3 起，系统更新、容器删除、防火墙写操作、反代重载同样要求确认：
    这些动作在 URL 上就能判定，不需要（也不能）读请求体。
    """
    action = _EXACT_ACTIONS.get((method, path))
    if action:
        return action
    for pattern, verb, name in _PATTERN_ACTIONS:
        if method == verb and pattern.match(path):
            return name
    return None


def _binding(session_token: str) -> str:
    """会话绑定指纹：只存哈希前缀，令牌本身不落结构、不进日志。"""
    if not session_token:
        return ""
    return hashlib.sha256(session_token.encode("utf-8")).hexdigest()[:16]


def _consume(nonce: str, expires_at: int) -> bool:
    """登记 nonce；同一 nonce 第二次调用返回 False（一次性语义）。"""
    now = int(time.time())
    with _USED_LOCK:
        for key, exp in list(_USED.items()):
            if exp < now:
                del _USED[key]
        if nonce in _USED:
            return False
        if len(_USED) >= _USED_MAX:
            # 正常使用远达不到；万一被刷，按最早过期的一批丢弃，保证内存有界
            for key in sorted(_USED, key=_USED.get)[: _USED_MAX // 4]:
                del _USED[key]
        _USED[nonce] = expires_at
        return True


def issue(action: str, session_token: str = "") -> dict:
    """签发确认令牌（动作必须是已知集合，避免签出无意义的令牌）。"""
    if action not in ACTIONS:
        raise HTTPException(400, "未知的高危操作")
    expires_at = int(time.time()) + TTL_SECONDS
    nonce = secrets.token_urlsafe(8)
    payload = f"{action}|{expires_at}|{nonce}|{_binding(session_token)}".encode()
    signature = hmac.new(_SECRET, payload, hashlib.sha256).hexdigest()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return {"token": f"{encoded}.{signature}", "expires_in": TTL_SECONDS}


def verify(token: str, action: str, session_token: str = "") -> bool:
    """校验令牌：签名、动作、会话绑定、有效期；成功即消费（不可重放）。"""
    try:
        encoded, signature = (token or "").split(".", 1)
        payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        expected = hmac.new(_SECRET, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        got_action, got_exp, nonce, got_binding = payload.decode().split("|", 3)
        if got_action != action or int(got_exp) < int(time.time()):
            return False
        if got_binding != _binding(session_token):
            return False
        return _consume(nonce, int(got_exp))
    except (ValueError, UnicodeDecodeError, TypeError):
        return False
