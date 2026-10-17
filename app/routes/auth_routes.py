"""登录、首次设置密码、退出、修改密码、TOTP 二次认证。

1.4.0 起：

- 登录成功/失败、退出、改密全部记入统一审计管道；
- 支持 TOTP 二次认证（RFC 6238）：启用后登录需「密码 + 6 位动态码」，
  动态码错误同样计入失败锁定（防在线爆破）；10 个一次性恢复码兜底；
- 密码策略强化：≥12 位 + 弱口令黑名单（PBKDF2 提升到 60 万轮）。
"""

from __future__ import annotations

import asyncio
import socket
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from .. import totp as totp_mod
from ..audit import AuditEvent, audit
from ..auth import (
    ROLE_ADMIN,
    ROLE_VIEWER,
    client_ip,
    extract_token,
    require_auth,
    resolve_role,
    session_username,
    sessions,
)
from ..config import COOKIE_NAME, config
from ..prefs import prefs

router = APIRouter(prefix="/api/auth", tags=["auth"])


async def _notify_lockout(ip: str) -> None:
    """1.6.0 F1：登录失败触发锁定时推送通知（通知故障不影响登录响应）。"""
    if sessions.locked_for(ip) > 0 and prefs.get("notify.on_lockout"):
        from ..notify import notify

        await asyncio.to_thread(notify, "lockout",
                                f"来源 {ip} 连续登录失败，已触发锁定")


class PasswordBody(BaseModel):
    password: str


class LoginBody(BaseModel):
    password: str
    code: str = ""          # TOTP 动态码或恢复码（启用 2FA 后必填）
    username: str = ""      # 多用户模式下的用户名（留空 = 内置 admin）


class ChangePasswordBody(BaseModel):
    current: str
    new: str


class TotpCodeBody(BaseModel):
    code: str


def _issue(request: Request, response: Response, username: str = "",
           role: str = "admin", user_id: str = "") -> str:
    token = sessions.create(client_ip(request), username=username, role=role, user_id=user_id)
    # TLS 常终止于反向代理（request.url.scheme 仍是 http），故 trust_proxy 时
    # 以 X-Forwarded-Proto 为准，避免 HTTPS 部署下 Cookie 走明文。
    proto = request.url.scheme
    if config.trust_proxy:
        proto = (request.headers.get("x-forwarded-proto") or proto).split(",")[0].strip()
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=sessions.ttl,  # 跟随「设置 → 快捷设置」里的会话时长
        httponly=True,
        samesite="lax",
        path="/",
        secure=proto == "https",  # HTTPS 部署时禁止 Cookie 走明文
    )
    return token


class _TotpScope:
    """二次认证的存储位置。

    多用户模式下 TOTP 落在**当前用户记录**上（每个账号自己的动态码），
    单密码模式仍沿用全局配置——因此 viewer 启用 2FA 不会把 admin 锁在门外。
    """

    def __init__(self, session: dict | None) -> None:
        session = session or {}
        self.user_id = str(session.get("user_id") or "")
        self.user: dict | None = None
        if config.has_users:
            self.user = (config.user_by_id(self.user_id) if self.user_id else None)
            if self.user is None:
                self.user = config.find_user(session_username(session))

    @property
    def enabled(self) -> bool:
        if self.user is not None:
            return bool(self.user.get("totp_enabled"))
        return config.totp_enabled

    @property
    def secret(self) -> str:
        if self.user is not None:
            return str(self.user.get("totp_secret") or "")
        return config.totp_secret

    @property
    def recovery_left(self) -> int:
        if self.user is not None:
            return len([h for h in (self.user.get("recovery_hashes") or []) if h])
        return len(config.totp_recovery_hashes)

    @property
    def enabled_at(self) -> int:
        if self.user is not None:
            return int(self.user.get("totp_enabled_at") or 0)
        return int(config.data.get("totp_enabled_at") or 0)

    def set_secret(self, secret: str) -> None:
        if self.user is not None:
            config.set_user_totp(self.user_id_of(), totp_secret=secret)
        else:
            config.set_totp_secret(secret)

    def enable(self, hashes: list[str]) -> None:
        if self.user is not None:
            config.set_user_totp(self.user_id_of(), totp_enabled=True,
                                 recovery_hashes=hashes, totp_enabled_at=int(time.time()))
        else:
            config.enable_totp(hashes)

    def disable(self) -> None:
        if self.user is not None:
            config.set_user_totp(self.user_id_of(), totp_secret="", totp_enabled=False,
                                 recovery_hashes=[], totp_enabled_at=0)
        else:
            config.disable_totp()

    def consume(self, code: str) -> bool:
        if self.user is not None:
            return config.consume_user_recovery_code(self.user_id_of(), code)
        return config.consume_recovery_code(code)

    def user_id_of(self) -> str:
        return str(self.user.get("id") or self.user_id)


def _totp_scope(session: dict | None) -> _TotpScope:
    return _TotpScope(session)


@router.get("/status")
async def status(request: Request):
    # 只读状态查询：不做滑动续期（未鉴权 GET 不应产生写副作用），
    # 会话数只对已登录用户可见。
    session = sessions.validate(extract_token(request), renew=False)
    authed = session is not None
    data = {
        "initialized": config.initialized,
        "authenticated": authed,
        "hostname": socket.gethostname(),
        "mode": config.mode,
        "mode_label": config.mode_label,
        "mode_updated_at": config.mode_updated_at,
        "totp_enabled": config.totp_enabled,  # 登录页据此显示动态码输入框
        "multi_user": config.has_users,       # 前端据此显示用户名输入框
    }
    if authed:
        role = resolve_role(session)
        data["active_sessions"] = sessions.active_count()
        data["username"] = session_username(session)
        data["role"] = role or ROLE_VIEWER
        data["user_totp_enabled"] = _totp_scope(session).enabled
    return data


@router.post("/setup")
async def setup(body: PasswordBody, request: Request, response: Response):
    """首次启动时设置面板密码。"""
    ip = client_ip(request)
    locked = sessions.locked_for(ip)
    if locked:
        raise HTTPException(429, f"尝试次数过多，请 {locked} 秒后重试")
    try:
        # PBKDF2 60 万轮约 100~400ms：绝不能跑在事件循环上（否则并发登录会
        # 让采样、WebSocket、健康检查整体卡顿）
        await asyncio.to_thread(config.set_password, body.password,
                                only_if_uninitialized=True)
    except ValueError as exc:
        sessions.record_failure(ip)
        # 弱口令/过短的提示直接透出；"已初始化"统一成中性错误
        detail = str(exc)
        if "已初始化" in detail:
            raise HTTPException(400, "面板已初始化，请直接登录")
        raise HTTPException(400, detail)
    sessions.clear_failures(ip)
    _issue(request, response)
    audit.record(AuditEvent(action="setup", summary="首次设置面板密码",
                            source="web", ip=ip))
    return {"ok": True, "message": "面板密码设置成功"}


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response):
    ip = client_ip(request)
    locked = sessions.locked_for(ip)
    if locked:
        raise HTTPException(429, f"尝试次数过多，请 {locked} 秒后重试"
                                 f"（连续失败会延长锁定，最长 24 小时）")
    if not config.initialized:
        raise HTTPException(400, "尚未设置面板密码")

    # 第一因素：密码
    user = _login_user(body.username)
    if not await _password_ok(user, body):
        sessions.record_failure(ip)
        audit.record(AuditEvent(action="login_failed", summary="密码错误",
                                source="web", ip=ip, ok=False))
        await _notify_lockout(ip)
        raise HTTPException(401, "密码错误")

    scope = _TotpScope({"user_id": (user or {}).get("id", ""),
                        "username": (user or {}).get("username", "")})
    # 第二因素：TOTP（启用后强制；未启用时忽略 code 字段）
    secret = scope.secret
    if scope.enabled and secret:
        if totp_mod.verify(secret, body.code):
            pass  # 动态码正确
        elif scope.consume(body.code):
            audit.record(AuditEvent(action="totp_recovery_used", source="web", ip=ip))
        else:
            sessions.record_failure(ip)
            audit.record(AuditEvent(action="login_failed", summary="TOTP 校验失败",
                                    source="web", ip=ip, ok=False))
            await _notify_lockout(ip)
            if not body.code:
                raise HTTPException(401, "需要二次验证码")
            raise HTTPException(401, "二次验证码错误")
    elif scope.enabled:
        # 配置里 enabled=true 但没有密钥（手工改坏/导入残缺包）：
        # 若按"校对空密钥的 HMAC"处理等于没有第二因素，且会把管理员
        # 永久挡在门外。这里明确降级为不校验，并留审计痕迹。
        audit.record(AuditEvent(action="totp_misconfigured", ok=False,
                                summary="totp_enabled=true 但缺少 totp_secret，已跳过第二因素",
                                source="web", ip=ip))

    sessions.clear_failures(ip)
    # 多用户模式下会话一律带用户名（缺省即内置 admin）：删除/禁用账号时
    # 才能按名字精确吊销，不会留下"改不到"的历史会话。
    username = (user or {}).get("username", "") or (ROLE_ADMIN if config.has_users else "")
    role = (user or {}).get("role") or ROLE_ADMIN
    _issue(request, response, username=username, role=role,
           user_id=(user or {}).get("id", ""))
    audit.record(AuditEvent(action="login", source="web", ip=ip, actor=username))
    return {"ok": True}


def _login_user(username: str) -> dict | None:
    """按用户名找用户记录；单密码模式下返回 None（走原密码校验）。"""
    if not config.has_users:
        return None
    name = (username or "").strip()
    if name:
        user = config.find_user(name)
        return user if (user and not user.get("disabled")) else None
    user = config.find_user(ROLE_ADMIN)
    if user is not None and not user.get("disabled"):
        return user
    return None


async def _password_ok(user: dict | None, body: LoginBody) -> bool:
    """第一因素校验：多用户按记录比对；单密码/无 admin 记录时回退原密码哈希。

    PBKDF2 是刻意放慢的算法（60 万轮），必须在工作线程里跑。
    """
    if user is not None:
        return await asyncio.to_thread(config.verify_user_password, user, body.password)
    name = (body.username or "").strip()
    if name and name != ROLE_ADMIN:
        return False  # 指定了不存在的用户名：不回退单密码，避免探测
    return await asyncio.to_thread(config.verify_password, body.password)


@router.post("/logout")
async def logout(request: Request, response: Response):
    sessions.revoke(extract_token(request))
    response.delete_cookie(COOKIE_NAME, path="/")
    audit.record(AuditEvent(action="logout", source="web",
                            ip=client_ip(request)))
    return {"ok": True}


@router.post("/password")
async def change_password(
    body: ChangePasswordBody,
    request: Request,
    response: Response,
    session: dict = Depends(require_auth),
):
    ip = client_ip(request)
    locked = sessions.locked_for(ip)
    if locked:
        raise HTTPException(429, f"尝试次数过多，请 {locked} 秒后重试")
    # 多用户模式下改的是「当前账号」的密码，不再是全局单密码
    current_user = config.user_by_id(session.get("user_id") or "") if config.has_users else None
    if current_user is not None:
        ok = await asyncio.to_thread(config.verify_user_password, current_user, body.current)
    else:
        ok = await asyncio.to_thread(config.verify_password, body.current)
    if not ok:
        sessions.record_failure(ip)  # 防持有效会话无限暴力猜当前密码
        raise HTTPException(401, "当前密码不正确")
    sessions.clear_failures(ip)
    try:
        if current_user is not None:
            await asyncio.to_thread(config.set_user_password, current_user["id"], body.new)
        else:
            await asyncio.to_thread(config.set_password, body.new)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if current_user is not None:
        # 只吊销本人其他会话；其他用户不受影响，当前会话随后重新签发
        sessions.revoke_user(current_user["username"])
        _issue(request, response, username=current_user["username"],
               role=current_user.get("role") or ROLE_VIEWER, user_id=current_user["id"])
    else:
        sessions.revoke_all()  # 改密后所有旧会话失效
        _issue(request, response)
    audit.record(AuditEvent(action="change_password", source="web", ip=ip,
                            actor=session_username(session)))
    return {"ok": True, "message": "密码已更新，其他设备需重新登录"}


# ---------------------------------------------------------------- TOTP 2FA


@router.get("/totp/status")
async def totp_status(session: dict = Depends(require_auth)):
    scope = _totp_scope(session)
    return {
        "enabled": scope.enabled,
        "pending": bool(scope.secret) and not scope.enabled,
        "recovery_left": scope.recovery_left,
        "enabled_at": scope.enabled_at,
    }


@router.post("/totp/setup")
async def totp_setup(session: dict = Depends(require_auth)):
    """生成 secret（未启用时的绑定流程）。

    1.4.1 修：**已启用时拒绝**。原实现只要求登录态，且
    ``set_totp_secret`` 会顺手把 ``totp_enabled`` 置回 False，
    于是任何有效会话（被劫持的 Cookie / 同站 CSRF / 脚本）一个 POST
    就能把二次认证拆掉，绕过 ``/totp/disable`` 的密码校验。
    重新绑定必须走"先用密码关闭，再重新 setup + enable"。
    """
    scope = _totp_scope(session)
    if scope.enabled:
        raise HTTPException(400, "二次认证已启用；如需重新绑定，请先用当前密码关闭二次认证")
    secret = totp_mod.generate_secret()
    scope.set_secret(secret)
    audit.record(AuditEvent(action="totp_setup", summary="生成 TOTP 密钥（未启用）",
                            source="web"))
    return {
        "ok": True,
        "secret": secret,
        "uri": totp_mod.provisioning_uri(secret),
        "message": "请用 authenticator App 扫码或手动输入密钥，"
                   "然后输入动态码完成启用",
    }


@router.post("/totp/enable")
async def totp_enable(body: TotpCodeBody, request: Request,
                      session: dict = Depends(require_auth)):
    """校验动态码后正式启用，返回一次性恢复码（仅此一次展示）。"""
    scope = _totp_scope(session)
    secret = scope.secret
    if not secret:
        raise HTTPException(400, "请先调用 /api/auth/totp/setup 生成密钥")
    if scope.enabled:
        raise HTTPException(400, "二次认证已启用")
    if not totp_mod.verify(secret, body.code):
        raise HTTPException(400, "动态码不正确，请检查 App 时间同步")
    recovery = totp_mod.generate_recovery_codes()
    scope.enable([totp_mod.hash_recovery(c) for c in recovery])
    audit.record(AuditEvent(action="totp_enabled", source="web",
                            ip=client_ip(request),
                            actor=session_username(session)))
    return {
        "ok": True,
        "recovery_codes": recovery,
        "message": "二次认证已启用。恢复码仅显示这一次，请妥善保管",
    }


@router.post("/totp/disable")
async def totp_disable(body: PasswordBody, request: Request,
                       session: dict = Depends(require_auth)):
    """关闭 2FA：需要验证当前密码（防会话被劫持后直接拆防护）。"""
    current_user = config.user_by_id(session.get("user_id") or "") if config.has_users else None
    if current_user is not None:
        ok = config.verify_user_password(current_user, body.password)
    else:
        ok = config.verify_password(body.password)
    if not ok:
        raise HTTPException(401, "当前密码不正确")
    _totp_scope(session).disable()
    audit.record(AuditEvent(action="totp_disabled", source="web",
                            ip=client_ip(request),
                            actor=session_username(session)))
    return {"ok": True, "message": "二次认证已关闭"}


@router.post("/totp/recovery-codes")
async def totp_regenerate(body: TotpCodeBody, request: Request,
                          session: dict = Depends(require_auth)):
    """重新生成恢复码（需验证一个有效动态码）。"""
    scope = _totp_scope(session)
    if not scope.enabled:
        raise HTTPException(400, "二次认证未启用")
    if not totp_mod.verify(scope.secret, body.code):
        raise HTTPException(400, "动态码不正确")
    recovery = totp_mod.generate_recovery_codes()
    scope.enable([totp_mod.hash_recovery(c) for c in recovery])
    audit.record(AuditEvent(action="totp_recovery_regenerated", source="web",
                            ip=client_ip(request),
                            actor=session_username(session)))
    return {"ok": True, "recovery_codes": recovery,
            "message": "恢复码已重新生成，旧恢复码全部作废"}
