"""登录、首次设置密码、退出、修改密码、TOTP 二次认证。

1.4.0 起：

- 登录成功/失败、退出、改密全部记入统一审计管道；
- 支持 TOTP 二次认证（RFC 6238）：启用后登录需「密码 + 6 位动态码」，
  动态码错误同样计入失败锁定（防在线爆破）；10 个一次性恢复码兜底；
- 密码策略强化：≥12 位 + 弱口令黑名单（PBKDF2 提升到 60 万轮）。
"""

from __future__ import annotations

import socket

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from .. import totp as totp_mod
from ..audit import AuditEvent, audit
from ..auth import client_ip, extract_token, require_auth, sessions
from ..config import COOKIE_NAME, config

router = APIRouter(prefix="/api/auth", tags=["auth"])


class PasswordBody(BaseModel):
    password: str


class LoginBody(BaseModel):
    password: str
    code: str = ""          # TOTP 动态码或恢复码（启用 2FA 后必填）


class ChangePasswordBody(BaseModel):
    current: str
    new: str


class TotpCodeBody(BaseModel):
    code: str


def _issue(request: Request, response: Response) -> str:
    token = sessions.create(client_ip(request))
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


@router.get("/status")
async def status(request: Request):
    # 只读状态查询：不做滑动续期（未鉴权 GET 不应产生写副作用），
    # 会话数只对已登录用户可见。
    authed = sessions.validate(extract_token(request), renew=False) is not None
    data = {
        "initialized": config.initialized,
        "authenticated": authed,
        "hostname": socket.gethostname(),
        "mode": config.mode,
        "mode_label": config.mode_label,
        "mode_updated_at": config.mode_updated_at,
        "totp_enabled": config.totp_enabled,  # 登录页据此显示动态码输入框
    }
    if authed:
        data["active_sessions"] = sessions.active_count()
    return data


@router.post("/setup")
async def setup(body: PasswordBody, request: Request, response: Response):
    """首次启动时设置面板密码。"""
    ip = client_ip(request)
    locked = sessions.locked_for(ip)
    if locked:
        raise HTTPException(429, f"尝试次数过多，请 {locked} 秒后重试")
    try:
        config.set_password(body.password, only_if_uninitialized=True)
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
    if not config.verify_password(body.password):
        sessions.record_failure(ip)
        audit.record(AuditEvent(action="login_failed", summary="密码错误",
                                source="web", ip=ip, ok=False))
        raise HTTPException(401, "密码错误")

    # 第二因素：TOTP（启用后强制；未启用时忽略 code 字段）
    if config.totp_enabled:
        secret = config.totp_secret
        if totp_mod.verify(secret, body.code):
            pass  # 动态码正确
        elif config.consume_recovery_code(body.code):
            audit.record(AuditEvent(action="totp_recovery_used", source="web", ip=ip))
        else:
            sessions.record_failure(ip)
            audit.record(AuditEvent(action="login_failed", summary="TOTP 校验失败",
                                    source="web", ip=ip, ok=False))
            if not body.code:
                raise HTTPException(401, "需要二次验证码")
            raise HTTPException(401, "二次验证码错误")

    sessions.clear_failures(ip)
    _issue(request, response)
    audit.record(AuditEvent(action="login", source="web", ip=ip))
    return {"ok": True}


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
    _session: dict = Depends(require_auth),
):
    ip = client_ip(request)
    locked = sessions.locked_for(ip)
    if locked:
        raise HTTPException(429, f"尝试次数过多，请 {locked} 秒后重试")
    if not config.verify_password(body.current):
        sessions.record_failure(ip)  # 防持有效会话无限暴力猜当前密码
        raise HTTPException(401, "当前密码不正确")
    sessions.clear_failures(ip)
    try:
        config.set_password(body.new)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    sessions.revoke_all()  # 改密后所有旧会话失效
    _issue(request, response)
    audit.record(AuditEvent(action="change_password", source="web", ip=ip))
    return {"ok": True, "message": "密码已更新，其他设备需重新登录"}


# ---------------------------------------------------------------- TOTP 2FA


@router.get("/totp/status")
async def totp_status(_session: dict = Depends(require_auth)):
    return {
        "enabled": config.totp_enabled,
        "pending": bool(config.totp_secret) and not config.totp_enabled,
        "recovery_left": len(config.totp_recovery_hashes),
        "enabled_at": int(config.data.get("totp_enabled_at") or 0),
    }


@router.post("/totp/setup")
async def totp_setup(_session: dict = Depends(require_auth)):
    """生成 secret（未启用）。重复调用会换一个新 secret，旧绑定作废。"""
    secret = totp_mod.generate_secret()
    config.set_totp_secret(secret)
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
async def totp_enable(body: TotpCodeBody, request: Request, _session: dict = Depends(require_auth)):
    """校验动态码后正式启用，返回一次性恢复码（仅此一次展示）。"""
    secret = config.totp_secret
    if not secret:
        raise HTTPException(400, "请先调用 /api/auth/totp/setup 生成密钥")
    if config.totp_enabled:
        raise HTTPException(400, "二次认证已启用")
    if not totp_mod.verify(secret, body.code):
        raise HTTPException(400, "动态码不正确，请检查 App 时间同步")
    recovery = totp_mod.generate_recovery_codes()
    config.enable_totp([totp_mod.hash_recovery(c) for c in recovery])
    audit.record(AuditEvent(action="totp_enabled", source="web",
                            ip=client_ip(request)))
    return {
        "ok": True,
        "recovery_codes": recovery,
        "message": "二次认证已启用。恢复码仅显示这一次，请妥善保管",
    }


@router.post("/totp/disable")
async def totp_disable(body: PasswordBody, request: Request,
                       _session: dict = Depends(require_auth)):
    """关闭 2FA：需要验证当前密码（防会话被劫持后直接拆防护）。"""
    if not config.verify_password(body.password):
        raise HTTPException(401, "当前密码不正确")
    config.disable_totp()
    audit.record(AuditEvent(action="totp_disabled", source="web",
                            ip=client_ip(request)))
    return {"ok": True, "message": "二次认证已关闭"}


@router.post("/totp/recovery-codes")
async def totp_regenerate(body: TotpCodeBody, request: Request,
                          _session: dict = Depends(require_auth)):
    """重新生成恢复码（需验证一个有效动态码）。"""
    if not config.totp_enabled:
        raise HTTPException(400, "二次认证未启用")
    if not totp_mod.verify(config.totp_secret, body.code):
        raise HTTPException(400, "动态码不正确")
    recovery = totp_mod.generate_recovery_codes()
    config.enable_totp([totp_mod.hash_recovery(c) for c in recovery])
    audit.record(AuditEvent(action="totp_recovery_regenerated", source="web",
                            ip=client_ip(request)))
    return {"ok": True, "recovery_codes": recovery,
            "message": "恢复码已重新生成，旧恢复码全部作废"}
