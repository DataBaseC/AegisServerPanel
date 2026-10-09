"""登录、首次设置密码、退出、修改密码。"""

from __future__ import annotations

import socket

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from ..auth import client_ip, extract_token, require_auth, sessions
from ..config import COOKIE_NAME, config

router = APIRouter(prefix="/api/auth", tags=["auth"])


class PasswordBody(BaseModel):
    password: str


class ChangePasswordBody(BaseModel):
    current: str
    new: str


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
    if len(body.password) < 8:
        sessions.record_failure(ip)
        raise HTTPException(400, "密码长度至少 8 位")
    # set_password 原子地校验「未初始化才写入」，并发 setup 只有第一个能成功
    try:
        config.set_password(body.password, only_if_uninitialized=True)
    except ValueError:
        raise HTTPException(400, "面板已初始化，请直接登录")
    _issue(request, response)
    return {"ok": True, "message": "面板密码设置成功"}


@router.post("/login")
async def login(body: PasswordBody, request: Request, response: Response):
    ip = client_ip(request)
    locked = sessions.locked_for(ip)
    if locked:
        raise HTTPException(429, f"尝试次数过多，请 {locked} 秒后重试")
    if not config.initialized:
        raise HTTPException(400, "尚未设置面板密码")
    if not config.verify_password(body.password):
        sessions.record_failure(ip)
        raise HTTPException(401, "密码错误")
    sessions.clear_failures(ip)
    _issue(request, response)
    return {"ok": True}


@router.post("/logout")
async def logout(request: Request, response: Response):
    sessions.revoke(extract_token(request))
    response.delete_cookie(COOKIE_NAME, path="/")
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
    if len(body.new) < 8:
        raise HTTPException(400, "新密码长度至少 8 位")
    config.set_password(body.new)
    sessions.revoke_all()  # 改密后所有旧会话失效
    _issue(request, response)
    return {"ok": True, "message": "密码已更新，其他设备需重新登录"}
