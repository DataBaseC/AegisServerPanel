"""登录、首次设置密码、退出、修改密码。"""

from __future__ import annotations

import socket

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from ..auth import client_ip, extract_token, require_auth, sessions
from ..config import COOKIE_NAME, SESSION_TTL, config

router = APIRouter(prefix="/api/auth", tags=["auth"])


class PasswordBody(BaseModel):
    password: str


class ChangePasswordBody(BaseModel):
    current: str
    new: str


def _issue(request: Request, response: Response) -> str:
    token = sessions.create(client_ip(request))
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
        secure=request.url.scheme == "https",  # HTTPS 部署时禁止 Cookie 走明文
    )
    return token


@router.get("/status")
async def status(request: Request):
    return {
        "initialized": config.initialized,
        "authenticated": sessions.validate(extract_token(request)) is not None,
        "hostname": socket.gethostname(),
        "active_sessions": sessions.active_count(),
        "mode": config.mode,
        "mode_label": config.mode_label,
        "mode_updated_at": config.mode_updated_at,
    }


@router.post("/setup")
async def setup(body: PasswordBody, request: Request, response: Response):
    """首次启动时设置面板密码。"""
    if config.initialized:
        raise HTTPException(400, "面板已初始化，请直接登录")
    if len(body.password) < 8:
        raise HTTPException(400, "密码长度至少 8 位")
    config.set_password(body.password)
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
    if not config.verify_password(body.current):
        raise HTTPException(401, "当前密码不正确")
    if len(body.new) < 8:
        raise HTTPException(400, "新密码长度至少 8 位")
    config.set_password(body.new)
    sessions.revoke_all()  # 改密后所有旧会话失效
    _issue(request, response)
    return {"ok": True, "message": "密码已更新，其他设备需重新登录"}
