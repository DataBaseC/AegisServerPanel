"""Agent 接入：本地脚本 / AI Agent 通过令牌直接控制服务器。

令牌只能在内网模式下生效，且只能由已登录的管理员在面板内生成或吊销，
或使用服务器本机命令 serverpanel --agent-token 生成。
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..auth import require_internal
from ..config import MODE_INTERNAL, config
from ..metrics import basic_info
from .terminal_routes import _pick_shell, recent_execs

router = APIRouter(prefix="/api/agent", tags=["agent"])

MIN_TOKEN_LENGTH = 16


class TokenBody(BaseModel):
    token: str = ""


@router.get("/info")
async def agent_info(request: Request, _session: dict = Depends(require_internal)):
    info = basic_info()
    return {
        "internal": config.mode == MODE_INTERNAL,
        "enabled": bool(config.agent_token),
        "token": config.agent_token,
        "token_updated_at": config.agent_token_updated_at,
        "endpoint": "/api/terminal/exec",
        "base_url": str(request.base_url).rstrip("/"),
        "hosts": [a["address"] for a in info["addresses"]],
        "hostname": info["hostname"],
        "shell": _pick_shell(),
        "user": os.environ.get("USER") or "root",
        "is_root": os.geteuid() == 0,
        "recent": recent_execs(),
    }


@router.post("/token")
async def issue_token(body: TokenBody, _session: dict = Depends(require_internal)):
    custom = body.token.strip()
    if custom and len(custom) < MIN_TOKEN_LENGTH:
        raise HTTPException(400, f"自定义令牌长度至少 {MIN_TOKEN_LENGTH} 位")
    token = config.issue_agent_token(custom or None)
    return {"ok": True, "token": token, "message": "Agent 令牌已生成，旧令牌立即失效"}


@router.delete("/token")
async def revoke_token(_session: dict = Depends(require_internal)):
    config.revoke_agent_token()
    return {"ok": True, "message": "Agent 令牌已吊销，旧令牌立即失效"}
