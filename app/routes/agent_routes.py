"""Agent 接入：本地脚本 / AI Agent 通过令牌直接控制服务器。

1.4.0 起支持**多令牌 + 作用域**：

- 每个令牌有名称、作用域（full / readonly / custom 前缀白名单）、
  可选过期时间；磁盘上只存 SHA-256 哈希，明文仅在创建时展示一次；
- 令牌只能在内网模式下生效，管理员关闭内网模式后所有令牌立即失效；
- 创建/吊销记入统一审计管道。

管理入口：面板「安全中心 → Agent 令牌」，或服务器本机
``serverpanel --agent-token``（full 作用域）。
"""

from __future__ import annotations

import asyncio
import os
import re
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..audit import AuditEvent, audit
from ..auth import client_ip, require_internal
from ..config import MODE_INTERNAL, config
from ..metrics import basic_info
from ..utils import is_root
from .terminal_routes import _pick_shell, recent_execs

router = APIRouter(prefix="/api/agent", tags=["agent"])

MIN_TOKEN_LENGTH = 16
_NAME_RE = re.compile(r"^[\w\-\u4e00-\u9fff. ()（）]{1,60}$")


class TokenBody(BaseModel):
    token: str = ""


class CreateTokenBody(BaseModel):
    name: str = "未命名令牌"
    scope: str = "full"               # full | readonly | custom
    prefixes: list[str] = []          # custom 作用域的前缀白名单
    expires_days: int = 0             # 0 = 永不过期
    note: str = ""
    custom_token: str = ""            # 可选：自定义令牌（仍会做强度校验）


def _token_view(item: dict) -> dict:
    """列表视图：不含哈希，过期状态实时计算。"""
    expires = int(item.get("expires_at") or 0)
    return {
        "id": item.get("id", ""),
        "name": item.get("name", ""),
        "scope": item.get("scope", "full"),
        "prefixes": item.get("prefixes") or [],
        "note": item.get("note", ""),
        "created_at": int(item.get("created_at") or 0),
        "last_used_at": int(item.get("last_used_at") or 0),
        "expires_at": expires,
        "expired": bool(expires and time.time() > expires),
    }


@router.get("/info")
async def agent_info(request: Request, _session: dict = Depends(require_internal)):
    info = basic_info()
    tokens = config.agent_tokens
    # 读审计文件是同步 I/O，下线程池
    recent = await asyncio.to_thread(recent_execs)
    return {
        "internal": config.mode == MODE_INTERNAL,
        "enabled": bool(tokens),
        "token_count": len(tokens),
        "full_tokens": sum(1 for t in tokens if t.get("scope") == "full"),
        # 1.4.1 起这里不再返回任何"令牌"字段：1.4.0 曾返回哨兵串
        # "configured"（config.agent_token 的兼容值），前端会把它当令牌
        # 展示、甚至渲染进代码片段，复制出去必然 401。
        "token_hint": "令牌以 SHA-256 哈希存储，无法取回明文；请在「安全中心 → Agent 令牌」创建",
        "token_updated_at": config.agent_token_updated_at,
        "endpoint": "/api/terminal/exec",
        "base_url": str(request.base_url).rstrip("/"),
        "hosts": [a["address"] for a in info["addresses"]],
        "hostname": info["hostname"],
        "shell": _pick_shell(),
        "user": os.environ.get("USER") or "root",
        "is_root": is_root(),
        "recent": recent,
    }


# ---------------------------------------------------------------- 令牌管理


@router.get("/tokens")
async def list_tokens(_session: dict = Depends(require_internal)):
    return {"tokens": [_token_view(t) for t in config.agent_tokens]}


@router.post("/tokens")
async def create_token(body: CreateTokenBody, request: Request,
                       _session: dict = Depends(require_internal)):
    if body.scope not in ("full", "readonly", "custom"):
        raise HTTPException(400, "作用域必须是 full / readonly / custom")
    if not _NAME_RE.match(body.name or ""):
        raise HTTPException(400, "令牌名称包含不支持的字符")
    if body.expires_days and not (1 <= body.expires_days <= 3650):
        raise HTTPException(400, "过期天数需在 1~3650 之间（0 表示永不过期）")
    custom = (body.custom_token or "").strip()
    if custom:
        # 自定义令牌同样要过强度关：拒绝过短/低熵
        if len(custom) < MIN_TOKEN_LENGTH:
            raise HTTPException(400, f"自定义令牌长度至少 {MIN_TOKEN_LENGTH} 位")
        if len(set(custom)) <= 4:
            raise HTTPException(400, "自定义令牌字符种类太少")
    try:
        token = config.create_agent_token(
            name=body.name, scope=body.scope, prefixes=body.prefixes,
            expires_days=body.expires_days, note=body.note)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    audit.record(AuditEvent(
        action="token_created",
        target=body.name,
        summary=f"scope={body.scope} expires_days={body.expires_days}",
        source="web",
        ip=client_ip(request),
    ))
    return {
        "ok": True,
        "token": token,
        "message": "令牌已创建（明文仅此一次展示，请立即保存；"
                   "磁盘上只存哈希，遗失需重新签发）",
    }


@router.delete("/tokens/{token_id}")
async def delete_token(token_id: str, request: Request,
                       _session: dict = Depends(require_internal)):
    if not config.revoke_agent_token(token_id):
        raise HTTPException(404, "令牌不存在")
    audit.record(AuditEvent(action="token_revoked", target=token_id,
                            source="web", ip=client_ip(request)))
    return {"ok": True, "message": "令牌已吊销，立即失效"}


@router.delete("/tokens")
async def delete_all_tokens(request: Request,
                            _session: dict = Depends(require_internal)):
    count = config.revoke_all_agent_tokens()
    audit.record(AuditEvent(action="tokens_revoked_all", target="-",
                            summary=f"吊销 {count} 个令牌",
                            source="web", ip=client_ip(request)))
    return {"ok": True, "message": f"已吊销全部 {count} 个令牌"}


# ---------------------------------------------------------------- 旧接口兼容


@router.post("/token")
async def issue_token(body: TokenBody, request: Request,
                      _session: dict = Depends(require_internal)):
    """兼容旧调用方：创建一条 full 作用域令牌。"""
    custom = body.token.strip()
    if custom:
        if len(custom) < MIN_TOKEN_LENGTH:
            raise HTTPException(400, f"自定义令牌长度至少 {MIN_TOKEN_LENGTH} 位")
        if len(set(custom)) <= 4:
            raise HTTPException(400, "自定义令牌字符种类太少")
        token = config.issue_agent_token(custom)
    else:
        token = config.issue_agent_token()
    audit.record(AuditEvent(action="token_created", target="（兼容接口 full）",
                            source="web", ip=client_ip(request)))
    return {"ok": True, "token": token, "message": "Agent 令牌已生成"}


@router.delete("/token")
async def revoke_token(request: Request, _session: dict = Depends(require_internal)):
    """兼容旧调用方：吊销全部令牌。"""
    count = config.revoke_all_agent_tokens()
    audit.record(AuditEvent(action="tokens_revoked_all", target="-",
                            summary=f"（兼容接口）吊销 {count} 个令牌",
                            source="web", ip=client_ip(request)))
    return {"ok": True, "message": f"已吊销全部 {count} 个 Agent 令牌"}
