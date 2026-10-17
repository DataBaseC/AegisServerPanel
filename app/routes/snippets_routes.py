"""代码 / 命令片段库 API：按当前面板地址与令牌渲染模板，供一键复制。

令牌默认渲染为 ``YOUR_TOKEN`` 占位符；只有显式 ``?reveal_token=1`` 时才填入真实
令牌（前端「显示令牌」按钮才发起这种请求），避免默认把凭据铺满页面。
"""

from __future__ import annotations

import sys

from fastapi import APIRouter, Depends, HTTPException, Request

from ..auth import require_internal
from ..snippets import TOKEN_PLACEHOLDER, public_snippets, render_text, snippet_by_id

router = APIRouter(prefix="/api/snippets", tags=["snippets"])


def _context(request: Request, reveal_token: bool) -> dict[str, str]:
    """渲染上下文。

    1.4.1 起 ``token`` **永远**是 ``YOUR_TOKEN`` 占位符：1.4.0 把令牌改成
    只存哈希后，``config.agent_token`` 变成了哨兵串 "configured"，
    ``reveal_token=1`` 会把它当令牌渲染进片段正文——用户"显示令牌→复制"
    拿到的是 ``X-Agent-Token: configured``，粘出去必然 401。
    真要令牌请在「安全中心 → Agent 令牌」创建（明文只展示一次）。
    """
    base_url = str(request.base_url).rstrip("/")
    return {
        "base_url": base_url,
        "endpoint": f"{base_url}/api/terminal/exec",
        "token": TOKEN_PLACEHOLDER,
        "host": request.url.hostname or "-",
        "port": str(request.url.port or ""),
        "shell": "/bin/bash" if sys.platform != "win32" else "cmd.exe",
    }


@router.get("")
async def list_snippets(request: Request, category: str = "", q: str = "",
                        reveal_token: bool = False,
                        _session: dict = Depends(require_internal)):
    context = _context(request, reveal_token)
    platform = "posix" if sys.platform != "win32" else "windows"
    items = public_snippets(context, platform)
    if category:
        items = [s for s in items if s["category"] == category]
    if q:
        needle = q.lower()
        items = [s for s in items if needle in s["title"].lower()
                 or needle in s["code"].lower() or needle in s["category"].lower()]
    categories = []
    for snippet in public_snippets(context, platform):
        if snippet["category"] not in categories:
            categories.append(snippet["category"])
    return {
        "total": len(items),
        "categories": categories,
        "snippets": items,
        # 令牌不可回显（哈希存储），保留字段是为了兼容旧前端
        "token_revealed": False,
        "token_hint": "令牌以哈希存储，无法回显；请在「安全中心 → Agent 令牌」创建后填入",
        "endpoint": context["endpoint"],
    }


@router.get("/{snippet_id}")
async def snippet_detail(snippet_id: str, request: Request, reveal_token: bool = False,
                         _session: dict = Depends(require_internal)):
    snippet = snippet_by_id(snippet_id)
    if snippet is None:
        raise HTTPException(404, "片段不存在")
    context = _context(request, reveal_token)
    return {
        "id": snippet.id,
        "category": snippet.category,
        "title": snippet.title,
        "language": snippet.language,
        "note": snippet.note,
        "requires": list(snippet.requires),
        "exec": snippet.exec and snippet.language == "bash",
        "code": render_text(snippet.code, context),
    }
