"""多用户与 RBAC 管理（2.0 M4）。

设计要点：

- **增量能力**：``config.users`` 为空时这里只返回空列表，面板完全沿用
  原有的单密码逻辑（单密码 = admin），不改变任何默认行为。
- **首个用户触发迁移**：创建第一个用户时，把历史 ``password_hash``（含
  TOTP 密钥）迁移成 ``username=admin`` 的一条记录，保证原密码仍可登录。
- **绝不外泄凭据**：列表/详情只返回 id、用户名、角色、状态与时间戳，
  密码哈希、TOTP 密钥、恢复码哈希一律不出现在响应里。
- **保护最后一个管理员**：不能删除、降级或禁用唯一的可用 admin，
  否则面板会永久失去管理入口（只能改配置文件救场）。
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..audit import AuditEvent, audit
from ..auth import ROLE_ADMIN, client_ip, require_internal, require_role, session_username
from ..config import ROLES, USERNAME_RE, config

router = APIRouter(prefix="/api/panel/users", tags=["users"],
                   dependencies=[Depends(require_internal)])


class UserCreateBody(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class UserUpdateBody(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    password: str | None = None


def _public(user: dict) -> dict:
    """对外可见的用户字段（不含任何哈希/密钥）。"""
    return {
        "id": user.get("id", ""),
        "username": user.get("username", ""),
        "role": user.get("role", "viewer"),
        "disabled": bool(user.get("disabled")),
        "totp_enabled": bool(user.get("totp_enabled")),
        "created_at": int(user.get("created_at") or 0),
    }


def _record(action: str, request: Request, detail: str, actor: str) -> None:
    audit.record(AuditEvent(action=f"user_{action}", summary=detail[:400],
                            source="web", ip=client_ip(request),
                            actor=actor))


@router.get("")
async def list_users(_session: dict = Depends(require_role(ROLE_ADMIN))):
    return {
        "users": [_public(u) for u in config.users],
        "roles": list(ROLES),
        "multi_user": config.has_users,
        "admin_count": config.admin_count(),
    }


@router.post("")
async def create_user(body: UserCreateBody, request: Request,
                      session: dict = Depends(require_role(ROLE_ADMIN))):
    username = body.username.strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "用户名只能用字母、数字、下划线、点、连字符，长度 3~32")
    if body.role not in ROLES:
        raise HTTPException(400, f"角色只能是：{', '.join(ROLES)}")
    try:
        # 密码哈希是 60 万轮 PBKDF2：放线程池，避免创建用户时整站卡顿
        user = await asyncio.to_thread(config.create_user, username, body.password, body.role)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    _record("create", request, f"{username} 角色={body.role}", session_username(session))
    return {"ok": True, "user": _public(user),
            "message": f"已创建用户 {username}（{body.role}）"}


@router.put("/{user_id}")
async def update_user(user_id: str, body: UserUpdateBody, request: Request,
                      session: dict = Depends(require_role(ROLE_ADMIN))):
    target = config.user_by_id(user_id)
    if target is None:
        raise HTTPException(404, "用户不存在")
    patch = body.model_dump(exclude_none=True)
    if not patch:
        raise HTTPException(400, "没有需要修改的项")
    changes = []
    if "role" in patch:
        changes.append(f"角色={patch['role']}")
    if "disabled" in patch:
        changes.append(f"禁用={bool(patch['disabled'])}")
    if "password" in patch:
        changes.append("重置密码")
    try:
        # 重置密码同样可能触发 PBKDF2（patch 里有 password 时）
        user = await asyncio.to_thread(config.update_user, user_id, patch)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    # 禁用或改密后立即踢掉该用户的全部会话，权限变更不用等会话过期
    from ..auth import sessions

    if patch.get("disabled") or "password" in patch or "role" in patch:
        sessions.revoke_user(user["username"])
    _record("update", request, f"{user['username']}：{', '.join(changes)}",
            session_username(session))
    return {"ok": True, "user": _public(user), "message": "用户已更新"}


@router.delete("/{user_id}")
async def delete_user(user_id: str, request: Request,
                      session: dict = Depends(require_role(ROLE_ADMIN))):
    target = config.user_by_id(user_id)
    if target is None:
        raise HTTPException(404, "用户不存在")
    if (target.get("username") == session_username(session)
            or target.get("id") == session.get("user_id")):
        raise HTTPException(400, "不能删除当前登录的账号")
    try:
        removed = config.delete_user(user_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    from ..auth import sessions

    sessions.revoke_user(removed["username"])
    _record("delete", request, removed["username"], session_username(session))
    return {"ok": True, "message": f"已删除用户 {removed['username']}"}
