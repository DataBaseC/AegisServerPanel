"""多用户 2FA 展示/巡检回归（2.0）：安全中心与安全巡检必须按**当前会话用户**判定。

背景：2FA 的**执行**早已是 per-user（``app/routes/auth_routes.py::_TotpScope``：
多用户模式下 secret / enabled / recovery_hashes 落在 ``config.data["users"]``
的对应记录上），但展示层（``GET /api/panel/security`` 与
``GET /api/panel/security/checkup``）曾读全局 ``config.totp_enabled``，
于是多用户下即便某个用户自己开了 TOTP，页面和巡检仍永久误报
「未启用二次认证」。

本文件锁住两类行为：

1. **单密码模式防回归**：``config.users`` 为空时沿用全局配置，
   未启用 → 巡检出现「未启用二次认证」；启用后 → 该项消失。
2. **多用户模式按会话用户**：已启用用户不再被误报，未启用用户仍被提示；
   两个账号互不影响（全局 ``config.totp_enabled`` 保持 False 也能正确判定）。
"""

from __future__ import annotations

import copy

import pytest
from fastapi.testclient import TestClient

from app import totp as totp_mod
from app.auth import sessions
from app.config import MODE_INTERNAL, config
from app.main import app

PASSWORD = "test-password-123"
ALICE_PASSWORD = "alice-password-123"
BOB_PASSWORD = "bob-password-123"
TOTP_WARNING = "未启用二次认证"
TOTP_FIELDS = ("totp_secret", "totp_enabled", "totp_recovery_hashes", "totp_enabled_at")


def _login_client(username: str, password: str) -> TestClient:
    """按指定账号登录，返回独立 TestClient（各自持一份会话 Cookie）。"""
    client = TestClient(app)
    payload = {"password": password}
    if username:
        payload["username"] = username
    res = client.post("/api/auth/login", json=payload)
    assert res.status_code == 200, res.text
    return client


def _checkup_items(client: TestClient) -> list[dict]:
    res = client.get("/api/panel/security/checkup")
    assert res.status_code == 200, res.text
    return res.json()["items"]


def _has_totp_warning(client: TestClient) -> bool:
    return any(item.get("title") == TOTP_WARNING for item in _checkup_items(client))


def _security_summary(client: TestClient) -> dict:
    res = client.get("/api/panel/security")
    assert res.status_code == 200, res.text
    return res.json()


@pytest.fixture(scope="module", autouse=True)
def _isolated_config():
    """复位到「已知密码、单密码模式、内网模式」，结束后整体还原。

    本文件会写 users / TOTP / 模式，绝不能给其他测试文件留下痕迹；
    同时主动清掉 users 与全局 TOTP 字段，避免被前序文件的状态影响。
    """
    snapshot = copy.deepcopy(config.data)
    baseline = copy.deepcopy(config.data)
    baseline.pop("users", None)
    for key in TOTP_FIELDS:
        baseline.pop(key, None)
    config.data = baseline
    config.save()
    config.set_mode(MODE_INTERNAL)
    config.set_password(PASSWORD)  # 固定密码，保证 login 用例可预期
    sessions.revoke_all()
    yield
    config.data = snapshot
    config.save()
    sessions.revoke_all()


# ---------------------------------------------------------------- 单密码模式（防回归）

def test_single_password_mode_uses_global_totp():
    """单密码模式：行为与 1.x 完全一致，只看全局配置。"""
    assert config.has_users is False
    config.disable_totp()
    client = _login_client("", PASSWORD)

    # 未启用：概览显示未启用，巡检提示「未启用二次认证」
    summary = _security_summary(client)
    assert summary["totp"]["enabled"] is False
    assert summary["totp"]["pending"] is False
    assert _has_totp_warning(client) is True

    # 只生成密钥、未完成启用：pending=True，仍视为未启用
    setup = client.post("/api/auth/totp/setup", json={})
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    summary = _security_summary(client)
    assert summary["totp"]["enabled"] is False
    assert summary["totp"]["pending"] is True
    assert _has_totp_warning(client) is True

    # 完成启用：概览显示已启用 + 恢复码数量，巡检不再提示
    res = client.post("/api/auth/totp/enable", json={"code": totp_mod.code(secret)})
    assert res.status_code == 200, res.text
    summary = _security_summary(client)
    assert summary["totp"]["enabled"] is True
    assert summary["totp"]["pending"] is False
    assert summary["totp"]["recovery_left"] == 10
    assert _has_totp_warning(client) is False


# ---------------------------------------------------------------- 多用户模式

def test_multi_user_totp_status_follows_session_user():
    """多用户模式：2FA 状态取自会话对应用户记录，两个账号互不影响。"""
    config.disable_totp()  # 全局 2FA 关闭，且下面创建用户时不会再迁移出启用的 admin
    assert config.has_users is False
    config.create_user("alice", ALICE_PASSWORD, role="viewer")
    config.create_user("bob", BOB_PASSWORD, role="viewer")
    assert config.has_users is True
    assert config.totp_enabled is False  # 全局仍关闭：证明判定不是全局字段

    alice = _login_client("alice", ALICE_PASSWORD)
    bob = _login_client("bob", BOB_PASSWORD)

    # 用真实的 per-user TOTP 流程给 alice 启用（setup + enable）
    setup = alice.post("/api/auth/totp/setup", json={})
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    res = alice.post("/api/auth/totp/enable",
                     json={"code": totp_mod.code(secret)})
    assert res.status_code == 200, res.text
    assert config.find_user("alice")["totp_enabled"] is True
    assert config.find_user("bob")["totp_enabled"] is False

    # 已启用用户：概览按本人记录显示已启用，巡检不再误报
    alice_summary = _security_summary(alice)
    assert alice_summary["totp"] == {
        "enabled": True, "pending": False, "recovery_left": 10,
    }, alice_summary["totp"]
    assert _has_totp_warning(alice) is False

    # 未启用用户：概览仍为未启用，巡检仍然提示（同一条全局/同一次请求）
    bob_summary = _security_summary(bob)
    assert bob_summary["totp"] == {
        "enabled": False, "pending": False, "recovery_left": 0,
    }, bob_summary["totp"]
    assert _has_totp_warning(bob) is True
    bob_warning = next(item for item in _checkup_items(bob)
                       if item.get("title") == TOTP_WARNING)
    assert bob_warning["level"] == "bad"
    assert bob_warning["target"] == "security-totp"

    # bob 生成密钥但未启用：pending=True，依旧按未启用提示
    setup = bob.post("/api/auth/totp/setup", json={})
    assert setup.status_code == 200, setup.text
    bob_summary = _security_summary(bob)
    assert bob_summary["totp"] == {
        "enabled": False, "pending": True, "recovery_left": 0,
    }, bob_summary["totp"]
    assert _has_totp_warning(bob) is True
