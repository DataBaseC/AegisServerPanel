"""平台化（2.0 M4）行为测试：多用户 RBAC、应用市场、诊断包、接口文档。

关键约束（与实现一一对应）：

- **兼容模式零变化**：``config.users`` 为空时 RBAC 完全旁路，
  单密码登录仍是 admin，历史行为与 M3 一致；
- **启用后按方法/路径收口**：viewer 只读、operator 不能碰管理员专属端点、
  admin 全通；会话内角色每次请求回查用户记录；
- **凭据不外泄**：用户列表与诊断包都不含密码哈希、TOTP 密钥、恢复码哈希。

用例按文件内顺序执行：先兼容模式，再创建用户进入多用户模式，
最后验证诊断包/文档；模块结束时把配置整体还原，避免污染后续测试文件。
"""

from __future__ import annotations

import copy
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.auth import sessions
from app.config import MODE_INTERNAL, config
from app.main import app

PASSWORD = "test-password-123"
VIEWER_PASSWORD = "viewer-password-123"
OPERATOR_PASSWORD = "operator-password-123"


def _login(client: TestClient, username: str, password: str):
    payload = {"password": password}
    if username:
        payload["username"] = username
    return client.post("/api/auth/login", json=payload)


def _identity(username: str, password: str) -> TestClient:
    """按某个账号登录，返回**独立的** TestClient（各自持一份会话 Cookie）。

    TestClient 的 per-request ``cookies=`` 不会覆盖实例上的 Cookie
    （starlette 自己也会给弃用警告），所以切换身份必须换客户端实例。
    """
    client = TestClient(app)
    res = _login(client, username, password)
    assert res.status_code == 200, res.text
    return client


def _anonymous() -> TestClient:
    return TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def _isolated_config():
    """保存并还原配置：本文件会写入 users / 模式，必须不给后面的测试留下痕迹。"""
    snapshot = copy.deepcopy(config.data)
    yield
    config.data = snapshot
    config.save()
    sessions.revoke_all()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin(client):
    """确保已初始化密码、处于内网模式，并以管理员身份登录。"""
    config.disable_totp()  # 前面的测试文件可能启用了 2FA，这里先恢复干净状态
    if not config.initialized:
        assert client.post("/api/auth/setup", json={"password": PASSWORD}).status_code == 200
    config.set_mode(MODE_INTERNAL)
    if _login(client, "", PASSWORD).status_code != 200:
        # 救援通道：前面的用例可能改过密码/TOTP，直接按 CLI 的方式重置
        config.set_password(PASSWORD)
        config.set_mode(MODE_INTERNAL)
        assert _login(client, "", PASSWORD).status_code == 200
    return client


# ---------------------------------------------------------------- 兼容模式

def test_legacy_single_password_unchanged(admin):
    assert config.has_users is False
    status = admin.get("/api/auth/status").json()
    assert status["multi_user"] is False
    assert status["role"] == "admin"          # 单密码即管理员
    assert admin.get("/api/system/info").status_code == 200


# ---------------------------------------------------------------- 应用市场

def test_market_catalog(admin):
    res = admin.get("/api/panel/market")
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["total"] >= 6
    entry = data["apps"][0]
    for key in ("id", "name", "description", "command", "port", "docs"):
        assert key in entry
    assert all(item["installed"] is False for item in data["apps"])


def test_market_install_registers_app(admin):
    res = admin.post("/api/panel/market/nginx/install", json={})
    assert res.status_code == 200, res.text
    app_id = res.json()["app"]["id"]
    listed = admin.get("/api/panel/apps").json()["apps"]
    installed = next(a for a in listed if a["id"] == app_id)
    assert installed["command"].startswith("nginx")
    market = admin.get("/api/panel/market").json()
    entry = next(i for i in market["apps"] if i["id"] == "nginx")
    assert entry["installed"] is True and entry["app_id"] == app_id
    # 重复注册被拒
    assert admin.post("/api/panel/market/nginx/install", json={}).status_code == 409
    # 未知条目 404
    assert admin.post("/api/panel/market/nope/install", json={}).status_code == 404
    # 清理，避免影响后续「常驻应用」相关断言
    admin.delete(f"/api/panel/apps/{app_id}")


# ---------------------------------------------------------------- 多用户与 RBAC

def test_create_users_and_no_secret_leak(admin):
    viewer = admin.post("/api/panel/users",
                        json={"username": "alice", "password": VIEWER_PASSWORD, "role": "viewer"})
    assert viewer.status_code == 200, viewer.text
    operator = admin.post(
        "/api/panel/users",
        json={"username": "bob", "password": OPERATOR_PASSWORD, "role": "operator"})
    assert operator.status_code == 200, operator.text
    assert config.has_users is True

    listed = admin.get("/api/panel/users").json()
    names = {u["username"] for u in listed["users"]}
    assert {"admin", "alice", "bob"} <= names       # 历史单密码被迁移成 admin
    for user in listed["users"]:
        for secret in ("password_hash", "totp_secret", "recovery_hashes"):
            assert secret not in user
    assert "password_hash" not in admin.get("/api/panel/users").text

    # 用户名 / 密码策略
    assert admin.post("/api/panel/users",
                      json={"username": "x", "password": VIEWER_PASSWORD}).status_code == 400
    assert admin.post("/api/panel/users",
                      json={"username": "carol", "password": "short"}).status_code == 400
    assert admin.post("/api/panel/users",
                      json={"username": "alice", "password": VIEWER_PASSWORD}).status_code == 400


def test_legacy_password_still_logs_in_as_admin(admin):
    """启用多用户后，原单密码（不填用户名）仍是 admin。"""
    res = _login(admin, "", PASSWORD)
    assert res.status_code == 200, res.text
    status = admin.get("/api/auth/status").json()
    assert status["role"] == "admin" and status["username"] == "admin"
    assert status["multi_user"] is True


def test_viewer_is_read_only(admin):
    viewer = _identity("alice", VIEWER_PASSWORD)
    assert viewer.get("/api/system/info").status_code == 200
    # 状态变更一律 403（白名单只有 /api/auth/* 的自身账号操作）
    assert viewer.post("/api/panel/confirm", json={"action": "power"}).status_code == 403
    assert viewer.post("/api/panel/users",
                       json={"username": "dave", "password": VIEWER_PASSWORD}).status_code == 403
    assert viewer.put("/api/panel/prefs",
                      json={"values": {"power.save_mode": True}}).status_code == 403
    # 自己的账号操作仍然放行：退出登录
    assert viewer.post("/api/auth/logout", json={}).status_code == 200


def test_operator_scope(admin):
    operator = _identity("bob", OPERATOR_PASSWORD)
    assert operator.get("/api/system/info").status_code == 200
    assert operator.get("/api/panel/market").status_code == 200   # 读市场允许
    # 电源、令牌管理、用户管理、配置导出都属管理员专属
    assert operator.post("/api/system/power",
                         json={"action": "reboot", "confirm": "CONFIRM"}).status_code == 403
    assert operator.get("/api/agent/tokens").status_code == 403
    assert operator.get("/api/panel/users").status_code == 403
    assert operator.get("/api/panel/config/export").status_code == 403
    # Docker 删除 / 防火墙写 / 反代重载按方法与路径判定
    assert operator.delete("/api/panel/infra/docker/containers/abc").status_code == 403
    assert operator.post("/api/panel/infra/firewall/allow", json={"port": 80}).status_code == 403
    assert operator.post("/api/panel/infra/proxy/reload", json={}).status_code == 403
    # 2.0.1：等同 root 的能力整体归 admin——网页终端（exec/PTY = 直接 shell）、
    # crontab 写入（= root 计划任务）、apt 应用更新（= 任意新代码以 root 落地）
    assert operator.get("/api/terminal/info").status_code == 403
    assert operator.post("/api/terminal/exec", json={"command": "id"}).status_code == 403
    assert operator.get("/api/panel/maintenance/cron").status_code == 403
    assert operator.post("/api/panel/maintenance/cron",
                         json={"lines": ["* * * * * echo hi"]}).status_code == 403
    assert operator.get("/api/panel/maintenance/updates").status_code == 403
    assert operator.post("/api/panel/maintenance/updates/apply",
                         json={"packages": ["nginx"]}).status_code == 403
    # 备份管理仍归 operator（不涉及 root 等价能力）
    assert operator.get("/api/panel/maintenance/backups").status_code != 403


def test_admin_can_reach_privileged_paths(admin):
    # admin 不再被 RBAC 拦下（电源本身因缺少 systemd/确认令牌返回 400，但不是 403）
    res = admin.post("/api/system/power", json={"action": "reboot", "confirm": "CONFIRM"})
    assert res.status_code != 403
    assert admin.get("/api/panel/users").status_code == 200
    # 2.0.1：终端/定时任务/更新对 admin 放行（info 200；exec 在测试环境无 PTY
    # 时可能 500，但绝不是 RBAC 的 403）
    # 2.1.0 修：Windows 等无 PTY 平台 info 恒为 501，这里放宽为「200 或 501」——
    # 断言「不是 403」才是这条用例的本意，翻车点在于把平台限制写成了结论。
    assert admin.get("/api/terminal/info").status_code in (200, 501)
    assert admin.get("/api/panel/maintenance/cron").status_code == 200
    assert admin.post("/api/terminal/exec",
                      json={"command": "id"}).status_code != 403


def test_last_admin_protected(admin):
    admin_id = next(u["id"] for u in admin.get("/api/panel/users").json()["users"]
                    if u["username"] == "admin")
    assert admin.put(f"/api/panel/users/{admin_id}", json={"role": "viewer"}).status_code == 400
    assert admin.put(f"/api/panel/users/{admin_id}", json={"disabled": True}).status_code == 400
    assert admin.delete(f"/api/panel/users/{admin_id}").status_code == 400


def test_disable_and_delete_user(admin):
    users = admin.get("/api/panel/users").json()["users"]
    alice = next(u for u in users if u["username"] == "alice")
    bob = next(u for u in users if u["username"] == "bob")
    viewer = _identity("alice", VIEWER_PASSWORD)

    assert admin.put(f"/api/panel/users/{alice['id']}", json={"disabled": True}).status_code == 200
    # 禁用后既有会话立即失效（不再只是"下次登录被拒"）
    assert viewer.get("/api/system/info").status_code == 401

    operator = _identity("bob", OPERATOR_PASSWORD)
    assert admin.delete(f"/api/panel/users/{bob['id']}").status_code == 200
    names = {u["username"] for u in admin.get("/api/panel/users").json()["users"]}
    assert "bob" not in names
    # 删除后该账号的会话立即失效（按用户名精确吊销，不会留下历史会话）
    assert operator.get("/api/system/info").status_code == 401


# ---------------------------------------------------------------- 诊断包与文档

def test_diagnostics_zip_is_scrubbed(admin):
    res = admin.get("/api/panel/diagnostics")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(res.content)) as bundle:
        names = set(bundle.namelist())
        assert {"version.json", "config.scrubbed.json", "capabilities.json",
                "metrics.json", "audit_recent.json", "README.txt"} <= names
        version = json.loads(bundle.read("version.json"))
        assert version["version"] and "mode" in version
        scrubbed = bundle.read("config.scrubbed.json").decode("utf-8")
        assert "password_hash" not in scrubbed
        assert "totp_secret" not in scrubbed
        assert "recovery_hashes" not in scrubbed
        payload = json.loads(scrubbed)
        # 用户仍然保留（便于排障），但凭据字段已被剔除
        assert payload["users"] and all("password_hash" not in u for u in payload["users"])
        assert "agent_tokens" not in payload
        readme = bundle.read("README.txt").decode("utf-8")
        assert "脱敏" in readme


def test_docs_and_openapi(admin):
    anonymous = _anonymous()
    assert anonymous.get("/api/openapi.json").status_code == 401
    assert anonymous.get("/api/docs").status_code == 401
    spec = admin.get("/api/openapi.json")
    assert spec.status_code == 200
    assert "/api/system/info" in spec.json()["paths"]
    page = admin.get("/api/docs")
    assert page.status_code == 200
    body = page.text
    assert "/api/system/info" in body and "接口文档" in body
    # 自包含：不引外部脚本/样式，CSP 不需要放宽
    assert "<script" not in body.lower()
    assert "cdn" not in body.lower()
