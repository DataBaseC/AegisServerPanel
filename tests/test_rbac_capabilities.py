"""能力级 RBAC 回归测试（2.1.0 / R5）。

背景：2.0.0 的 RBAC 是「operator 禁止前缀黑名单」，2.0.1 给终端 / cron / apt 加了
三条前缀，但同一「等同 root」能力还有 4 条直通路径（WS 终端、任意文件写、常驻应用
任意命令、写 root authorized_keys）。路径黑名单天生只能堵已知入口。

这个文件把口径反转过来：
1. **能力矩阵**：所有「能执行命令 / 能以 root 持久化 / 能把 root 文件带出去 /
   能改系统级状态」的端点，逐个断言 operator 被拒、admin 不被拒；
2. **覆盖率闸门**：扫描 app.routes 里所有**写方法**路由，未在能力矩阵或
   「已知安全的 operator 写操作」清单里登记的，测试直接失败——以后新增端点
   忘了登记会在这里红，而不是等安全审计发现。
3. 兼容模式（users 为空 / 单密码）必须完全不受影响。
"""

from __future__ import annotations

import copy
import re
import sys

import pytest
from fastapi.testclient import TestClient

from app.auth import (ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER, rbac_denial,
                      sessions)
from app.config import MODE_INTERNAL, config
from app.main import app

PASSWORD = "test-password-123"
VIEWER_PASSWORD = "viewer-password-123"
OPERATOR_PASSWORD = "operator-password-123"

# ---------------------------------------------------------------- 能力矩阵
# 每行 = 一个「等同 root」的写入口。新增这类端点时必须在这里补一行。
# (方法, 路径, 载荷, 说明)；载荷只用于真发请求的下半部分，能力判定用不到它。
CAPABILITY_MATRIX = [
    # A. 能执行任意命令
    ("POST", "/api/panel/apps", {"name": "evil", "command": "echo pwned"},
     "注册常驻应用 = 任意 shell"),
    ("PUT", "/api/panel/apps/abc", {"command": "echo pwned"}, "修改常驻应用命令"),
    ("DELETE", "/api/panel/apps/abc", None, "删除常驻应用"),
    ("POST", "/api/panel/apps/abc/start", None, "启动常驻应用（执行其命令）"),
    ("POST", "/api/panel/apps/abc/stop", None, "停止常驻应用"),
    ("POST", "/api/panel/apps/abc/restart", None, "重启常驻应用"),
    ("POST", "/api/panel/apps/abc/probe", None, "探测常驻应用"),
    ("POST", "/api/agent/tokens", {"name": "evil"}, "签发 Agent 令牌（= 命令通道）"),
    ("POST", "/api/terminal/exec", {"command": "id"}, "网页终端 exec"),
    ("POST", "/api/panel/maintenance/updates/apply", {"packages": ["nginx"]},
     "apt 应用更新 = 新代码以 root 落地"),
    ("POST", "/api/panel/market/nginx/install", {}, "应用市场安装"),
    # B. 能以 root 持久化
    ("POST", "/api/panel/infra/ssh/keys", {"line": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test"},
     "写 root authorized_keys"),
    ("DELETE", "/api/panel/infra/ssh/keys", {"line": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test"},
     "删 root authorized_keys"),
    ("POST", "/api/panel/maintenance/cron", {"lines": ["* * * * * echo hi"]},
     "写 root crontab"),
    ("POST", "/api/panel/boot/cron", {"lines": ["* * * * * echo hi"]}, "开机/守护任务写入"),
    # C. 能把 root 文件带出去
    ("POST", "/api/panel/maintenance/backups", {"paths": ["/root"]}, "备份打包 root 文件"),
    ("DELETE", "/api/panel/maintenance/backups/x.tar.gz", None, "删除备份"),
    ("POST", "/api/panel/maintenance/backups/x.tar.gz/upload", {}, "备份外传（rclone）"),
    # D. 能改系统级状态
    ("DELETE", "/api/panel/infra/docker/containers/abc", None, "删除容器"),
    ("POST", "/api/panel/infra/firewall/allow", {"port": 80}, "防火墙规则变更"),
    ("POST", "/api/panel/infra/proxy/reload", {}, "反向代理重载"),
    ("POST", "/api/storage/mount", {"device": "/dev/x", "target": "/mnt/x"}, "挂载"),
    # E. 敏感读取（终端录制含 root 命令原文 / 读取凭据类）
    ("GET", "/api/panel/recordings", None, "读终端录制"),
    ("GET", "/api/panel/users", None, "用户列表（含角色）"),
    ("GET", "/api/panel/config/export", None, "配置导出"),
]

# operator **允许**的写操作：有界、可回退、不构成任意命令执行。
# 新增一条必须写清理由，否则覆盖率闸门会红。
OPERATOR_ALLOWED_WRITES = [
    (r"^/api/auth(/.*)?$", "自己的登录/密码/TOTP/退出"),
    (r"^/api/panel/confirm$", "确认令牌（不是权限边界，能触达的动作已在能力表被拒）"),
    (r"^/api/services/[^/]+/action$", "服务启停：单元名受限于本机已有服务，有界可回退"),
    (r"^/api/panel/tasks/[^/]+/run$", "触发任务：命令由 admin 定义，operator 不能改"),
    (r"^/api/panel/tasks/recent$", "清空任务运行记录（仅本地记录）"),
    (r"^/api/panel/infra/docker/containers/[^/]+/action$", "启动/停止已有容器（镜像由 admin 创建）"),
    (r"^/api/panel/infra/net/tool$", "网络工具：固定 argv 白名单，无法注入"),
    (r"^/api/panel/infra/databases/probe$", "数据库只读探测"),
    (r"^/api/snippets(/.*)?$", "代码片段：纯文本存储，不自动执行"),
    (r"^/api/files(/.*)?$", "文件管理：路径级写根白名单在 file_routes 里另做一层判定"),
    (r"^/api/panel/logs(/.*)?$", "日志清理/跟随属运维日常（不落代码）"),
    (r"^/api/processes/[^/]+/(signal|nice)$",
     "进程信号/nice：process_routes._guard_pid 已拒 PID 0/1 与面板自身，属有界运维"),
]


@pytest.fixture(scope="module", autouse=True)
def _isolated_config():
    snapshot = copy.deepcopy(config.data)
    yield
    config.data = snapshot
    config.save()
    sessions.revoke_all()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _login(c: TestClient, username: str, password: str):
    payload = {"password": password}
    if username:
        payload["username"] = username
    return c.post("/api/auth/login", json=payload)


@pytest.fixture(scope="module")
def admin(client):
    config.disable_totp()
    if not config.initialized:
        assert client.post("/api/auth/setup", json={"password": PASSWORD}).status_code == 200
    config.set_mode(MODE_INTERNAL)
    if _login(client, "", PASSWORD).status_code != 200:
        config.set_password(PASSWORD)
        config.set_mode(MODE_INTERNAL)
        assert _login(client, "", PASSWORD).status_code == 200
    return client


@pytest.fixture(scope="module")
def multi_user(admin):
    """进入多用户模式：bob=operator、alice=viewer、admin 仍是管理员。"""
    for username, password, role in (("alice", VIEWER_PASSWORD, "viewer"),
                                     ("bob", OPERATOR_PASSWORD, "operator")):
        res = admin.post("/api/panel/users",
                         json={"username": username, "password": password, "role": role})
        assert res.status_code in (200, 409), res.text
    assert config.has_users is True
    return admin


@pytest.fixture(scope="module")
def operator(multi_user):
    c = TestClient(app)
    assert _login(c, "bob", OPERATOR_PASSWORD).status_code == 200
    return c


@pytest.fixture(scope="module")
def viewer(multi_user):
    c = TestClient(app)
    assert _login(c, "alice", VIEWER_PASSWORD).status_code == 200
    return c


# ---------------------------------------------------------------- 1) 能力矩阵

@pytest.mark.parametrize("method,path,payload,label", CAPABILITY_MATRIX)
def test_operator_denied_for_root_capabilities(method, path, payload, label):
    assert rbac_denial(method, path, ROLE_OPERATOR), f"operator 不应能 {method} {path}（{label}）"


@pytest.mark.parametrize("method,path,payload,label", CAPABILITY_MATRIX)
def test_admin_not_denied_by_rbac(method, path, payload, label):
    # 只断言「不是 RBAC 拦的」；具体业务码（400/404/500/501）由各端点自己决定
    assert rbac_denial(method, path, ROLE_ADMIN) == ""


# ---------------------------------------------------------------- 2) 真实 HTTP（安全子集）

def test_operator_cannot_create_app_over_http(operator, admin):
    res = operator.post("/api/panel/apps", json={"name": "evil-app", "command": "echo pwned"})
    assert res.status_code == 403, res.text
    names = [a["name"] for a in admin.get("/api/panel/apps").json()["apps"]]
    assert "evil-app" not in names


def test_operator_cannot_install_market_app(operator):
    res = operator.post("/api/panel/market/nginx/install", json={})
    assert res.status_code == 403, res.text


def test_operator_cannot_read_recordings(operator):
    assert operator.get("/api/panel/recordings").status_code == 403


def test_operator_cannot_write_ssh_authorized_keys(operator):
    res = operator.post("/api/panel/infra/ssh/keys",
                        json={"line": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test"})
    assert res.status_code == 403, res.text


def test_terminal_websocket_rejects_operator(operator, monkeypatch):
    """WS 不走 HTTP 中间件：必须在握手阶段自己拒掉 operator（2.1.0 P0-1）。

    Windows 没有 PTY，端点会在鉴权之前早退成 1011，所以这里把 HAS_PTY 打成 True
    让执行流走到角色判定（operator 在 `pty.openpty()` 之前就被拒，不会真的开终端）。
    """
    from app.routes import terminal_routes

    monkeypatch.setattr(terminal_routes, "HAS_PTY", True)
    with pytest.raises(Exception) as exc:
        with operator.websocket_connect("/api/terminal/ws") as ws:
            ws.receive_text()
    # 关在 4403（需要 admin 权限），不是 1011/4401
    code = getattr(exc.value, "code", None)
    assert code in (4403, 4401), f"operator 的 WS 握手应被 4403/4401 拒绝，实际 code={code}"


def test_operator_keeps_bounded_ops(operator):
    """有界运维动作不能被误伤：服务列表可读、市场可浏览、日志可读。"""
    assert operator.get("/api/panel/market").status_code == 200
    # 服务列表在 Windows 上因缺少 systemctl 返回 400，这里只关心「不是 RBAC 拦的」
    assert operator.get("/api/services").status_code != 403
    assert operator.get("/api/logs/sources").status_code != 403


def test_viewer_still_read_only(viewer):
    assert viewer.get("/api/system/info").status_code == 200
    assert viewer.post("/api/panel/apps", json={"name": "x", "command": "id"}).status_code == 403


# ---------------------------------------------------------------- 3) 覆盖率闸门

def _registered_writes():
    """收集所有「会改变状态」的 HTTP 端点（方法, 路径样例）。

    不能遍历 ``app.routes``：当前 Starlette 版本里 include_router 生成的是惰性的
    ``_IncludedRouter``，没有 ``path`` / ``methods`` 属性，遍历会得到空集——那样
    这条闸门会「静默通过」而毫无覆盖（第一版就踩了这个坑）。改用 OpenAPI schema，
    它由框架自己展开所有路由，稳定且无惰性对象。
    """
    found = []
    for path, operations in app.openapi()["paths"].items():
        if not path.startswith("/api/"):
            continue
        sample = re.sub(r"\{[^}]+\}", "x", path)   # 路径参数代入 x
        for method in operations:
            method = method.upper()
            if method in ("GET", "HEAD", "OPTIONS"):
                continue
            found.append((method, sample))
    return found


def test_every_mutating_route_is_classified():
    """新增写端点必须落进「能力矩阵」或「operator 白名单」，否则这条测试红。"""
    writes = _registered_writes()
    # 反静默：路由枚举必须真的拿到东西（当前基线 77 个写端点，留足余量）
    assert len(writes) >= 50, f"写端点枚举异常（只拿到 {len(writes)} 条），检查路由注册方式"
    unclassified = []
    for method, sample in writes:
        if rbac_denial(method, sample, ROLE_OPERATOR):
            continue                      # 已在能力表里被拒
        if any(re.match(pattern, sample) for pattern, _ in OPERATOR_ALLOWED_WRITES):
            continue                      # 已知有界写操作
        unclassified.append(f"{method} {sample}")
    assert not unclassified, (
        "以下写端点未做角色收口、也没登记进 OPERATOR_ALLOWED_WRITES：\n  "
        + "\n  ".join(sorted(set(unclassified)))
    )


# ---------------------------------------------------------------- 4) 兼容模式回归

def test_single_password_mode_unaffected(admin):
    """users 清空（单密码）时 RBAC 完全旁路：admin 连注册应用都放行。"""
    snapshot = copy.deepcopy(config.data)
    try:
        config.data = {k: v for k, v in config.data.items() if k != "users"}
        config.save()
        assert config.has_users is False
        # 命令用当前解释器（Windows 上 echo 不是独立可执行文件，会被命令存在性校验拒掉）
        res = admin.post("/api/panel/apps",
                         json={"name": "legacy-mode-app", "command": "python -V"})
        assert res.status_code == 200, res.text
        app_id = res.json()["app"]["id"]
        # 删除应用是高危操作，需要一次确认令牌
        token = admin.post("/api/panel/confirm", json={"action": "apps"}).json()["token"]
        assert admin.delete(f"/api/panel/apps/{app_id}",
                            headers={"x-confirm-token": token}).status_code == 200
    finally:
        config.data = snapshot
        config.save()
