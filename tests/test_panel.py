"""面板核心行为测试：鉴权、双模式门禁、日志白名单（P0 回归）、Agent 令牌、下载守护。

测试按文件内定义顺序执行，前面的用例把面板置为公网模式，后面的用例切到内网模式，
最后的 finalizer 恢复公网模式。
"""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path

import psutil
import pytest
from fastapi.testclient import TestClient

from app import config as config_mod
from app.main import app

PASSWORD = "test-password-123"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def authed(client):
    """完成首次设置密码并保持登录会话。"""
    r = client.post("/api/auth/setup", json={"password": PASSWORD})
    assert r.status_code == 200, r.text
    return client


# ---------- 未登录 / 基础 ----------

def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert "version" in r.json()


def test_unauthenticated_rejected(client):
    r = client.get("/api/system/info")
    assert r.status_code == 401
    r = client.get("/api/logs/sources")
    assert r.status_code == 401


def test_security_headers(client):
    r = client.get("/healthz")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    r = client.get("/api/auth/status")
    assert r.headers["Cache-Control"] == "no-store"


def test_api_docs_not_exposed(client):
    assert client.get("/docs").status_code in (404, 307)
    assert client.get("/openapi.json").status_code == 404


# ---------- 登录与防爆破 ----------

def test_login_lockout_and_xff(authed):
    # 5 次错误触发锁定；每次换 XFF 伪造来源，计数不被重置（trust_proxy 默认关闭）
    for i in range(5):
        r = authed.post("/api/auth/login", json={"password": "wrong"},
                        headers={"X-Forwarded-For": f"10.9.9.{i}"})
        assert r.status_code == 401
    r = authed.post("/api/auth/login", json={"password": "wrong"},
                    headers={"X-Forwarded-For": "10.9.9.200"})
    assert r.status_code == 429  # 未被 XFF 绕过，触发锁定
    r = authed.post("/api/auth/login", json={"password": PASSWORD})
    assert r.status_code == 429
    # 等锁定期过后正常登录，恢复后续用例
    deadline = time.time() + 70
    while time.time() < deadline:
        r = authed.post("/api/auth/login", json={"password": PASSWORD})
        if r.status_code == 200:
            break
        time.sleep(2)
    assert r.status_code == 200


# ---------- 公网模式（只读）门禁 ----------

def test_public_mode_blocks_internal_views(authed):
    r = authed.get("/api/files/roots")
    assert r.status_code == 403
    r = authed.post("/api/terminal/exec", json={"command": "echo hi"})
    assert r.status_code == 403
    r = authed.post("/api/system/power", json={"action": "reboot", "confirm": "CONFIRM"})
    assert r.status_code == 403
    r = authed.get("/api/apps")
    assert r.status_code == 403


def test_public_mode_log_whitelist_blocks_sensitive_paths(authed, tmp_path):
    """P0 回归：root 运行时公网模式也只允许读日志白名单内的文件。"""
    for probe in ("/etc/shadow", "/etc/serverpanel/config.json", "/var/log/../../etc/shadow"):
        r = authed.get("/api/logs/file", params={"path": probe})
        assert r.status_code == 403, f"{probe} 不应可读"
        r = authed.get("/api/logs/tail", params={"path": probe})
        assert r.status_code == 403, f"{probe} 不应可读"


def test_public_mode_log_whitelist_allows_configured_dirs(authed, tmp_path):
    config_mod.config.data["log_dirs"] = [str(tmp_path)]
    config_mod.config.save()
    try:
        target = tmp_path / "app.log"
        target.write_text("hello log", encoding="utf-8")
        r = authed.get("/api/logs/file", params={"path": str(target)})
        assert r.status_code == 200
        assert "hello log" in r.json()["content"]
        # 白名单外仍然拒绝
        outside = tmp_path.parent / "outside.log"
        outside.write_text("x", encoding="utf-8")
        r = authed.get("/api/logs/file", params={"path": str(outside)})
        assert r.status_code == 403
    finally:
        config_mod.config.data.pop("log_dirs", None)
        config_mod.config.save()


def test_log_symlink_escape_blocked(authed, tmp_path):
    """白名单目录内的符号链接指向外部时必须被 realpath 拦下（POSIX）。"""
    if os.name != "posix":
        pytest.skip("符号链接测试仅 POSIX")
    config_mod.config.data["log_dirs"] = [str(tmp_path)]
    config_mod.config.save()
    try:
        secret = tmp_path.parent / "secret-data.txt"
        secret.write_text("secret", encoding="utf-8")
        link = tmp_path / "evil.log"
        if link.exists() or link.is_symlink():
            link.unlink()
        try:
            os.symlink(secret, link)
        except OSError:
            pytest.skip("无法创建符号链接（权限不足）")
        r = authed.get("/api/logs/file", params={"path": str(link)})
        assert r.status_code == 403
    finally:
        config_mod.config.data.pop("log_dirs", None)
        config_mod.config.save()


# ---------- 内网模式 ----------

@pytest.fixture()
def internal_mode():
    config_mod.config.set_mode(config_mod.MODE_INTERNAL)
    yield
    config_mod.config.set_mode(config_mod.MODE_PUBLIC)


def test_internal_mode_unlocks_views(authed, internal_mode):
    r = authed.get("/api/files/roots")
    assert r.status_code == 200
    # 非 POSIX 平台（本地开发/测试）没有 pty，终端接口应优雅返回 501 而不是 500
    from app.routes.terminal_routes import HAS_PTY
    r = authed.get("/api/terminal/info")
    assert r.status_code == (200 if HAS_PTY else 501)


@pytest.fixture()
def anon():
    """不带任何会话 Cookie 的客户端，用于验证纯令牌身份。"""
    return TestClient(app)


def test_exec_with_agent_token(authed, anon, internal_mode):
    token = config_mod.config.issue_agent_token("test-agent-token-123456")
    assert token == "test-agent-token-123456"
    r = authed.post("/api/terminal/exec", json={"command": "echo ok"},
                    headers={"X-Agent-Token": token})
    assert r.status_code == 200
    body = r.json()
    assert body["code"] == 0
    assert "ok" in body["stdout"]

    # 无会话 + 无效令牌 → 401（不能只凭一个错误令牌通过）
    r = anon.post("/api/terminal/exec", json={"command": "echo hi"},
                  headers={"X-Agent-Token": "wrong-token-0000000000"})
    assert r.status_code == 401
    # 无会话 + 无任何凭据 → 401
    r = anon.post("/api/terminal/exec", json={"command": "echo hi"})
    assert r.status_code == 401


def test_exec_timeout_returns_clean_error(authed, internal_mode):
    """命令超时必须返回 code=-1 的干净结果，而不是 500（回归：超时杀进程竞态）。"""
    import sys
    if sys.platform == "win32":
        hang = "python -c \"import time; time.sleep(8)\""
    else:
        hang = "sleep 8"
    r = authed.post("/api/terminal/exec", json={"command": hang, "timeout": 2})
    assert r.status_code == 200
    body = r.json()
    assert body["code"] == -1
    assert "超时" in body["stderr"]


def test_agent_token_dead_in_public_mode(anon):
    """不进入内网模式：即使持有有效令牌也必须 403。"""
    token = config_mod.config.agent_token
    if not token:
        token = config_mod.config.issue_agent_token()
    r = anon.post("/api/terminal/exec", json={"command": "echo hi"},
                  headers={"X-Agent-Token": token})
    assert r.status_code == 403


# ---------- 文件下载保护 ----------

def test_download_blocks_protected_dirs(authed, internal_mode):
    # 文件系统根：任何平台都拒绝打包（Windows 下 "/" 解析为当前盘符根）
    r = authed.get("/api/files/download", params={"path": "/"})
    assert r.status_code == 400
    if os.name == "posix":
        r = authed.get("/api/files/download", params={"path": "/etc"})
        assert r.status_code == 400


def test_download_single_file(authed, internal_mode, tmp_path):
    target = tmp_path / "dl.txt"
    target.write_text("download-me", encoding="utf-8")
    r = authed.get("/api/files/download", params={"path": str(target)})
    assert r.status_code == 200
    assert "download-me" in r.content.decode("utf-8")


# ---------- 临时打包目录清扫 ----------

def test_cleanup_stale_archives(tmp_path, monkeypatch):
    from app.routes import file_routes

    monkeypatch.setattr(file_routes.tempfile, "gettempdir", lambda: str(tmp_path))
    stale = tmp_path / (file_routes.ARCHIVE_PREFIX + "stale")
    fresh = tmp_path / (file_routes.ARCHIVE_PREFIX + "fresh")
    stale.mkdir()
    fresh.mkdir()
    old = time.time() - file_routes.ARCHIVE_STALE_SECONDS - 10
    os.utime(stale, (old, old))
    file_routes.cleanup_stale_archives()
    assert not stale.exists()
    assert fresh.exists()


# ---------- 管理模块纯逻辑 ----------

def test_metrics_degrades_when_io_counters_blocked(monkeypatch):
    """Android/PRoot 屏蔽 /sys/block 时，采样必须降级而不是炸掉整个采样器。"""
    import psutil

    from app import metrics as metrics_mod

    def denied(*args, **kwargs):
        raise PermissionError(13, "Permission denied: '/sys/block'")

    monkeypatch.setattr(psutil, "disk_io_counters", denied)
    monkeypatch.setattr(psutil, "net_io_counters", denied)
    s = metrics_mod.metrics.sample()
    assert s["io_limited"] is True
    assert s["disk"]["disk_read"] == 0
    assert s["net"]["net_recv"] == 0
    assert s["cpu"] >= 0 and "mem" in s


def test_sessions_survive_restart(authed):
    """会话落盘：新起的 SessionStore 实例（等价进程重启后）能恢复登录态。"""
    from app.auth import SessionStore, sessions

    token = next(iter(sessions._sessions), None)
    assert token, "应存在至少一个活动会话"

    revived = SessionStore()
    assert revived.validate(token) is not None


def test_sessions_file_permissions(authed):
    import stat as stat_mod

    from app.config import config as cfg

    f = Path(cfg.path).parent / "sessions.json"
    if os.name != "posix":
        pytest.skip("POSIX 权限位")
    assert f.exists()
    assert stat_mod.S_IMODE(f.stat().st_mode) & 0o777 == 0o600


def test_healthz_has_build_field(client):
    r = client.get("/healthz")
    assert "build" in r.json()


def test_self_update_blocked_in_public_mode(authed, monkeypatch):
    """公网模式拒绝自升级；内网模式只允许真正 spawn（用假 Popen 验证参数）。"""
    from app.routes import system_routes

    captured = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return type("PopenStub", (), {"pid": 0})()  # 占位，端点不使用返回值

    monkeypatch.setattr(system_routes.subprocess, "Popen", fake_popen)

    # 内网模式
    config_mod.config.set_mode(config_mod.MODE_INTERNAL)
    try:
        r = authed.post("/api/system/self-update", json={})
        assert r.status_code == 200
        assert "start_new_session" in captured["kwargs"]
        assert "--update" in captured["cmd"]
        # 自定义 ref 透传
        authed.post("/api/system/self-update", json={"ref": "origin/dev"})
        assert "origin/dev" in captured["cmd"]
        # 更新进程必须以生命周期标志运行，确保 _panel_pids 不会把它误杀
        assert any(a.startswith("--") for a in captured["cmd"])
    finally:
        config_mod.config.set_mode(config_mod.MODE_PUBLIC)
    # 公网模式
    r = authed.post("/api/system/self-update", json={})
    assert r.status_code == 403


def test_pid_alive():
    from app import manage

    if os.name != "posix":
        pytest.skip("进程存活探测依赖 /proc，仅 POSIX")
    assert manage._pid_alive(os.getpid())
    assert not manage._pid_alive(999999999)


def test_metadata_roundtrip(tmp_path, monkeypatch):
    from app import manage

    fake = tmp_path / "cfg" / "config.json"
    fake.parent.mkdir(parents=True)
    monkeypatch.setattr(config_mod.config, "path", fake)
    manage._save_metadata(tmp_path, "0.0.0.0", 9999)
    meta = manage._load_metadata()
    assert meta["port"] == 9999
    assert meta["app_dir"] == str(tmp_path)


def test_supervisor_script_content(tmp_path):
    """守护脚本必须带单实例锁与 pidfile（防 cron/Boot 双拉起）。"""
    from app import manage

    script = manage.write_supervisor(tmp_path, "0.0.0.0", 8787)
    content = script.read_text("utf-8")
    assert "flock -n 9" in content
    assert manage.PID_NAME in content
    assert "while :" in content
    if os.name == "posix":
        assert os.stat(script).st_mode & stat.S_IXUSR


# ---------- 常驻应用（P0） ----------

def _tick_command(directory) -> str:
    """生成一条"持续输出心跳"的跨平台命令，用于托管应用的冒烟测试。"""
    script = Path(directory) / "tick.py"
    script.write_text(
        "import time\nfor i in range(600):\n    print('tick', i, flush=True)\n    time.sleep(0.5)\n",
        encoding="utf-8",
    )
    return f"{Path(sys.executable).as_posix()} {script.as_posix()}"


def test_public_mode_blocks_apps_and_tasks(authed):
    """公网（只读）模式下，托管应用与常用操作必须整体 403——它们等价于 root shell。"""
    assert authed.get("/api/panel/apps").status_code == 403
    assert authed.get("/api/panel/tasks").status_code == 403
    assert authed.post("/api/panel/apps", json={"name": "x", "command": "ls"}).status_code == 403
    assert authed.post("/api/panel/tasks/sys-snapshot/run", json={}).status_code == 403
    assert authed.get("/api/snippets").status_code == 403


def test_app_definition_validation(authed, internal_mode, tmp_path):
    """注册校验：坏名字 / 空命令 / 不存在的目录 / 递归启动面板自身都必须被拒绝。"""
    bad = [
        {"name": "bad name!", "command": "echo hi"},
        {"name": "ok-name", "command": "   "},
        {"name": "ok-name", "command": "echo hi", "cwd": str(tmp_path / "not-exists")},
        {"name": "ok-name", "command": "echo hi", "restart": "sometimes"},
        {"name": "ok-name", "command": "echo hi", "max_restarts": 999},
        {"name": "ok-name", "command": "python -m app.main --host 0.0.0.0"},
    ]
    for payload in bad:
        r = authed.post("/api/panel/apps", json=payload)
        assert r.status_code == 400, f"{payload} 应被拒绝，实际 {r.status_code} {r.text}"
    # 命令不存在 → 400（而不是注册成功后一启动就崩）
    r = authed.post("/api/panel/apps", json={"name": "ghost-bin", "command": "no-such-binary-xyz"})
    assert r.status_code == 400


def test_app_lifecycle_and_logs(authed, internal_mode, tmp_path):
    """注册 → 试运行 → 启动 → 读日志 → 停止 → 删除，全链路走 API。"""
    payload = {
        "name": "test-tick",
        "command": _tick_command(tmp_path),
        "cwd": str(tmp_path),
        "restart": "on-failure",
        "max_restarts": 3,
        "restart_delay": 0.5,
        "description": "回归测试用",
    }
    r = authed.post("/api/panel/apps", json=payload)
    assert r.status_code == 200, r.text
    app_id = r.json()["app"]["id"]
    assert r.json()["app"]["runtime"]["status"] == "stopped"   # 注册不自动启动

    # 重名 → 409（提示去编辑已有的）
    assert authed.post("/api/panel/apps", json=payload).status_code == 409

    # 试运行：能抓到输出且进程在观察期内活着
    r = authed.post(f"/api/panel/apps/{app_id}/probe", json={"seconds": 2})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["survived"] is True, body
    assert "tick" in body["output"]

    r = authed.post(f"/api/panel/apps/{app_id}/start", json={})
    assert r.status_code == 200, r.text
    pid = r.json()["app"]["runtime"]["pid"]
    assert pid, "启动后应返回 PID"

    time.sleep(1.6)
    r = authed.get(f"/api/panel/apps/{app_id}/logs", params={"lines": 50})
    assert r.status_code == 200, r.text
    log_data = r.json()
    content = log_data["content"]
    assert "tick" in content, f"托管应用的输出没有被收集：{content!r} memory={log_data.get('memory')!r}"
    offset = log_data["next_offset"]
    time.sleep(1.2)
    delta = authed.get(f"/api/panel/apps/{app_id}/logs", params={"offset": offset}).json()
    assert "tick" in delta["content"], "增量读取应拿到新输出"

    # 列表里能看到运行状态与 PID
    listed = authed.get("/api/panel/apps").json()["apps"]
    row = next(a for a in listed if a["id"] == app_id)
    assert row["runtime"]["status"] == "running"
    assert row["runtime"]["pid"] == pid

    # 运行中不允许直接删除
    r = authed.delete(f"/api/panel/apps/{app_id}")
    assert r.status_code == 400, r.text

    # PID 1 之类的保护不适用于这里，但停止必须真正结束进程
    r = authed.post(f"/api/panel/apps/{app_id}/stop", json={})
    assert r.status_code == 200
    assert r.json()["app"]["runtime"]["status"] == "stopped"
    deadline = time.time() + 5
    while time.time() < deadline and psutil.pid_exists(pid):
        time.sleep(0.2)
    assert not psutil.pid_exists(pid), "停止后进程必须真的退出"

    # 清空日志 + 删除
    assert authed.delete(f"/api/panel/apps/{app_id}/logs").status_code == 200
    assert authed.get(f"/api/panel/apps/{app_id}/logs").json()["content"] == ""
    assert authed.delete(f"/api/panel/apps/{app_id}").status_code == 200
    assert authed.get(f"/api/panel/apps/{app_id}").status_code == 400  # 已不存在


def test_managed_process_is_isolated_from_panel_group(authed, internal_mode, tmp_path):
    """托管进程必须独立成组：否则面板升级 / 守护重启会连带杀死所有应用。"""
    if os.name != "posix":
        pytest.skip("进程组语义仅 POSIX")
    r = authed.post("/api/panel/apps", json={
        "name": "isolation-check",
        "command": _tick_command(tmp_path),
        "cwd": str(tmp_path),
    })
    app_id = r.json()["app"]["id"]
    pid = authed.post(f"/api/panel/apps/{app_id}/start", json={}).json()["app"]["runtime"]["pid"]
    try:
        assert os.getpgid(pid) != os.getpgid(os.getpid()), "托管进程不能与面板同组"
    finally:
        authed.post(f"/api/panel/apps/{app_id}/stop", json={})
        authed.delete(f"/api/panel/apps/{app_id}")


def test_registry_file_is_atomic_and_private(authed, internal_mode, tmp_path):
    """注册表写盘必须原子替换且权限 0600（面板与 CLI 可能并发写）。"""
    from app.apps import supervisor

    r = authed.post("/api/panel/apps", json={
        "name": "registry-check",
        "command": _tick_command(tmp_path),
        "cwd": str(tmp_path),
    })
    app_id = r.json()["app"]["id"]
    path = Path(supervisor.registry.path)
    try:
        assert path.exists()
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) & 0o777 == 0o600
        # 没有残留的 .tmp 文件
        leftovers = list(path.parent.glob(f"{path.name}.*.tmp"))
        assert leftovers == [], f"残留临时文件：{leftovers}"
    finally:
        authed.delete(f"/api/panel/apps/{app_id}")


# ---------- 常用操作（P1） ----------

def test_task_params_block_shell_injection(authed, internal_mode):
    """任务参数只允许白名单字符，注入类输入必须被拒（而不是被静默转义）。"""
    from app import tasks as tasks_mod

    task = tasks_mod.task_by_id("net-ping")
    assert task is not None
    for bad in ("1.1.1.1; rm -rf /", "$(id)", "`id`", "a|b", "'", "1.1.1.1 && whoami"):
        with pytest.raises(ValueError):
            tasks_mod.render(task, {"target": bad})
    assert "1.1.1.1" in tasks_mod.render(task, {"target": "1.1.1.1"})

    r = authed.post("/api/panel/tasks/net-ping/run", json={"params": {"target": "1.1.1.1; id"}})
    assert r.status_code == 400


def test_task_list_and_run(authed, internal_mode):
    data = authed.get("/api/panel/tasks").json()
    ids = {t["id"] for t in data["tasks"]}
    assert {"sys-snapshot", "disk-inodes", "panel-status"} <= ids
    assert all("title" in t and "group" in t for t in data["tasks"])

    # 用一条跨平台命令验证"任务真的被执行了"（内置任务是 Linux 向的，跑不了不代表机制不通）
    r = authed.post("/api/panel/tasks/sys-snapshot/run", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["title"] == "资源总览"
    assert body["command"] and "uptime" in body["command"]
    assert isinstance(body["code"], int)

    # 执行记录可查、可清空
    recent = authed.get("/api/panel/tasks/recent").json()["recent"]
    assert any(item["task_id"] == "sys-snapshot" for item in recent)
    assert authed.delete("/api/panel/tasks/recent").status_code == 200
    assert authed.get("/api/panel/tasks/recent").json()["recent"] == []


def test_unknown_task_returns_404(authed, internal_mode):
    assert authed.post("/api/panel/tasks/no-such-task/run", json={}).status_code == 404


# ---------- 代码片段（P2） ----------

def test_snippets_render_current_endpoint(authed, internal_mode):
    data = authed.get("/api/snippets").json()
    assert data["total"] > 5
    assert "Agent 接入" in data["categories"]
    first = data["snippets"][0]
    assert "/api/terminal/exec" in first["code"]
    assert "{{" not in first["code"], "占位符必须全部被渲染掉"
    # 默认不回显真实令牌
    token = config_mod.config.agent_token
    if token:
        assert token not in first["code"]
        assert "YOUR_TOKEN" in first["code"]
    # 显式 reveal 才填入令牌
    revealed = authed.get("/api/snippets", params={"reveal_token": 1}).json()
    if token:
        assert token in revealed["snippets"][0]["code"]
        assert revealed["token_revealed"] is True
    # 分类与关键词过滤
    only = authed.get("/api/snippets", params={"category": "Docker"}).json()
    assert only["snippets"] and all(s["category"] == "Docker" for s in only["snippets"])
    assert authed.get("/api/snippets", params={"q": "docker"}).json()["total"] >= 1
    assert authed.get("/api/snippets/no-such-snippet").status_code == 404


def test_apps_cli_list_runs(capsys):
    """CLI 兜底入口必须能在面板不可用时工作（只读注册表，不依赖服务进程）。"""
    from app import manage

    assert manage.cmd_apps(Path("."), ["list"]) == 0
    out = capsys.readouterr().out
    assert "注册表" in out

    assert manage.cmd_recipe(["list"]) == 0
    out = capsys.readouterr().out
    assert "sys-snapshot" in out
    assert manage.cmd_recipe(["run", "no-such-task"]) == 1
    assert manage.cmd_apps(Path("."), ["start", "no-such-app"]) == 1
    # 参数注入在 CLI 侧同样被拦下
    assert manage.cmd_recipe(["run", "net-ping", "target=1.1.1.1; id"]) == 1


def test_shutdown_stops_managed_apps(tmp_path):
    """面板停止时必须收走自己拉起的应用：否则会留下无人认领的孤儿进程。"""
    import asyncio

    from app.apps import Registry, normalize_definition, Supervisor

    registry = Registry(tmp_path / "apps.json")
    sup = Supervisor(registry, tmp_path / "logs")
    definition = normalize_definition({
        "name": "shutdown-check",
        "command": _tick_command(tmp_path),
        "cwd": str(tmp_path),
        "restart": "always",          # 即便策略是 always，面板退出也必须停干净
        "restart_delay": 0.5,
    })
    registry.add(definition)

    async def scenario() -> int:
        await sup.serve()
        started = await sup.start(definition["id"])
        pid = started["runtime"]["pid"]
        assert pid
        await asyncio.sleep(0.6)
        await sup.shutdown()
        return pid

    pid = asyncio.run(scenario())
    deadline = time.time() + 5
    while time.time() < deadline and psutil.pid_exists(pid):
        time.sleep(0.2)
    assert not psutil.pid_exists(pid), "面板退出后托管应用必须一并结束（不能留孤儿）"


def test_panel_pids_excludes_lifecycle_commands(tmp_path, monkeypatch):
    """`serverpanel --apps list` 这类运维命令不能被当成面板服务进程误杀。

    面板 Agent 通道里执行的 `--restart` / `--apps` 与服务进程命令行高度相似，
    `_panel_pids` 靠生命周期标志区分，缺了区分就会"重启命令把自己杀掉"。
    """
    from app import manage

    if not os.path.isdir("/proc"):
        pytest.skip("_panel_pids 依赖 /proc，仅 POSIX")

    python = str(tmp_path / ".venv" / "bin" / "python")
    argv_map = {
        4242: [python, "-m", "app.main", "--host", "0.0.0.0"],
        4243: [python, "-m", "app.main", "--restart"],
        4244: [python, "-m", "app.main", "--apps", "list"],
        4245: ["/bin/sh", "-c", "echo hi"],
    }
    monkeypatch.setattr(manage, "_read_cmdline", lambda pid: argv_map.get(pid, []))
    monkeypatch.setattr(
        manage.os, "listdir",
        lambda path: ["1"] + [str(pid) for pid in argv_map] + ["self"],
    )
    pids = manage._panel_pids(tmp_path)
    assert pids == [4242], f"只应识别真正的服务进程，实际 {pids}"

    started = {}
    monkeypatch.setattr(manage, "_systemd_available", lambda: False)
    monkeypatch.setattr(manage, "_start_supervisor", lambda target_dir: started.setdefault("ok", True))
    manage._restart_service(tmp_path)
    # 已经找到服务进程时不应再拉起守护
    assert not started


# ---------- 快捷设置：prefs 模型 ----------

def test_prefs_defaults_and_validation():
    """默认值可读；越界/未知键必须被拒（而不是静默兜底）。"""
    from app.prefs import PrefsError, prefs

    values = prefs.all()
    assert values["session.ttl_hours"] == 12
    assert values["logs.app_max_bytes"] == 4 * 1024 * 1024
    assert values["autostart.apps_enabled"] is True

    for bad in (
        {"session.ttl_hours": 0},
        {"session.ttl_hours": 999},
        {"listen.port": 80},
        {"listen.port": 70000},
        {"logs.panel_max_bytes": 1024},
        {"security.max_failures": 1},
        {"security.allowed_origins": ["ftp://x"]},
        {"security.allowed_origins": ["http://ok", "nonsense"]},
        {"security.log_dirs": ["relative/dir"]},
        {"security.log_dirs": ["/"]},
        {"security.log_dirs": ["/etc/shadow"]},
        {"security.log_dirs": []},
        {"unknown.key": 1},
        {},
    ):
        with pytest.raises(PrefsError):
            prefs.update(bad)

    # 合法值写入后可读回，并同步到顶层 legacy 键
    result = prefs.update({"security.trust_proxy": True, "session.ttl_hours": 6})
    assert result["changed"]["session.ttl_hours"] == 6
    assert prefs.session_ttl_seconds() == 6 * 3600
    assert config_mod.config.trust_proxy is True
    assert config_mod.config.data["trust_proxy"] is True
    # 恢复，避免影响后续用例
    prefs.update({"security.trust_proxy": False, "session.ttl_hours": 12})


def test_prefs_survives_corrupted_values():
    """手工把配置改坏时回落到默认值，不能让面板起不来。"""
    from app.prefs import prefs

    config_mod.config.data.setdefault("prefs", {})["session"] = {"ttl_hours": "oops"}
    config_mod.config.save()
    prefs._invalidate()
    assert prefs.get("session.ttl_hours") == 12


def test_log_whitelist_self_check_blocks_dangerous_dirs(tmp_path):
    """C 组自检：写入白名单前必须确认敏感路径仍被拒。"""
    from app.boot import set_pref_with_check
    from app.prefs import PrefsError, prefs

    for bad in ("/", "/etc", "/root", "/usr"):
        with pytest.raises(PrefsError):
            set_pref_with_check({"security.log_dirs": [bad]})

    safe = str(tmp_path)
    result = set_pref_with_check({"security.log_dirs": [safe]})
    try:
        assert result["changed"]["security.log_dirs"] == [os.path.realpath(safe)]
        assert config_mod.config.log_dirs == [os.path.realpath(safe)]
    finally:
        prefs.update({"security.log_dirs": ["/var/log"] if os.path.isdir("/var/log") else [safe]})


def test_public_mode_blocks_quick_settings(authed):
    """快捷设置全部接口在公网只读模式下必须 403。"""
    for path in ("/api/panel/boot", "/api/panel/prefs", "/api/panel/boot/guardian",
                 "/api/panel/timezone", "/api/panel/listen", "/api/panel/config/backups"):
        assert authed.get(path).status_code == 403, path
    assert authed.put("/api/panel/prefs", json={"values": {"session.ttl_hours": 1}}).status_code == 403
    assert authed.post("/api/panel/boot/cron", json={}).status_code == 403
    assert authed.post("/api/panel/logs/trim", json={}).status_code == 403
    assert authed.get("/api/panel/config/export").status_code == 403
    assert authed.post("/api/panel/config/backup", json={}).status_code == 403


def test_boot_probe_reports_chain(authed, internal_mode, monkeypatch, tmp_path):
    """体检必须给出 5 截链路的结论，且结论随探测结果变化。"""
    from app import boot as boot_mod

    data = authed.get("/api/panel/boot").json()
    assert data["verdict"] in ("ok", "warn", "broken")
    ids = {link["id"] for link in data["links"]}
    assert {"device-autostart", "guardian", "panel", "apps", "device-power"} <= ids
    assert data["termux_script"].startswith("#!/data/data/com.termux/files/usr/bin/sh")
    assert "panel-supervisor.sh" in data["termux_script"]

    # 构造"容器 + 无 crontab"：应判为需手工并给出 Termux 处方
    # （用自备的 app_dir，不依赖仓库工作区里是否恰好存在守护脚本）
    monkeypatch.setattr(boot_mod, "detect_platform", lambda: {
        "init": "init", "systemd": False, "kernel": "Linux PRoot", "proot": True,
        "container": True, "cron": False, "termux": {"present": False}, "python": "python3",
    })
    monkeypatch.setattr(boot_mod, "cron_status",
                        lambda: {"available": False, "configured": False, "lines": [], "total_lines": 0})
    fake_dir = tmp_path / "deployed"
    fake_dir.mkdir()
    (fake_dir / boot_mod.SUPERVISOR_NAME).write_text("#!/bin/sh\necho fake\n", "utf-8")
    broken = boot_mod.probe(app_dir=fake_dir, health={"ok": True, "version": "1.1.0"})
    assert broken["verdict"] == "broken"
    device = next(link for link in broken["links"] if link["id"] == "device-autostart")
    assert device["state"] == "manual"
    assert any(a["id"] == "copy-termux-script" for a in device["actions"])

    # 构造"crontab 已配置"：这一截应变绿
    monkeypatch.setattr(boot_mod, "cron_status", lambda: {
        "available": True, "configured": True,
        "lines": ["@reboot /root/aegis/AegisServerPanel/panel-supervisor.sh &"], "total_lines": 1,
    })
    fixed = boot_mod.probe(app_dir=fake_dir, health={"ok": True, "version": "1.1.0"})
    device = next(link for link in fixed["links"] if link["id"] == "device-autostart")
    # 该环境若同时存在 systemd 单元，会优先走 systemd 分支；两种都算"通"
    assert device["state"] == "ok"

    # 连守护脚本都没有：必须判 broken 并给出重装守护的处方
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    missing = boot_mod.probe(app_dir=empty_dir, health={"ok": True, "version": "1.1.0"})
    device = next(link for link in missing["links"] if link["id"] == "device-autostart")
    assert device["state"] == "broken"
    assert any(a["id"] == "guardian-repair" for a in device["actions"])


class _CrontabStub:
    """模拟 crontab 命令：``-l`` 读，``<file>`` 写；可注入写失败与读回异常。"""

    def __init__(self, initial: str = "", fail_write: bool = False,
                 stale_readback: bool = False) -> None:
        self.content = initial
        self.fail_write = fail_write
        self.stale_readback = stale_readback
        self.writes = 0

    def __call__(self, cmd, **kwargs):
        import subprocess as sp

        if len(cmd) >= 2 and cmd[1] == "-l":
            if self.stale_readback and self.writes >= 1:
                return sp.CompletedProcess(cmd, 0, "stale content without tag\n", "")
            if self.content:
                return sp.CompletedProcess(cmd, 0, self.content, "")
            return sp.CompletedProcess(cmd, 1, "", "no crontab for root")
        if self.fail_write:
            return sp.CompletedProcess(cmd, 1, "", "disk on fire")
        self.content = Path(cmd[1]).read_text("utf-8")
        self.writes += 1
        return sp.CompletedProcess(cmd, 0, "", "")


def _prepare_cron(monkeypatch, app_dir: Path) -> None:
    from app import boot as boot_mod

    (app_dir / boot_mod.SUPERVISOR_NAME).write_text("#!/bin/sh\necho fake\n", "utf-8")
    monkeypatch.setattr(boot_mod.shutil, "which",
                        lambda name: "/usr/bin/crontab" if name == "crontab" else None)
    monkeypatch.setattr(boot_mod.os, "access", lambda path, mode: True)


def test_cron_install_is_idempotent_and_preserves_other_lines(monkeypatch, tmp_path):
    """写入 @reboot：保留用户其它定时任务、重复安装不产生第二行。"""
    from app import boot as boot_mod

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    _prepare_cron(monkeypatch, app_dir)
    stub = _CrontabStub(initial="0 3 * * * /usr/bin/keep-me.sh\n")
    monkeypatch.setattr(boot_mod.subprocess, "run", stub)
    monkeypatch.setattr(boot_mod, "_backup_crontab", lambda content: None)

    result = boot_mod.cron_install(app_dir)
    assert result["ok"] is True
    assert "keep-me.sh" in stub.content, "不能动用户已有的定时任务"
    assert len([ln for ln in stub.content.splitlines() if boot_mod.CRON_TAG in ln]) == 1

    boot_mod.cron_install(app_dir)  # 幂等
    assert len([ln for ln in stub.content.splitlines() if boot_mod.CRON_TAG in ln]) == 1
    assert stub.content.count("keep-me.sh") == 1


def test_cron_install_rolls_back_on_failure(monkeypatch, tmp_path):
    """写失败 / 读回校验失败都必须回滚到原内容，绝不留半截 crontab。"""
    from app import boot as boot_mod

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    _prepare_cron(monkeypatch, app_dir)

    original = "0 3 * * * keep-me.sh\n"
    backups: list[str] = []

    def backup(content):
        if not content.strip():
            return None
        path = tmp_path / f"crontab.backup.{len(backups)}"
        path.write_text(content, "utf-8")
        backups.append(content)
        return path

    monkeypatch.setattr(boot_mod, "_backup_crontab", backup)

    # 场景 A：写直接失败
    failing = _CrontabStub(initial=original, fail_write=True)
    monkeypatch.setattr(boot_mod.subprocess, "run", failing)
    with pytest.raises(boot_mod.BootError):
        boot_mod.cron_install(app_dir)
    assert failing.content == original

    # 场景 B：写成功但读回校验失败 → 回滚
    stale = _CrontabStub(initial=original, stale_readback=True)
    monkeypatch.setattr(boot_mod.subprocess, "run", stale)
    with pytest.raises(boot_mod.BootError):
        boot_mod.cron_install(app_dir)
    assert stale.content == original, "读回校验失败后必须把原 crontab 写回去"
    assert backups and backups[-1] == original


def test_cron_install_without_crontab_binary(monkeypatch, tmp_path):
    """没有 crontab 命令时给出明确指引，而不是静默写入一个不会执行的文件。"""
    from app import boot as boot_mod

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / boot_mod.SUPERVISOR_NAME).write_text("#!/bin/sh\n", "utf-8")
    monkeypatch.setattr(boot_mod.shutil, "which", lambda name: None)
    with pytest.raises(boot_mod.BootError) as exc:
        boot_mod.cron_install(app_dir)
    assert "crontab" in str(exc.value)


def test_global_autostart_switch(authed, internal_mode, tmp_path):
    """全局开关关闭后，autostart 应用不会被拉起；显式 start 仍生效。"""
    import asyncio

    from app.apps import Registry, normalize_definition, Supervisor
    from app.prefs import prefs

    registry = Registry(tmp_path / "apps.json")
    sup = Supervisor(registry, tmp_path / "logs")
    definition = normalize_definition({
        "name": "autostart-check",
        "command": _tick_command(tmp_path),
        "cwd": str(tmp_path),
        "autostart": True,
        "restart_delay": 0.5,
    })
    registry.add(definition)

    async def scenario() -> tuple[int | None, int | None]:
        prefs.update({"autostart.apps_enabled": False})
        await sup.serve()
        await asyncio.sleep(2.6)  # 超过 BOOT_DELAY
        after_boot = sup.get(definition["id"])["runtime"]["pid"]

        prefs.update({"autostart.apps_enabled": True})
        explicit = await sup.start(definition["id"])
        return after_boot, explicit["runtime"]["pid"]

    try:
        after_boot, explicit_pid = asyncio.run(scenario())
    finally:
        prefs.update({"autostart.apps_enabled": True})
    assert after_boot is None, "全局开关关闭时不应自动拉起"
    assert explicit_pid, "显式 start 不受全局开关影响"


def test_app_log_limit_from_prefs(tmp_path):
    """日志上限改小后立即生效：写满即轮转为 .1，无需重启。"""
    from app.apps import AppLog
    from app.prefs import prefs

    original = prefs.get("logs.app_max_bytes")
    try:
        prefs.update({"logs.app_max_bytes": 256 * 1024})  # 下限
        log = AppLog(tmp_path / "app.log")               # 不传上限 → 每次读 prefs
        assert log.max_bytes == 256 * 1024
        log.append("x" * 300 * 1024)
        log.append("trigger-rotate\n")
        assert (tmp_path / "app.log.1").exists(), "超过上限必须轮转出 .1"
    finally:
        prefs.update({"logs.app_max_bytes": original})


# ---------- 快捷设置：B2/B3 会话与防爆破参数 ----------

def test_session_ttl_from_prefs(authed, internal_mode):
    """改会话时长：SessionStore 动态读取，新登录的 cookie max-age 同步；旧会话不受影响。"""
    from app.auth import sessions
    from app.prefs import prefs

    original = prefs.get("session.ttl_hours")
    try:
        prefs.update({"session.ttl_hours": 2})
        assert sessions.ttl == 2 * 3600

        r = authed.post("/api/auth/login", json={"password": PASSWORD})
        assert r.status_code == 200
        assert "max-age=7200" in r.headers.get("set-cookie", "").lower()
        # 会话仍有效（改 TTL 不踢已登录会话）
        assert authed.get("/api/auth/status").status_code == 200
    finally:
        prefs.update({"session.ttl_hours": original})
        authed.post("/api/auth/login", json={"password": PASSWORD})


def test_lockout_params_from_prefs(authed, internal_mode):
    """防爆破阈值与锁定时长走 prefs：改小阈值后更少的失败即触发锁定，到期自动解锁。"""
    from app.auth import sessions
    from app.prefs import prefs

    original = (prefs.get("security.max_failures"), prefs.get("security.lockout_seconds"))
    try:
        prefs.update({"security.max_failures": 3, "security.lockout_seconds": 10})
        probe_ip = "10.5.5.5"  # 与其它用例的失败计数隔离
        assert sessions.locked_for(probe_ip) == 0
        for _ in range(3):
            sessions.record_failure(probe_ip)
        locked = sessions.locked_for(probe_ip)
        assert 0 < locked <= 10, "达到新阈值后必须按 prefs 的锁定时长计算"
        time.sleep(10.5)
        assert sessions.locked_for(probe_ip) == 0, "锁定到期应自动解锁"
    finally:
        prefs.update({"security.max_failures": original[0],
                      "security.lockout_seconds": original[1]})


def test_timezone_endpoints_are_safe(authed, internal_mode):
    """时区状态只读可用；非法/不存在的时区在写入前被拒（跨平台安全，不真改机器）。"""
    status = authed.get("/api/panel/timezone").json()
    assert "current" in status
    assert isinstance(status.get("common"), list) and status["common"]

    for bad in ("not a zone!", "Nowhere/Nowhere"):
        r = authed.post("/api/panel/timezone", json={"zone": bad})
        assert r.status_code == 400, bad


# ---------- 快捷设置：D 组 导出 / 导入 / 审计 ----------

def test_config_export_scrubs_secrets(authed, internal_mode):
    """默认导出不含密码哈希与 Agent 令牌；include_secrets=1 才包含。"""
    import io
    import zipfile

    default = authed.get("/api/panel/config/export")
    assert default.status_code == 200
    assert default.headers["content-type"].startswith("application/zip")
    with zipfile.ZipFile(io.BytesIO(default.content)) as bundle:
        assert "config.json" in bundle.namelist()
        exported = json.loads(bundle.read("config.json").decode("utf-8"))
        assert "README.txt" in bundle.namelist()
    assert "password_hash" not in exported
    assert "agent_token" not in exported
    assert exported["mode"] == config_mod.config.mode

    full = authed.get("/api/panel/config/export", params={"include_secrets": "1"})
    with zipfile.ZipFile(io.BytesIO(full.content)) as bundle:
        exported = json.loads(bundle.read("config.json").decode("utf-8"))
    assert "password_hash" in exported, "显式带凭据的导出必须包含密码哈希"


def test_config_import_merges_and_keeps_local_secrets(authed, internal_mode):
    """导入合并：prefs/应用定义生效，但密码哈希与 Agent 令牌始终以本机为准；坏包被拒且配置不变。"""
    import io
    import zipfile

    from app.prefs import prefs

    snapshot = json.loads(json.dumps(config_mod.config.data))  # 深拷贝，用于恢复
    prefs_original = prefs.get("session.ttl_hours")
    try:
        payload = {
            "config.json": {
                "mode": "internal",
                "password_hash": "attacker-hash",
                "agent_token": "stolen-token",
                "prefs": {"session": {"ttl_hours": 3}},
            },
            "apps.json": {"version": 1, "apps": []},
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as bundle:
            for name, data in payload.items():
                bundle.writestr(name, json.dumps(data))
        buffer.seek(0)

        r = authed.post("/api/panel/config/import",
                        files={"file": ("export.zip", buffer.read(), "application/zip")})
        assert r.status_code == 200, r.text
        result = r.json()
        assert "password_hash" in result["kept_secrets"], "本机已有的凭据必须保留"
        assert config_mod.config.data["password_hash"] == snapshot["password_hash"], "本机密码不能被覆盖"
        assert config_mod.config.data.get("agent_token") in (None, snapshot.get("agent_token")), \
            "不能从导入包领养外来凭据"
        assert prefs.get("session.ttl_hours") == 3, "导入的 prefs 应生效"
        assert result["backup"], "导入前必须自动生成就地备份"

        # 坏 zip：400 且配置不变
        before = json.dumps(config_mod.config.data, sort_keys=True)
        bad = authed.post("/api/panel/config/import",
                          files={"file": ("bad.zip", b"not a zip", "application/zip")})
        assert bad.status_code == 400
        assert json.dumps(config_mod.config.data, sort_keys=True) == before
        assert prefs.get("session.ttl_hours") == 3, "拒绝导入时不能动现有配置"
    finally:
        config_mod.config.data = snapshot
        config_mod.config.save()
        prefs._invalidate()
        prefs.update({"session.ttl_hours": prefs_original})


def test_panel_audit_records_writes(authed, internal_mode):
    """写操作必须留下审计记录（时间线接口可查）。"""
    from app.prefs import prefs

    original = prefs.get("session.ttl_hours")
    try:
        # 走 API 而不是直接改 prefs：审计记录在路由层
        r = authed.put("/api/panel/prefs", json={"values": {"session.ttl_hours": 5}})
        assert r.status_code == 200
        recent = authed.get("/api/panel/audit").json()["recent"]
        entry = next((item for item in recent
                      if item.get("kind") == "panel" and item.get("action") == "prefs"), None)
        assert entry is not None, "prefs 修改必须出现在审计时间线"
        assert "session.ttl_hours" in entry["detail"]
        assert entry["time"] > 0
    finally:
        prefs.update({"session.ttl_hours": original})

