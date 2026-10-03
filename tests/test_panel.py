"""面板核心行为测试：鉴权、双模式门禁、日志白名单（P0 回归）、Agent 令牌、下载守护。

测试按文件内定义顺序执行，前面的用例把面板置为公网模式，后面的用例切到内网模式，
最后的 finalizer 恢复公网模式。
"""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

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
