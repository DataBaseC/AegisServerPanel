"""1.4.0「安全版」功能回归：TOTP 二次认证、Agent 多令牌作用域、回收站、
统一审计查询、登录锁定持久化、安全中心与会话管理。

这些用例依赖模块内顺序执行（前面的用例可能创建令牌/会话），
但每个用例都自带清理，不向后续用例泄漏状态。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import shutil
import struct
import time

import pytest
from fastapi.testclient import TestClient

from app import config as config_mod
from app import totp as totp_mod
from app.auth import FailureTracker, failures
from app.main import app

PASSWORD = "test-password-123"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def authed(client):
    """完成登录（兼容两种模块顺序：密码已设置 / 未设置）。"""
    r = client.post("/api/auth/setup", json={"password": PASSWORD})
    if r.status_code != 200:
        r = client.post("/api/auth/login", json={"password": PASSWORD})
    assert r.status_code == 200, r.text
    return client


@pytest.fixture()
def internal_mode():
    config_mod.config.set_mode(config_mod.MODE_INTERNAL)
    yield
    config_mod.config.set_mode(config_mod.MODE_PUBLIC)


@pytest.fixture()
def anon():
    return TestClient(app)


def _code(secret: str, drift: int = 0) -> str:
    """按服务器同样的算法算当前动态码（drift 用于制造错误码）。"""
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    counter = int(time.time()) // 30 + drift
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 1_000_000).zfill(6)


def _exec(anon, token, command):
    return anon.post("/api/terminal/exec", json={"command": command},
                     headers={"X-Agent-Token": token})


# ---------- TOTP 二次认证 ----------


def test_totp_full_lifecycle(authed, internal_mode):
    # 初始状态（可能被本模块其他用例改过，先确保关闭）
    if config_mod.config.totp_enabled:
        authed.post("/api/auth/totp/disable", json={"password": PASSWORD})
    r = authed.get("/api/auth/totp/status")
    assert r.json()["enabled"] is False

    # 生成密钥（未启用）
    r = authed.post("/api/auth/totp/setup", json={})
    assert r.status_code == 200
    secret = r.json()["secret"]
    assert config_mod.config.totp_secret == secret
    assert config_mod.config.totp_enabled is False

    # 错误动态码不能启用（取当前码 +2，避开 ±1 步漂移窗口）
    r = authed.post("/api/auth/totp/enable", json={"code": _code(secret, drift=2)})
    assert r.status_code == 400
    assert config_mod.config.totp_enabled is False

    # 正确动态码启用，返回 10 个恢复码
    r = authed.post("/api/auth/totp/enable", json={"code": _code(secret)})
    assert r.status_code == 200, r.text
    recovery = r.json()["recovery_codes"]
    assert len(recovery) == 10
    assert config_mod.config.totp_enabled is True

    # 登录必须带二次验证码
    r = authed.post("/api/auth/login", json={"password": PASSWORD})
    assert r.status_code == 401
    assert "二次验证码" in r.json()["detail"]
    r = authed.post("/api/auth/login", json={"password": PASSWORD, "code": "000000"})
    assert r.status_code == 401
    assert "二次验证码错误" in r.json()["detail"]

    # 密码 + 动态码登录成功
    r = authed.post("/api/auth/login", json={"password": PASSWORD, "code": _code(secret)})
    assert r.status_code == 200

    # 恢复码可登录，且一次性
    r = authed.post("/api/auth/login", json={"password": PASSWORD, "code": recovery[0]})
    assert r.status_code == 200
    r = authed.post("/api/auth/login", json={"password": PASSWORD, "code": recovery[0]})
    assert r.status_code == 401

    # 关闭需要验证当前密码
    r = authed.post("/api/auth/totp/disable", json={"password": "wrong-password"})
    assert r.status_code == 401
    assert config_mod.config.totp_enabled is True
    r = authed.post("/api/auth/totp/disable", json={"password": PASSWORD})
    assert r.status_code == 200
    assert config_mod.config.totp_enabled is False

    # 恢复纯密码登录
    r = authed.post("/api/auth/login", json={"password": PASSWORD})
    assert r.status_code == 200


def test_totp_recovery_codes_regenerate(authed, internal_mode):
    if not config_mod.config.totp_enabled:
        secret = totp_mod.generate_secret()
        config_mod.config.set_totp_secret(secret)
        r = authed.post("/api/auth/totp/enable", json={"code": _code(secret)})
        assert r.status_code == 200
    secret = config_mod.config.totp_secret
    old_left = len(config_mod.config.totp_recovery_hashes)

    r = authed.post("/api/auth/totp/recovery-codes", json={"code": _code(secret, drift=2)})
    assert r.status_code == 400
    r = authed.post("/api/auth/totp/recovery-codes", json={"code": _code(secret)})
    assert r.status_code == 200
    new_codes = r.json()["recovery_codes"]
    assert len(new_codes) == 10
    # 旧恢复码全部作废（用启用时的那批随便取一个应失败——这里验证剩余数重置）
    assert len(config_mod.config.totp_recovery_hashes) == 10
    assert old_left <= 10
    # 收尾：关闭 2FA，避免影响后续用例
    authed.post("/api/auth/totp/disable", json={"password": PASSWORD})
    assert config_mod.config.totp_enabled is False


# ---------- Agent 多令牌 + 作用域 ----------


def test_agent_token_scope_readonly(authed, anon, internal_mode):
    r = authed.post("/api/agent/tokens", json={"name": "只读令牌", "scope": "readonly"})
    assert r.status_code == 200
    token = r.json()["token"]
    assert len(token) >= 16

    # 列表不泄露哈希/明文
    r = authed.get("/api/agent/tokens")
    items = [t for t in r.json()["tokens"] if t["name"] == "只读令牌"]
    assert items
    view = items[0]
    assert "hash" not in view and "token" not in view
    assert view["scope"] == "readonly"

    # 只读命令放行（判定的是"作用域是否放行"：403 才是拒绝。
    # 退出码取决于宿主机有没有 df —— Windows 开发机上 df 来自 MSYS，
    # 是否在 PATH 里取决于 pytest 由哪个 shell 启动，不能拿它当断言）
    r = _exec(anon, token, "df -h")
    assert r.status_code == 200, r.text
    if shutil.which("df"):
        assert r.json()["code"] == 0, r.text
    r = _exec(anon, token, "systemctl status ssh")
    assert r.status_code == 200

    # 危险命令拒绝
    r = _exec(anon, token, "systemctl restart ssh")
    assert r.status_code == 403
    r = _exec(anon, token, "touch /tmp/sp-scope-probe")
    assert r.status_code == 403

    # 尾挂恶意段同样拒绝（逐段校验）
    r = _exec(anon, token, "df -h && touch /tmp/sp-scope-probe")
    assert r.status_code == 403
    r = _exec(anon, token, "df -h; touch /tmp/sp-scope-probe")
    assert r.status_code == 403
    assert not __import__("os").path.exists("/tmp/sp-scope-probe")

    # 吊销后立即失效
    r = authed.delete(f"/api/agent/tokens/{view['id']}")
    assert r.status_code == 200
    r = _exec(anon, token, "df -h")
    assert r.status_code == 401


def test_agent_token_scope_custom(authed, anon, internal_mode):
    r = authed.post("/api/agent/tokens", json={
        "name": "自定义令牌", "scope": "custom", "prefixes": ["echo", "uptime"]})
    assert r.status_code == 200
    token = r.json()["token"]

    r = _exec(anon, token, "echo custom-ok")
    assert r.status_code == 200
    assert "custom-ok" in r.json()["stdout"]

    # 白名单外命令拒绝
    r = _exec(anon, token, "whoami")
    assert r.status_code == 403
    # 前缀匹配但尾挂危险段仍拒绝
    r = _exec(anon, token, "echo hi && touch /tmp/sp-scope-probe")
    assert r.status_code == 403

    r = authed.delete("/api/agent/tokens")
    assert r.status_code == 200


def test_agent_token_full_scope_and_expiry(authed, anon, internal_mode):
    r = authed.post("/api/agent/tokens", json={
        "name": "完整令牌", "scope": "full", "expires_days": 7, "note": "回归测试用"})
    assert r.status_code == 200
    token = r.json()["token"]
    r = _exec(anon, token, "echo full-scope-ok")
    assert r.status_code == 200
    assert "full-scope-ok" in r.json()["stdout"]

    # 过期时间写入且未过期
    r = authed.get("/api/agent/tokens")
    item = [t for t in r.json()["tokens"] if t["name"] == "完整令牌"][0]
    assert item["expires_at"] > time.time()
    assert item["expired"] is False
    assert item["note"] == "回归测试用"

    # 非法作用域 / 过短自定义令牌被拒
    r = authed.post("/api/agent/tokens", json={"name": "x", "scope": "root"})
    assert r.status_code == 400
    r = authed.post("/api/agent/tokens",
                    json={"name": "x", "scope": "full", "custom_token": "short"})
    assert r.status_code == 400

    authed.delete(f"/api/agent/tokens/{item['id']}")


# ---------- 回收站 ----------


def test_trash_delete_restore_purge(authed, internal_mode, tmp_path):
    target = tmp_path / "doomed.txt"
    r = authed.post("/api/files/write", json={"path": str(target), "content": "bye"})
    assert r.status_code == 200

    # 删除 → 移入回收站（不是立即抹除）
    r = authed.post("/api/files/delete", json={"paths": [str(target)]})
    assert r.status_code == 200
    assert not target.exists()

    r = authed.get("/api/files/trash")
    entry = [e for e in r.json()["entries"] if e["original"] == str(target)][0]
    assert entry["reason"] == "delete"
    assert entry["size"] == 3

    # 还原
    r = authed.post("/api/files/trash/restore", json={"id": entry["id"]})
    assert r.status_code == 200
    assert target.read_text(encoding="utf-8") == "bye"

    # 覆盖写 → 原内容自动备份
    r = authed.post("/api/files/write", json={"path": str(target), "content": "v2"})
    assert r.status_code == 200
    assert "回收站" in r.json()["message"]
    r = authed.get("/api/files/trash")
    backup = [e for e in r.json()["entries"]
              if e["original"] == str(target) and e["reason"] == "overwrite"][0]

    # 原文件已存在时还原被拒（不猜测合并）
    r = authed.post("/api/files/trash/restore", json={"id": backup["id"]})
    assert r.status_code == 409

    # 彻底删除
    r = authed.post("/api/files/trash/purge", json={"id": backup["id"]})
    assert r.status_code == 200
    r = authed.get("/api/files/trash")
    assert not [e for e in r.json()["entries"] if e["id"] == backup["id"]]

    # 不存在的条目
    r = authed.post("/api/files/trash/purge", json={"id": "no-such-entry"})
    assert r.status_code == 404


def test_trash_purge_all(authed, internal_mode, tmp_path):
    target = tmp_path / "batch.txt"
    authed.post("/api/files/write", json={"path": str(target), "content": "x"})
    authed.post("/api/files/delete", json={"paths": [str(target)]})
    r = authed.get("/api/files/trash")
    assert any(e["original"] == str(target) for e in r.json()["entries"])

    r = authed.post("/api/files/trash/purge-all", json={})
    assert r.status_code == 200
    r = authed.get("/api/files/trash")
    assert not any(e["original"] == str(target) for e in r.json()["entries"])


# ---------- 审计日志 ----------


def test_audit_log_query_and_filters(authed, internal_mode):
    marker = "audit-probe-token"
    r = authed.post("/api/agent/tokens", json={"name": marker, "scope": "readonly"})
    assert r.status_code == 200

    # 全量查询包含刚发生的令牌创建
    r = authed.get("/api/panel/audit/log", params={"days": 7})
    assert r.status_code == 200
    events = r.json()["events"]
    hit = [e for e in events if e["action"] == "token_created" and e["target"] == marker]
    assert hit, "令牌创建应记入审计"
    assert hit[0]["source"] == "web"
    assert hit[0]["ok"] is True

    # action 过滤
    r = authed.get("/api/panel/audit/log", params={"action": "token_created"})
    assert all(e["action"] == "token_created" for e in r.json()["events"])
    # source 过滤
    r = authed.get("/api/panel/audit/log", params={"source": "web"})
    assert all(e["source"] == "web" for e in r.json()["events"])
    # 关键字过滤
    r = authed.get("/api/panel/audit/log", params={"q": marker})
    assert any(e["target"] == marker for e in r.json()["events"])
    # 天数下限（1 天起）
    r = authed.get("/api/panel/audit/log", params={"days": 0})
    assert r.status_code == 200

    authed.delete("/api/agent/tokens")


def test_audit_records_cli_mode_switch(tmp_path, monkeypatch):
    """CLI 切换模式同样落审计（source=cli）。"""
    from app.audit import audit

    monkeypatch.setenv("SERVERPANEL_CONFIG", str(tmp_path / "cfg.json"))
    audit.record_cli("mode_enabled", target="-", summary="测试内网模式")
    events = audit.query(days=1, action="mode_enabled")
    assert events and events[0]["source"] == "cli"


# ---------- 登录锁定持久化 ----------


def test_lockout_persists_across_restart():
    ip = "203.0.113.77"
    failures.clear_failures(ip)
    for _ in range(5):
        failures.record_failure(ip)
    assert failures.locked_for(ip) > 0

    # 模拟重启：全新实例从 failures.json 恢复计数
    revived = FailureTracker()
    assert revived.locked_for(ip) > 0
    assert revived.status(ip)["ip_failures"] == 5

    # 清理，避免污染后续用例
    failures.clear_failures(ip)
    assert FailureTracker().locked_for(ip) == 0


# ---------- 安全中心 / 会话管理 ----------


def test_security_summary_shape(authed, internal_mode):
    r = authed.get("/api/panel/security")
    assert r.status_code == 200
    data = r.json()
    assert {"totp", "lockout", "sessions", "tokens", "audit", "trash"} <= set(data)
    lock = data["lockout"]
    assert {"ip", "ip_failures", "global_failures", "locked_seconds", "tiers"} <= set(lock)
    assert [(t["attempts"], t["lock_seconds"]) for t in lock["tiers"]] == \
        [(5, 60), (10, 3600), (20, 86400)]


def test_sessions_list_and_revoke_others(authed, internal_mode):
    r = authed.get("/api/panel/sessions")
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert sessions, "至少存在当前会话"
    assert sum(1 for s in sessions if s["current"]) == 1

    # 第二个独立登录 → 新会话
    other = TestClient(app)
    r = other.post("/api/auth/login", json={"password": PASSWORD})
    assert r.status_code == 200
    r = authed.get("/api/panel/sessions")
    assert len(r.json()["sessions"]) == len(sessions) + 1

    # 踢出其他会话：精确踢出此前存在的全部非当前会话，当前不受影响
    r = authed.post("/api/panel/sessions/revoke-others", json={})
    assert r.status_code == 200
    assert r.json()["message"] == f"已踢出 {len(sessions)} 个其他会话"
    r = other.get("/api/system/info")
    assert r.status_code == 401
    r = authed.get("/api/system/info")
    assert r.status_code == 200

    # 不能踢出当前会话
    current = [s for s in authed.get("/api/panel/sessions").json()["sessions"] if s["current"]][0]
    r = authed.post("/api/panel/sessions/revoke", json={"id": current["id"]})
    assert r.status_code == 400


def test_healthz_minimal_and_version_guarded():
    """健康端点不泄露版本/构建/初始化状态；版本信息需登录。"""
    with TestClient(app) as fresh:
        r = fresh.get("/healthz")
        assert r.json() == {"ok": True}
        r = fresh.get("/api/system/version")
        assert r.status_code == 401


# ---------- 1.4.1 验收修复回归 ----------


def test_scope_rejects_shell_metacharacters(anon, authed, internal_mode):
    """只读/自定义作用域必须挡住 & 换行 $() 反引号 重定向（1.4.0 全漏）。"""
    from app.scopes import command_allowed

    bypasses = [
        "ls & rm -rf /tmp/sp-bypass",
        "ls\nid",
        "ls\r\nid",
        "ls $(touch /tmp/sp-bypass)",
        "ls `touch /tmp/sp-bypass`",
        "df -h > /tmp/sp-bypass",
        "ls;touch /tmp/sp-bypass",          # 这个 1.4.0 就挡住了，一并回归
    ]
    for command in bypasses:
        assert command_allowed("readonly", [], command) is False, command
        assert command_allowed("custom", ["ls"], command) is False, command

    # 真实链路：只读令牌执行 "ls & echo hijacked" 必须是 403
    r = authed.post("/api/agent/tokens", json={"name": "meta-probe", "scope": "readonly"})
    token = r.json()["token"]
    token_id = [t for t in authed.get("/api/agent/tokens").json()["tokens"]
                if t["name"] == "meta-probe"][0]["id"]
    try:
        r = _exec(anon, token, "ls & echo hijacked")
        assert r.status_code == 403, r.text
        r = _exec(anon, token, "ls\necho hijacked")
        assert r.status_code == 403, r.text
        r = _exec(anon, token, "df -h > /tmp/sp-bypass")
        assert r.status_code == 403, r.text
        # 正常只读命令仍然放行
        assert _exec(anon, token, "df -h").status_code == 200
    finally:
        authed.delete(f"/api/agent/tokens/{token_id}")


def test_scope_readonly_excludes_state_changing_commands(anon, authed, internal_mode):
    """mount / 改名 hostname / ip addr add / ip link set / dmesg -C 不在只读范围。"""
    from app.scopes import command_allowed

    for command in ("mount -o remount,rw /", "hostname pwned",
                    "ip addr add 10.9.9.9/32 dev eth0", "ip link set eth0 down",
                    "ip route add 10.9.9.0/24 dev eth0", "dmesg -C",
                    "journalctl --vacuum-time=1s", "date -s '2020-01-01'",
                    "systemctl restart nginx"):
        assert command_allowed("readonly", [], command) is False, command
    for command in ("df -h", "systemctl status nginx", "ip addr show", "ip -4 route",
                    "cat /proc/meminfo", "journalctl -u nginx -n 20", "date -u",
                    "hostname -f", "dmesg", "ping -c 1 127.0.0.1"):
        assert command_allowed("readonly", [], command) is True, command
    # 方案外的路径与敏感虚拟文件
    assert command_allowed("readonly", [], "cat /etc/shadow") is False
    assert command_allowed("readonly", [], "cat /proc/1/environ") is False


def test_legacy_agent_token_migrates_on_first_use(tmp_path, monkeypatch):
    """1.3.1 遗留配置升级后，旧令牌必须仍然可用（自动迁移不能被门挡住）。"""
    from app import config as cfg_mod

    monkeypatch.setenv("SERVERPANEL_CONFIG", str(tmp_path / "config.json"))
    cfg = cfg_mod.Config()
    legacy = "legacy-token-1234567890abcdef"
    cfg.data["agent_token"] = legacy
    cfg.data["agent_token_updated_at"] = int(time.time())
    cfg.save()

    # 迁移前：属性层面就该能看到（agent_tokens 读取即触发迁移）
    assert cfg.agent_tokens and cfg.agent_tokens[0]["scope"] == "full"
    assert "agent_token" not in cfg.data, "迁移后必须清掉明文字段"
    # 明文比对仍然命中，且旧令牌不会被当成"已配置"哨兵
    assert cfg.find_agent_token(legacy) is not None
    assert cfg.find_agent_token("wrong-token-000000000000") is None


def test_totp_setup_cannot_silently_disable_2fa(authed, internal_mode):
    """已启用 2FA 时 /totp/setup 必须拒绝（1.4.0 用它一键拆掉 2FA）。"""
    if config_mod.config.totp_enabled:
        authed.post("/api/auth/totp/disable", json={"password": PASSWORD})
    secret = totp_mod.generate_secret()
    config_mod.config.set_totp_secret(secret)
    r = authed.post("/api/auth/totp/enable", json={"code": _code(secret)})
    assert r.status_code == 200, r.text
    assert config_mod.config.totp_enabled is True

    r = authed.post("/api/auth/totp/setup", json={})
    assert r.status_code == 400, r.text
    assert config_mod.config.totp_enabled is True, "setup 不得关掉二次认证"
    assert config_mod.config.totp_secret == secret, "setup 不得替换已启用密钥"

    # 收尾：关掉 2FA，避免影响后续用例
    authed.post("/api/auth/totp/disable", json={"password": PASSWORD})
    assert config_mod.config.totp_enabled is False


def test_totp_verify_rejects_empty_secret():
    """空密钥等于没有第二因素，必须显式拒绝（不能拿空 HMAC 当动态码）。"""
    assert totp_mod.verify("", "000000") is False
    assert totp_mod.verify("", totp_mod.code("")) is False


def test_session_revoke_requires_exact_short_id(authed, internal_mode):
    """空串/短前缀不得踢掉会话（1.4.0 的空 id 会踢掉字典里第一个会话）。"""
    other = TestClient(app)
    assert other.post("/api/auth/login", json={"password": PASSWORD}).status_code == 200
    before = len(authed.get("/api/panel/sessions").json()["sessions"])
    assert before >= 2

    for bad in ("", "a", "abc", "Z" * 12, "0" * 11):
        r = authed.post("/api/panel/sessions/revoke", json={"id": bad})
        assert r.status_code in (400, 404), f"{bad!r} -> {r.status_code}"
    assert len(authed.get("/api/panel/sessions").json()["sessions"]) == before

    # 用准确的 12 位短标识踢掉另一个会话
    target = [s for s in authed.get("/api/panel/sessions").json()["sessions"]
              if not s["current"]][0]
    r = authed.post("/api/panel/sessions/revoke", json={"id": target["id"]})
    assert r.status_code == 200, r.text
    assert other.get("/api/system/info").status_code == 401


def test_legacy_plaintext_sessions_dropped_on_load(tmp_path):
    """升级后旧明文会话不得留在 sessions.json 里（也无法再通过校验）。"""
    import json as json_mod
    from pathlib import Path as PathCls

    from app.auth import SessionStore
    from app.config import config as cfg

    path = PathCls(cfg.path).parent / "sessions.json"
    backup = path.read_text("utf-8") if path.exists() else None
    plaintext = "legacy-plaintext-session-token-value"
    try:
        path.write_text(json_mod.dumps({plaintext: {
            "ip": "10.0.0.9", "created": int(time.time()),
            "expires": int(time.time()) + 3600, "label": ""}}), "utf-8")
        store = SessionStore()
        assert store.validate(plaintext) is None, "明文键不得再能登录"
        on_disk = path.read_text("utf-8")
        assert plaintext not in on_disk, "加载时必须把明文键清出磁盘"
    finally:
        if backup is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(backup, "utf-8")


def test_audit_query_reads_tail_only(tmp_path):
    """审计查询只倒读文件尾部：超长文件里最老的那条不会被翻出来。"""
    import json as json_mod

    from app.audit import AuditLog

    log = AuditLog(tmp_path / "audit")
    try:
        today = log._path_for(time.time())
        old = json_mod.dumps({"ts": 0, "time": 0, "action": "ancient_marker",
                              "target": "old", "summary": "old", "source": "cli",
                              "ip": "", "actor": "", "ok": True, "code": 0,
                              "duration": None}, ensure_ascii=False)
        filler = json_mod.dumps({"ts": 0, "time": 0, "action": "exec",
                                 "target": "x" * 200, "summary": "y" * 200,
                                 "source": "agent", "ip": "", "actor": "", "ok": True,
                                 "code": 0, "duration": None}, ensure_ascii=False)
        with open(today, "w", encoding="utf-8") as fh:
            fh.write(old + "\n")
            for _ in range(80_000):          # ≈40MB，远超 8MB 倒读上限
                fh.write(filler + "\n")
        # 新事件照常查到
        assert log.query(days=1, action="exec", limit=1)
        # 文件开头的旧事件不再被全量扫描出来（这正是"不再 readlines"的证据）
        assert log.query(days=1, action="ancient_marker") == []
        # 倒读结果仍然是最新的在前
        events = log.query(days=1, action="exec", limit=5)
        assert len(events) == 5
    finally:
        log.close()


def test_exec_and_task_records_keep_ui_fields(anon, authed, internal_mode):
    """接口载荷必须保留前端消费的兼容字段（1.4.0 换审计事件后 UI 空白）。"""
    r = authed.post("/api/agent/tokens", json={"name": "shape-probe", "scope": "readonly"})
    token = r.json()["token"]
    token_id = [t for t in authed.get("/api/agent/tokens").json()["tokens"]
                if t["name"] == "shape-probe"][0]["id"]
    try:
        assert _exec(anon, token, "df -h").status_code == 200
        recent = authed.get("/api/agent/info").json()["recent"]
        assert recent, "应有执行记录"
        assert recent[0]["kind"] == "agent"
        assert "df -h" in recent[0]["command"]
    finally:
        authed.delete(f"/api/agent/tokens/{token_id}")

    authed.post("/api/panel/tasks/sys-snapshot/run", json={"params": {}})
    recent = authed.get("/api/panel/tasks/recent").json()["recent"]
    assert recent, "应有任务执行记录"
    item = recent[0]
    assert item["action"] == "task_run"
    assert item["task_id"] == "sys-snapshot"
    assert item["title"], "任务标题不能为空（面板据此渲染）"
    assert item["command"], "任务命令不能为空（面板据此渲染）"


def test_lockout_escalates_even_for_slow_attack():
    """慢速爆破也必须被锁：锁定时长从跨档那一刻起算（1.4.0 会算成 0 秒）。"""
    ip = "198.51.100.9"
    failures.clear_failures(ip)
    now = time.time()
    try:
        # 5 次失败散布在 10 分钟内 —— 1.4.0 实测 locked_for == 0
        failures._ips[ip] = [now - 600 + i * 100 for i in range(5)]
        failures._global = list(failures._ips[ip])
        failures._locked_until.pop(ip, None)
        failures.record_failure(ip)          # 第 6 次：跨过第一档 → 起算 60s
        assert failures.locked_for(ip) > 0

        # 10 次失败散布在 2 小时内 —— 1.4.0 实测 locked_for == 0
        failures.clear_failures(ip)
        failures._ips[ip] = [now - 7200 + i * 800 for i in range(10)]
        failures._global = list(failures._ips[ip])
        failures.record_failure(ip)          # 第 11 次：跨过第二档 → 起算 1 小时
        locked = failures.locked_for(ip)
        assert locked > 3500, f"应锁约 1 小时，实际 {locked}s"
        # 重启后仍然锁着（locked_until 落盘）
        assert FailureTracker().locked_for(ip) > 3500
    finally:
        failures.clear_failures(ip)
