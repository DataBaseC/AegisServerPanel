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

import sys

import pytest
from fastapi.testclient import TestClient

from app import config as config_mod
from app import totp as totp_mod
from app.auth import FailureTracker, failures
from app.main import app

PASSWORD = "test-password-123"


def _confirm(client, action: str) -> dict:
    """高危操作确认令牌（2.0 M1）：先申请再带 X-Confirm-Token。"""
    token = client.post("/api/panel/confirm", json={"action": action}).json()["token"]
    return {"X-Confirm-Token": token}


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

    r = authed.delete("/api/agent/tokens", headers=_confirm(authed, "tokens"))
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

    authed.delete("/api/agent/tokens", headers=_confirm(authed, "tokens"))


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


def test_scope_readonly_allows_harmless_commands(anon, authed, internal_mode):
    """1.6.0 S1：只读白名单补充的零副作用命令放行；组合命令逐段通过；绕过向量拒绝。"""
    from app.scopes import command_allowed

    harmless = [
        "pwd", "readlink /proc/self", "realpath /var/log", "basename /a/b",
        "dirname /a/b", "arch", "nproc", "lsb_release -a",
        "getconf LONG_BIT", "which python3",
    ]
    for command in harmless:
        assert command_allowed("readonly", [], command) is True, command

    # 组合命令：整条经 && / ; / | 拆段后每段都得放行
    for command in ("ls; pwd", "df -h && pwd", "pwd | readlink -f /proc/self"):
        assert command_allowed("readonly", [], command) is True, command

    # 绕过向量（E1）：新命令不得变成拼接/元字符的跳板
    for command in ("pwd && rm -rf /tmp/sp-bypass", "pwd; touch /tmp/sp-bypass",
                    "pwd & touch /tmp/sp-bypass", "pwd $(id)", "pwd > /tmp/sp-bypass",
                    "pwd\nid"):
        assert command_allowed("readonly", [], command) is False, command

    # 明确不收的命令：输出可能含敏感环境变量或命令历史
    for command in ("env", "printenv", "set", "history"):
        assert command_allowed("readonly", [], command) is False, command


def test_scope_readonly_file_meta_path_guard(anon, authed, internal_mode):
    """1.6.0 S2：wc/stat/file/du 的敏感路径拒绝、常规路径放行；含绕过向量（E1）。"""
    from app.scopes import command_allowed

    denied = [
        "wc /etc/shadow", "stat /etc/shadow", "du -sh /root/.ssh",
        "file /etc/gshadow", "stat /root/.ssh/id_rsa", "wc -l /etc/sudoers",
        "du /etc/sudoers.d", "file /etc/.htpasswd", "wc /proc/1/mem",
        "stat /root/.ssh/authorized_keys", "du -sh /etc/ssh",
    ]
    for command in denied:
        assert command_allowed("readonly", [], command) is False, command

    allowed = [
        "wc /var/log/syslog", "stat /etc/hostname", "du -sh /var/log",
        "file /etc/hostname", "cat /proc/meminfo", "ls /root/.ssh",
        "stat /etc/ssh_config", "wc -l /var/log/apt/history.log",
    ]
    for command in allowed:
        assert command_allowed("readonly", [], command) is True, command

    # 绕过向量（E1）：路径归一化写法、藏在组合命令里的写法都不得逃逸
    for command in ("wc /etc/./shadow", "stat /etc//shadow", "du -sh /root/./.ssh",
                    "wc -l /etc/shadow; ls", "ls && wc /etc/shadow",
                    "wc /etc/sudoers.d/x", "du /etc/ssh/ssh_host_rsa_key"):
        assert command_allowed("readonly", [], command) is False, command


def test_scope_readonly_accepts_glued_short_options(anon, authed, internal_mode):
    """1.6.0 S3：短选项粘连写法（-c1 / -i:80 / -bn1）等价放行；未登记选项仍拒。"""
    from app.scopes import command_allowed

    for command in ("ping -c1 127.0.0.1", "lsof -i:80", "top -bn1",
                    "ping -c 1", "lsof -i", "top -b"):
        assert command_allowed("readonly", [], command) is True, command

    # 未登记选项、长选项、无选项一律拒绝（粘连规则不得成为绕过通道）
    for command in ("ping -n 127.0.0.1", "ping --count=1 127.0.0.1",
                    "smartctl -x /dev/sda", "smartctl --scan", "lsof -p 123", "lsof"):
        assert command_allowed("readonly", [], command) is False, command


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


# ---------- 1.6.0 U1 一键安全巡检 ----------


def test_security_checkup_requires_internal(authed):
    """巡检端点鉴权：未登录 401，公网模式 403。"""
    anon_client = TestClient(app)
    assert anon_client.get("/api/panel/security/checkup").status_code == 401
    config_mod.config.set_mode(config_mod.MODE_PUBLIC)
    try:
        assert authed.get("/api/panel/security/checkup").status_code == 403
    finally:
        config_mod.config.set_mode(config_mod.MODE_INTERNAL)


def test_security_checkup_items(authed, internal_mode):
    """逐项造数：未开 2FA / 弱密码 / full 令牌 / 闲置令牌 / 当前 IP 锁定。"""
    from app.auth import failures

    if config_mod.config.totp_enabled:
        authed.post("/api/auth/totp/disable", json={"password": PASSWORD})

    items = authed.get("/api/panel/security/checkup").json()["items"]
    assert any(i["level"] == "bad" and "二次认证" in i["title"] for i in items), items

    # 完整权限令牌 + 新建令牌（last_used_at=0 → 闲置）
    r = authed.post("/api/agent/tokens", json={"name": "checkup-full", "scope": "full"})
    assert r.status_code == 200
    token_id = [t for t in authed.get("/api/agent/tokens").json()["tokens"]
                if t["name"] == "checkup-full"][0]["id"]
    try:
        items = authed.get("/api/panel/security/checkup").json()["items"]
        assert any("完整权限令牌" in i["title"] for i in items), items
        assert any("闲置令牌" in i["title"] for i in items), items
    finally:
        authed.delete(f"/api/agent/tokens/{token_id}")

    # 弱密码：12 位纯小写能过准入门槛，但只有 1 类字符（真实配置改出来）
    config_mod.config.set_password("abcdefghijkl")
    try:
        items = authed.get("/api/panel/security/checkup").json()["items"]
        assert any("密码强度" in i["title"] for i in items), items
    finally:
        config_mod.config.set_password(PASSWORD)

    # 当前来源 IP 锁定
    ip = authed.get("/api/panel/security").json()["lockout"]["ip"]
    for _ in range(6):
        failures.record_failure(ip)
    try:
        items = authed.get("/api/panel/security/checkup").json()["items"]
        assert any(i["level"] == "bad" and "锁定" in i["title"] for i in items), items
    finally:
        failures.clear_failures(ip)


def test_security_checkup_ok_when_clean(authed, internal_mode):
    """全部检查项通过时只返回一条 ok（清空令牌、开启 2FA、清锁定）。"""
    from app.auth import failures

    authed.delete("/api/agent/tokens", headers=_confirm(authed, "tokens"))          # 吊销全部令牌
    ip = authed.get("/api/panel/security").json()["lockout"]["ip"]
    failures.clear_failures(ip)
    try:
        if not config_mod.config.totp_enabled:
            secret = authed.post("/api/auth/totp/setup", json={}).json()["secret"]
            r = authed.post("/api/auth/totp/enable", json={"code": _code(secret)})
            assert r.status_code == 200, r.text
        items = authed.get("/api/panel/security/checkup").json()["items"]
        assert len(items) == 1 and items[0]["level"] == "ok", items
    finally:
        if config_mod.config.totp_enabled:
            authed.post("/api/auth/totp/disable", json={"password": PASSWORD})


def test_audit_export_records_event(authed, internal_mode):
    """1.6.0 U2：导出动作写入审计（action=audit_export，summary 含条数）。"""
    r = authed.post("/api/panel/audit/export",
                    json={"count": 7, "filters": "7天 / 全部来源"})
    assert r.status_code == 200
    events = authed.get("/api/panel/audit/log?days=1&action=audit_export").json()["events"]
    assert events, "导出动作应写入审计"
    assert "7" in events[0]["summary"]


# ---------- 1.6.0 U3 回收站水位告警 ----------


def test_trash_water_level(authed, internal_mode, tmp_path):
    """配置阈值后 over_limit 生效，巡检与安全摘要同步告警；调大后消失。"""
    from app.trash import trash

    r = authed.put("/api/panel/prefs",
                   json={"values": {"security.trash_max_bytes": 64 * 1024 * 1024}})
    assert r.status_code == 200, r.text
    big = tmp_path / "big.bin"
    with open(big, "wb") as fh:
        fh.truncate(65 * 1024 * 1024)      # 稀疏文件，不实际占盘
    entry = trash.move(str(big), reason="test")
    try:
        summary = authed.get("/api/panel/security").json()
        assert summary["trash"]["over_limit"] is True, summary["trash"]
        items = authed.get("/api/panel/security/checkup").json()["items"]
        assert any("回收站" in i["title"] for i in items), items
    finally:
        trash.purge(entry.entry_id)
        authed.put("/api/panel/prefs",
                   json={"values": {"security.trash_max_bytes": 1024 ** 3}})
    assert authed.get("/api/panel/security").json()["trash"]["over_limit"] is False


def test_trash_pref_validation(authed, internal_mode):
    """阈值范围 64MiB–10GiB；坏值与越界在写入时即被拒。"""
    from app.prefs import FIELDS, PrefsError

    check = FIELDS["security.trash_max_bytes"][1]
    assert check(64 * 1024 * 1024) == 64 * 1024 * 1024
    for bad in ("abc", 1024, 11 * 1024 ** 3, None):
        with pytest.raises(PrefsError):
            check(bad)
    r = authed.put("/api/panel/prefs",
                   json={"values": {"security.trash_max_bytes": "abc"}})
    assert r.status_code == 400


# ---------- 1.6.0 F1 事件通知 Webhook ----------


def _start_webhook_receiver():
    """启动本地收包服务，返回 (server, received)。"""
    import json as json_mod
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            received.append(json_mod.loads(self.rfile.read(length) or b"{}"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):  # 静音
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, received


def _set_notify(authed, **values):
    r = authed.put("/api/panel/prefs", json={"values": values})
    assert r.status_code == 200, r.text


def _allow_private(flag: bool) -> None:
    config_mod.config.data["fetch_allow_private"] = flag
    config_mod.config.save()


def test_ssrf_guard_shared_by_notify_and_file_fetch():
    """1.6.0 F1：SSRF 判定抽到 app/ssrf.py 后与文件拉取行为完全一致（含绕过向量）。"""
    from fastapi import HTTPException

    from app.routes.file_routes import _assert_url_allowed
    from app.ssrf import assert_url_allowed

    blocked = [
        "http://127.0.0.1/", "http://127.0.0.1:8787/", "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/", "http://10.1.2.3/",
        "http://172.16.0.1/", "http://192.168.1.1/", "http://100.64.0.1/",
        "http://[::1]/", "http://[fc00::1]/", "file:///etc/passwd",
        "gopher://127.0.0.1/",
    ]
    for url in blocked:
        for fn in (assert_url_allowed, _assert_url_allowed):
            try:
                fn(url)
            except HTTPException as exc:
                assert exc.status_code == 400, url
            else:
                raise AssertionError(f"{url} 应被 SSRF 拦截")
    # 公网直连 IP 放行（两个入口一致）
    assert assert_url_allowed("http://1.1.1.1/") is None
    assert _assert_url_allowed("http://1.1.1.1/") is None


def test_notify_webhook_delivery_and_switch(authed, internal_mode):
    """Webhook 收到正确 JSON；私网默认被拦截；开关关闭时不发送。"""
    from app.notify import notify

    server, received = _start_webhook_receiver()
    port = server.server_address[1]
    try:
        _set_notify(authed, **{"notify.webhook_url": f"http://127.0.0.1:{port}/hook",
                               "notify.on_task_fail": True,
                               "notify.on_lockout": True})
        # 默认不放行私网：SSRF 拦截，不发包
        notify("task_fail", "blocked-by-ssrf")
        assert received == []

        _allow_private(True)
        try:
            notify("task_fail", "任务失败：boom")
            assert received and received[-1]["event"] == "task_fail"
            assert received[-1]["text"] == "任务失败：boom"
            assert isinstance(received[-1]["time"], int)

            _set_notify(authed, **{"notify.on_task_fail": False})
            before = len(received)
            notify("task_fail", "should-not-send")
            assert len(received) == before, "开关关闭时不应发送"
        finally:
            _allow_private(False)
    finally:
        _set_notify(authed, **{"notify.webhook_url": "", "notify.on_task_fail": False,
                               "notify.on_lockout": False})
        server.shutdown()
        server.server_close()


def test_notify_failure_never_raises(authed, internal_mode):
    """Webhook 不可达时只记审计（notify_failed），绝不向上抛。"""
    from app.notify import notify

    _set_notify(authed, **{"notify.webhook_url": "http://127.0.0.1:1/hook",
                           "notify.on_task_fail": True})
    _allow_private(True)
    try:
        notify("task_fail", "unreachable")      # 不应抛
    finally:
        _allow_private(False)
        _set_notify(authed, **{"notify.webhook_url": "", "notify.on_task_fail": False})
    events = authed.get("/api/panel/audit/log?days=1&action=notify_failed").json()["events"]
    assert events, "应记录 notify_failed"


def test_notify_prefs_validation(authed, internal_mode):
    """Webhook 地址写入时校验：非 http/https 拒绝，合法地址接受。"""
    for bad in ("ftp://example.com/hook", "notaurl", "javascript:alert(1)"):
        r = authed.put("/api/panel/prefs", json={"values": {"notify.webhook_url": bad}})
        assert r.status_code == 400, bad
    r = authed.put("/api/panel/prefs",
                   json={"values": {"notify.webhook_url": "https://example.com/hook"}})
    assert r.status_code == 200
    _set_notify(authed, **{"notify.webhook_url": ""})


def test_task_fail_triggers_webhook(authed, internal_mode, monkeypatch):
    """任务退出码非 0 且开关开启时，异步路由层发出通知。"""
    from app.routes import tasks_routes

    server, received = _start_webhook_receiver()
    port = server.server_address[1]
    try:
        _set_notify(authed, **{"notify.webhook_url": f"http://127.0.0.1:{port}/hook",
                               "notify.on_task_fail": True})
        _allow_private(True)

        class _Result:
            code = 3
            out = ""
            err = "boom"

        async def fake_run(*args, **kwargs):
            return _Result()

        monkeypatch.setattr(tasks_routes.shell, "run", fake_run)
        r = authed.post("/api/panel/tasks/sys-snapshot/run", json={"params": {}})
        assert r.status_code == 200, r.text
        assert received and received[-1]["event"] == "task_fail"
        assert "任务" in received[-1]["text"]
    finally:
        _allow_private(False)
        _set_notify(authed, **{"notify.webhook_url": "", "notify.on_task_fail": False})
        server.shutdown()
        server.server_close()


def test_lockout_triggers_webhook(authed, internal_mode):
    """登录失败触发锁定时，异步路由层发出通知。"""
    from app.auth import failures

    server, received = _start_webhook_receiver()
    port = server.server_address[1]
    ip = authed.get("/api/panel/security").json()["lockout"]["ip"]
    anon_client = TestClient(app)
    try:
        _set_notify(authed, **{"notify.webhook_url": f"http://127.0.0.1:{port}/hook",
                               "notify.on_lockout": True})
        _allow_private(True)
        failures.clear_failures(ip)
        for _ in range(6):
            anon_client.post("/api/auth/login", json={"password": "definitely-wrong"})
            if received:
                break
        assert received and received[-1]["event"] == "lockout"
    finally:
        failures.clear_failures(ip)
        _allow_private(False)
        _set_notify(authed, **{"notify.webhook_url": "", "notify.on_lockout": False})
        server.shutdown()
        server.server_close()


# ---------- 1.6.0 F2 文件批量移动 / 打包 ----------

# Windows 上这些用例的前提不成立：`/etc`、`/` 的「受保护目录」语义是 POSIX 路径语义
# （Windows 下 abspath 会变成 D:\etc，与 PROTECTED 字面量对不上）。
_win = pytest.mark.skipif(sys.platform == "win32",
                          reason="依赖 POSIX 路径语义，Windows 开发机跳过")


@_win
def test_files_batch_move(authed, internal_mode, tmp_path):
    """批量移动：内容一致、部分成功有明细、目标非法与受保护目录被拒。"""
    src = tmp_path / "src"
    src.mkdir()
    dst = tmp_path / "dst"
    dst.mkdir()
    a = src / "a.txt"
    a.write_text("AAA")
    b = src / "b.txt"
    b.write_text("BBB")

    r = authed.post("/api/files/move", json={"paths": [str(a), str(b)], "dest": str(dst)})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ok"] is True and len(data["moved"]) == 2, data
    assert (dst / "a.txt").read_text() == "AAA"
    assert not a.exists()

    # 部分成功：不存在的路径进 failed，其余照常移动
    c = src / "c.txt"
    c.write_text("C")
    r = authed.post("/api/files/move",
                    json={"paths": [str(src / "ghost.txt"), str(c)], "dest": str(dst)})
    data = r.json()
    assert data["ok"] is False
    assert len(data["moved"]) == 1 and len(data["failed"]) == 1, data
    assert (dst / "c.txt").exists()

    # 目标不存在 / 目标是文件 → 400
    r = authed.post("/api/files/move",
                    json={"paths": [str(dst / "a.txt")], "dest": str(tmp_path / "nope")})
    assert r.status_code == 400
    r = authed.post("/api/files/move",
                    json={"paths": [str(dst / "a.txt")], "dest": str(dst / "b.txt")})
    assert r.status_code == 400

    # 受保护的系统关键目录：单条失败但不抛 500
    r = authed.post("/api/files/move", json={"paths": ["/etc"], "dest": str(dst)})
    assert r.status_code == 200
    assert r.json()["ok"] is False and r.json()["failed"], r.text

    events = authed.get("/api/panel/audit/log?days=1&action=file_move").json()["events"]
    assert events, "移动动作应写审计"


@_win
def test_files_batch_archive(authed, internal_mode, tmp_path):
    """批量打包：zip 结构/内容正确、符号链接不跟随、关键目录与超限被拒。"""
    import io
    import zipfile

    folder = tmp_path / "pack"
    folder.mkdir()
    (folder / "one.txt").write_text("1")
    sub = folder / "sub"
    sub.mkdir()
    (sub / "two.txt").write_text("2")
    lone = tmp_path / "lone.txt"
    lone.write_text("L")
    link = folder / "link.txt"
    try:
        link.symlink_to(lone)
    except OSError:
        link = None

    r = authed.post("/api/files/archive", json={"paths": [str(folder), str(lone)]})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/zip")
    with zipfile.ZipFile(io.BytesIO(r.content)) as bundle:
        names = set(bundle.namelist())
        assert "pack/one.txt" in names
        assert "pack/sub/two.txt" in names
        assert "lone.txt" in names
        assert bundle.read("pack/one.txt") == b"1"
        if link is not None:
            assert "pack/link.txt" not in names, "符号链接不得跟随打包"

    events = authed.get("/api/panel/audit/log?days=1&action=file_archive").json()["events"]
    assert events, "打包动作应写审计"

    # 系统关键目录拒绝
    r = authed.post("/api/files/archive", json={"paths": ["/etc"]})
    assert r.status_code == 400

    # 单次总体积上限（稀疏文件只改元数据，不占实际磁盘）
    big = tmp_path / "big.bin"
    with open(big, "wb") as fh:
        fh.truncate(1024 ** 3 + 1)
    r = authed.post("/api/files/archive", json={"paths": [str(big)]})
    assert r.status_code == 400


# ---------- 1.6.0 F3 最近登录卡片（数据源契约） ----------


def test_recent_login_audit_feed(authed, internal_mode):
    """最近登录卡片依赖的两个审计查询：login / login_failed 都能查到可渲染字段。"""
    from app.auth import failures

    anon_client = TestClient(app)
    ip = authed.get("/api/panel/security").json()["lockout"]["ip"]
    try:
        if config_mod.config.totp_enabled:      # 保证能用密码直接完成一次成功登录
            authed.post("/api/auth/totp/disable", json={"password": PASSWORD})
        failures.clear_failures(ip)          # 确保这次失败不会被历史锁定挡住（429）
        assert anon_client.post("/api/auth/login", json={"password": PASSWORD}).status_code == 200
        anon_client.post("/api/auth/login", json={"password": "wrong-login-feed"})
        for action in ("login", "login_failed"):
            events = authed.get(
                f"/api/panel/audit/log?days=7&action={action}&limit=20").json()["events"]
            assert events, f"{action} 应有审计记录"
            for item in events[:3]:
                assert "time" in item and "ip" in item
    finally:
        failures.clear_failures(ip)


# ---------- 2.0 M1 安全收口 ----------


def test_confirm_token_gate(authed, internal_mode):
    """高危操作必须带服务端确认令牌；伪造/动作不符/过期一律拒绝。"""
    r = authed.post("/api/system/power", json={"action": "reboot", "confirm": "CONFIRM"})
    assert r.status_code == 400 and "确认令牌" in r.json()["detail"], r.text

    r = authed.post("/api/system/power", json={"action": "reboot", "confirm": "CONFIRM"},
                    headers={"X-Confirm-Token": "forged.token"})
    assert r.status_code == 400

    wrong = authed.post("/api/panel/confirm", json={"action": "update"}).json()["token"]
    r = authed.post("/api/system/power", json={"action": "reboot", "confirm": "CONFIRM"},
                    headers={"X-Confirm-Token": wrong})
    assert r.status_code == 400

    # 正确动作的令牌能通过门禁：用不存在的 unit，确保不会真的动服务
    good = authed.post("/api/panel/confirm", json={"action": "service"}).json()["token"]
    r = authed.post("/api/services/definitely-not-a-unit/action",
                    json={"action": "status"}, headers={"X-Confirm-Token": good})
    assert r.status_code in (400, 404), r.text

    assert authed.post("/api/panel/confirm", json={"action": "rm-rf"}).status_code == 400


def test_confirm_token_expires(monkeypatch):
    """令牌 2 分钟过期。"""
    from app import confirm

    token = confirm.issue("power")["token"]
    assert confirm.verify(token, "power")
    real = confirm.time.time
    monkeypatch.setattr(confirm.time, "time", lambda: real() + confirm.TTL_SECONDS + 1)
    assert confirm.verify(token, "power") is False


def test_write_rejects_symlink(authed, internal_mode, tmp_path):
    """写盘不得跟随符号链接（P1-7）。"""
    target = tmp_path / "outside.txt"
    target.write_text("ORIGINAL")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    r = authed.post("/api/files/write", json={"path": str(link), "content": "PWNED"})
    assert r.status_code == 400, r.text
    assert target.read_text() == "ORIGINAL", "链接目标不能被改写"

    normal = tmp_path / "normal.txt"
    r = authed.post("/api/files/write", json={"path": str(normal), "content": "OK"})
    assert r.status_code == 200
    assert normal.read_text() == "OK"


def test_security_headers_and_csp(authed):
    """CSP 关键指令齐全；HTTP 下不发 HSTS。"""
    r = authed.get("/")
    csp = r.headers["content-security-policy"]
    for part in ("object-src 'none'", "base-uri 'self'",
                 "form-action 'self'", "frame-ancestors 'none'"):
        assert part in csp, csp
    assert "strict-transport-security" not in r.headers


def test_sha256sums_manifest_current():
    """代码完整性清单必须与工作树一致（CI 同样校验）。"""
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "tools/gen_sha256sums.py", "--check"],
        cwd=root, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_terminal_idle_pref_validation():
    """终端空闲超时配置：0–1440 分钟，越界拒绝。"""
    from app.prefs import FIELDS, PrefsError

    check = FIELDS["terminal.idle_timeout_minutes"][1]
    assert check(0) == 0
    assert check(1440) == 1440
    for bad in (-1, 1441, "abc"):
        with pytest.raises(PrefsError):
            check(bad)


# ---------- 2.0 M2 指标持久化 / 阈值告警 / 能耗 ----------


def test_metrics_store_roundtrip(tmp_path):
    """SQLite 存储：写入后可查询，非法范围回落 1h。"""
    from app.metrics_store import MetricsStore

    db = MetricsStore(tmp_path / "metrics.db")
    now = int(time.time())
    try:
        for i in range(3):
            db.append({
                "time": now - i * 10, "cpu": 10 + i,
                "mem": {"percent": 20 + i}, "swap": {"percent": 0},
                "disk": {"percent": 30, "disk_read": 1, "disk_write": 2},
                "net": {"net_sent": 3, "net_recv": 4},
                "load": [0.5, 0.4, 0.3], "temps": [],
            })
        points = db.query("1h")
        assert points, "应能查到刚写入的采样"
        assert points[-1]["cpu"] is not None
        assert db.query("bogus"), "非法范围应回落到 1h"
    finally:
        db.close()


def test_history_endpoint_sources(authed, internal_mode):
    body = authed.get("/api/system/history?period=1d").json()
    assert "points" in body
    assert body["source"] in ("sqlite", "memory")


def test_alert_manager_debounce_and_silence(authed, internal_mode):
    """告警：超阈值触发一次，静默期内不重复，恢复后清零。"""
    from app.alerts import AlertManager

    authed.put("/api/panel/prefs", json={"values": {
        "alerts.enabled": True, "alerts.cpu_percent": 50,
        "alerts.for_seconds": 0, "alerts.silence_minutes": 60,
        "alerts.mem_percent": 0, "alerts.disk_percent": 0,
        "alerts.temp_c": 0, "alerts.load1": 0,
    }})
    try:
        manager = AlertManager()
        hot = {"cpu": 99, "mem": {"percent": 1}, "disk": {"percent": 1},
               "temps": [], "load": [0.1]}
        messages = manager.evaluate(hot)
        assert messages and "CPU" in messages[0]
        assert manager.evaluate(hot) == [], "静默期内不重复告警"
        cool = {"cpu": 1, "mem": {"percent": 0}, "disk": {"percent": 0},
                "temps": [], "load": [0]}
        assert manager.evaluate(cool) == []
    finally:
        authed.put("/api/panel/prefs", json={"values": {"alerts.enabled": False}})


def test_power_save_mode_interval(authed, internal_mode):
    """低功耗模式把采样间隔放宽到 10 秒；快照带功耗字段。"""
    authed.put("/api/panel/prefs", json={"values": {"power.save_mode": True}})
    try:
        body = authed.get("/api/system/metrics").json()
        assert body["sample_interval"] == 10
        assert "power_w" in body
    finally:
        authed.put("/api/panel/prefs", json={"values": {"power.save_mode": False}})
    assert authed.get("/api/system/metrics").json()["sample_interval"] == 2


# ---------- 2.0 M2 日志实时跟随 ----------


@pytest.mark.skipif(sys.platform == "win32",
                    reason="Windows 无 tail 的文本流语义（CRLF），且本机不跑 POSIX 日志跟随")
def test_log_stream_ws(authed, internal_mode, tmp_path):
    """WebSocket 实时跟随：先回放末尾，再推送新写入的行。"""
    log = tmp_path / "app.log"
    log.write_text("first-line\n", encoding="utf-8")
    old = config_mod.config.data.get("log_dirs")
    config_mod.config.data["log_dirs"] = [str(tmp_path)]
    try:
        with authed.websocket_connect(f"/api/logs/ws?path={log}&lines=10") as ws:
            assert ws.receive_text() == "first-line"
            with open(log, "a", encoding="utf-8") as fh:
                fh.write("second-line\n")
            assert ws.receive_text() == "second-line"
    finally:
        if old is None:
            config_mod.config.data.pop("log_dirs", None)
        else:
            config_mod.config.data["log_dirs"] = old
