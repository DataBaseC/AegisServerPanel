"""M3 运维扩展测试：解析器单测 + 端点（CLI 全部用假的 shell.run 替换）。

覆盖范围：

- ``app/ops.py`` 的纯逻辑：crontab 行、apt 可升级列表、docker JSON、ufw/iptables、
  authorized_keys、网络工具目标、备份文件名与容器 id。
- 端点：定时任务读写、备份增删、系统更新列表/升级、docker 列表与非法 id、
  防火墙只读与写入门禁、反代重载、数据库只读探测、SSH 公钥增删、网络工具。
- 确认令牌：docker 删除 / 防火墙写 / 反代重载 / 系统升级在无令牌时一律 400。
"""

from __future__ import annotations

import os
import stat
from types import SimpleNamespace

import sys

import pytest
from fastapi.testclient import TestClient

from app import confirm, ops, shell
from app import config as config_mod
from app.auth import sessions
from app.config import COOKIE_NAME
from app.main import app
from app.shell import Result

GOOD_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghijklmnopqrstuvwxyz0123456789"
            " me@laptop")


def _confirm(client, action: str) -> dict:
    token = client.post("/api/panel/confirm", json={"action": action}).json()["token"]
    return {"X-Confirm-Token": token}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def authed(client):
    """直接签发一个会话 Cookie。

    这里**故意不调用** ``/api/auth/setup``：本文件按字母序先于 test_panel.py 执行，
    设置密码会让那边的 setup 用例拿不到 200。直接签发会话既不碰全局密码状态，
    又能覆盖 require_internal 的真实鉴权链路。
    """
    token = sessions.create("127.0.0.1", "pytest-ops")
    client.cookies.set(COOKIE_NAME, token)
    assert client.get("/api/system/info").status_code == 200
    return client


@pytest.fixture()
def internal_mode():
    config_mod.config.set_mode(config_mod.MODE_INTERNAL)
    yield
    config_mod.config.set_mode(config_mod.MODE_PUBLIC)


@pytest.fixture()
def fake_shell(monkeypatch):
    """可编程的 shell 替身：``script`` 按命令前缀给返回值，``bins`` 控制能力探测。"""
    fake = SimpleNamespace(calls=[], script={}, bins={"crontab"}, state={"cron": ""})

    async def fake_run(cmd, timeout=30, shell=False, cwd=None, env=None, stdin=None):
        args = [cmd] if isinstance(cmd, str) else list(cmd)
        fake.calls.append({"args": args, "stdin": stdin, "env": env, "timeout": timeout})
        handler = fake.script.get(" ".join(args[:2])) or fake.script.get(args[0])
        if handler:
            return handler(args, stdin, env)
        return Result(0, "", "")

    monkeypatch.setattr(shell, "run", fake_run)
    monkeypatch.setattr(shell, "available", lambda binary: binary in fake.bins)
    monkeypatch.setattr(shell, "which",
                        lambda binary: f"/usr/bin/{binary}" if binary in fake.bins else None)
    return fake


# ================================================================ 解析器


def test_parse_crontab_lines():
    text = ("# 由面板管理\n"
            "*/5 * * * * /usr/bin/foo --bar\n"
            "@reboot /opt/start.sh\n"
            "#30 2 * * * /usr/bin/off\n")
    lines = ops.parse_crontab(text)
    assert [line["enabled"] for line in lines] == [False, True, True, False]
    assert lines[1]["schedule"] == "*/5 * * * *"
    assert lines[1]["command"] == "/usr/bin/foo --bar"
    assert lines[2]["schedule"] == "@reboot"
    # 停用行仍能看到"启用后会跑什么"
    assert lines[3]["schedule"] == "30 2 * * *"
    assert lines[3]["command"] == "/usr/bin/off"
    assert lines[0]["error"] == ""


def test_parse_cron_line_rejects_garbage():
    assert ops.parse_cron_line("bad line")["error"]
    assert ops.parse_cron_line("0 0 * * * *")["error"]  # 6 段但没有命令


def test_validate_cron_line_blocks_injection():
    assert ops.validate_cron_line("0 * * * * /bin/true") == "0 * * * * /bin/true"
    assert ops.validate_cron_line("# 注释行") == "# 注释行"
    with pytest.raises(ops.OpsError):
        ops.validate_cron_line("0 * * * * /bin/true\n0 * * * * /bin/false")
    with pytest.raises(ops.OpsError):
        ops.validate_cron_line("rm -rf /")


def test_render_and_normalize_crontab():
    assert ops.render_crontab(["a", "", " b "]) == "a\nb\n"
    assert ops.normalize_crontab("a  \n\nb\n") == ["a", "b"]


def test_parse_apt_upgradable():
    text = ("Listing...\n"
            "nodejs/jammy-security 18.19.1+dfsg-6ubuntu5 amd64 [upgradable from: 18.19.0]\n"
            "curl/jammy-updates 7.81.0-1ubuntu1.18 amd64 [upgradable from: 7.81.0]\n")
    packages = ops.parse_apt_upgradable(text)
    assert [item["name"] for item in packages] == ["nodejs", "curl"]
    assert packages[0]["security"] is True
    assert packages[0]["version"].startswith("18.19.1")
    assert packages[1]["security"] is False


def test_parse_docker_json_skips_broken_lines():
    text = '{"ID":"abc","Names":"web","State":"running"}\nnot json\n{"ID":"def"}\n'
    items = ops.parse_docker_json(text)
    assert [item["id"] for item in items] == ["abc", "def"]
    assert items[0]["names"] == "web"


def test_parse_ufw_and_iptables():
    ufw = ("[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
           "[ 2] 8787/tcp                   ALLOW IN    Anywhere\n"
           "[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n")
    rules = ops.parse_ufw_status(ufw, {"22", "8787"})
    assert len(rules) == 3
    assert rules[0]["port"] == "22" and rules[0]["proto"] == "tcp"
    assert rules[0]["risky"] is True
    assert rules[2]["v6"] is True

    iptables = ("-P INPUT ACCEPT\n"
                "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"
                "-A INPUT -p tcp -m tcp --dport 8787 -s 10.0.0.5 -j ACCEPT\n")
    parsed = ops.parse_iptables(iptables, {"22", "8787"})
    assert len(parsed) == 2
    assert parsed[0]["risky"] is True
    assert parsed[1]["risky"] is False


def test_public_key_parse_and_validate():
    parsed = ops.parse_key_line(GOOD_KEY)
    assert parsed["valid"] is True
    assert parsed["type"] == "ssh-ed25519"
    assert parsed["comment"] == "me@laptop"
    with pytest.raises(ops.OpsError):
        ops.validate_public_key("ssh-ed25519 not-base64")
    with pytest.raises(ops.OpsError):
        ops.validate_public_key(f"{GOOD_KEY}\nssh-rsa AAAAB3NzaC1yc2EAAAA")
    with pytest.raises(ops.OpsError):
        ops.validate_public_key("command=\"rm -rf /\" ssh-rsa AAAAB3NzaC1yc2EAAAA")
    assert ops.parse_key_line("garbage")["valid"] is False


def test_parse_fingerprint():
    assert ops.parse_fingerprint("256 SHA256:abcDEF me@host (ED25519)") == "SHA256:abcDEF"
    assert ops.parse_fingerprint("") == ""


def test_target_and_tool_validation():
    assert ops.check_target("example.com") == "example.com"
    assert ops.check_target("[2001:db8::1]") == "[2001:db8::1]"
    for bad in ("a b", "a;id", "a|b", "x>y", "$(id)", "a&b", ""):
        with pytest.raises(ops.OpsError):
            ops.check_target(bad)
    with pytest.raises(ops.OpsError):
        ops.check_net_tool("nmap")


def test_backup_name_validation():
    assert ops.check_backup_name("backup-20250101-000000.tar.gz")
    for bad in ("../etc.tar.gz", "a/b.tar.gz", "x.zip", ".hidden.tar.gz",
                "a..b.tar.gz", "-rf.tar.gz"):
        with pytest.raises(ops.OpsError):
            ops.check_backup_name(bad)


def test_container_id_and_remote_validation():
    assert ops.check_container_id("abc123") == "abc123"
    for bad in ("-rf", "a b", "a" * 70, "", "../x"):
        with pytest.raises(ops.OpsError):
            ops.check_container_id(bad)
    assert ops.check_remote("gdrive:backups/panel") == "gdrive:backups/panel"
    with pytest.raises(ops.OpsError):
        ops.check_remote("gdrive:../../etc")


def test_parse_not_after():
    parsed = ops.parse_not_after("notAfter=Jun  1 12:00:00 2027 GMT")
    assert parsed["not_after"].startswith("2027-06-01")
    assert parsed["days_left"] > 0
    assert ops.parse_not_after("garbage") == {}


def test_confirm_actions_registered():
    for action in ("docker", "firewall", "proxy"):
        assert action in confirm.ACTIONS
    assert confirm.action_for("DELETE", "/api/panel/infra/docker/containers/abc") == "docker"
    assert confirm.action_for("POST", "/api/panel/infra/firewall/allow") == "firewall"
    assert confirm.action_for("POST", "/api/panel/infra/firewall/deny") == "firewall"
    assert confirm.action_for("POST", "/api/panel/infra/proxy/reload") == "proxy"
    assert confirm.action_for("POST", "/api/panel/maintenance/updates/apply") == "update"


# ================================================================ 定时任务


def test_cron_read_when_tool_missing(authed, internal_mode, fake_shell):
    fake_shell.bins = set()
    body = authed.get("/api/panel/maintenance/cron").json()
    assert body["capabilities"]["crontab"] is False
    assert body["lines"] == []


def test_cron_read_and_write_roundtrip(authed, internal_mode, fake_shell):
    def read(args, stdin, env):
        if fake_shell.state["cron"]:
            return Result(0, fake_shell.state["cron"], "")
        return Result(1, "", "no crontab for root")

    def write(args, stdin, env):
        fake_shell.state["cron"] = (stdin or b"").decode()
        return Result(0, "", "")

    fake_shell.script["crontab -l"] = read
    fake_shell.script["crontab -"] = write

    body = authed.get("/api/panel/maintenance/cron").json()
    assert body["capabilities"]["crontab"] is True
    assert body["lines"] == []

    r = authed.post("/api/panel/maintenance/cron",
                    json={"lines": ["*/5 * * * * /bin/true", "# 0 1 * * * /bin/false"]})
    assert r.status_code == 200, r.text
    assert r.json()["raw"] == "*/5 * * * * /bin/true\n# 0 1 * * * /bin/false\n"
    assert fake_shell.state["cron"].startswith("*/5 * * * * /bin/true")

    # 第二次写入会先备份上一次的内容
    r = authed.post("/api/panel/maintenance/cron", json={"content": "0 4 * * * /bin/true\n"})
    assert r.status_code == 200, r.text
    assert r.json()["backup"].startswith("crontab.bak.")

    # 非法行（换行注入 / 段数不足）必须 400，且不落到 crontab
    before = fake_shell.state["cron"]
    r = authed.post("/api/panel/maintenance/cron",
                    json={"lines": ["0 * * * * /bin/true\n0 * * * * /bin/false"]})
    assert r.status_code == 400
    r = authed.post("/api/panel/maintenance/cron", json={"lines": ["just-a-command"]})
    assert r.status_code == 400
    assert fake_shell.state["cron"] == before


def test_cron_write_detects_mismatch(authed, internal_mode, fake_shell):
    """读回内容与提交内容不一致时必须回滚并报错。"""
    fake_shell.state["cron"] = "0 1 * * * /bin/true\n"
    fake_shell.script["crontab -l"] = lambda args, stdin, env: Result(
        0, fake_shell.state["cron"], "")
    fake_shell.script["crontab -"] = lambda args, stdin, env: Result(0, "", "")
    r = authed.post("/api/panel/maintenance/cron", json={"content": "0 5 * * * /bin/true\n"})
    assert r.status_code == 500
    assert "校验" in r.json()["detail"]


# ================================================================ 备份


def test_backup_create_list_delete(authed, internal_mode, tmp_path, monkeypatch):
    from app.routes import maintenance_routes

    backup_dir = tmp_path / "backups"
    monkeypatch.setattr(maintenance_routes, "backup_dir", lambda: backup_dir)
    source = tmp_path / "conf"
    source.mkdir()
    (source / "a.txt").write_text("hello", "utf-8")

    body = authed.get("/api/panel/maintenance/backups").json()
    assert body["dir"] == str(backup_dir)
    assert backup_dir.is_dir()

    r = authed.post("/api/panel/maintenance/backups",
                    json={"paths": [str(source)], "name": "backup-test.tar.gz"})
    assert r.status_code == 200, r.text
    assert r.json()["size"] > 0
    assert (backup_dir / "backup-test.tar.gz").is_file()

    names = [item["name"] for item in authed.get("/api/panel/maintenance/backups").json()["items"]]
    assert names == ["backup-test.tar.gz"]

    r = authed.post("/api/panel/maintenance/backups",
                    json={"paths": [str(source)], "name": "backup-test.tar.gz"})
    assert r.status_code == 409

    r = authed.delete("/api/panel/maintenance/backups/backup-test.tar.gz")
    assert r.status_code == 200
    assert not (backup_dir / "backup-test.tar.gz").exists()

    r = authed.delete("/api/panel/maintenance/backups/backup-test.tar.gz")
    assert r.status_code == 404
    r = authed.delete("/api/panel/maintenance/backups/..%2Fetc.tar.gz")
    assert r.status_code in (400, 404)


@pytest.mark.skipif(sys.platform == "win32",
                    reason="受保护路径断言基于 POSIX 路径语义（/、/etc）")
def test_backup_rejects_protected_and_missing_paths(authed, internal_mode, tmp_path, monkeypatch):
    from app.routes import maintenance_routes

    monkeypatch.setattr(maintenance_routes, "backup_dir", lambda: tmp_path / "backups")
    r = authed.post("/api/panel/maintenance/backups", json={"paths": ["/"]})
    assert r.status_code == 400
    r = authed.post("/api/panel/maintenance/backups", json={"paths": ["/etc"]})
    assert r.status_code == 400
    r = authed.post("/api/panel/maintenance/backups", json={"paths": [str(tmp_path / "nope")]})
    assert r.status_code == 400
    r = authed.post("/api/panel/maintenance/backups", json={"paths": []})
    assert r.status_code == 400


def test_backup_remotes_and_upload(authed, internal_mode, tmp_path, monkeypatch, fake_shell):
    from app.routes import maintenance_routes

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    archive = backup_dir / "backup-x.tar.gz"
    archive.write_bytes(b"x")
    monkeypatch.setattr(maintenance_routes, "backup_dir", lambda: backup_dir)

    fake_shell.bins = {"crontab"}
    body = authed.get("/api/panel/maintenance/backups/remotes").json()
    assert body["capabilities"]["rclone"] is False
    r = authed.post("/api/panel/maintenance/backups/backup-x.tar.gz/upload",
                    json={"remote": "gdrive:backups"})
    assert r.status_code == 400
    assert "rclone" in r.json()["detail"]

    fake_shell.bins = {"crontab", "rclone"}
    fake_shell.script["rclone listremotes"] = lambda args, stdin, env: Result(
        0, "gdrive:\ns3:\n", "")
    body = authed.get("/api/panel/maintenance/backups/remotes").json()
    assert [item["label"] for item in body["remotes"]] == ["gdrive", "s3"]

    r = authed.post("/api/panel/maintenance/backups/backup-x.tar.gz/upload",
                    json={"remote": "gdrive:../etc"})
    assert r.status_code == 400
    r = authed.post("/api/panel/maintenance/backups/backup-x.tar.gz/upload",
                    json={"remote": "gdrive:backups"})
    assert r.status_code == 200, r.text
    assert any(call["args"][:2] == ["rclone", "copy"] for call in fake_shell.calls)


# ================================================================ 系统更新


def test_updates_list_and_apply(authed, internal_mode, fake_shell):
    # 查询用 apt list（apt-get 没有 list 子命令），升级用 apt-get install
    fake_shell.bins = {"apt", "apt-get"}
    fake_shell.script["apt list"] = lambda args, stdin, env: Result(
        0, "Listing...\nnodejs/jammy-security 18.19.1 amd64 [upgradable from: 18.19.0]\n"
           "curl/jammy-updates 7.81.0-2 amd64 [upgradable from: 7.81.0-1]\n", "")
    body = authed.get("/api/panel/maintenance/updates").json()
    assert body["capabilities"]["apt"] is True
    assert body["count"] == 2 and body["security"] == 1
    assert body["packages"][0]["name"] == "nodejs"

    # 无确认令牌 → 中间件直接 400
    r = authed.post("/api/panel/maintenance/updates/apply", json={"packages": ["nodejs"]})
    assert r.status_code == 400

    r = authed.post("/api/panel/maintenance/updates/apply", json={"packages": ["nope"]},
                    headers=_confirm(authed, "update"))
    assert r.status_code == 400
    assert "没有可用更新" in r.json()["detail"]

    fake_shell.script["apt-get install"] = lambda args, stdin, env: Result(0, "done", "")
    r = authed.post("/api/panel/maintenance/updates/apply", json={"packages": ["nodejs"]},
                    headers=_confirm(authed, "update"))
    assert r.status_code == 200, r.text
    command = [call["args"] for call in fake_shell.calls
               if call["args"][:2] == ["apt-get", "install"]]
    assert command
    assert command[-1] == ["apt-get", "install", "-y", "--only-upgrade", "--", "nodejs"]
    assert ["apt", "list", "--upgradable"] in [call["args"] for call in fake_shell.calls]


def test_updates_unavailable(authed, internal_mode, fake_shell):
    fake_shell.bins = set()
    body = authed.get("/api/panel/maintenance/updates").json()
    assert body["capabilities"]["apt"] is False and body["count"] == 0
    r = authed.post("/api/panel/maintenance/updates/apply", json={},
                    headers=_confirm(authed, "update"))
    assert r.status_code == 400


# ================================================================ Docker


def _docker_list(args, stdin, env):
    return Result(0, '{"ID":"abc123","Names":"web","Image":"nginx","State":"running",'
                     '"Status":"Up 2 hours","Ports":"0.0.0.0:80->80/tcp"}\n', "")


def test_docker_containers_and_images(authed, internal_mode, fake_shell):
    fake_shell.bins = {"docker"}
    fake_shell.script["docker ps"] = _docker_list
    fake_shell.script["docker images"] = lambda args, stdin, env: Result(
        0, '{"ID":"sha256:1","Repository":"nginx","Tag":"latest","Size":"142MB"}\n', "")
    body = authed.get("/api/panel/infra/docker/containers").json()
    assert body["capabilities"]["docker"] is True
    assert body["containers"][0]["name"] == "web"
    assert body["containers"][0]["state"] == "running"
    images = authed.get("/api/panel/infra/docker/images").json()
    assert images["images"][0]["repository"] == "nginx"


def test_docker_missing_and_illegal_id(authed, internal_mode, fake_shell):
    fake_shell.bins = set()
    body = authed.get("/api/panel/infra/docker/containers").json()
    assert body["capabilities"]["docker"] is False
    assert body["containers"] == []

    fake_shell.bins = {"docker"}
    for bad in ("-rf", "a%20b", "a" * 70):
        r = authed.get(f"/api/panel/infra/docker/containers/{bad}/logs")
        assert r.status_code == 400, bad
    r = authed.post("/api/panel/infra/docker/containers/-rf/action", json={"action": "start"})
    assert r.status_code == 400


def test_docker_action_and_remove(authed, internal_mode, fake_shell):
    fake_shell.bins = {"docker"}
    r = authed.post("/api/panel/infra/docker/containers/abc123/action",
                    json={"action": "restart"})
    assert r.status_code == 200, r.text
    assert ["docker", "restart", "abc123"] in [call["args"] for call in fake_shell.calls]

    r = authed.post("/api/panel/infra/docker/containers/abc123/action", json={"action": "remove"})
    assert r.status_code == 400
    assert "DELETE" in r.json()["detail"]

    # 删除必须带确认令牌（中间件把关）
    r = authed.delete("/api/panel/infra/docker/containers/abc123")
    assert r.status_code == 400
    r = authed.delete("/api/panel/infra/docker/containers/abc123",
                      headers=_confirm(authed, "docker"))
    assert r.status_code == 200, r.text
    assert ["docker", "rm", "abc123"] in [call["args"] for call in fake_shell.calls]


def test_docker_logs(authed, internal_mode, fake_shell):
    fake_shell.bins = {"docker"}
    fake_shell.script["docker logs"] = lambda args, stdin, env: Result(0, "line-1\nline-2\n", "")
    body = authed.get("/api/panel/infra/docker/containers/abc123/logs").json()
    assert body["lines"] == ["line-1", "line-2"]
    assert body["ok"] is True


# ================================================================ 防火墙


def test_firewall_ufw_readonly_and_risky(authed, internal_mode, fake_shell):
    fake_shell.bins = {"ufw"}
    fake_shell.script["ufw status"] = lambda args, stdin, env: Result(
        0, "Status: active\n\n"
           "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
           "[ 2] 5432/tcp                   DENY IN     Anywhere\n", "")
    body = authed.get("/api/panel/infra/firewall").json()
    assert body["backend"] == "ufw" and body["writable"] is True
    assert body["rules"][0]["risky"] is True
    assert body["rules"][1]["risky"] is False


def test_firewall_iptables_backend_is_readonly(authed, internal_mode, fake_shell):
    fake_shell.bins = {"iptables"}
    fake_shell.script["iptables -S"] = lambda args, stdin, env: Result(
        0, "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n", "")
    body = authed.get("/api/panel/infra/firewall").json()
    assert body["backend"] == "iptables" and body["writable"] is False
    assert body["rules"][0]["port"] == "22" and body["rules"][0]["risky"] is True

    r = authed.post("/api/panel/infra/firewall/allow", json={"port": 8080},
                    headers=_confirm(authed, "firewall"))
    assert r.status_code == 400
    assert "ufw" in r.json()["detail"]


def test_firewall_write_requires_token(authed, internal_mode, fake_shell):
    fake_shell.bins = {"ufw"}
    fake_shell.script["ufw allow"] = lambda args, stdin, env: Result(0, "Rule added", "")

    r = authed.post("/api/panel/infra/firewall/allow", json={"port": 8080, "proto": "tcp"})
    assert r.status_code == 400  # 缺少确认令牌

    r = authed.post("/api/panel/infra/firewall/allow", json={"port": 0, "proto": "tcp"},
                    headers=_confirm(authed, "firewall"))
    assert r.status_code == 400
    r = authed.post("/api/panel/infra/firewall/allow", json={"port": 8080, "proto": "icmp"},
                    headers=_confirm(authed, "firewall"))
    assert r.status_code == 400

    r = authed.post("/api/panel/infra/firewall/allow", json={"port": 8080, "proto": "tcp"},
                    headers=_confirm(authed, "firewall"))
    assert r.status_code == 200, r.text
    assert ["ufw", "allow", "8080/tcp"] in [call["args"] for call in fake_shell.calls]

    r = authed.delete("/api/panel/infra/firewall/allow", headers=_confirm(authed, "firewall"))
    assert r.status_code in (404, 405)


# ================================================================ 反向代理 / 证书


def test_proxy_status_and_reload(authed, internal_mode, fake_shell):
    fake_shell.bins = {"nginx", "caddy"}
    fake_shell.script["nginx -v"] = lambda args, stdin, env: Result(
        0, "", "nginx version: nginx/1.24.0")
    fake_shell.script["nginx -t"] = lambda args, stdin, env: Result(
        0, "", "syntax is ok\nconfiguration file /etc/nginx/nginx.conf test is successful")
    fake_shell.script["caddy version"] = lambda args, stdin, env: Result(0, "v2.7.6", "")
    fake_shell.script["nginx -s"] = lambda args, stdin, env: Result(0, "", "")

    body = authed.get("/api/panel/infra/proxy").json()
    assert body["capabilities"]["nginx"] is True
    assert "1.24.0" in body["nginx"]["version"]
    assert body["nginx"]["config_test"]["ok"] is True
    assert body["caddy"]["version"].startswith("v2.7")

    r = authed.post("/api/panel/infra/proxy/reload")
    assert r.status_code == 400  # 缺少确认令牌
    r = authed.post("/api/panel/infra/proxy/reload", headers=_confirm(authed, "proxy"))
    assert r.status_code == 200, r.text
    commands = [call["args"] for call in fake_shell.calls]
    assert ["nginx", "-s", "reload"] in commands or ["systemctl", "reload", "nginx"] in commands

    # nginx -t 不通过时拒绝重载
    fake_shell.script["nginx -t"] = lambda args, stdin, env: Result(1, "", "unknown directive")
    r = authed.post("/api/panel/infra/proxy/reload", headers=_confirm(authed, "proxy"))
    assert r.status_code == 400
    assert "nginx -t" in r.json()["detail"]


def test_proxy_certificates(authed, internal_mode, fake_shell, monkeypatch):
    from app.routes import infra_routes

    monkeypatch.setattr(infra_routes, "_certificate_files",
                        lambda: [{"name": "example.com", "path": "/x/cert.pem"}])
    fake_shell.bins = {"openssl"}
    fake_shell.script["openssl x509"] = lambda args, stdin, env: Result(
        0, "notAfter=Jun  1 12:00:00 2027 GMT\n", "")
    body = authed.get("/api/panel/infra/proxy/certificates").json()
    assert body["certificates"][0]["name"] == "example.com"
    assert body["certificates"][0]["days_left"] > 0
    assert body["certificates"][0]["expiring"] is False

    fake_shell.bins = set()
    body = authed.get("/api/panel/infra/proxy/certificates").json()
    assert body["capabilities"]["openssl"] is False
    assert body["certificates"][0]["not_after"] == ""


# ================================================================ 数据库


def test_databases_detect_and_probe(authed, internal_mode, fake_shell):
    fake_shell.bins = {"redis-cli"}
    body = authed.get("/api/panel/infra/databases").json()
    engines = {item["kind"]: item for item in body["engines"]}
    assert engines["redis-cli"]["available"] is True
    assert engines["mysql"]["available"] is False

    fake_shell.script["redis-cli -h"] = lambda args, stdin, env: Result(
        0, "# Server\nredis_version:7.0.0\n", "")
    r = authed.post("/api/panel/infra/databases/probe",
                    json={"kind": "redis-cli", "host": "127.0.0.1", "password": "s3cret"})
    assert r.status_code == 200, r.text
    assert "redis_version" in r.json()["output"]
    call = fake_shell.calls[-1]
    assert call["args"] == ["redis-cli", "-h", "127.0.0.1", "INFO"]
    assert call["env"] == {"REDISCLI_AUTH": "s3cret"}


def test_databases_probe_validation(authed, internal_mode, fake_shell):
    fake_shell.bins = {"mysql"}
    body = {"kind": "mysql", "host": "127.0.0.1; id"}
    r = authed.post("/api/panel/infra/databases/probe", json=body)
    assert r.status_code == 400
    fake_shell.bins = set()
    r = authed.post("/api/panel/infra/databases/probe", json={"kind": "mysql"})
    assert r.status_code == 400
    r = authed.post("/api/panel/infra/databases/probe", json={"kind": "sqlite"})
    assert r.status_code == 400


def test_database_password_scrubbed(authed, internal_mode, fake_shell):
    fake_shell.bins = {"mysql"}
    fake_shell.script["mysql -h"] = lambda args, stdin, env: Result(
        1, "", "Access denied for user 'root' using password 'p@ss'")
    r = authed.post("/api/panel/infra/databases/probe",
                    json={"kind": "mysql", "user": "root", "password": "p@ss"})
    assert r.status_code == 502
    assert "p@ss" not in r.json()["detail"]


# ================================================================ SSH 公钥


def test_ssh_keys_roundtrip(authed, internal_mode, fake_shell, tmp_path, monkeypatch):
    from app.routes import infra_routes

    key_file = tmp_path / ".ssh" / "authorized_keys"
    monkeypatch.setattr(infra_routes, "_keys_path", lambda: key_file)
    fake_shell.bins = {"ssh-keygen"}
    fake_shell.script["ssh-keygen -lf"] = lambda args, stdin, env: Result(
        0, "256 SHA256:abcDEF me@laptop (ED25519)\n", "")

    body = authed.get("/api/panel/infra/ssh/keys").json()
    assert body["capabilities"]["ssh_keygen"] is True
    assert body["keys"] == []

    r = authed.post("/api/panel/infra/ssh/keys", json={"line": "garbage"})
    assert r.status_code == 400
    r = authed.post("/api/panel/infra/ssh/keys", json={"line": f"{GOOD_KEY}\nssh-rsa AAAA"})
    assert r.status_code == 400

    r = authed.post("/api/panel/infra/ssh/keys", json={"line": GOOD_KEY})
    assert r.status_code == 200, r.text
    assert key_file.read_text("utf-8").strip() == GOOD_KEY
    if os.name == "posix":
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600

    body = authed.get("/api/panel/infra/ssh/keys").json()
    assert body["keys"][0]["fingerprint"] == "SHA256:abcDEF"
    assert body["keys"][0]["comment"] == "me@laptop"

    r = authed.post("/api/panel/infra/ssh/keys", json={"line": GOOD_KEY})
    assert r.status_code == 409

    other = GOOD_KEY.replace("me@laptop", "me@desktop")
    key_file.write_text(f"{other}\n{GOOD_KEY}\n", "utf-8")
    r = authed.request("DELETE", "/api/panel/infra/ssh/keys", json={"line": other})
    assert r.status_code == 200, r.text
    assert key_file.read_text("utf-8").strip() == GOOD_KEY
    r = authed.request("DELETE", "/api/panel/infra/ssh/keys", json={"line": other})
    assert r.status_code == 404


# ================================================================ 网络工具


def test_net_tool_target_validation(authed, internal_mode, fake_shell):
    fake_shell.bins = {"ping"}
    for bad in ("example.com; id", "example.com|cat", "$(id)", "a b"):
        r = authed.post("/api/panel/infra/net/tool", json={"tool": "ping", "target": bad})
        assert r.status_code == 400, bad

    r = authed.post("/api/panel/infra/net/tool", json={"tool": "traceroute", "target": "1.1.1.1"})
    assert r.status_code == 400
    assert "traceroute" in r.json()["detail"]

    fake_shell.script["ping -c"] = lambda args, stdin, env: Result(
        0, "64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=2.1 ms\n", "")
    r = authed.post("/api/panel/infra/net/tool", json={"tool": "ping", "target": "1.1.1.1"})
    assert r.status_code == 200, r.text
    assert "ttl=58" in r.json()["output"]
    assert ["ping", "-c", "4", "-W", "2", "1.1.1.1"] in [c["args"] for c in fake_shell.calls]


def test_net_tool_output_truncated(authed, internal_mode, fake_shell):
    fake_shell.bins = {"ping"}
    fake_shell.script["ping -c"] = lambda args, stdin, env: Result(0, "x" * 100000, "")
    r = authed.post("/api/panel/infra/net/tool", json={"tool": "ping", "target": "1.1.1.1"})
    assert r.status_code == 200
    assert len(r.json()["output"]) == 64 * 1024


# ================================================================ 模式门禁


def test_ops_endpoints_blocked_in_public_mode(authed, fake_shell):
    """公网只读模式下运维端点整体 403（与文件管理、终端一致）。"""
    config_mod.config.set_mode(config_mod.MODE_PUBLIC)
    for url in ("/api/panel/maintenance/cron", "/api/panel/infra/databases",
                "/api/panel/infra/docker/containers"):
        assert authed.get(url).status_code == 403
