"""2.0 审查修复的回归测试。

覆盖本轮修掉的几类真实缺陷：

- 配置文件损坏时不能降级成「未初始化」（否则可被接管、并被空配置覆盖）；
- SSRF 的 IPv4-mapped IPv6 绕过；
- crontab 环境变量行（PATH=/MAILTO=）不应阻塞整份保存；
- 确认令牌的一次性与会话绑定；
- 目录列举的截断元数据、命令输出上限、录制清理。
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

from app import config as config_mod
from app import confirm, recording, shell
from app.auth import sessions
from app.config import COOKIE_NAME, Config
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def authed(client):
    token = sessions.create("127.0.0.1", "pytest-review")
    client.cookies.set(COOKIE_NAME, token)
    yield client
    client.cookies.clear()


@pytest.fixture()
def internal_mode():
    config_mod.config.set_mode(config_mod.MODE_INTERNAL)
    yield
    config_mod.config.set_mode(config_mod.MODE_PUBLIC)


# ================================================================ 配置加载


def test_config_keeps_old_data_when_file_corrupt(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"mode": "internal", "password_hash": "keep-me"}),
                    encoding="utf-8")
    cfg = Config(path)
    assert cfg.mode == "internal" and cfg.load_error is None

    path.write_text("{ not json", encoding="utf-8")
    assert cfg.reload_if_changed() is True
    # 关键：坏文件不能把内存配置清空（否则 = 未初始化 = 可被 setup 接管）
    assert cfg.mode == "internal"
    assert cfg.data.get("password_hash") == "keep-me"
    assert cfg.load_error

    with pytest.raises(ValueError):
        cfg.set_password("Str0ng-Passw0rd!2026", only_if_uninitialized=True)


def test_config_rejects_non_object_top_level(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"mode": "internal"}), encoding="utf-8")
    cfg = Config(path)
    path.write_text("[]", encoding="utf-8")
    cfg.reload_if_changed()
    assert cfg.mode == "internal"          # 顶层不是对象：保留旧值，不 500
    assert cfg.load_error


def test_config_recovers_after_file_fixed(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{ broken", encoding="utf-8")
    cfg = Config(path)
    assert cfg.load_error
    path.write_text(json.dumps({"mode": "internal"}), encoding="utf-8")
    cfg.reload_if_changed()
    assert cfg.mode == "internal" and cfg.load_error is None


def test_config_keeps_old_data_when_file_disappears(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"mode": "internal", "password_hash": "keep-me"}),
                    encoding="utf-8")
    cfg = Config(path)
    path.unlink()
    cfg.reload_if_changed()
    # 已初始化的部署：文件消失时保留内存配置，不能退回「未初始化」
    assert cfg.data.get("password_hash") == "keep-me"
    assert cfg.load_error


# ================================================================ SSRF


@pytest.mark.parametrize("ip", ["::ffff:127.0.0.1", "::ffff:169.254.169.254",
                                "::ffff:10.0.0.1", "::ffff:192.168.1.1"])
def test_ssrf_blocks_ipv4_mapped_ipv6(ip):
    from app.ssrf import _ip_blocked

    assert _ip_blocked(ip) is True


def test_ssrf_allows_public_address():
    from app.ssrf import _ip_blocked

    assert _ip_blocked("93.184.216.34") is False


# ================================================================ crontab 环境行


@pytest.mark.parametrize("line", ["PATH=/usr/local/bin:/usr/bin",
                                  "MAILTO=root", "SHELL=/bin/bash"])
def test_cron_env_lines_are_valid(line):
    from app.ops import parse_cron_line, validate_cron_line

    assert validate_cron_line(line) == line
    item = parse_cron_line(line)
    assert item["error"] == "" and item["command"] == line


def test_cron_still_rejects_bad_schedule():
    from app.ops import OpsError, validate_cron_line

    with pytest.raises(OpsError):
        validate_cron_line("1 2 3 echo hi")


# ================================================================ 确认令牌


def test_confirm_token_is_single_use():
    token = confirm.issue("power", "session-a")["token"]
    assert confirm.verify(token, "power", "session-a") is True
    assert confirm.verify(token, "power", "session-a") is False   # 重放


def test_confirm_token_bound_to_session_and_action():
    token = confirm.issue("power", "session-a")["token"]
    assert confirm.verify(token, "power", "session-b") is False   # 跨会话
    assert confirm.verify(token, "update", "session-a") is False  # 跨动作
    assert confirm.verify(token, "power", "session-a") is True    # 仍未消费


# ================================================================ 文件列表截断


def test_files_list_reports_truncation(authed, internal_mode, tmp_path):
    for index in range(6):
        (tmp_path / f"file-{index}.txt").write_text("x", encoding="utf-8")
    data = authed.get("/api/files/list",
                      params={"path": str(tmp_path), "limit": 2}).json()
    assert data["total"] == 6
    assert data["truncated"] is True
    assert len(data["entries"]) == 2
    # limit 由服务端钳制，客户端传超大值不会绕过上限
    big = authed.get("/api/files/list",
                     params={"path": str(tmp_path), "limit": 10 ** 9}).json()
    assert big["truncated"] is False and len(big["entries"]) == 6


# ================================================================ 命令输出上限


def test_shell_output_is_capped():
    code = "import sys; sys.stdout.write('x' * 2000000)"
    result = asyncio.run(shell.run([sys.executable, "-c", code], timeout=30))
    assert result.code == 0
    assert len(result.out) <= shell.MAX_OUTPUT


def test_shell_timeout_kills_process_group():
    # 子进程再 fork 一个孙进程，超时后整组都应被清理（否则会留下孤儿）
    code = ("import subprocess, sys, time; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
            "time.sleep(60)")
    started = time.time()
    result = asyncio.run(shell.run([sys.executable, "-c", code], timeout=1))
    assert result.code == -1 and "超时" in result.err
    assert time.time() - started < 15


# ================================================================ 录制清理


def test_recording_cleanup_removes_expired(tmp_path, monkeypatch):
    monkeypatch.setattr(recording, "recordings_dir", lambda: tmp_path)
    rec = recording.Recorder(1024 * 1024).start()
    assert rec is not None and rec.path is not None
    rec.output("old")
    rec.close()
    path = rec.path
    old = time.time() - (recording.RETENTION_DAYS + 5) * 86400
    os.utime(path, (old, old))
    assert recording.cleanup_old() >= 1
    assert not path.exists()
