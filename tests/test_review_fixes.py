"""2.0 审查修复的回归测试。

覆盖本轮修掉的几类真实缺陷：

- 配置文件损坏时不能降级成「未初始化」（否则可被接管、并被空配置覆盖）；
- SSRF 的 IPv4-mapped IPv6 绕过；
- crontab 环境变量行（PATH=/MAILTO=）不应阻塞整份保存；
- 确认令牌的一次性与会话绑定；
- 目录列举的截断元数据、命令输出上限、录制清理；
- `shell.run(stdin=...)` 必须真的把内容喂给子进程（crontab 写入依赖它）；
- readonly 令牌不得经 `/proc/<pid>/root|cwd|fd` 魔法链接读到真实根目录文件。
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

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


# ================================================================ stdin 管道（P0）
#
# 2026-10-26 第三方审查动态复现：`shell.run(..., stdin=...)` 从不给子进程建 stdin
# 管道（kwargs 只有 stdout/stderr），内容被静默丢弃。crontab 写入正是靠它，
# systemd 下子进程继承 /dev/null → `crontab -` 读到 EOF → 安装空 crontab。


def test_shell_run_delivers_stdin():
    code = "import sys; sys.stdout.write(sys.stdin.read())"
    result = asyncio.run(shell.run([sys.executable, "-c", code], timeout=30,
                                   stdin=b"AEGIS-STDIN-MARKER\n"))
    assert result.code == 0
    assert "AEGIS-STDIN-MARKER" in result.out


def test_shell_run_without_stdin_is_unchanged():
    """不传 stdin 时不应额外建管道（避免命令等待输入而挂住）。"""
    result = asyncio.run(shell.run([sys.executable, "-c", "print('no-stdin')"], timeout=30))
    assert result.code == 0 and "no-stdin" in result.out


# ================================================================ /proc 魔法链接


@pytest.mark.parametrize("command", [
    "cat /proc/self/root/etc/hostname",
    "cat /proc/1/root/etc/shadow",
    "cat /proc/1/root/root/.ssh/id_rsa",
    "cat /proc/1/cwd/.env",
    "cat /proc/self/fd/3",
    "stat /proc/1/root/etc/shadow",
    "du /proc/1/root/etc",
])
def test_readonly_scope_blocks_proc_magic_links(command):
    from app.scopes import command_allowed

    assert command_allowed("readonly", [], command) is False


@pytest.mark.parametrize("command", [
    "cat /proc/meminfo",
    "cat /proc/loadavg",
    "cat /sys/class/thermal/thermal_zone0/temp",
    "du /proc/self/status",
])
def test_readonly_scope_keeps_plain_proc_reads(command):
    from app.scopes import command_allowed

    assert command_allowed("readonly", [], command) is True


# ================================================================ --config 隔离
#
# 2026-10-26 审查 P1-5 动态复现：`--config` 只在 main() 里赋值，而审计 / 指标 /
# 回收站 / 应用注册表都是导入期单例，目录早就按默认配置定型 → 自定义配置路径
# 只换了主配置，其余状态仍写默认目录（多实例会互相混写）。


def test_config_flag_isolates_all_state_dirs(tmp_path):
    import subprocess
    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    target = tmp_path / "custom" / "config.json"
    code = (
        "import sys\n"
        f"sys.argv = ['serverpanel', '--config', {str(target)!r}]\n"
        "from app import audit, apps, metrics_store, trash\n"
        "print(audit.audit._dir)\n"
        "print(metrics_store.store.path)\n"
        "print(trash.trash._dir)\n"
        "print(apps.supervisor.registry.path)\n"
    )
    env = {k: v for k, v in os.environ.items()
           if k not in ("SERVERPANEL_CONFIG", "SERVERPANEL_APPS_DIR",
                        "SERVERPANEL_METRICS_DB")}
    out = subprocess.run([sys.executable, "-c", code], cwd=str(repo),
                         capture_output=True, text=True, env=env, timeout=120)
    assert out.returncode == 0, out.stderr
    paths = [Path(line.strip()) for line in out.stdout.splitlines() if line.strip()]
    assert len(paths) == 4, out.stdout
    audit_dir, metrics_db, trash_dir, registry = paths
    base = str(target.parent)
    for path in (audit_dir, metrics_db, registry):
        assert str(path).startswith(base), f"{path} 未跟随 --config（期望在 {base} 下）"
    # 回收站是**有意**不跟随 --config 的：root 部署固定在 /var/lib/serverpanel/trash
    # （回收站可能几个 GB，不能塞进 /etc）；非 root 才退到配置目录旁。
    # 要给它单独指定位置用 SERVERPANEL_TRASH_DIR。
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
        assert str(trash_dir) == "/var/lib/serverpanel/trash", trash_dir
    else:
        assert str(trash_dir).startswith(base), f"非 root 时回收站应随配置目录：{trash_dir}"


# ================================================================ 升级不打断托管应用


def _sleeper_command(tmp_path) -> str:
    script = tmp_path / "sleeper.py"
    script.write_text(
        "import time\nprint('adopt-me', flush=True)\nfor _ in range(240):\n    time.sleep(0.5)\n",
        encoding="utf-8",
    )
    return f"{Path(sys.executable).as_posix()} {script.as_posix()}"


def _app_payload(tmp_path) -> dict:
    import time as _time

    return {
        "id": "adopt01", "name": "sleeper", "command": _sleeper_command(tmp_path),
        "cwd": str(tmp_path), "env": {}, "autostart": False, "restart": "never",
        "max_restarts": 1, "restart_delay": 0.5, "description": "",
        "created_at": int(_time.time()),
    }


def test_survive_marker_is_one_shot_and_expires(tmp_path, monkeypatch):
    from app import apps as apps_mod

    monkeypatch.setattr(apps_mod, "survive_marker_path",
                        lambda: tmp_path / ".apps-survive")
    assert apps_mod.consume_survive() is False          # 没有标记
    apps_mod.mark_survive()
    assert apps_mod.consume_survive() is True           # 一次性
    assert apps_mod.consume_survive() is False
    apps_mod.mark_survive(ttl=-1)                       # 已过期（重启没发生）
    assert apps_mod.consume_survive() is False


def test_supervisor_adopts_apps_across_panel_restart(tmp_path):
    """升级/重启：旧面板 keep_apps 退出，新面板按 pidfile 接管，绝不拉起第二份。"""
    import psutil

    from app import apps as apps_mod

    registry_path = tmp_path / "apps" / "apps.json"
    log_dir = tmp_path / "apps" / "logs"
    seed = apps_mod.Registry(registry_path)
    seed.add(_app_payload(tmp_path))

    async def scenario() -> int:
        first = apps_mod.Supervisor(apps_mod.Registry(registry_path), log_dir=log_dir)
        await first.serve()
        await first.start("adopt01")
        pid = first.get("adopt01")["runtime"]["pid"]
        assert pid
        await first.shutdown(keep_apps=True)            # 模拟升级退出
        return pid

    pid = asyncio.run(scenario())
    try:
        assert psutil.pid_exists(pid), "升级退出时不能杀死托管进程"
        # 交接凭据必须留着，否则新实例既无法接管也无法避免重复拉起
        assert (log_dir / "sleeper.pid").exists()

        async def adopt() -> dict:
            second = apps_mod.Supervisor(apps_mod.Registry(registry_path), log_dir=log_dir)
            await second.serve()
            snap = second.get("adopt01")["runtime"]
            assert snap["status"] == "running", snap
            assert snap["pid"] == pid, snap             # 接管，不是新拉一份
            await second.shutdown()                     # 正常停面板 → 应一并收走
            return snap

        asyncio.run(adopt())
        deadline = time.time() + 8
        while time.time() < deadline and psutil.pid_exists(pid):
            time.sleep(0.2)
        assert not psutil.pid_exists(pid), "正常停止面板时必须结束托管进程"
    finally:
        if psutil.pid_exists(pid):
            psutil.Process(pid).kill()


def test_adopt_ignores_recycled_pid(tmp_path):
    """pidfile 里的 PID 被内核回收给别的进程时，绝不能把别人的进程当成自己的。"""
    from app import apps as apps_mod

    registry_path = tmp_path / "apps" / "apps.json"
    log_dir = tmp_path / "apps" / "logs"
    seed = apps_mod.Registry(registry_path)
    seed.add({**_app_payload(tmp_path), "command": "no-such-binary-for-adopt --flag"})

    sup = apps_mod.Supervisor(apps_mod.Registry(registry_path), log_dir=log_dir)
    app = sup.registry.get("adopt01")
    sup.log_dir.mkdir(parents=True, exist_ok=True)
    sup._write_pidfile(app, os.getpid())      # 一个活着但命令行不匹配的 PID
    assert sup.adopt_all() == 0
    runtime = sup.runtimes.get("adopt01")
    assert runtime is not None and runtime.adopted is False and runtime.pid is None
    assert not sup._pid_path(app).exists(), "不匹配的 pidfile 必须清掉，避免反复误判"


# ================================================================ 网络工具目标校验


@pytest.mark.parametrize("value", ["-x127.0.0.1:8888", "-f", "-s65000", "-HX-A:1", "-o"])
def test_net_target_rejects_option_like_values(value):
    """目标会被追加到固定 argv 尾部：`-x…` 对 curl 是 --proxy，`-f` 对 ping 是泛洪。"""
    from app.ops import OpsError, check_target

    with pytest.raises(OpsError):
        check_target(value)


@pytest.mark.parametrize("value", ["1.1.1.1", "example.com", "[2001:db8::1]"])
def test_net_target_still_accepts_normal_values(value):
    from app.ops import check_target

    assert check_target(value) == value


def test_net_http_task_goes_through_ssrf(authed, internal_mode):
    """常用操作的 net-http 走 shell=True 且能自定义 URL：必须过 SSRF，不能当跳板。"""
    r = authed.post("/api/panel/tasks/net-http/run",
                    json={"params": {"url": "http://127.0.0.1:1/"}})
    assert r.status_code == 400, r.text
    assert "内网" in r.json()["detail"] or "回环" in r.json()["detail"], r.text


# ================================================================ 覆盖写原子性


def test_write_is_atomic_and_keeps_mode(authed, internal_mode, tmp_path):
    import stat as stat_mod

    target = tmp_path / "conf.txt"
    target.write_text("old", encoding="utf-8")
    os.chmod(target, 0o640)
    r = authed.post("/api/files/write", json={"path": str(target), "content": "new"})
    assert r.status_code == 200, r.text
    assert target.read_text(encoding="utf-8") == "new"
    if os.name == "posix":
        # mkstemp 默认 0600：不做权限继承就会把 0640 的配置悄悄改成 0600
        assert stat_mod.S_IMODE(target.stat().st_mode) == 0o640
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".serverpanel-write-")]
    assert not leftovers, f"临时文件必须清理：{leftovers}"


# ================================================================ 长连接续期


def test_session_still_valid_tracks_revocation():
    from app.auth import session_still_valid, sessions

    token = sessions.create("127.0.0.1", "pytest-ws")
    assert session_still_valid(token) is True
    sessions.revoke(token)              # 安全中心「踢出会话」/ 改密
    assert session_still_valid(token) is False
    assert session_still_valid(None) is False


# ================================================================ 升级健康检查


def test_health_check_rejects_version_mismatch(monkeypatch):
    """版本不符必须判失败，否则升级会把"旧进程还在响应"当成成功。"""
    from app import manage

    class _Resp:
        def __init__(self, payload: dict) -> None:
            self._payload = payload

        def read(self) -> bytes:
            return json.dumps(self._payload).encode()

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> bool:
            return False

    monkeypatch.setattr(manage.urllib.request, "urlopen",
                        lambda *a, **k: _Resp({"ok": True, "version": "9.9.9"}))
    assert manage.health_check(8787, "127.0.0.1", expect_version="2.0",
                               tries=1, delay=0.01) is None
    # 不校验版本时照常成功（--status 这类调用）
    assert manage.health_check(8787, "127.0.0.1", tries=1, delay=0.01)["ok"] is True


# ================================================================ TOTP 重放


def test_totp_code_cannot_be_replayed():
    """同一个 30 秒窗口里的同一个动态码只能用一次（否则"一次性"是错觉）。"""
    from app import totp as totp_mod

    secret = totp_mod.generate_secret()
    at = 1_700_000_000.0
    current = totp_mod.code(secret, at)
    assert totp_mod.verify(secret, current, at) is True
    assert totp_mod.verify_once(secret, current, at) is True
    assert totp_mod.verify_once(secret, current, at) is False      # 重放
    # 下一个时间步的新码照常可用
    later = at + 30
    assert totp_mod.verify_once(secret, totp_mod.code(secret, later), later) is True


# ================================================================ 并发启动


def test_concurrent_start_spawns_single_process(tmp_path):
    """双击启动 / 客户端超时重试 / 自启与手动启动并发，只能拉起一个进程。"""
    import psutil

    from app import apps as apps_mod

    registry_path = tmp_path / "apps2" / "apps.json"
    log_dir = tmp_path / "apps2" / "logs"
    apps_mod.Registry(registry_path).add(_app_payload(tmp_path))

    async def scenario() -> tuple[set, dict]:
        sup = apps_mod.Supervisor(apps_mod.Registry(registry_path), log_dir=log_dir)
        await sup.serve()
        results = await asyncio.gather(sup.start("adopt01"), sup.start("adopt01"))
        pids = {r["runtime"]["pid"] for r in results}
        record = sup._read_pidfile(sup.registry.get("adopt01"))
        await sup.shutdown()
        return pids, record

    pids, record = asyncio.run(scenario())
    assert len(pids) == 1, f"并发启动拉起了 {len(pids)} 个进程：{pids}"
    only = pids.pop()
    assert record.get("pid") == only, "pidfile 必须指向真正在跑的那个进程"
    deadline = time.time() + 8
    while time.time() < deadline and psutil.pid_exists(only):
        time.sleep(0.2)
    assert not psutil.pid_exists(only), "停止面板必须收走唯一那个进程"


