"""serverpanel 管理命令：install / start / stop / restart / status / update。

设计原则：

- 同一套命令覆盖两种运行环境：有 systemd 的原生 Linux，以及无 systemd 的
  容器 / PRoot 环境（后者用内置守护脚本 + pidfile + flock 单实例）。
- 配置文件永远在应用目录之外（/etc/serverpanel 或 ~/.config/serverpanel），
  安装与升级绝不触碰它；update 前仍会自动备份一份以防万一。
- update 失败自动回滚到旧版本；在健康检查通过之前，正在运行的服务始终
  运行旧代码（git checkout 只改磁盘文件，不影响内存中的旧进程）。

极端情况处理一览：
- 重复 install / start：幂等，检测到已在运行则直接返回
- cron @reboot 与 Termux Boot 同时拉起守护：supervisor 内 flock 单实例
- 守护被杀：while 循环 3 秒内拉起面板；日志超 10MB 自动轮转
- pidfile 过期/损坏：清理后重建
- update 时仓库有本地改动：默认中止（--force 自动 stash）
- update 时 fetch / pip 失败：中止，旧服务不受影响
- update 后健康检查不过：自动回滚旧版本并重启
- 并发 update：update.lock 文件锁互斥
- 无 .git 的 zip 安装：明确报错并给出迁移指引
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from . import __version__
from .config import config
from .utils import is_root

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows 开发环境
    fcntl = None

BIN = "/usr/local/bin/serverpanel"
SYSTEMD_UNIT = "/etc/systemd/system/serverpanel.service"
SUPERVISOR_NAME = "panel-supervisor.sh"
PID_NAME = ".supervisor.pid"
LOCK_NAME = "update.lock"
LOG_NAME = "panel.log"
LOG_ROTATE_BYTES = 10 * 1024 * 1024
HEALTH_TRIES = 15
HEALTH_DELAY = 1.0


def fail(msg: str) -> int:
    print(f"错误: {msg}", file=sys.stderr)
    return 1


def app_dir() -> Path:
    return Path(__file__).resolve().parent.parent


def _require_root() -> int | None:
    if not is_root():
        print("该操作需要 root 权限：sudo serverpanel ...", file=sys.stderr)
        return 1
    return None


def _systemd_available() -> bool:
    return Path("/run/systemd/system").is_dir() and shutil.which("systemctl") is not None


def _venv_python(target_dir: Path) -> Path:
    return target_dir / ".venv" / "bin" / "python"


# ---------- 安装元数据（记录在配置同目录，升级/启停都从这里读回端口等） ----------

def _metadata_path() -> Path:
    return config.path.parent / "install.json"


def _load_metadata() -> dict:
    try:
        data = json.loads(_metadata_path().read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_metadata(target_dir: Path, host: str, port: int) -> None:
    path = _metadata_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "app_dir": str(target_dir),
        "host": host,
        "port": port,
        "installed_at": int(time.time()),
        "version": __version__,
    }, indent=2, ensure_ascii=False), "utf-8")


# ---------- 生成物：wrapper / systemd unit / supervisor ----------

def write_wrapper(target_dir: Path) -> bool:
    """生成 /usr/local/bin/serverpanel 启动命令。非 root 时跳过并返回 False。"""
    wrapper = (
        "#!/usr/bin/env bash\n"
        f'cd "{target_dir}" || exit 1\n'
        f'exec "{_venv_python(target_dir)}" -m app.main "$@"\n'
    )
    try:
        bin_path = Path(BIN)
        bin_path.write_text(wrapper, "utf-8")
        os.chmod(bin_path, 0o755)
        return True
    except OSError:
        return False


def write_systemd_unit(target_dir: Path, host: str, port: int) -> None:
    unit = f"""[Unit]
Description=ServerPanel 本地系统控制台
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 面板需要 root 才能管理系统、读取日志与执行终端命令
User=root
WorkingDirectory={target_dir}
ExecStart={_venv_python(target_dir)} -m app.main --host {host} --port {port}
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=serverpanel

[Install]
WantedBy=multi-user.target
"""
    Path(SYSTEMD_UNIT).write_text(unit, "utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=False)


def write_supervisor(target_dir: Path, host: str, port: int) -> Path:
    """无 systemd 环境的守护脚本：崩溃拉起 + flock 单实例 + 日志轮转。"""
    script = f"""#!/usr/bin/env bash
# 由 serverpanel install 生成，用于无 systemd 环境（容器 / PRoot）。请勿手改。
set -u
cd "{target_dir}" || exit 1
LOG="{target_dir}/{LOG_NAME}"
LOCK="{target_dir}/.supervisor.lock"

# 单实例：拿不到锁说明已有守护在跑（防 cron @reboot / Termux Boot 重复拉起）
exec 9>"$LOCK"
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || exit 0
fi
echo $$ > "{target_dir}/{PID_NAME}"

rotate_log() {{
  [ -f "$LOG" ] || return 0
  size=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
  [ "$size" -gt {LOG_ROTATE_BYTES} ] && mv -f "$LOG" "$LOG.1"
  return 0
}}

# 退出后 1 秒即重试拉起（升级切换的总间隙 ≈ 1.5s）；
# 连续崩溃超过 10 次放慢到 5 秒，防止瞬时故障拖垮设备
fails=0
while :; do
  rotate_log
  "{_venv_python(target_dir)}" -m app.main --host {host} --port {port} >> "$LOG" 2>&1
  code=$?
  if [ "$code" = "0" ] || [ "$code" = "143" ]; then fails=0; else fails=$((fails+1)); fi
  if [ "$fails" -gt 10 ]; then
    echo "[$(date '+%F %T')] panel exited (code=$code), 连续失败 $fails 次，5s 后重启" >> "$LOG"
    sleep 5
  else
    echo "[$(date '+%F %T')] panel exited (code=$code), 1s 后重启" >> "$LOG"
    sleep 1
  fi
done
"""
    path = target_dir / SUPERVISOR_NAME
    path.write_text(script, "utf-8")
    os.chmod(path, 0o755)
    return path


def write_version_stamp(target_dir: Path) -> str:
    """写 VERSION 标记。来源：git describe > 短哈希 > source-snapshot。"""
    stamp = "source-snapshot"
    if (target_dir / ".git").exists():
        for args in (
            ["git", "describe", "--tags", "--always", "--dirty"],
            ["git", "rev-parse", "--short", "HEAD"],
        ):
            r = subprocess.run(args, cwd=target_dir, capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                stamp = r.stdout.strip()
                break
    (target_dir / "VERSION").write_text(stamp + "\n", "utf-8")
    return stamp


# ---------- 进程管理 ----------

def _pid_alive(pid: int) -> bool:
    if os.path.isdir(f"/proc/{pid}"):
        return True
    if sys.platform != "win32" and hasattr(os, "kill"):
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    return False


def _read_pidfile(target_dir: Path) -> int | None:
    pidfile = target_dir / PID_NAME
    try:
        return int(pidfile.read_text().strip())
    except (OSError, ValueError):
        return None


def _kill_process_group(pid: int, sig: int) -> None:
    if hasattr(os, "killpg"):
        try:
            os.killpg(pid, sig)
            return
        except (ProcessLookupError, PermissionError):
            pass
    with contextlib.suppress(ProcessLookupError, OSError):
        os.kill(pid, sig)


def _stop_supervisor(target_dir: Path) -> bool:
    """停止守护及其整个进程组。返回是否原本在运行。"""
    pid = _read_pidfile(target_dir)
    if pid is None or not _pid_alive(pid):
        (target_dir / PID_NAME).unlink(missing_ok=True)
        return False
    _kill_process_group(pid, signal.SIGTERM)
    for _ in range(20):  # 最多等 10 秒优雅退出
        if not _pid_alive(pid):
            break
        time.sleep(0.5)
    else:
        print("优雅退出超时，强制结束进程组", file=sys.stderr)
        _kill_process_group(pid, signal.SIGKILL)
        time.sleep(1)
    (target_dir / PID_NAME).unlink(missing_ok=True)
    return True


def _start_supervisor(target_dir: Path) -> None:
    sup = target_dir / SUPERVISOR_NAME
    if not sup.exists():
        raise RuntimeError("未找到守护脚本，请先执行 serverpanel --install")
    pid = _read_pidfile(target_dir)
    if pid is not None and _pid_alive(pid):
        print(f"面板守护已在运行（PID {pid}）")
        return
    subprocess.Popen(
        [str(sup)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,  # 等价 setsid：脱离当前终端，killpg 可整组控制
    )


def _panel_pids(target_dir: Path) -> list[int]:
    """找到面板服务进程的 PID（排除本进程与生命周期命令自身）。

    服务进程的特征：本 venv 的 python -m app.main，且不带任何生命周期标志。
    面板 Agent exec 里执行的 `serverpanel --restart` 与服务进程命令行几乎相同，
    靠标志位区分，否则重启命令会把自己误杀。
    """
    marker = f"{target_dir}/.venv/bin/python"
    self_pid = os.getpid()
    lifecycle_flags = {
        "install", "start", "stop", "restart", "status", "update", "show-version",
        "set-password", "enable-internal", "disable-internal", "show-mode",
        "agent-token", "show-agent-token", "revoke-agent-token",
    }
    pids = []
    if not os.path.isdir("/proc"):
        return pids
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == self_pid:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                argv = fh.read().decode("utf-8", "replace").split("\0")
        except OSError:
            continue
        if marker not in " ".join(argv) or "-m" not in argv or "app.main" not in argv:
            continue
        if any(a.startswith("--") and a[2:] in lifecycle_flags for a in argv):
            continue
        pids.append(pid)
    return pids


def _restart_service(target_dir: Path) -> None:
    if _systemd_available():
        subprocess.run(["systemctl", "restart", "serverpanel"], check=False)
    else:
        # 只 TERM 面板服务进程本身，由 supervisor 的 while 循环 3 秒内拉起新进程。
        # 不能 killpg 整组：经面板 exec 执行的 restart 命令也在组内，会自杀，
        # 导致 stop 之后 start 永远执行不到、面板彻底下线。
        pids = _panel_pids(target_dir)
        for pid in pids:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.kill(pid, signal.SIGTERM)
        if not pids:
            print("（未发现运行中的面板进程，将由守护直接拉起）", file=sys.stderr)
            _start_supervisor(target_dir)


# ---------- 健康检查 ----------

def _health_targets(host: str) -> list[str]:
    targets = ["http://127.0.0.1"]
    if host not in ("", "0.0.0.0", "::", "127.0.0.1", "localhost"):
        targets.append(f"http://{host}")  # 面板可能只绑定了特定内网地址
    return targets


def health_check(port: int, host: str = "127.0.0.1",
                 expect_version: str | None = None,
                 tries: int | None = None, delay: float | None = None) -> dict | None:
    """轮询 /healthz。expect_version 给定时，返回旧版本视为未就绪。"""
    tries = HEALTH_TRIES if tries is None else tries
    delay = HEALTH_DELAY if delay is None else delay
    deadline = time.time() + tries * delay
    last: dict | None = None
    while time.time() < deadline:
        for base in _health_targets(host):
            try:
                with urllib.request.urlopen(f"{base}:{port}/healthz", timeout=2) as resp:
                    data = json.loads(resp.read())
                last = data
                if expect_version is None or data.get("version") == expect_version:
                    return data
            except (OSError, ValueError):
                pass
        time.sleep(delay)
    return last  # 不为 None 说明服务在跑但版本不符，调用方据此回滚


# ---------- 子命令实现 ----------

def cmd_install(target_dir: Path, host: str, port: int) -> int:
    guard = _require_root()
    if guard is not None:
        return guard
    if not _venv_python(target_dir).exists():
        return fail("未找到虚拟环境，请通过 install.sh 安装（或先运行 run.sh 一次）")

    print("==> 校验依赖")
    constraints = target_dir / "constraints.txt"
    pip_args = [str(_venv_python(target_dir)), "-m", "pip", "install", "--quiet",
                "-r", str(target_dir / "requirements.txt")]
    if constraints.exists():
        pip_args += ["-c", str(constraints)]
    r = subprocess.run(pip_args)
    if r.returncode != 0:
        return fail("依赖安装失败，请检查网络后重试")

    print(f"==> 生成启动命令 {BIN}")
    if not write_wrapper(target_dir):
        print(f"    （无权限写 {BIN}，已跳过；可直接用 {target_dir}/{SUPERVISOR_NAME} 或 "
              f"{_venv_python(target_dir)} -m app.main 启动）")

    stamp = write_version_stamp(target_dir)
    _save_metadata(target_dir, host, port)

    if _systemd_available():
        print("==> 安装 systemd 服务")
        write_systemd_unit(target_dir, host, port)
        subprocess.run(["systemctl", "enable", "--now", "serverpanel"], check=False)
        print("    守护方式：systemd（开机自启，崩溃自动重启）")
    else:
        print("==> 未检测到 systemd，安装守护脚本（崩溃自动拉起）")
        write_supervisor(target_dir, host, port)
        _start_supervisor(target_dir)
        print("    守护方式：panel-supervisor.sh（崩溃 1 秒内自动拉起，flock 单实例）")
        print("    注意：容器 / PRoot 环境的开机自启需在容器层配置，例如 Termux：")
        print("    安装 Termux:Boot APP 并添加 proot-distro login 启动脚本，")
        print("    并在容器 root 的 crontab 中加 @reboot 拉起守护。")

    print()
    print(f"==> 安装完成（版本标记 {stamp}）")
    print(f"    访问: http://<服务器IP>:{port}    健康: /healthz")
    print("    常用: serverpanel --status | --stop | --restart | --update | --show-version")
    return 0


def cmd_start(target_dir: Path) -> int:
    meta = _load_metadata()
    if _systemd_available():
        subprocess.run(["systemctl", "start", "serverpanel"], check=False)
        subprocess.run(["systemctl", "status", "serverpanel", "--no-pager", "--lines=3"], check=False)
        return 0
    port = int(meta.get("port") or 8787)
    host = str(meta.get("host") or "0.0.0.0")
    try:
        _start_supervisor(target_dir)
    except RuntimeError as exc:
        return fail(str(exc))
    if health_check(port, host):
        print("面板已启动并通过健康检查")
        return 0
    print("守护已拉起，但健康检查未通过，请查看 " + str(target_dir / LOG_NAME), file=sys.stderr)
    return 1


def cmd_stop(target_dir: Path) -> int:
    if _systemd_available():
        subprocess.run(["systemctl", "stop", "serverpanel"], check=False)
        print("服务已停止")
        return 0
    # 注意：经面板 exec 执行 --stop 时，killpg 也会终止调用链本身（响应不会返回），
    # 但停止结果正确；残留 pidfile 由下一次 --start 自愈。
    if _stop_supervisor(target_dir):
        print("面板守护已停止")
        return 0
    print("面板未在运行")
    return 0


def cmd_status(target_dir: Path) -> int:
    meta = _load_metadata()
    stamp = ""
    version_file = target_dir / "VERSION"
    if version_file.exists():
        stamp = version_file.read_text().strip()
    if _systemd_available():
        r = subprocess.run(["systemctl", "is-active", "serverpanel"],
                           capture_output=True, text=True)
        state = r.stdout.strip() or "unknown"
        print(f"systemd 服务: {state}")
    else:
        pid = _read_pidfile(target_dir)
        running = pid is not None and _pid_alive(pid)
        print(f"守护进程: {'运行中 (PID %d)' % pid if running else '未运行'}")
    port = int(meta.get("port") or 8787)
    health = health_check(port, str(meta.get("host") or "127.0.0.1"), tries=2, delay=0.5)
    if health:
        print(f"健康检查: 正常  version={health.get('version')}  "
              f"initialized={health.get('initialized')}")
    else:
        print(f"健康检查: 无响应（端口 {port}）")
    if stamp:
        print(f"版本标记: {stamp}")
    return 0


def cmd_restart(target_dir: Path) -> int:
    _restart_service(target_dir)
    print("已发送重启指令，守护将在数秒内拉起新进程")
    return 0


# ---------- update ----------

def _git(target_dir: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=target_dir, capture_output=True, text=True)


@contextlib.contextmanager
def _update_lock(target_dir: Path):
    lock_path = target_dir / LOCK_NAME
    fh = open(lock_path, "w")
    locked = False
    if fcntl is not None:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError:
            fh.close()
            raise RuntimeError("另一个 update 正在进行中")
    try:
        yield
    finally:
        if locked and fcntl is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


def _pip_install(target_dir: Path) -> int:
    constraints = target_dir / "constraints.txt"
    args = [str(_venv_python(target_dir)), "-m", "pip", "install", "--quiet",
            "-r", str(target_dir / "requirements.txt")]
    if constraints.exists():
        args += ["-c", str(constraints)]
    r = subprocess.run(args)
    return r.returncode


def _installed_version(target_dir: Path) -> str:
    r = subprocess.run(
        [str(_venv_python(target_dir)), "-c", "from app import __version__; print(__version__)"],
        cwd=target_dir, capture_output=True, text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else ""


def cmd_update(target_dir: Path, ref: str, force: bool) -> int:
    guard = _require_root()
    if guard is not None:
        return guard
    if not (target_dir / ".git").exists():
        return fail("当前是 zip/快照安装（无 .git），无法增量升级。\n"
                    f"    请参照 README 迁移为 git 部署：克隆新目录 → 复用配置 → 停旧起新。")
    meta = _load_metadata()
    port = int(meta.get("port") or 8787)
    host = str(meta.get("host") or "0.0.0.0")

    try:
        with _update_lock(target_dir):
            return _do_update(target_dir, ref, force, host, port)
    except RuntimeError as exc:
        return fail(str(exc))


def _do_update(target_dir: Path, ref: str, force: bool, host: str, port: int) -> int:
    current = _git(target_dir, "rev-parse", "HEAD")
    if current.returncode != 0:
        return fail(f"读取当前版本失败: {current.stderr.strip()}")

    dirty = _git(target_dir, "status", "--porcelain")
    if dirty.returncode != 0:
        return fail("git status 失败，仓库状态异常")
    if dirty.stdout.strip():
        if not force:
            return fail("仓库存在本地改动，为避免丢失已中止。确认丢弃/保留后可 "
                        "加 --force（改动会先自动 stash）。改动列表:\n" + dirty.stdout)
        stash = _git(target_dir, "stash", "push", "-u", "-m", "serverpanel update autostash")
        if stash.returncode != 0:
            return fail(f"stash 失败: {stash.stderr.strip()}")
        print("本地改动已自动 stash")

    # 配置备份：update 原则上不碰配置，这是最后防线
    backup = config.path.with_name(f"{config.path.name}.bak.{time.strftime('%Y%m%d%H%M%S')}")
    if config.path.exists():
        shutil.copy2(config.path, backup)
        print(f"配置已备份: {backup}")

    print(f"==> 拉取远端（{ref}）")
    fetch = _git(target_dir, "fetch", "origin", "--prune")
    if fetch.returncode != 0:
        return fail(f"git fetch 失败（不影响正在运行的服务）: {fetch.stderr.strip()}")

    target = _git(target_dir, "rev-parse", "--verify", ref)
    if target.returncode != 0:
        return fail(f"目标 {ref} 不存在: {target.stderr.strip()}")
    if target.stdout.strip() == current.stdout.strip():
        print("已是最新版本，无需升级")
        return 0

    print(f"==> 切换代码 {current.stdout.strip()[:10]} -> {target.stdout.strip()[:10]}")
    checkout = _git(target_dir, "checkout", target.stdout.strip())
    if checkout.returncode != 0:
        return fail(f"git checkout 失败: {checkout.stderr.strip()}")

    print("==> 安装依赖")
    if _pip_install(target_dir) != 0:
        _git(target_dir, "checkout", current.stdout.strip())
        return fail("依赖安装失败，已回退代码（服务未重启，仍在运行旧版本）")

    new_version = _installed_version(target_dir)
    print(f"==> 重启服务（新版本 {new_version or '未知'}）")
    _restart_service(target_dir)

    print("==> 健康检查")
    health = health_check(port, host, expect_version=new_version or None)
    if health is None:
        print("新版本未通过健康检查，回滚中…", file=sys.stderr)
        _git(target_dir, "checkout", current.stdout.strip())
        _pip_install(target_dir)
        _restart_service(target_dir)
        rolled = health_check(port, host, expect_version=None)
        if rolled is None:
            return fail("回滚后健康检查仍失败！请立即查看服务日志排查。")
        print("已回滚到旧版本并恢复运行")
        return 1

    stamp = write_version_stamp(target_dir)
    _save_metadata(target_dir, host, port)
    print(f"==> 升级完成: {stamp}（version={health.get('version')}）")
    print("    提示：重启后所有浏览器会话已失效，需重新登录。")
    return 0
