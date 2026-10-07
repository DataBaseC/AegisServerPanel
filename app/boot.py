"""开机自启链路：体检 + 容器 crontab 兜底 + 时区设置。

背景：面板的自启链是 5 截串起来的（设备 → 守护 → 面板 → 托管应用 → 设备保活），
其中"设备/容器拉起守护"这一截历史上完全靠手工，且面板里看不到断在哪。
本模块把这截做成**可体检（只读）**，并在容器内提供**可回滚的 crontab 写入**。

原则：

- 探测全部是读操作（读文件 / 读命令输出），不产生副作用
- 写操作单独成函数，做「备份 → 去重 → 原子写 → 读回校验 → 失败回滚」
- 容器内改不到的层面（Android 宿主的 Termux:Boot、电池优化）只报告 + 给处方，不假装能改
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import config
from .prefs import PrefsError, prefs

SUPERVISOR_NAME = "panel-supervisor.sh"
TERMUX_PREFIX = Path("/data/data/com.termux/files/usr")
TERMUX_BOOT_DIR = Path("/data/data/com.termux/files/home/.termux/boot")
CRON_TAG = "serverpanel-supervisor"      # 便于识别与去重的注释标记
CRON_TIMEOUT = 10

# 体检结论
STATE_OK = "ok"
STATE_BROKEN = "broken"
STATE_MANUAL = "manual"
STATE_UNKNOWN = "unknown"

COMMON_TIMEZONES = [
    "Asia/Shanghai", "Asia/Hong_Kong", "Asia/Taipei", "Asia/Tokyo", "Asia/Singapore",
    "UTC", "Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles",
]


class BootError(RuntimeError):
    """自启链路操作失败（调用方翻成 HTTP 400/500）。"""


@dataclass
class Link:
    id: str
    title: str
    state: str
    detail: str
    evidence: str = ""
    manual: bool = False
    actions: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "state": self.state,
            "detail": self.detail, "evidence": self.evidence,
            "manual": self.manual, "actions": self.actions,
        }


# ---------------------------------------------------------------- 平台探测

def _read_text(path: str | Path, limit: int = 4096) -> str:
    try:
        return Path(path).read_text("utf-8", "replace")[:limit].strip()
    except OSError:
        return ""


def detect_platform() -> dict:
    """判断当前运行环境：systemd / 容器 / PRoot / Termux。"""
    init_comm = _read_text("/proc/1/comm") or "unknown"
    kernel = _read_text("/proc/version", 512)
    systemd = os.path.isdir("/run/systemd/system") and shutil.which("systemctl") is not None
    proot = "proot" in kernel.lower()
    container = proot or init_comm not in ("systemd", "init") or os.path.exists("/.dockerenv")
    return {
        "init": init_comm.splitlines()[0] if init_comm else "unknown",
        "systemd": systemd,
        "kernel": kernel.splitlines()[0] if kernel else "",
        "proot": proot,
        "container": container,
        "cron": shutil.which("crontab") is not None,
        "termux": {
            "present": TERMUX_PREFIX.exists(),
            # as_posix：Windows 开发机上也会渲染成 /data/data/... 形式，避免给出反斜杠路径
            "prefix": TERMUX_PREFIX.as_posix(),
            "boot_dir": TERMUX_BOOT_DIR.as_posix(),
            "boot_dir_exists": TERMUX_BOOT_DIR.is_dir(),
        },
        "python": sys.executable,
    }


# ---------------------------------------------------------------- crontab

def _crontab_read() -> tuple[bool, str]:
    """读取当前 crontab。返回 ``(可用, 内容)``；不可用时内容为空串。"""
    if shutil.which("crontab") is None:
        return False, ""
    try:
        proc = subprocess.run(["crontab", "-l"], capture_output=True, text=True,
                              timeout=CRON_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return False, ""
    if proc.returncode == 0:
        return True, proc.stdout
    # 首次没有 crontab 时多数实现返回 1 且 stderr 提示 "no crontab for xxx"
    if "no crontab" in (proc.stderr or "").lower():
        return True, ""
    return False, ""


def _crontab_write(content: str) -> None:
    """原子写入 crontab：先写临时文件再交给 crontab，避免管道半截写入。"""
    fd, tmp_name = tempfile.mkstemp(prefix="sp-crontab-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        proc = subprocess.run(["crontab", tmp_name], capture_output=True, text=True,
                              timeout=CRON_TIMEOUT)
        if proc.returncode != 0:
            raise BootError((proc.stderr or proc.stdout or "crontab 写入失败").strip()[:400])
    except (OSError, subprocess.SubprocessError) as exc:
        raise BootError(f"crontab 写入失败：{exc}")
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)


def _backup_crontab(content: str) -> Path | None:
    if not content.strip():
        return None
    path = Path(config.path).parent / f"crontab.backup.{int(time.time())}"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, "utf-8")
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
        return path
    except OSError:
        return None


def _strip_supervisor_lines(content: str) -> tuple[str, int]:
    """移除已有的守护自启行 / 标记注释，返回 ``(剩余内容, 移除条数)``。"""
    kept, removed = [], 0
    for line in content.splitlines():
        stripped = line.strip()
        if CRON_TAG in stripped or SUPERVISOR_NAME in stripped:
            removed += 1
            continue
        kept.append(line)
    text = "\n".join(kept).strip("\n")
    return (text + "\n" if text else ""), removed


def cron_status() -> dict:
    available, content = _crontab_read()
    lines = [line for line in content.splitlines()
             if SUPERVISOR_NAME in line or CRON_TAG in line]
    return {
        "available": available,
        "configured": bool(lines),
        "lines": lines,
        "total_lines": len([ln for ln in content.splitlines() if ln.strip()]),
    }


def _resolve_app_dir(app_dir: Path | None = None) -> Path:
    return Path(app_dir) if app_dir else Path(__file__).resolve().parent.parent


def cron_install(app_dir: Path | None = None) -> dict:
    """写入容器 ``@reboot`` 兜底（幂等：重复执行不会产生第二行）。

    不额外做平台判断：读写都通过 ``crontab`` 命令，命令不存在时下面会给出明确提示
    （Windows 开发机上自然走这条路）。
    """
    available, content = _crontab_read()
    if not available:
        raise BootError("本机没有可用的 crontab 命令；容器内请改用 Termux:Boot 方案"
                        "（可在本页复制启动脚本）")

    app_dir = _resolve_app_dir(app_dir)
    supervisor = app_dir / SUPERVISOR_NAME
    if not supervisor.exists():
        raise BootError(f"未找到守护脚本 {supervisor}，请先执行 serverpanel --install")
    if not os.access(supervisor, os.X_OK):
        with contextlib.suppress(OSError):
            os.chmod(supervisor, 0o755)

    backup = _backup_crontab(content)
    stripped, removed = _strip_supervisor_lines(content)
    line = f"@reboot {supervisor} >/dev/null 2>&1 &  # {CRON_TAG}"
    new_content = stripped + line + "\n"

    try:
        _crontab_write(new_content)
        ok, readback = _crontab_read()
        matched = [ln for ln in readback.splitlines() if CRON_TAG in ln]
        if not ok or len(matched) != 1:
            raise BootError("写入后校验失败（目标行数量不为 1）")
    except BootError:
        if backup is not None:
            with contextlib.suppress(BootError, OSError):
                _crontab_write(content)  # 回滚
        raise
    return {
        "ok": True,
        "line": line,
        "removed": removed,
        "backup": str(backup) if backup else None,
        "message": "已在容器 crontab 写入 @reboot 兜底" + (f"（替换了 {removed} 条旧配置）" if removed else ""),
    }


def cron_remove(app_dir: Path | None = None) -> dict:
    available, content = _crontab_read()
    if not available:
        raise BootError("本机没有可用的 crontab 命令")
    _ = _resolve_app_dir(app_dir)
    stripped, removed = _strip_supervisor_lines(content)
    if removed == 0:
        return {"ok": True, "removed": 0, "message": "crontab 中没有守护自启配置"}
    backup = _backup_crontab(content)
    try:
        _crontab_write(stripped)
        ok, readback = _crontab_read()
        if not ok or CRON_TAG in readback:
            raise BootError("移除后校验失败")
    except BootError:
        if backup is not None:
            with contextlib.suppress(BootError, OSError):
                _crontab_write(content)
        raise
    return {"ok": True, "removed": removed,
            "backup": str(backup) if backup else None,
            "message": f"已移除 {removed} 条守护自启配置"}


# ---------------------------------------------------------------- 体检

def _termux_script(app_dir: Path) -> str:
    return (
        "#!/data/data/com.termux/files/usr/bin/sh\n"
        "# Termux:Boot 开机脚本（需先安装 Termux:Boot APP）\n"
        "termux-wake-lock\n"
        f'proot-distro login ubuntu -- bash -c "service cron start; '
        f'setsid nohup {app_dir}/{SUPERVISOR_NAME} >/dev/null 2>&1 &"\n'
    )


def probe(app_dir: Path | None = None, port: int | None = None,
          health: dict | None = None) -> dict:
    """自启链全体检（只读）。``health`` 由调用方传入 /healthz 结果可省一次自请求。"""
    from . import manage

    app_dir = Path(app_dir or Path(__file__).resolve().parent.parent)
    port = int(port or manage._load_metadata().get("port") or 8787)
    platform = detect_platform()
    links: list[Link] = []

    # ① 设备 / 容器拉起守护
    cron = cron_status()
    script_exists = (app_dir / SUPERVISOR_NAME).exists()
    systemd_unit = Path("/etc/systemd/system/serverpanel.service").exists()
    if not script_exists and not systemd_unit:
        links.append(Link(
            "device-autostart", "设备/容器开机拉起面板", STATE_BROKEN,
            "既没有守护脚本也没有 systemd 单元，机器重启后面板不会自己起来",
            f"缺少 {app_dir}/{SUPERVISOR_NAME}",
            actions=[{"id": "guardian-repair", "label": "重装面板守护",
                      "method": "POST", "endpoint": "/api/panel/boot/guardian/repair",
                      "needs_confirm": True}],
        ))
    elif systemd_unit and platform["systemd"]:
        links.append(Link(
            "device-autostart", "设备/容器开机拉起面板", STATE_OK,
            "已注册 systemd 单元并启用开机自启", "serverpanel.service",
        ))
    elif cron["configured"]:
        links.append(Link(
            "device-autostart", "设备/容器开机拉起面板", STATE_OK,
            "容器 crontab 已配置 @reboot 兜底", cron["lines"][0],
            actions=[{"id": "cron-remove", "label": "移除 crontab 配置", "method": "DELETE",
                      "endpoint": "/api/panel/boot/cron", "needs_confirm": True}],
        ))
    elif not cron["available"]:
        links.append(Link(
            "device-autostart", "设备/容器开机拉起面板", STATE_MANUAL,
            "本机没有 crontab，容器内无法自动配置；需在设备侧用 Termux:Boot 拉起守护",
            "crontab 命令不存在", manual=True,
            actions=[{"id": "copy-termux-script", "label": "复制 Termux:Boot 启动脚本",
                      "method": "copy", "payload": _termux_script(app_dir)}],
        ))
    else:
        detail = ("本机是容器环境，容器重启后面板不会自己起来"
                  if platform["container"] else "未检测到开机自启配置")
        actions = [{"id": "cron-install", "label": "写入容器 @reboot 兜底",
                    "method": "POST", "endpoint": "/api/panel/boot/cron", "needs_confirm": True}]
        if platform["termux"]["present"] or platform["proot"]:
            actions.append({"id": "copy-termux-script", "label": "复制 Termux:Boot 启动脚本",
                            "method": "copy", "payload": _termux_script(app_dir)})
        links.append(Link("device-autostart", "设备/容器开机拉起面板", STATE_BROKEN,
                          detail, f"crontab 有 {cron['total_lines']} 行但无守护配置",
                          actions=actions))

    # ② 守护进程
    pid = manage._read_pidfile(app_dir)
    if manage._systemd_available():
        links.append(Link("guardian", "守护进程", STATE_OK,
                          "systemd 托管（Restart=always）", "serverpanel.service"))
    elif pid and manage._pid_alive(pid):
        links.append(Link("guardian", "守护进程", STATE_OK, f"守护 PID {pid} 运行中",
                          str(app_dir / manage.PID_NAME),
                          actions=[{"id": "guardian-restart", "label": "重启面板",
                                    "method": "POST",
                                    "endpoint": "/api/panel/boot/guardian/restart",
                                    "needs_confirm": True}]))
    else:
        links.append(Link("guardian", "守护进程", STATE_BROKEN, "守护未在运行（面板可能随时掉线）",
                          f"pidfile: {app_dir / manage.PID_NAME}",
                          actions=[{"id": "guardian-restart", "label": "拉起守护",
                                    "method": "POST",
                                    "endpoint": "/api/panel/boot/guardian/restart",
                                    "needs_confirm": True}]))

    # ③ 面板服务自身
    if health and health.get("ok"):
        links.append(Link("panel", "面板服务", STATE_OK,
                          f"健康检查正常（version {health.get('version')}）",
                          f"http://127.0.0.1:{port}/healthz"))
    elif health:
        links.append(Link("panel", "面板服务", STATE_BROKEN, "健康检查返回异常", str(health)[:200]))
    else:
        links.append(Link("panel", "面板服务", STATE_UNKNOWN,
                          f"未能连接 http://127.0.0.1:{port}/healthz", "健康检查无响应"))

    # ④ 托管应用自启
    from .apps import supervisor

    apps = supervisor.registry.all()
    auto = [a for a in apps if a.get("autostart")]
    enabled = prefs.apps_autostart_enabled()
    if not apps:
        links.append(Link("apps", "常驻应用自启", STATE_OK, "尚未注册常驻应用"))
    elif not enabled:
        links.append(Link("apps", "常驻应用自启", STATE_MANUAL,
                          f"全局开关已关闭：{len(auto)} 个标记自启的应用不会自动拉起",
                          "设置 → 快捷设置 → 常驻应用自启", manual=True))
    else:
        links.append(Link("apps", "常驻应用自启", STATE_OK,
                          f"{len(apps)} 个应用中 {len(auto)} 个标记自启，面板启动时会拉起"))

    # ⑤ 设备侧保活（容器内改不到）
    if platform["proot"] or platform["termux"]["present"]:
        links.append(Link("device-power", "设备侧保活", STATE_MANUAL,
                          "需在手机上关闭 Termux 电池优化、允许后台运行（Termux:Boot 脚本里已包含 wake-lock）",
                          "容器内无法探测 Android 宿主设置", manual=True))
    else:
        links.append(Link("device-power", "设备侧保活", STATE_OK, "非 Android 环境，无需额外保活"))

    states = {link.state for link in links}
    if STATE_BROKEN in states:
        verdict = "broken"
    elif STATE_MANUAL in states or STATE_UNKNOWN in states:
        verdict = "warn"
    else:
        verdict = "ok"
    return {
        "platform": platform,
        "links": [link.as_dict() for link in links],
        "verdict": verdict,
        "cron": cron,
        "app_dir": str(app_dir),
        "port": port,
        "termux_script": _termux_script(app_dir),
        "checked_at": int(time.time()),
    }


# ---------------------------------------------------------------- 时区

def _current_timezone() -> str:
    text = _read_text("/etc/timezone", 200)
    if text:
        return text.splitlines()[0]
    with contextlib.suppress(OSError):
        target = os.path.realpath("/etc/localtime")
        marker = "/zoneinfo/"
        if marker in target:
            return target.split(marker, 1)[1]
    env_tz = os.environ.get("TZ", "")
    if env_tz:
        return env_tz
    return time.tzname[0] if time.tzname else "unknown"


def timezone_status() -> dict:
    if os.name != "posix":
        return {"supported": False, "reason": "仅支持 Linux/容器环境",
                "current": time.tzname[0] if time.tzname else "-",
                "ntp_supported": False, "common": COMMON_TIMEZONES}
    zoneinfo = Path("/usr/share/zoneinfo")
    available = sorted(p.name for p in zoneinfo.iterdir()
                       if p.is_dir()) if zoneinfo.is_dir() else []
    return {
        "supported": zoneinfo.is_dir(),
        "reason": "" if zoneinfo.is_dir() else "本机缺少 /usr/share/zoneinfo，无法切换时区",
        "current": _current_timezone(),
        "ntp_supported": shutil.which("timedatectl") is not None
        and os.path.isdir("/run/systemd/system"),
        "ntp_enabled": _ntp_enabled(),
        "common": COMMON_TIMEZONES,
        "regions": available[:40],
        "tz_env": os.environ.get("TZ", ""),
    }


def _ntp_enabled() -> bool:
    if not (shutil.which("timedatectl") and os.path.isdir("/run/systemd/system")):
        return False
    try:
        proc = subprocess.run(["timedatectl", "show", "-p", "NTP", "--value"],
                              capture_output=True, text=True, timeout=CRON_TIMEOUT)
        return proc.stdout.strip().lower() == "yes"
    except (OSError, subprocess.SubprocessError):
        return False


def set_timezone(zone: str, enable_ntp: bool | None = None) -> dict:
    """切换时区：优先 timedatectl，无 systemd 时直接改 /etc 下的链接与 /etc/timezone。"""
    zone = (zone or "").strip()
    if os.name != "posix":
        raise BootError("仅支持 Linux/容器环境（Windows 开发环境不支持）")
    if not re.fullmatch(r"[A-Za-z0-9_+\-/]{1,64}", zone):
        raise BootError(f"时区名不合法：{zone}")
    if not (Path("/usr/share/zoneinfo") / zone).exists():
        raise BootError(f"时区不存在：{zone}（可在 /usr/share/zoneinfo 下查找）")

    used = ""
    errors: list[str] = []
    if shutil.which("timedatectl") and os.path.isdir("/run/systemd/system"):
        proc = subprocess.run(["timedatectl", "set-timezone", zone],
                              capture_output=True, text=True, timeout=CRON_TIMEOUT)
        if proc.returncode == 0:
            used = "timedatectl"
        else:
            errors.append((proc.stderr or proc.stdout or "").strip()[:200])

    if not used:
        # PRoot / 容器：直接操作文件（这也是这些环境里的唯一可行路径）
        try:
            Path("/etc/timezone").write_text(zone + "\n", "utf-8")
            link = Path("/etc/localtime")
            target = Path("/usr/share/zoneinfo") / zone
            with contextlib.suppress(OSError):
                link.unlink()
            link.symlink_to(target)
            used = "files"
        except OSError as exc:
            detail = f"（timedatectl 也失败：{'; '.join(errors)}）" if errors else ""
            raise BootError(f"无法写入 /etc/timezone 与 /etc/localtime：{exc}{detail}")

    ntp_result = None
    if enable_ntp is not None:
        if shutil.which("timedatectl") and os.path.isdir("/run/systemd/system"):
            proc = subprocess.run(["timedatectl", "set-ntp", "true" if enable_ntp else "false"],
                                  capture_output=True, text=True, timeout=CRON_TIMEOUT)
            ntp_result = proc.returncode == 0
        else:
            # PRoot / 容器：时钟由宿主控制，没有可用的对时机制，如实回报失败
            ntp_result = False

    os.environ["TZ"] = zone
    with contextlib.suppress(Exception):
        time.tzset()
    message = f"时区已切换为 {zone}（{'systemd timedatectl' if used == 'timedatectl' else '直接写入 /etc'}）"
    if enable_ntp is not None:
        message += "；NTP " + ("已开启" if ntp_result else "设置失败或本环境不支持")
    return {
        "ok": True,
        "method": used,
        "zone": zone,
        "ntp": ntp_result,
        "ntp_supported": bool(shutil.which("timedatectl") and os.path.isdir("/run/systemd/system")),
        "errors": errors,
        "message": message,
    }


# ---------------------------------------------------------------- 日志清理

def trim_logs(app_dir: Path | None = None) -> dict:
    """把面板日志与托管应用日志截断到各自上限，返回释放的字节数。"""
    from .apps import a_name, supervisor

    app_dir = Path(app_dir or Path(__file__).resolve().parent.parent)
    freed = 0
    details: list[dict] = []

    panel_log = app_dir / "panel.log"
    panel_limit = prefs.panel_log_limit()
    freed += _trim_file(panel_log, panel_limit, details, "面板日志 panel.log")
    for rotated in (app_dir / "panel.log.1",):
        with contextlib.suppress(OSError):
            if rotated.exists():
                size = rotated.stat().st_size
                rotated.unlink()
                freed += size
                details.append({"name": rotated.name, "freed": size, "note": "已删除轮转归档"})

    app_limit = prefs.app_log_limit()
    for app in supervisor.registry.all():
        name = a_name(app)
        path = supervisor.log_dir / f"{name}.log"
        freed += _trim_file(path, app_limit, details, f"应用 {name}")
        with contextlib.suppress(OSError):
            rotated = path.with_suffix(path.suffix + ".1")
            if rotated.exists():
                size = rotated.stat().st_size
                rotated.unlink()
                freed += size
                details.append({"name": rotated.name, "freed": size, "note": "已删除轮转归档"})
        runtime = supervisor.runtimes.get(app["id"])
        if runtime and runtime.log:
            runtime.log._buffer.clear()

    return {
        "ok": True,
        "freed_bytes": freed,
        "details": details,
        "message": f"已清理日志，释放 {freed / 1024:.0f} KB",
        "limits": {"panel": panel_limit, "app": app_limit},
    }


def _trim_file(path: Path, limit: int, details: list[dict], label: str) -> int:
    try:
        size = path.stat().st_size
    except OSError:
        return 0
    if size <= limit:
        return 0
    keep = limit // 2  # 保留最近一半，避免"清完立刻又满"
    try:
        with open(path, "rb") as fh:
            fh.seek(-keep, os.SEEK_END)
            tail = fh.read()
        path.write_bytes("[... 历史日志已按上限截断 ...]\n".encode("utf-8") + tail)
    except OSError as exc:
        details.append({"name": path.name, "label": label, "error": str(exc), "freed": 0})
        return 0
    freed = size - path.stat().st_size
    details.append({"name": path.name, "label": label, "freed": freed, "note": "已截断到上限的一半"})
    return freed


# ---------------------------------------------------------------- 监听地址

def listen_status() -> dict:
    from . import manage

    meta = manage._load_metadata()
    return {
        "host": str(meta.get("host") or prefs.get("listen.host")),
        "port": int(meta.get("port") or prefs.get("listen.port")),
        "app_dir": str(meta.get("app_dir") or manage.app_dir()),
        "systemd": manage._systemd_available(),
        "installed_at": int(meta.get("installed_at") or 0),
    }


def apply_listen(host: str | None = None, port: int | None = None) -> dict:
    """变更监听地址：重建守护产物 → 后台重启面板（脱离当前进程组）。

    只做"下发"，重启由守护完成；调用方（前端）负责轮询新地址的 /healthz。
    """
    from . import manage

    current = listen_status()
    values = prefs.update({
        k: v for k, v in (("listen.host", host), ("listen.port", port)) if v is not None
    })
    target_host = values["values"]["listen.host"]
    target_port = int(values["values"]["listen.port"])
    if (target_host, target_port) == (current["host"], current["port"]):
        return {"ok": True, "changed": False, "host": target_host, "port": target_port,
                "message": "监听地址未变化"}

    app_dir = Path(current["app_dir"])
    backups: dict[str, str] = {}
    try:
        supervisor_path = app_dir / manage.SUPERVISOR_NAME
        unit_path = Path(manage.SYSTEMD_UNIT)
        for path in (supervisor_path, unit_path):
            if path.exists():
                backups[str(path)] = path.read_text("utf-8")

        manage._save_metadata(app_dir, target_host, target_port)
        if manage._systemd_available():
            manage.write_systemd_unit(app_dir, target_host, target_port)
        else:
            manage.write_supervisor(app_dir, target_host, target_port)
    except Exception as exc:
        # 回滚配置与已生成的文件
        prefs.update({"listen.host": current["host"], "listen.port": current["port"]})
        for path_str, content in backups.items():
            with contextlib.suppress(OSError):
                Path(path_str).write_text(content, "utf-8")
        raise BootError(f"重建守护产物失败，已回滚：{exc}")

    # 后台拉起新配置：必须脱离面板进程组，否则面板退出会把它一起带走
    manage._restart_service(app_dir)
    return {
        "ok": True,
        "changed": True,
        "host": target_host,
        "port": target_port,
        "previous": {"host": current["host"], "port": current["port"]},
        "backups": sorted(backups),
        "message": f"监听地址已改为 {target_host}:{target_port}，面板正在重启",
    }


def set_pref_with_check(patch: dict) -> dict:
    """带自检的 prefs 写入（供路由复用）：写日志白名单前先确认仍拒绝敏感路径。"""
    if "security.log_dirs" in patch:
        candidate = patch["security.log_dirs"]
        try:
            dirs = [os.path.realpath(os.path.abspath(str(d))) for d in
                    (candidate if isinstance(candidate, list) else [candidate])]
        except OSError as exc:
            raise PrefsError(f"日志目录解析失败：{exc}")
        secret = "/etc/shadow"
        if any(secret == d or secret.startswith(os.path.join(d, "")) for d in dirs):
            raise PrefsError("该目录会让 /etc/shadow 之类敏感文件进入白名单范围，已拒绝")
        for probe in ("/", "/etc", "/root", "/usr"):
            real = os.path.realpath(probe)
            if any(d == real for d in dirs):
                raise PrefsError(f"不能把系统关键目录加入日志白名单：{probe}")
    return prefs.update(patch)
