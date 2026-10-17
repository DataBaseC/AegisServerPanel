"""快捷设置 API：开机自启体检、守护恢复、可调参数、日志清理、时区、监听地址、配置备份。

全部要求内网模式——这些接口能改面板自身的运行参数（端口、白名单、会话时长），
权限等级不低于终端。

一个例外是"体检"（GET /api/panel/boot）：它只读系统状态，但仍要求内网模式，
因为输出里包含路径、crontab 内容等部署细节。
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import re
import socket
import time
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .. import boot as boot_mod
from .. import confirm
from ..apps import supervisor
from ..audit import AuditEvent, audit
from ..auth import client_ip, extract_token, require_internal, session_username
from ..auth import sessions as sessions_mod
from ..config import config
from ..prefs import PrefsError, prefs
from ..trash import trash
from ..utils import is_root
from .apps_routes import recent_audit as apps_audit
from .tasks_routes import recent_runs

router = APIRouter(prefix="/api/panel", tags=["panel-settings"])

SECRET_KEYS = ("password_hash", "agent_token", "agent_token_updated_at",
               "agent_tokens", "totp_secret", "totp_enabled",
               "totp_recovery_hashes", "totp_enabled_at")
BACKUP_KEEP = 10
BACKUP_DIRNAME = "backups"
MASK_HINTS = ("TOKEN", "KEY", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL")


class PrefsBody(BaseModel):
    values: dict


class ListenBody(BaseModel):
    host: str | None = None
    port: int | None = None
    force: bool = False


class TimezoneBody(BaseModel):
    zone: str
    enable_ntp: bool | None = None


def record(action: str, detail: str = "", ip: str = "") -> None:
    """面板设置类操作记入统一审计管道（1.4.0 起落盘可追溯）。"""
    audit.record(AuditEvent(
        action=f"panel_{action}",
        summary=detail[:400],
        source="web",
        ip=ip,
        extra={"detail": detail[:400]},
    ))


@router.get("/audit")
async def audit_timeline(request: Request, _session: dict = Depends(require_internal)):
    # 读审计文件是同步磁盘 I/O，必须下线程池（1.4.1 修：原实现在
    # async 路由里直调，日志一大就冻住整个事件循环）
    return {"recent": await asyncio.to_thread(recent_audit)}


def recent_audit() -> list[dict]:
    """面板设置 + 常驻应用 + 常用操作，合并成一条时间线（读统一审计管道）。"""
    merged: list[dict] = []
    for item in audit.query(days=7, limit=500):
        action = str(item.get("action", ""))
        if action.startswith("panel_"):
            merged.append({
                "time": item.get("time", 0),
                "kind": "panel",
                "action": action[6:],
                "detail": (item.get("detail") or item.get("summary") or "")[:400],
            })
    for item in apps_audit():
        merged.append({**item, "kind": "apps"})
    for item in recent_runs():
        merged.append({
            "time": item["time"], "kind": "task", "action": item.get("target", ""),
            "detail": f"退出码 {item['code']} · {item['duration']}s · {item['summary'][:120]}",
        })
    merged.sort(key=lambda item: item["time"], reverse=True)
    return merged[:40]


def _guard(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except PrefsError as exc:
        raise HTTPException(400, str(exc))
    except boot_mod.BootError as exc:
        raise HTTPException(400, str(exc))


# ---------------------------------------------------------------- 体检 / 守护


@router.get("/boot")
async def boot_probe(request: Request, _session: dict = Depends(require_internal)):
    health = await _health_probe(request)
    data = await asyncio.to_thread(_guard, boot_mod.probe, None, None, health)  # 体检要跑一串系统命令
    return data


@router.post("/boot/cron")
async def cron_install(_session: dict = Depends(require_internal)):
    """写入容器 crontab 的 @reboot 兜底（幂等、可回滚）。"""
    result = await asyncio.to_thread(_guard, boot_mod.cron_install)  # 读写 crontab 走子进程
    record("cron-install", result["message"])
    return result


@router.delete("/boot/cron")
async def cron_remove(_session: dict = Depends(require_internal)):
    result = await asyncio.to_thread(_guard, boot_mod.cron_remove)
    record("cron-remove", result["message"])
    return result


@router.get("/boot/guardian")
async def guardian_status(request: Request, _session: dict = Depends(require_internal)):
    from .. import manage

    app_dir = Path(boot_mod.listen_status()["app_dir"])
    pid = manage._read_pidfile(app_dir)
    return {
        "systemd": manage._systemd_available(),
        "pid": pid,
        "alive": bool(pid and manage._pid_alive(pid)),
        "pidfile": str(app_dir / manage.PID_NAME),
        "supervisor": str(app_dir / manage.SUPERVISOR_NAME),
        "supervisor_exists": (app_dir / manage.SUPERVISOR_NAME).exists(),
        "unit": manage.SYSTEMD_UNIT if manage._systemd_available() else "",
        "app_dir": str(app_dir),
        "health": await _health_probe(request),
    }


@router.post("/boot/guardian/restart")
async def guardian_restart(_session: dict = Depends(require_internal)):
    from .. import manage

    app_dir = Path(boot_mod.listen_status()["app_dir"])
    record("guardian-restart", str(app_dir))
    code = await asyncio.to_thread(manage.cmd_restart, app_dir)  # 可能触发 systemd/supervisor 子进程
    if code != 0:
        raise HTTPException(500, "重启指令下发失败，请查看 panel.log")
    return {"ok": True, "message": "重启指令已下发，面板将在数秒内回来"}


@router.post("/boot/guardian/repair")
async def guardian_repair(_session: dict = Depends(require_internal)):
    from .. import manage
    from ..prefs import prefs as prefs_obj

    listen = boot_mod.listen_status()
    app_dir = Path(listen["app_dir"])
    record("guardian-repair", f"{listen['host']}:{listen['port']}")
    code = await asyncio.to_thread(  # cmd_install 内含 pip install，可能跑数分钟
        manage.cmd_install, app_dir, str(listen["host"]), int(listen["port"])
    )
    if code != 0:
        raise HTTPException(500, "重装守护失败，请查看命令输出与 panel.log")
    return {"ok": True, "message": f"守护已按 {prefs_obj.get('listen.host')}:{prefs_obj.get('listen.port')} 重新安装"}


async def _health_probe(request: Request) -> dict | None:
    """内部探一次 /healthz，避免让前端再发一次请求。"""
    import asyncio
    import urllib.request

    port = int(boot_mod.listen_status()["port"])
    url = f"http://127.0.0.1:{port}/healthz"

    def _fetch() -> dict | None:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                return json.loads(resp.read())
        except Exception:
            return None

    return await asyncio.to_thread(_fetch)


# ---------------------------------------------------------------- prefs


@router.get("/prefs")
async def get_prefs(_session: dict = Depends(require_internal)):
    return {
        "fields": prefs.describe(),
        "values": prefs.all(),
        "pending_restart": False,
        "listen": boot_mod.listen_status(),
        "timezone": boot_mod.timezone_status(),
        # 读审计文件（含 apps/task 视图）是同步 I/O，下线程池（1.4.1）
        "audit": await asyncio.to_thread(recent_audit),
    }


@router.put("/prefs")
async def put_prefs(body: PrefsBody, _session: dict = Depends(require_internal)):
    result = await asyncio.to_thread(_guard, boot_mod.set_pref_with_check, body.values)  # 含路径自检与写盘
    record("prefs", json.dumps(result["changed"], ensure_ascii=False)[:300])
    return {**result, "fields": prefs.describe()}


# ---------------------------------------------------------------- 日志清理


@router.post("/logs/trim")
async def trim_logs(_session: dict = Depends(require_internal)):
    result = await asyncio.to_thread(_guard, boot_mod.trim_logs)  # 逐个截断日志文件
    record("logs-trim", result["message"])
    return result


# ---------------------------------------------------------------- 时区


@router.get("/timezone")
async def get_timezone(_session: dict = Depends(require_internal)):
    return boot_mod.timezone_status()


@router.post("/timezone")
async def set_timezone(body: TimezoneBody, _session: dict = Depends(require_internal)):
    if os.name == "posix" and not is_root():
        raise HTTPException(403, "切换时区需要 root 权限（要写入 /etc/timezone 与 /etc/localtime）")
    result = await asyncio.to_thread(_guard, boot_mod.set_timezone, body.zone, body.enable_ntp)  # timedatectl 子进程
    record("timezone", result["message"])
    return {**result, "status": boot_mod.timezone_status()}


# ---------------------------------------------------------------- 监听地址


@router.get("/listen")
async def get_listen(_session: dict = Depends(require_internal)):
    return boot_mod.listen_status()


@router.post("/listen")
async def set_listen(body: ListenBody, _session: dict = Depends(require_internal)):
    current = boot_mod.listen_status()
    host = body.host if body.host is not None else current["host"]
    port = int(body.port if body.port is not None else current["port"])

    if port != current["port"] and not body.force:
        busy = _port_busy(host, port)
        if busy:
            raise HTTPException(409, f"端口 {port} 已被占用（{busy}）；确认要强制切换请再次提交")
    if host in ("127.0.0.1", "::1") and current["host"] not in ("127.0.0.1", "::1") and not body.force:
        raise HTTPException(409, "改成只监听回环地址后，局域网设备将无法访问面板；"
                                 "确认继续请再次提交")
    result = await asyncio.to_thread(_guard, boot_mod.apply_listen, host, port)  # 写配置 + 下发重启
    record("listen", f"{current['host']}:{current['port']} → {result['host']}:{result['port']}")
    return result


def _port_busy(host: str, port: int) -> str:
    """返回占用者描述；空闲返回空串。"""
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    with contextlib.suppress(OSError):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.6)
            if sock.connect_ex((probe_host, port)) != 0:
                return ""
    import psutil

    with contextlib.suppress(Exception):
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == port:
                name = "-"
                if conn.pid:
                    with contextlib.suppress(psutil.Error):
                        name = psutil.Process(conn.pid).name()
                return f"PID {conn.pid} {name}"
    return "未知进程"


# ---------------------------------------------------------------- 配置导出 / 导入 / 备份


def _config_dir() -> Path:
    return Path(config.path).parent


def _wanted_files() -> list[tuple[Path, str]]:
    """返回 ``(路径, 包内规范名)``。包内名固定为 config/apps/install.json——
    配置文件在磁盘上叫什么（SERVERPANEL_CONFIG 指定）不影响导出与再导入。"""
    base = _config_dir()
    candidates = [
        (Path(config.path), "config.json"),
        (base / "apps.json", "apps.json"),
        (base / "install.json", "install.json"),
    ]
    return [(path, name) for path, name in candidates if path.exists()]


def _scrub(data: dict, include_secrets: bool) -> tuple[dict, list[str]]:
    """按需剔除凭据。返回 ``(处理后的数据, 被剔除的键名)``。

    2.0 M4 起 ``users`` 里的凭据单独处理：即使显式导出密钥，多用户密码
    哈希也不随配置导出（各账号的凭据只留在本机），但保留用户名/角色便于
    迁移后重建账号。
    """
    removed: list[str] = []
    if include_secrets:
        return data, removed
    for key in SECRET_KEYS:
        if key in data:
            data.pop(key)
            removed.append(key)
    prefs_node = data.get("prefs")
    if isinstance(prefs_node, dict):
        for key in list(prefs_node):
            if key in SECRET_KEYS:
                prefs_node.pop(key)
                removed.append(f"prefs.{key}")
    removed.extend(_scrub_users(data))
    return data, removed


def _scrub_users(data: dict) -> list[str]:
    """抹掉多用户记录里的凭据字段（用户名/角色保留，便于迁移后重建账号）。"""
    removed: list[str] = []
    users = data.get("users")
    if not isinstance(users, list):
        return removed
    for user in users:
        if not isinstance(user, dict):
            continue
        for key in ("password_hash", "totp_secret", "totp_enabled",
                    "recovery_hashes", "totp_enabled_at"):
            if key in user:
                user.pop(key)
                removed.append(f"users.{key}")
    return removed


def _mask_env(apps_data: dict) -> int:
    """把疑似凭据的环境变量值打码（仍写入导出文件，只是便于肉眼确认）。"""
    masked = 0
    for app in apps_data.get("apps", []) or []:
        env = app.get("env")
        if not isinstance(env, dict):
            continue
        for key, value in list(env.items()):
            if any(hint in str(key).upper() for hint in MASK_HINTS) and value:
                env[key] = "***已打码***"
                masked += 1
    return masked


@router.get("/config/export")
async def export_config(include_secrets: bool = False,
                        _session: dict = Depends(require_internal)):
    """导出配置为 zip。默认剔除密码哈希与 Agent 令牌。"""
    buffer = io.BytesIO()
    removed: list[str] = []
    masked = 0
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path, arcname in _wanted_files():
            try:
                data = json.loads(path.read_text("utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if arcname == "config.json":
                data, removed = _scrub(data, include_secrets)
            elif arcname == "apps.json":
                masked = _mask_env(data)
            bundle.writestr(arcname, json.dumps(data, indent=2, ensure_ascii=False))
        bundle.writestr("README.txt", (
            "AegisServerPanel 配置导出\n"
            f"导出时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"包含凭据：{'是（含密码哈希与 Agent 令牌，请妥善保管）' if include_secrets else '否'}\n"
            f"剔除的敏感键：{', '.join(removed) if removed else '无'}\n"
            f"打码的环境变量：{masked} 项\n\n"
            "导入方式：面板「设置 → 快捷设置 → 备份与迁移」上传本文件，"
            "或手动解包后覆盖 /etc/serverpanel/ 下同名文件。\n"
        ))
    buffer.seek(0)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    record("config-export", f"include_secrets={include_secrets} removed={removed}")
    filename = f"serverpanel-config-{stamp}.zip"
    return StreamingResponse(
        buffer, media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _keep_local_users(incoming: dict) -> None:
    """多用户记录（2.0 M4）只认本机。

    导出包里的 ``users`` 已脱敏（哈希被剔除），若整体替换，所有账号会失去
    可用哈希——等于把所有人锁在门外。与密码哈希、Agent 令牌同等对待。
    """
    if config.data.get("users"):
        incoming["users"] = config.data["users"]
    else:
        incoming.pop("users", None)


@router.post("/config/import")
async def import_config(file: UploadFile = File(...),
                        _session: dict = Depends(require_internal)):
    # 先限长再读：直接 read() 会把整个上传体读进内存，几 GB 文件足以 OOM
    raw = await file.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(400, "文件过大（上限 2MB）")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
            names = set(bundle.namelist())
            if "config.json" not in names:
                raise HTTPException(400, "压缩包里没有 config.json，不是有效导出文件")
            payload = {}
            for name in ("config.json", "apps.json", "install.json"):
                if name in names:
                    try:
                        # 用 open()+限长读，避免 zip 炸弹成员被一次性解压进内存
                        with bundle.open(name) as member:
                            blob = member.read(2 * 1024 * 1024 + 1)
                        if len(blob) > 2 * 1024 * 1024:
                            raise HTTPException(400, f"{name} 过大（上限 2MB）")
                        payload[name] = json.loads(blob.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        raise HTTPException(400, f"{name} 不是合法 JSON")
    except zipfile.BadZipFile:
        raise HTTPException(400, "不是有效的 zip 文件")

    incoming = payload["config.json"]
    if not isinstance(incoming, dict):
        raise HTTPException(400, "config.json 内容格式不对")

    # 凭据以本机为准：导入不覆盖密码哈希与 Agent 令牌，避免把别人的登录态带进来；
    # 本机没有的凭据也不会从包里领养（缺就保持缺，重新生成本机令牌即可）
    kept = {key for key in SECRET_KEYS if key in config.data}
    merged = {**incoming}
    for key in kept:
        merged[key] = config.data[key]
    for key in SECRET_KEYS:
        if key not in kept:
            merged.pop(key, None)
    _keep_local_users(merged)
    # 运行模式同理：模式只能由服务器本机命令决定（README 安全模型基石），导入不得触碰
    if "mode" in config.data:
        merged["mode"] = config.data["mode"]
        if "mode_updated_at" in config.data:
            merged["mode_updated_at"] = config.data["mode_updated_at"]
        else:
            merged.pop("mode_updated_at", None)
    # install.json 里的路径/端口会被守护接口直接使用，先做基本校验
    incoming_install = payload.get("install.json")
    if isinstance(incoming_install, dict):
        app_dir_value = incoming_install.get("app_dir")
        if app_dir_value is not None and (
            not isinstance(app_dir_value, str) or not os.path.isabs(app_dir_value)
        ):
            raise HTTPException(400, "install.json 的 app_dir 必须是绝对路径")
        port_value = incoming_install.get("port")
        if port_value is not None and (
            not isinstance(port_value, int) or not 1024 <= port_value <= 65535
        ):
            raise HTTPException(400, "install.json 的 port 需要在 1024 ~ 65535 之间")
    incoming_prefs = merged.get("prefs")
    if incoming_prefs is not None and not isinstance(incoming_prefs, dict):
        raise HTTPException(400, "prefs 字段格式不对")
    # 日志白名单（顶层 legacy 键与 prefs 命名空间都要过）：导入是整体替换 config.data，
    # 绕过了 prefs 层，若不在这里校验，一份带 log_dirs=/etc/ssh 的配置就能把公网
    # 只读用户的读取边界推开 —— 正是 PUT /api/panel/prefs 那道自检要防的事
    log_dir_candidates = []
    if "log_dirs" in merged:
        log_dir_candidates.append(merged["log_dirs"])
    if isinstance(incoming_prefs, dict) and "security.log_dirs" in incoming_prefs:
        log_dir_candidates.append(incoming_prefs["security.log_dirs"])
    for candidate in log_dir_candidates:
        try:
            boot_mod.assert_log_dirs_ok(candidate)
        except PrefsError as exc:
            raise HTTPException(400, f"配置里的 log_dirs 不合法：{exc}")

    backup = _write_backup("import")
    applied: list[str] = []
    config.data = merged
    config.save()
    applied.append("config.json")
    prefs._invalidate()

    if "apps.json" in payload:
        registry = supervisor.registry
        apps = payload["apps.json"].get("apps") if isinstance(payload["apps.json"], dict) else None
        if isinstance(apps, list):
            with contextlib.suppress(OSError):
                registry.path.parent.mkdir(parents=True, exist_ok=True)
                registry.path.write_text(
                    json.dumps({"version": 1, "apps": apps}, indent=2, ensure_ascii=False), "utf-8")
                with contextlib.suppress(OSError):
                    os.chmod(registry.path, 0o600)
                registry.reload_if_changed()
                applied.append("apps.json")
    if "install.json" in payload and isinstance(payload["install.json"], dict):
        meta_path = _config_dir() / "install.json"
        with contextlib.suppress(OSError):
            meta_path.write_text(json.dumps(payload["install.json"], indent=2, ensure_ascii=False),
                                 "utf-8")
            applied.append("install.json")

    # 统一判定「监听是否变更」：两处用同一表达式，避免 pending_restart 与提示语不一致
    listen_changed = (isinstance(incoming_prefs, dict)
                      and any(key.startswith("listen.") for key in incoming_prefs.keys()))
    record("config-import", f"applied={applied}")
    return {
        "ok": True,
        "applied": applied,
        "kept_secrets": sorted(kept),
        "backup": str(backup) if backup else None,
        "pending_restart": listen_changed,
        "message": "配置已导入（本机密码、Agent 令牌与运行模式保持不变）"
                   + ("，监听地址变更需重启面板" if listen_changed else ""),
    }


@router.get("/config/backups")
async def list_backups(_session: dict = Depends(require_internal)):
    directory = _config_dir() / BACKUP_DIRNAME
    items = []
    if directory.is_dir():
        for path in sorted(directory.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True):
            with contextlib.suppress(OSError):
                stat = path.stat()
                items.append({"name": path.name, "size": stat.st_size, "time": int(stat.st_mtime)})
    return {"items": items, "dir": str(directory), "keep": BACKUP_KEEP}


@router.post("/config/backup")
async def make_backup(_session: dict = Depends(require_internal)):
    path = _write_backup("manual")
    if path is None:
        raise HTTPException(500, "备份失败，请查看 panel.log")
    record("config-backup", path.name)
    return {"ok": True, "name": path.name, "path": str(path), "message": f"已生成备份 {path.name}"}


def _write_backup(reason: str) -> Path | None:
    """就地备份当前配置（含凭据，因为它的用途就是灾难恢复）。"""
    directory = _config_dir() / BACKUP_DIRNAME
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(directory, 0o700)
        name = f"{time.strftime('%Y%m%d-%H%M%S')}-{reason}.zip"
        target = directory / name
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as bundle:
            for path, arcname in _wanted_files():
                bundle.write(path, arcname)
        with contextlib.suppress(OSError):
            os.chmod(target, 0o600)
    except OSError:
        return None
    # 只保留最近 N 份
    with contextlib.suppress(OSError):
        existing = sorted(directory.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        for stale in existing[BACKUP_KEEP:]:
            stale.unlink()
    return target


# ---------------------------------------------------------------- 安全中心（1.4.0）


class ConfirmBody(BaseModel):
    action: str


@router.post("/confirm")
async def issue_confirm(body: ConfirmBody, request: Request,
                        _session: dict = Depends(require_internal)):
    """签发高危操作确认令牌（2.0 M1）：2 分钟有效、绑定动作与会话、一次性。"""
    result = confirm.issue(body.action, extract_token(request))
    record("confirm", f"签发确认令牌：{body.action}")
    return result


def _totp_state(session: dict | None) -> dict:
    """当前身份看到的 2FA 状态（与 ``/api/auth/totp/*`` 的执行侧同源）。

    2.0 起多用户模式把 TOTP 存在**每个用户记录**里（字段
    ``totp_enabled`` / ``totp_secret`` / ``recovery_hashes``），单密码模式
    仍用全局配置。展示与巡检必须用同一套判定，否则多用户下会永久误报
    「未启用二次认证」；单密码模式（``config.users`` 为空）保持原有语义。

    用户记录按会话里的 ``user_id`` 精确取，取不到再按用户名回查——与
    :class:`app.routes.auth_routes._TotpScope` 的顺序一致；仍未命中时
    （救援用的内置 admin 无记录等）回退全局配置。
    """
    session = session or {}
    if config.has_users:
        user = None
        user_id = str(session.get("user_id") or "")
        if user_id:
            user = config.user_by_id(user_id)
        if user is None:
            user = config.find_user(session_username(session))
        if user is not None:
            enabled = bool(user.get("totp_enabled"))
            return {
                "enabled": enabled,
                "pending": bool(user.get("totp_secret")) and not enabled,
                "recovery_left": len([h for h in (user.get("recovery_hashes") or [])
                                      if isinstance(h, str) and h]),
            }
    return {
        "enabled": config.totp_enabled,
        "pending": bool(config.totp_secret) and not config.totp_enabled,
        "recovery_left": len(config.totp_recovery_hashes),
    }


@router.get("/security")
async def security_summary(request: Request, _session: dict = Depends(require_internal)):
    """安全中心摘要：2FA 状态、防爆破状态、会话与令牌概况、审计统计。"""
    from ..auth import failures

    # 审计统计要扫最近 7 天的 JSONL，同样是同步 I/O → 下线程池
    audit_counts = await asyncio.to_thread(audit.actions_summary, 7)
    from ..prefs import TRASH_MAX_BYTES_DEFAULT

    trash_usage = trash.usage()
    trash_limit = int(prefs.all().get("security.trash_max_bytes", TRASH_MAX_BYTES_DEFAULT))
    return {
        # 多用户模式按当前会话用户取，单密码模式回退全局配置
        "totp": _totp_state(_session),
        "lockout": failures.status(client_ip(request)),
        "sessions": {
            "active": sessions_mod.active_count(),
        },
        "tokens": {
            "total": len(config.agent_tokens),
            "full": sum(1 for t in config.agent_tokens if t.get("scope") == "full"),
        },
        "audit": audit_counts,
        "trash": {**trash_usage,
                  "over_limit": int(trash_usage.get("bytes") or 0) > trash_limit},
    }


def _human_bytes(value: int) -> str:
    """把字节数格式化成便于阅读的单位（巡检详情用）。"""
    size = float(max(0, value))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


@router.get("/security/checkup")
async def security_checkup(request: Request, _session: dict = Depends(require_internal)):
    """一键安全巡检（1.6.0 U1）：汇总"当前该修什么"。

    数据全部来自现有配置/接口（config、失败计数、回收站 usage、prefs），
    不新增存储；前端按 ``target`` 跳转对应卡片。
    """
    from ..auth import failures
    from ..prefs import TRASH_MAX_BYTES_DEFAULT

    lock = failures.status(client_ip(request))
    tokens = [t for t in config.agent_tokens if isinstance(t, dict)]
    full_count = sum(1 for t in tokens if t.get("scope") == "full")
    idle_cutoff = time.time() - 30 * 86400
    idle_count = sum(
        1 for t in tokens
        if not int(t.get("last_used_at") or 0)
        or int(t.get("last_used_at") or 0) < idle_cutoff
    )
    used = trash.usage()
    limit = int(prefs.all().get("security.trash_max_bytes", TRASH_MAX_BYTES_DEFAULT))

    items: list[dict] = []
    # 2FA 状态按当前会话用户判定（多用户），单密码模式回退全局配置
    if not _totp_state(_session)["enabled"]:
        items.append({
            "level": "bad", "title": "未启用二次认证",
            "detail": "面板密码即 root shell，建议启用 TOTP（密码 + 6 位动态码）",
            "target": "security-totp",
        })
    if config.password_weak:
        items.append({
            "level": "warn", "title": "密码强度偏弱",
            "detail": "当前密码长度不足 12 位或字符类别少于 3 类，建议尽快更换",
            "target": "settings",
        })
    if full_count:
        items.append({
            "level": "warn", "title": f"存在 {full_count} 个完整权限令牌",
            "detail": "完整权限令牌等价 root shell，建议按最小权限改为 custom / readonly",
            "target": "security-tokens",
        })
    if idle_count:
        items.append({
            "level": "warn", "title": f"存在 {idle_count} 个闲置令牌",
            "detail": "从未使用或超过 30 天未使用，建议吊销",
            "target": "security-tokens",
        })
    if int(used.get("bytes") or 0) > limit:
        items.append({
            "level": "warn", "title": "回收站占用超过水位",
            "detail": f"当前 {_human_bytes(int(used.get('bytes') or 0))}，"
                      f"阈值 {_human_bytes(limit)}，建议清理或调高阈值",
            "target": "security-trash",
        })
    if int(lock.get("locked_seconds") or 0) > 0:
        items.append({
            "level": "bad", "title": "当前来源 IP 处于锁定状态",
            "detail": f"剩余 {lock['locked_seconds']} 秒自动解锁",
            "target": "security-lockout",
        })
    if not items:
        items.append({
            "level": "ok", "title": "未发现待处理项",
            "detail": "当前安全配置未发现明显短板", "target": "",
        })
    return {"items": items}


@router.get("/audit/log")
async def audit_log(days: int = 7, action: str = "", source: str = "", q: str = "",
                    limit: int = 200, _session: dict = Depends(require_internal)):
    """统一审计日志查询（安全中心 → 审计日志）。"""
    events = await asyncio.to_thread(audit.query, days, action, source, q, limit)
    return {"events": events}


class AuditExportBody(BaseModel):
    count: int = 0
    filters: str = ""


@router.post("/audit/export")
async def audit_export(body: AuditExportBody, request: Request,
                       _session: dict = Depends(require_internal)):
    """记录一次审计日志导出（1.6.0 U2）。

    导出数据本身由前端用已查询到的结果生成 Blob（不新增数据端点）；
    这个接口只把"导出了多少条、当时什么筛选条件"写进审计，保证导出可追溯。
    """
    count = max(0, int(body.count or 0))
    summary = f"导出 {count} 条审计记录"
    if body.filters:
        summary += f"（筛选：{body.filters[:120]}）"
    audit.record(AuditEvent(
        action="audit_export", summary=summary, source="web",
        ip=client_ip(request), extra={"count": count, "filters": body.filters[:120]},
    ))
    return {"ok": True}


@router.get("/sessions")
async def active_sessions(request: Request, _session: dict = Depends(require_internal)):
    """活跃会话列表（安全中心 → 会话管理）。"""
    current = sessions_mod.validate(extract_token(request))
    current_id = ""
    if current:
        from ..auth import token_digest

        token = extract_token(request)
        current_id = token_digest(token)[:12] if token else ""
    items = sessions_mod.list_active()
    for item in items:
        item["current"] = item["id"] == current_id
    return {"sessions": items}


class SessionIdBody(BaseModel):
    id: str


# 会话短标识：token_digest() 的前 12 位十六进制
_SESSION_ID_RE = re.compile(r"[0-9a-f]{12}")


@router.post("/sessions/revoke")
async def revoke_session(body: SessionIdBody, request: Request,
                         _session: dict = Depends(require_internal)):
    """踢出指定会话（按列表里展示的 12 位哈希短标识精确定位）。

    1.4.1 修：原实现用 ``digest.startswith(body.id)`` 做前缀匹配且不校验
    长度——``id=""`` 会匹配到字典里的第一个会话并把它踢掉，"不能踢当前
    会话"的守卫也只在 id 恰好 12 位时才生效。现在要求 id 必须是
    12 位十六进制，并且必须与某个会话的短标识完全相等。
    """
    if not _SESSION_ID_RE.fullmatch(body.id or ""):
        raise HTTPException(400, "会话标识格式不对（应为 12 位十六进制短标识）")
    target = next((d for d in list(sessions_mod._sessions)
                   if d[:12] == body.id), None)
    if target is None:
        raise HTTPException(404, "会话不存在或已过期")
    if _is_current(request, target):
        raise HTTPException(400, "不能踢出当前会话（请直接退出登录）")
    if sessions_mod.revoke_digest(target):
        audit.record(AuditEvent(action="session_revoked", target=body.id,
                                source="web", ip=client_ip(request)))
        return {"ok": True, "message": "会话已踢出"}
    raise HTTPException(404, "会话不存在或已过期")


def _is_current(request: Request, digest: str) -> bool:
    from ..auth import token_digest

    token = extract_token(request)
    return bool(token) and token_digest(token) == digest


@router.post("/sessions/revoke-others")
async def revoke_other_sessions(request: Request,
                                _session: dict = Depends(require_internal)):
    """踢出除当前会话外的所有会话。"""
    from ..auth import token_digest

    token = extract_token(request)
    current = token_digest(token) if token else ""
    count = 0
    for digest in list(sessions_mod._sessions):
        if digest != current and sessions_mod.revoke_digest(digest):
            count += 1
    audit.record(AuditEvent(action="sessions_revoked_others", target="-",
                            summary=f"踢出 {count} 个会话",
                            source="web", ip=client_ip(request)))
    return {"ok": True, "message": f"已踢出 {count} 个其他会话"}
