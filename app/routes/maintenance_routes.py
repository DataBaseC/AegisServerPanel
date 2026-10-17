"""运维扩展：定时任务可视化、备份（本地 + rclone）、系统更新（2.0 M3）。

全部能力都建立在系统自带 CLI 上（``crontab`` / ``tarfile`` / ``rclone`` / ``apt``），
不引入任何 Python 依赖；外部命令缺失时能力探测返回 false，前端隐藏对应面板，
绝不因为工具缺失让面板起不来。

安全约定（与 M1/M2 保持一致）：

- 所有端点挂 ``require_internal``（公网只读模式一律 403）。
- 所有写操作记审计；用户输入一律走 ``app/ops.py`` 的白名单校验，
  命令行一律以参数列表交给 ``shell.run``，绝不拼接字符串。
- 覆盖式写入（crontab）先备份再"写后读回"校验，不一致立即回滚。
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import tarfile
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from .. import ops, shell
from ..audit import AuditEvent, audit
from ..auth import client_ip, require_internal
from ..config import config
from ..prefs import prefs
from .file_routes import PROTECTED

router = APIRouter(prefix="/api/panel/maintenance", tags=["maintenance"],
                   dependencies=[Depends(require_internal)])

CRON_TIMEOUT = 15
APT_TIMEOUT = 60
UPLOAD_TIMEOUT = 300          # rclone 传输可能很久，但也不能无限挂着
UPDATE_TIMEOUT = 900          # apt 升级大包（内核）可能十几分钟
BACKUP_MAX_BYTES = 2 * 1024 ** 3   # 单次备份总体积上限 2GiB
BACKUP_MAX_PATHS = 20


class CronBody(BaseModel):
    lines: list[str] | None = None
    content: str | None = None


class BackupBody(BaseModel):
    paths: list[str]
    name: str | None = None


class UploadBody(BaseModel):
    remote: str


class UpdateBody(BaseModel):
    packages: list[str] | None = None


def _guard(fn, *args, **kwargs):
    """把 OpsError（用户输入问题）翻译成 400，而不是 500。"""
    try:
        return fn(*args, **kwargs)
    except ops.OpsError as exc:
        raise HTTPException(400, str(exc)) from exc


# ---------------------------------------------------------------- 路径


def config_dir() -> Path:
    return Path(config.path).parent


def backup_dir() -> Path:
    """备份目录：``backup.dir`` 优先，留空落到 ``<配置目录>/backups``。"""
    default = str(config_dir() / "backups")
    return Path(prefs.backup_dir(default))


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700)  # 备份里可能有配置与私钥，只有 root 可读
    return path


# ---------------------------------------------------------------- crontab


async def _read_crontab() -> tuple[bool, str, str]:
    """读取 crontab，返回 ``(命令可用, 内容, 错误信息)``。

    首次没有 crontab 时多数实现返回 1 + ``no crontab for user``，这属于正常空态。
    """
    if not shell.available("crontab"):
        return False, "", ""
    result = await shell.run(["crontab", "-l"], timeout=CRON_TIMEOUT)
    if result.ok:
        return True, result.out, ""
    if "no crontab" in f"{result.err}{result.out}".lower():
        return True, "", ""
    return True, "", (result.text or "读取 crontab 失败").strip()[:400]


async def _restore_crontab(text: str) -> None:
    """写入校验失败时回滚：原文为空则删除整份 crontab。"""
    if not text.strip():
        await shell.run(["crontab", "-r"], timeout=CRON_TIMEOUT)
        return
    await shell.run(["crontab", "-"], timeout=CRON_TIMEOUT, stdin=text.encode())


def _save_cron_backup(text: str) -> str:
    """把当前 crontab 落到配置目录的 ``crontab.bak.<时间戳>``，返回文件名。"""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = config_dir() / f"crontab.bak.{stamp}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, "utf-8")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return path.name


@router.get("/cron")
async def cron_read():
    available, text, error = await _read_crontab()
    return {"capabilities": {"crontab": available}, "raw": text,
            "lines": ops.parse_crontab(text), "error": error}


@router.post("/cron")
async def cron_write(body: CronBody, request: Request):
    """覆盖写入 crontab：逐行校验 → 备份 → 写入 → 读回校验 → 记审计。"""
    available, current, _error = await _read_crontab()
    if not available:
        raise HTTPException(400, "本机没有 crontab 命令，无法管理定时任务")
    submitted: list[str] = list(body.content.splitlines()) if body.content else []
    submitted.extend(str(item) for item in (body.lines or []))
    cleaned = [_guard(ops.validate_cron_line, line) for line in submitted if line.strip()]
    content = ops.render_crontab(cleaned)
    backup = ""
    if current.strip():
        backup = await asyncio.to_thread(_save_cron_backup, current)
    result = await shell.run(["crontab", "-"], timeout=CRON_TIMEOUT, stdin=content.encode())
    if not result.ok:
        raise HTTPException(500, (result.text or "写入 crontab 失败").strip()[:400])
    check = await shell.run(["crontab", "-l"], timeout=CRON_TIMEOUT)
    if not check.ok or ops.normalize_crontab(check.out) != ops.normalize_crontab(content):
        await _restore_crontab(current)
        raise HTTPException(500, "写入后校验不一致，已恢复原 crontab")
    audit.record(AuditEvent(action="cron_write", target="crontab",
                            summary=f"{len(cleaned)} 行；备份 {backup or '无'}",
                            source="web", ip=client_ip(request)))
    return {"ok": True, "raw": check.out, "lines": ops.parse_crontab(check.out),
            "backup": backup, "message": f"已写入 {len(cleaned)} 行定时任务"}


# ---------------------------------------------------------------- 本地备份


def _list_backup_files(path: Path) -> list[dict]:
    try:
        entries = list(os.scandir(path))
    except OSError:
        return []
    items = []
    for entry in entries:
        try:
            if not entry.is_file():
                continue
            info = entry.stat()
        except OSError:
            continue
        items.append({"name": entry.name, "size": info.st_size, "mtime": int(info.st_mtime)})
    items.sort(key=lambda item: item["mtime"], reverse=True)
    return items


def _make_archive(dest: Path, sources: list[str]) -> int:
    """打包成 gzip tar，返回归档体积。"""
    with tarfile.open(dest, "w:gz") as tar:
        for src in sources:
            arcname = os.path.basename(src.rstrip("/")) or "root"
            tar.add(src, arcname=arcname, recursive=True)
    return dest.stat().st_size


@router.get("/backups")
async def list_backups():
    path = await asyncio.to_thread(_ensure_dir, backup_dir())
    items = await asyncio.to_thread(_list_backup_files, path)
    return {"dir": str(path), "items": items,
            "max_bytes": BACKUP_MAX_BYTES,
            "capabilities": {"rclone": shell.available("rclone")}}


@router.post("/backups")
async def create_backup(body: BackupBody, request: Request):
    paths = [str(item).strip() for item in (body.paths or []) if str(item).strip()]
    if not paths:
        raise HTTPException(400, "请至少选择一个要备份的路径")
    if len(paths) > BACKUP_MAX_PATHS:
        raise HTTPException(400, f"单次最多备份 {BACKUP_MAX_PATHS} 个路径")
    sources = [_guard(ops.check_backup_source, item, PROTECTED) for item in paths]
    target_dir = await asyncio.to_thread(_ensure_dir, backup_dir())
    name = _guard(ops.check_backup_name, body.name) if body.name else ops.default_backup_name()
    dest = target_dir / name
    if dest.exists():
        raise HTTPException(409, f"备份已存在：{name}")
    try:
        total = await asyncio.to_thread(ops.tree_size, sources, BACKUP_MAX_BYTES)
        size = await asyncio.to_thread(_make_archive, dest, sources)
    except ops.OpsError as exc:
        raise HTTPException(400, str(exc)) from exc
    except OSError as exc:
        with contextlib.suppress(OSError):
            dest.unlink()
        raise HTTPException(500, f"打包失败：{exc}") from exc
    audit.record(AuditEvent(action="backup_create", target=name,
                            summary=f"{len(sources)} 个路径，{total} 字节 → {size} 字节",
                            source="web", ip=client_ip(request)))
    return {"ok": True, "name": name, "size": size, "source_bytes": total,
            "paths": sources, "dir": str(target_dir),
            "message": f"已创建备份 {name}"}


@router.delete("/backups/{name}")
async def delete_backup(name: str, request: Request):
    clean = _guard(ops.check_backup_name, name)
    path = backup_dir() / clean
    if not path.is_file():
        raise HTTPException(404, "备份不存在")
    await asyncio.to_thread(path.unlink)
    audit.record(AuditEvent(action="backup_delete", target=clean, source="web",
                            ip=client_ip(request)))
    return {"ok": True, "message": f"已删除备份 {clean}"}


# ---------------------------------------------------------------- 远程备份


@router.get("/backups/remotes")
async def list_remotes():
    available = shell.available("rclone")
    remotes: list[dict] = []
    error = ""
    if available:
        result = await shell.run(["rclone", "listremotes"], timeout=20)
        if result.ok:
            remotes = ops.parse_rclone_remotes(result.out)
        else:
            error = (result.text or "rclone 未配置任何远程").strip()[:400]
    return {"capabilities": {"rclone": available}, "remotes": remotes, "error": error}


@router.post("/backups/{name}/upload")
async def upload_backup(name: str, body: UploadBody, request: Request):
    if not shell.available("rclone"):
        raise HTTPException(400, "本机没有 rclone，无法上传到远程存储")
    clean = _guard(ops.check_backup_name, name)
    path = backup_dir() / clean
    if not path.is_file():
        raise HTTPException(404, "备份不存在")
    remote = _guard(ops.check_remote, body.remote)
    started = time.perf_counter()
    result = await shell.run(["rclone", "copy", str(path), remote], timeout=UPLOAD_TIMEOUT)
    audit.record(AuditEvent(action="backup_upload", target=clean, summary=f"→ {remote}",
                            source="web", ip=client_ip(request), ok=result.ok,
                            code=result.code, duration=round(time.perf_counter() - started, 3)))
    if not result.ok:
        raise HTTPException(500, (result.text or "rclone 上传失败").strip()[-600:])
    return {"ok": True, "message": f"已上传 {clean} → {remote}"}


# ---------------------------------------------------------------- 系统更新


def _apt_list_tool() -> str:
    """``apt list --upgradable`` 只有 apt(8) 提供——apt-get 没有 ``list`` 子命令。"""
    return "apt" if shell.available("apt") else ""


def _apt_install_tool() -> str:
    """安装/升级优先 apt-get（脚本友好、警告少），退到 apt。"""
    if shell.available("apt-get"):
        return "apt-get"
    return "apt" if shell.available("apt") else ""


async def _upgradable() -> tuple[list[dict], str]:
    tool = _apt_list_tool()
    if not tool:
        return [], ""
    result = await shell.run([tool, "list", "--upgradable"], timeout=APT_TIMEOUT,
                             env={"LC_ALL": "C", "LANG": "C"})
    packages = ops.parse_apt_upgradable(result.out)
    error = "" if result.ok or packages else (result.text or "").strip()[:400]
    return packages, error


@router.get("/updates")
async def list_updates():
    if not _apt_list_tool():
        return {"capabilities": {"apt": False}, "packages": [], "count": 0,
                "security": 0, "error": "本机没有 apt 命令，无法查询系统更新"}
    packages, error = await _upgradable()
    return {"capabilities": {"apt": True}, "packages": packages, "count": len(packages),
            "security": sum(1 for item in packages if item["security"]), "error": error}


@router.post("/updates/apply")
async def apply_updates(body: UpdateBody, request: Request):
    """只允许"安装更新"：``--only-upgrade`` 保证不会顺带装新包或删包。"""
    tool = _apt_install_tool()
    if not tool:
        raise HTTPException(400, "本机没有 apt-get，无法管理系统更新")
    names = [_guard(ops.check_package_name, item) for item in (body.packages or [])]
    if names and _apt_list_tool():
        # 只允许升级"真的有待升级版本"的包，避免拿本接口当通用安装器
        packages, _error = await _upgradable()
        known = {item["name"] for item in packages}
        unknown = [name for name in names if name not in known]
        if unknown:
            raise HTTPException(400, f"以下软件包当前没有可用更新：{', '.join(unknown[:5])}")
    if names:
        command = [tool, "install", "-y", "--only-upgrade", "--"] + names
    else:
        command = [tool, "upgrade", "-y"]
    started = time.perf_counter()
    result = await shell.run(command, timeout=UPDATE_TIMEOUT,
                             env={"DEBIAN_FRONTEND": "noninteractive"})
    detail = "指定包 " + " ".join(names) if names else "全部可升级包"
    audit.record(AuditEvent(action="system_update", target="apt", summary=detail,
                            source="web", ip=client_ip(request), ok=result.ok,
                            code=result.code,
                            duration=round(time.perf_counter() - started, 3)))
    if not result.ok:
        raise HTTPException(500, (result.text or "升级失败").strip()[-600:])
    return {"ok": True, "message": f"已完成升级（{detail}）",
            "output": (result.out or result.err).strip()[-4000:]}
