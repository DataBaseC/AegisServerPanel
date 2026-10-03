"""文件管理：浏览、读写、上传下载、删除、重命名、搜索。"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import time
from typing import List

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .. import shell
from ..auth import require_internal

# 文件管理涉及读写、上传、删除，仅在内网模式开放
router = APIRouter(prefix="/api/files", tags=["files"], dependencies=[Depends(require_internal)])

# 这些路径本身禁止删除/重命名（其内部文件不受限制）
PROTECTED = {
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
    "/libx32", "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin",
    "/srv", "/sys", "/tmp", "/usr", "/var",
}
EDIT_LIMIT = 2 * 1024 * 1024  # 在线编辑上限 2MB


class WriteBody(BaseModel):
    path: str
    content: str


class PathBody(BaseModel):
    path: str


class RenameBody(BaseModel):
    path: str
    target: str


class DeleteBody(BaseModel):
    paths: List[str]


def _abs(path: str) -> str:
    if not path:
        raise HTTPException(400, "缺少路径参数")
    return os.path.abspath(path)


def _guard_delete(path: str) -> None:
    normalized = os.path.abspath(path).rstrip("/") or "/"
    if normalized in PROTECTED:
        raise HTTPException(403, f"受保护的系统目录，禁止操作：{normalized}")


def _entry(path: str, name: str) -> dict:
    full = os.path.join(path, name)
    try:
        st = os.lstat(full)
    except OSError:
        return {"name": name, "path": full, "error": True}
    is_link = stat.S_ISLNK(st.st_mode)
    is_dir = stat.S_ISDIR(st.st_mode)
    entry = {
        "name": name,
        "path": full,
        "is_dir": is_dir,
        "is_link": is_link,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
        "mode": oct(stat.S_IMODE(st.st_mode)),
        "uid": st.st_uid,
        "gid": st.st_gid,
    }
    if is_link:
        try:
            entry["link_target"] = os.readlink(full)
        except OSError:
            entry["link_target"] = None
    return entry


@router.get("/roots")
async def roots():
    """返回文件管理器的快捷入口。"""
    candidates = [
        ("/", "根目录"), ("/root", "root 家目录"), ("/home", "用户目录"),
        ("/etc", "配置"), ("/var/log", "日志"), ("/opt", "opt"),
        ("/srv", "srv"), ("/mnt", "mnt"), ("/media", "media"), ("/tmp", "临时文件"),
    ]
    return {
        "roots": [{"path": p, "label": label, "exists": os.path.isdir(p)} for p, label in candidates],
        "cwd": os.getcwd(),
    }


@router.get("/list")
async def list_dir(path: str = "/", show_hidden: bool = True):
    full = _abs(path)
    if not os.path.exists(full):
        raise HTTPException(404, "路径不存在")
    if not os.path.isdir(full):
        raise HTTPException(400, "路径不是目录")
    try:
        names = os.listdir(full)
    except PermissionError:
        raise HTTPException(403, "没有权限读取该目录")

    entries = [_entry(full, n) for n in names]
    if not show_hidden:
        entries = [e for e in entries if not e["name"].startswith(".")]
    entries.sort(key=lambda e: (not e.get("is_dir", False), e["name"].lower()))

    parent = os.path.dirname(full.rstrip("/")) or "/"
    try:
        usage = shutil.disk_usage(full)
        disk = {"total": usage.total, "used": usage.used, "free": usage.free}
    except OSError:
        disk = None
    return {"path": full, "parent": parent, "entries": entries, "disk": disk}


@router.get("/stat")
async def stat_path(path: str):
    full = _abs(path)
    if not os.path.lexists(full):
        raise HTTPException(404, "路径不存在")
    return _entry(os.path.dirname(full), os.path.basename(full))


@router.get("/read")
async def read_file(path: str, max_bytes: int = EDIT_LIMIT):
    full = _abs(path)
    if not os.path.isfile(full):
        raise HTTPException(404, "文件不存在或不是普通文件")
    size = os.path.getsize(full)
    if size > max_bytes:
        raise HTTPException(413, f"文件过大（{size} 字节），请直接下载查看")
    with open(full, "rb") as fh:
        data = fh.read()
    if b"\x00" in data[:8192]:
        raise HTTPException(415, "二进制文件，不支持在线编辑")
    return {"path": full, "size": size,
            "content": data.decode("utf-8", "replace"), "mtime": int(os.path.getmtime(full))}


@router.post("/write")
async def write_file(body: WriteBody):
    full = _abs(body.path)
    if os.path.isdir(full):
        raise HTTPException(400, "目标是一个目录")
    if len(body.content.encode()) > EDIT_LIMIT:
        raise HTTPException(413, "内容过大，请改用上传方式")
    os.makedirs(os.path.dirname(full) or "/", exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(body.content)
    return {"ok": True, "message": f"已保存 {full}"}


@router.post("/mkdir")
async def make_dir(body: PathBody):
    full = _abs(body.path)
    if os.path.exists(full):
        raise HTTPException(400, "路径已存在")
    try:
        os.makedirs(full, exist_ok=False)
    except OSError as exc:
        raise HTTPException(500, f"创建失败: {exc}")
    return {"ok": True, "message": f"已创建目录 {full}"}


@router.post("/rename")
async def rename(body: RenameBody):
    source = _abs(body.path)
    _guard_delete(source)
    target = body.target if os.path.isabs(body.target) else os.path.join(os.path.dirname(source), body.target)
    target = os.path.abspath(target)
    if not os.path.lexists(source):
        raise HTTPException(404, "源路径不存在")
    if os.path.exists(target):
        raise HTTPException(400, "目标路径已存在")
    try:
        os.makedirs(os.path.dirname(target) or "/", exist_ok=True)
        shutil.move(source, target)
    except OSError as exc:
        raise HTTPException(500, f"移动失败: {exc}")
    return {"ok": True, "message": f"已移动到 {target}"}


@router.post("/copy")
async def copy(body: RenameBody):
    source = _abs(body.path)
    target = os.path.abspath(body.target)
    if not os.path.lexists(source):
        raise HTTPException(404, "源路径不存在")
    if os.path.exists(target):
        raise HTTPException(400, "目标路径已存在")
    try:
        if os.path.isdir(source):
            shutil.copytree(source, target, symlinks=True)
        else:
            os.makedirs(os.path.dirname(target) or "/", exist_ok=True)
            shutil.copy2(source, target)
    except OSError as exc:
        raise HTTPException(500, f"复制失败: {exc}")
    return {"ok": True, "message": f"已复制到 {target}"}


@router.post("/delete")
async def delete(body: DeleteBody):
    if not body.paths:
        raise HTTPException(400, "未指定要删除的路径")
    removed, failed = [], []
    for item in body.paths:
        full = _abs(item)
        try:
            _guard_delete(full)
            if not os.path.lexists(full):
                failed.append({"path": full, "error": "不存在"})
                continue
            if os.path.isdir(full) and not os.path.islink(full):
                shutil.rmtree(full)
            else:
                os.remove(full)
            removed.append(full)
        except HTTPException as exc:
            failed.append({"path": full, "error": exc.detail})
        except OSError as exc:
            failed.append({"path": full, "error": str(exc)})
    return {"ok": not failed, "removed": removed, "failed": failed,
            "message": f"已删除 {len(removed)} 项" + (f"，{len(failed)} 项失败" if failed else "")}


@router.get("/download")
async def download(path: str = Query(...)):
    full = _abs(path)
    if not os.path.lexists(full):
        raise HTTPException(404, "路径不存在")
    if os.path.isfile(full):
        return FileResponse(full, filename=os.path.basename(full))
    # 目录打包后下载
    tmp_dir = tempfile.mkdtemp(prefix="serverpanel-")
    archive_base = os.path.join(tmp_dir, os.path.basename(full.rstrip("/")) or "root")
    archive = shutil.make_archive(archive_base, "zip", root_dir=full)
    return FileResponse(archive, filename=os.path.basename(archive), media_type="application/zip")


@router.post("/upload")
async def upload(
    path: str = Form(...),
    overwrite: bool = Form(True),
    files: List[UploadFile] = File(...),
):
    target_dir = _abs(path)
    if not os.path.isdir(target_dir):
        raise HTTPException(400, "上传目标必须是已存在的目录")
    saved, failed = [], []
    for upload_file in files:
        raw_name = (upload_file.filename or "unnamed").replace("\\", "/")
        parts = [p for p in raw_name.split("/") if p not in ("", ".", "..")]
        if not parts:
            failed.append({"name": raw_name, "error": "文件名不合法"})
            continue
        destination = os.path.join(target_dir, *parts)
        if os.path.exists(destination) and not overwrite:
            failed.append({"name": raw_name, "error": "文件已存在"})
            continue
        try:
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            with open(destination, "wb") as fh:
                shutil.copyfileobj(upload_file.file, fh, length=1024 * 1024)
            saved.append(destination)
        except OSError as exc:
            failed.append({"name": raw_name, "error": str(exc)})
        finally:
            await upload_file.close()
    return {"ok": not failed, "saved": saved, "failed": failed,
            "message": f"已上传 {len(saved)} 个文件" + (f"，{len(failed)} 个失败" if failed else "")}


@router.get("/search")
async def search(path: str = "/", q: str = "", limit: int = 200):
    full = _abs(path)
    if not q:
        raise HTTPException(400, "请输入搜索关键词")
    if not shell.available("find"):
        raise HTTPException(400, "本机缺少 find 命令")
    limit = max(1, min(limit, 1000))
    result = await shell.run(
        ["find", full, "-xdev", "-iname", f"*{q}*", "-not", "-path", "*/proc/*"],
        timeout=40,
    )
    matches = [line for line in result.out.splitlines() if line][:limit]
    return {"query": q, "root": full, "matches": [
        {"path": m, "name": os.path.basename(m), "is_dir": os.path.isdir(m)} for m in matches
    ], "truncated": len(matches) >= limit}


@router.get("/usage")
async def path_usage(path: str):
    """查看单个路径占用的磁盘空间（目录递归统计）。"""
    full = _abs(path)
    if not os.path.exists(full):
        raise HTTPException(404, "路径不存在")
    if not shell.available("du"):
        return {"path": full, "size": None, "error": "缺少 du 命令"}
    result = await shell.run(["du", "-x", "-sb", full], timeout=60)
    size = None
    if result.ok and result.out:
        try:
            size = int(result.out.split()[0])
        except (ValueError, IndexError):
            size = None
    return {"path": full, "size": size, "mtime": int(time.time())}
