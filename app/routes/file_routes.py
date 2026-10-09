"""文件管理：浏览、读写、上传下载、删除、重命名、搜索、解压、远程拉取、权限。"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile
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
ARCHIVE_PREFIX = "serverpanel-"
ARCHIVE_STALE_SECONDS = 3600  # 进程崩溃遗留的打包临时目录，超过 1 小时后清扫
FETCH_CHUNK = 256 * 1024
FETCH_MAX_BYTES = 1024 * 1024 * 1024  # 单个远程文件上限 1GB
FETCH_TIMEOUT = 30                    # 远程拉取的连接/读超时（秒）
OCTAL_RE = re.compile(r"^[0-7]{3,4}$")
# 乐观锁时间戳的精度分界：小于该值视作秒级（1e12 秒 = 公元 33658 年，
# 1e12 纳秒 = 1970-01-01 之后 1000 秒），两种情况都不会误判
NS_THRESHOLD = 10 ** 12

# 压缩包识别：按扩展名（前缀匹配 tar 的多级后缀）
ARCHIVE_SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2", ".txz", ".tar", ".zip")


class WriteBody(BaseModel):
    path: str
    content: str
    expected_mtime: int | None = None  # 乐观锁：与读取时的 mtime 不符则拒绝保存


class PathBody(BaseModel):
    path: str


class RenameBody(BaseModel):
    path: str
    target: str


class DeleteBody(BaseModel):
    paths: List[str]


class ChmodBody(BaseModel):
    path: str
    mode: str            # 八进制字符串，如 "644" / "0755"
    recursive: bool = False


class FetchBody(BaseModel):
    url: str
    dest_dir: str
    filename: str | None = None


def _abs(path: str) -> str:
    if not path:
        raise HTTPException(400, "缺少路径参数")
    try:
        return os.path.abspath(path)
    except ValueError:  # 路径里混入 NUL 字节等非法内容
        raise HTTPException(400, "路径不合法")


def cleanup_stale_archives() -> None:
    """清扫历史遗留的下载打包临时目录（正常流程在响应后即删，
    这里兜底进程中途被杀的情况，防止 /tmp 被慢慢塞满）。"""
    tmp_root = tempfile.gettempdir()
    now = time.time()
    try:
        names = os.listdir(tmp_root)
    except OSError:
        return
    for name in names:
        if not name.startswith(ARCHIVE_PREFIX):
            continue
        full = os.path.join(tmp_root, name)
        try:
            if now - os.stat(full).st_mtime > ARCHIVE_STALE_SECONDS:
                if os.path.isdir(full):
                    shutil.rmtree(full, ignore_errors=True)
                else:
                    os.remove(full)
        except OSError:
            continue


def _rmtree_quiet(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


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
    # 上限钳制在服务端：客户端传再大的 max_bytes 也只按 EDIT_LIMIT 读，
    # 否则一个查询参数就能让面板把任意大文件整个读进内存（OOM 打挂面板）
    max_bytes = max(1, min(max_bytes, EDIT_LIMIT))
    size = os.path.getsize(full)
    if size > max_bytes:
        raise HTTPException(413, f"文件过大（{size} 字节），请直接下载查看")

    def _load() -> tuple[bytes, int]:
        with open(full, "rb") as fh:
            data = fh.read(max_bytes + 1)
        return data, os.stat(full).st_mtime_ns

    data, mtime_ns = await asyncio.to_thread(_load)  # 大文件读盘不阻塞事件循环
    if b"\x00" in data[:8192]:
        raise HTTPException(415, "二进制文件，不支持在线编辑")
    return {"path": full, "size": size,
            "content": data.decode("utf-8", "replace"), "mtime": mtime_ns}


@router.post("/write")
async def write_file(body: WriteBody):
    full = _abs(body.path)
    if os.path.isdir(full):
        raise HTTPException(400, "目标是一个目录")
    if len(body.content.encode()) > EDIT_LIMIT:
        raise HTTPException(413, "内容过大，请改用上传方式")
    if body.expected_mtime is not None and os.path.exists(full):
        # 乐观锁取纳秒（秒级精度下同秒内外部修改检测不到），但**双精度接受**：
        # 外部脚本 / Agent / 浏览器缓存的旧前端仍可能传秒级时间戳，
        # 只按纳秒比对会让它们的保存永远 409。
        current = os.stat(full).st_mtime_ns
        expected = body.expected_mtime
        if expected < NS_THRESHOLD:  # < 1e12 视作秒级时间戳
            stale = current // 1_000_000_000 != expected
        else:
            stale = current != expected
        if stale:
            try:
                when = time.strftime("%H:%M:%S", time.localtime(current / 1e9))
            except (OSError, OverflowError, ValueError):
                # 磁盘 mtime 越界（异常文件系统 / 被写坏的时间戳）不能让 409 变 500
                when = "未知时间"
            raise HTTPException(409, f"文件在编辑期间已被修改（磁盘版本更新于 {when}），"
                                     f"直接保存会覆盖它")

    def _save() -> None:
        os.makedirs(os.path.dirname(full) or "/", exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(body.content)

    await asyncio.to_thread(_save)  # 写盘不阻塞事件循环
    return {"ok": True, "message": f"已保存 {full}"}


@router.post("/mkdir")
async def make_dir(body: PathBody):
    full = _abs(body.path)
    if os.path.exists(full):
        raise HTTPException(400, "路径已存在")
    try:
        await asyncio.to_thread(os.makedirs, full, exist_ok=False)
    except OSError as exc:
        raise HTTPException(500, f"创建失败: {exc.strerror or exc}")
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

    def _move() -> None:
        os.makedirs(os.path.dirname(target) or "/", exist_ok=True)
        shutil.move(source, target)  # 跨设备 move = 复制 + 删除，大目录会很久

    try:
        await asyncio.to_thread(_move)
    except OSError as exc:
        raise HTTPException(500, f"移动失败: {exc.strerror or exc}")
    return {"ok": True, "message": f"已移动到 {target}"}


@router.post("/copy")
async def copy(body: RenameBody):
    source = _abs(body.path)
    target = os.path.abspath(body.target)
    if not os.path.lexists(source):
        raise HTTPException(404, "源路径不存在")
    if os.path.exists(target):
        raise HTTPException(400, "目标路径已存在")

    def _copy() -> None:
        if os.path.isdir(source):
            shutil.copytree(source, target, symlinks=True)
        else:
            os.makedirs(os.path.dirname(target) or "/", exist_ok=True)
            shutil.copy2(source, target)

    try:
        await asyncio.to_thread(_copy)  # 大目录复制动辄几十秒，绝不能卡事件循环
    except OSError as exc:
        raise HTTPException(500, f"复制失败: {exc.strerror or exc}")
    return {"ok": True, "message": f"已复制到 {target}"}


@router.post("/delete")
async def delete(body: DeleteBody):
    if not body.paths:
        raise HTTPException(400, "未指定要删除的路径")

    def _delete() -> tuple[list, list]:
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
        return removed, failed

    removed, failed = await asyncio.to_thread(_delete)  # rmtree 大目录会很久
    return {"ok": not failed, "removed": removed, "failed": failed,
            "message": f"已删除 {len(removed)} 项" + (f"，{len(failed)} 项失败" if failed else "")}


@router.get("/download")
async def download(background: BackgroundTasks, path: str = Query(...)):
    full = _abs(path)
    if not os.path.lexists(full):
        raise HTTPException(404, "路径不存在")
    if os.path.isfile(full):
        return FileResponse(full, filename=os.path.basename(full))
    # 系统关键目录与文件系统根（"/"、盘符根、UNC 根）体量巨大且无下载意义，
    # 直接拒绝——否则一次请求就会尝试打包整个磁盘，写满临时分区
    normalized = os.path.abspath(full).rstrip("/") or "/"
    if normalized in PROTECTED or os.path.dirname(normalized) == normalized:
        raise HTTPException(400, f"{normalized} 是系统关键目录或文件系统根，请进入子目录逐级下载")
    # 打包可能耗时较长，放线程池执行，避免阻塞事件循环拖死整个面板
    tmp_dir = tempfile.mkdtemp(prefix=ARCHIVE_PREFIX)
    archive_base = os.path.join(tmp_dir, os.path.basename(normalized) or "root")
    try:
        archive = await asyncio.to_thread(
            shutil.make_archive, archive_base, "zip", root_dir=full
        )
    except OSError as exc:
        _rmtree_quiet(tmp_dir)
        raise HTTPException(500, f"打包失败: {exc}")
    # FileResponse 发送完毕后删除临时目录；进程中途被杀时由 cleanup_stale_archives 兜底
    background.add_task(_rmtree_quiet, tmp_dir)
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
        def _save(dest: str = destination) -> None:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as fh:
                shutil.copyfileobj(upload_file.file, fh, length=1024 * 1024)

        try:
            await asyncio.to_thread(_save)  # 大文件写盘不阻塞事件循环
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
    # 关键词里带通配符就按用户写的匹配（如 *.log），否则按"文件名包含关键词"匹配
    pattern = q if any(ch in q for ch in "*?[") else f"*{q}*"
    # timeout 保证超时时已搜到的部分结果还能拿到（shell.run 超时会丢掉全部输出）
    cmd: list[str] = []
    if os.name == "posix" and shutil.which("timeout"):
        cmd += ["timeout", "25"]
    cmd += [
        "find", full, "-xdev",
        "-path", "/proc", "-prune", "-o",
        "-path", "/sys", "-prune", "-o",
        "-path", "/dev", "-prune", "-o",
        "-iname", pattern,
        "-printf", "%y\t%T@\t%s\t%p\n",
    ]
    result = await shell.run(cmd, timeout=35)

    note = ""
    if result.code == 124:
        note = "搜索超时，结果可能不完整（换更具体的目录或关键词会更快）"
    elif result.code == -1 and result.err:
        note = result.err
    elif not result.out and result.err and result.code not in (0, 1):
        note = result.err

    matches: list[dict] = []
    for line in (result.out or "").splitlines():
        parts = line.split("\t", 3)
        if len(parts) != 4 or not parts[3]:
            continue
        ftype, mtime, size, p = parts
        try:
            mtime, size = int(float(mtime)), int(float(size))
        except ValueError:
            mtime, size = 0, 0
        matches.append({"path": p, "name": os.path.basename(p),
                        "is_dir": ftype == "d", "size": size, "mtime": mtime})
        if len(matches) >= limit:
            break
    return {"query": q, "root": full, "matches": matches,
            "truncated": len(matches) >= limit, "note": note}


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


# ---------------------------------------------------------------- 解压

def _archive_dest(source: str) -> str:
    """解压目标目录：同级、去掉压缩后缀；已存在则拒绝（不猜用户想不想合并）。"""
    name = os.path.basename(source)
    for suffix in ARCHIVE_SUFFIXES:
        if name.lower().endswith(suffix) and len(name) > len(suffix):
            name = name[:-len(suffix)]
            break
    else:
        raise HTTPException(400, "不是可识别的压缩包（支持 zip / tar / tar.gz / tgz / tar.bz2 / tar.xz）")
    name = name.strip() or "extracted"
    dest = os.path.join(os.path.dirname(source), name)
    if os.path.exists(dest):
        raise HTTPException(400, f"目标目录已存在：{dest}，请先重命名或删除")
    return dest


def _extract(source: str, dest: str) -> int:
    """同步解压，返回解出的条目数。tar 的成员路径逐个校验，防止写出目标目录之外。"""
    lower = source.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(source) as bundle:
            # CPython 的 zipfile 自带成员路径清洗（去盘符、去绝对路径、去 ..）
            bundle.extractall(dest)
            return len(bundle.namelist())
    base = os.path.realpath(dest)
    count = 0
    try:
        with tarfile.open(source, "r:*") as bundle:
            if sys.version_info >= (3, 12):
                # 3.12+ 官方安全过滤器：越界链接 / 设备文件 / 绝对路径会被拒绝并抛 FilterError
                bundle.extractall(dest, filter="data")
                return len(bundle.getmembers())
            safe = []
            for member in bundle.getmembers():
                parts = Path(member.name).parts
                if member.name.startswith(("/", "\\")) or ".." in parts:
                    continue  # 绝对路径 / 穿越目标目录：丢弃
                if member.isdev():
                    continue  # 设备文件不还原
                if member.issym() or member.islnk():
                    # 链接不还原：「link -> /etc」+「link/shadow」两段式成员在校验阶段
                    # 第二段的目标还不存在（realpath 解析不出逃逸），只有落盘后才暴露，
                    # 因此这个分支直接不建链接，彻底断掉该路径（3.12+ 分支走官方 data 过滤器）
                    continue
                target = os.path.realpath(os.path.join(base, member.name))
                if target != base and not target.startswith(base + os.sep):
                    continue
                safe.append(member)
            bundle.extractall(dest, members=safe)
            count = len(safe)
    except tarfile.FilterError as exc:
        # 越界条目被过滤器拦下：清掉半解压现场，按用户输入错误报 400 而不是 500
        shutil.rmtree(dest, ignore_errors=True)
        raise HTTPException(400, f"压缩包包含越界或非法条目，已中止解压（{type(exc).__name__}）")
    return count


@router.post("/extract")
async def extract(body: PathBody):
    source = _abs(body.path)
    if not os.path.isfile(source):
        raise HTTPException(404, "压缩包不存在或不是普通文件")
    dest = _archive_dest(source)
    os.makedirs(dest)
    try:
        count = await asyncio.to_thread(_extract, source, dest)
    except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        shutil.rmtree(dest, ignore_errors=True)  # 解压失败不留半个目录
        raise HTTPException(500, f"解压失败: {exc}")
    return {"ok": True, "dest": dest, "count": count,
            "message": f"已解压 {count} 项到 {dest}"}


# ---------------------------------------------------------------- 远程拉取

def _fetch_sync(url: str, dest_file: str) -> int:
    """同步流式下载，返回字节数。仅 http/https（urllib 对 file:// 等协议照单全收，必须显式拦）。"""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(400, "仅支持 http/https 直链")
    request = urllib.request.Request(url, headers={"User-Agent": "AegisServerPanel/1.1"})
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as resp, \
                open(dest_file, "wb") as fh:
            while True:
                chunk = resp.read(FETCH_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > FETCH_MAX_BYTES:
                    raise HTTPException(413, f"文件超过上限（{FETCH_MAX_BYTES // (1024 * 1024)}MB），已中止")
                fh.write(chunk)
    except HTTPException:
        with contextlib.suppress(OSError):
            os.remove(dest_file)
        raise
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.remove(dest_file)
        raise HTTPException(502, f"拉取失败: {exc}")
    return total


@router.post("/fetch")
async def fetch_url(body: FetchBody):
    dest_dir = _abs(body.dest_dir)
    if not os.path.isdir(dest_dir):
        raise HTTPException(400, "目标必须是已存在的目录")
    name = (body.filename or os.path.basename(urllib.parse.urlparse(body.url).path) or "").strip()
    name = name.replace("\\", "/").split("/")[-1]
    if not name or name in (".", ".."):
        raise HTTPException(400, "无法从 URL 判断文件名，请手动指定")
    dest_file = os.path.join(dest_dir, name)
    if os.path.exists(dest_file):
        raise HTTPException(400, f"目标已存在：{dest_file}")
    size = await asyncio.to_thread(_fetch_sync, body.url, dest_file)
    return {"ok": True, "path": dest_file, "size": size,
            "message": f"已下载 {name}（{size} 字节）到 {dest_dir}"}


# ---------------------------------------------------------------- 权限

@router.post("/chmod")
async def chmod_path(body: ChmodBody):
    full = _abs(body.path)
    if not os.path.lexists(full):
        raise HTTPException(404, "路径不存在")
    if not OCTAL_RE.fullmatch(body.mode):
        raise HTTPException(400, "权限必须是 3~4 位八进制，如 644 / 755")
    _guard_delete(full)  # 系统关键目录本身的权限不允许在界面里改
    value = int(body.mode, 8)
    targets = [full]
    if body.recursive and os.path.isdir(full) and not os.path.islink(full):
        for root, dirs, files in os.walk(full):
            # os.chmod 会跟随符号链接，目录树里的链接一律跳过
            targets.extend(os.path.join(root, name) for name in dirs + files
                           if not os.path.islink(os.path.join(root, name)))
    changed, failed = 0, []
    for target in targets:
        try:
            os.chmod(target, value)
            changed += 1
        except OSError as exc:
            failed.append({"path": target, "error": str(exc)})
    if failed and not changed:
        raise HTTPException(500, f"权限修改失败: {failed[0]['error']}")
    return {"ok": not failed, "changed": changed, "failed": failed,
            "message": f"已修改 {changed} 项权限为 {body.mode}"
                       + (f"，{len(failed)} 项失败" if failed else "")}
