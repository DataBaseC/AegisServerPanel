"""存储：分区概览、目录占用分析、挂载/卸载。"""

from __future__ import annotations

import json
import os
import shutil

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import shell
from ..auth import require_auth, require_internal
from ..utils import is_root

router = APIRouter(prefix="/api/storage", tags=["storage"], dependencies=[Depends(require_auth)])


class MountBody(BaseModel):
    device: str
    mountpoint: str
    fstype: str | None = None
    options: str | None = None


class UnmountBody(BaseModel):
    path: str
    force: bool = False


@router.get("/overview")
async def overview():
    import psutil

    partitions = []
    degraded: list[str] = []
    # Android / PRoot 屏蔽 /proc/filesystems 并抛裸 PermissionError（不是 psutil.Error）：
    # 原来会让整个「存储」视图 500。拿不到分区表就退化成"只报盘使用率"。
    try:
        parts = psutil.disk_partitions(all=False)
    except (psutil.Error, OSError) as exc:
        parts = []
        degraded.append(f"disk_partitions: {exc}")
    for part in parts:
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            usage = None
        partitions.append({
            "device": part.device,
            "mountpoint": part.mountpoint,
            "fstype": part.fstype,
            "options": part.opts,
            "total": usage.total if usage else None,
            "used": usage.used if usage else None,
            "free": usage.free if usage else None,
            "percent": round(usage.percent, 1) if usage else None,
        })
    partitions.sort(key=lambda p: p["mountpoint"])

    try:
        io = psutil.disk_io_counters(perdisk=True) or {}
    except (psutil.Error, OSError):
        # Android / PRoot 屏蔽 /sys/block 并抛裸 PermissionError（不是 psutil.Error）：
        # 拿不到块设备计数就给空列表，别让整个「存储」视图 500
        io = {}
    disks = [
        {
            "name": name,
            "read_bytes": c.read_bytes,
            "write_bytes": c.write_bytes,
            "read_count": c.read_count,
            "write_count": c.write_count,
        }
        for name, c in sorted(io.items())
    ]

    block = []
    if shell.available("lsblk"):
        result = await shell.run(["lsblk", "-J", "-b", "-o",
                                  "NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL,RO,LABEL,UUID"], timeout=10)
        if result.ok:
            try:
                block = json.loads(result.out).get("blockdevices", [])
            except json.JSONDecodeError:
                block = []
    return {"partitions": partitions, "disks": disks, "blockdevices": block,
            "degraded": degraded}


@router.get("/dirsize")
async def dirsize(path: str = "/", depth: int = 1):
    """分析目录占用（子目录大小），按大小倒序。"""
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        raise HTTPException(400, "路径不存在或不是目录")
    if not shell.available("du"):
        raise HTTPException(400, "本机缺少 du 命令")
    depth = max(1, min(depth, 3))
    result = await shell.run(
        ["du", "-x", "-B1", f"-d{depth}", path], timeout=60
    )
    entries = []
    total = 0  # du 自身行 = 该目录（含全部子项）总占用
    for line in result.out.splitlines():
        size_str, _, item = line.partition("\t")
        if not item:
            continue
        try:
            size = int(size_str)
        except ValueError:
            continue
        if os.path.abspath(item) == path:
            total = size
            continue
        entries.append({"path": item, "name": os.path.basename(item.rstrip("/")) or item,
                        "size": size, "isdir": os.path.isdir(item)})
    entries.sort(key=lambda e: e["size"], reverse=True)
    usage = shutil.disk_usage(path)
    return {
        "path": path,
        "total": total,
        "entries": entries[:200],
        "mount_total": usage.total,
        "mount_used": usage.used,
        "mount_free": usage.free,
        "truncated": result.code == -1,
    }


@router.get("/mounts")
async def mounts():
    entries = []
    try:
        with open("/proc/mounts", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4:
                    entries.append({
                        "device": parts[0], "mountpoint": parts[1],
                        "fstype": parts[2], "options": parts[3],
                    })
    except OSError as exc:
        raise HTTPException(500, f"读取 /proc/mounts 失败: {exc}")
    return {"mounts": entries}


@router.post("/mount", dependencies=[Depends(require_internal)])
async def mount(body: MountBody):
    if not is_root():
        raise HTTPException(403, "挂载需要以 root 运行本服务")
    if not os.path.isabs(body.mountpoint):
        raise HTTPException(400, "挂载点必须是绝对路径")
    os.makedirs(body.mountpoint, exist_ok=True)
    cmd = ["mount"]
    if body.fstype:
        cmd += ["-t", body.fstype]
    if body.options:
        cmd += ["-o", body.options]
    cmd += ["--", body.device, body.mountpoint]
    result = await shell.run(cmd, timeout=30)
    if not result.ok:
        raise HTTPException(500, result.text or "挂载失败")
    return {"ok": True, "message": f"已挂载 {body.device} 到 {body.mountpoint}"}


@router.post("/unmount", dependencies=[Depends(require_internal)])
async def unmount(body: UnmountBody):
    if not is_root():
        raise HTTPException(403, "卸载需要以 root 运行本服务")
    cmd = ["umount"] + (["-f"] if body.force else []) + ["--", body.path]
    result = await shell.run(cmd, timeout=30)
    if not result.ok:
        raise HTTPException(500, result.text or "卸载失败")
    return {"ok": True, "message": f"已卸载 {body.path}"}


@router.get("/smart")
async def smart(device: str):
    if not shell.available("smartctl"):
        raise HTTPException(400, "未安装 smartctl（apt install smartmontools）")
    # realpath 归一化后再校验，拒绝 /dev/../etc/passwd 这类绕过写法
    real = os.path.realpath(os.path.abspath(device))
    if not real.startswith("/dev/"):
        raise HTTPException(400, "设备路径不合法")
    result = await shell.run(["smartctl", "-H", "-A", "-i", real], timeout=30)
    return {"device": device, "ok": result.ok, "output": result.text}
