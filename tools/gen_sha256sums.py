#!/usr/bin/env python3
"""生成 / 校验 SHA256SUMS 清单（2.0 M1 / P1-8）。

用途：``serverpanel --update`` 在切换代码后、安装依赖前，按仓库根目录的
``SHA256SUMS`` 逐文件校验，发现内容被篡改或缺失立即回退（服务不重启）。

清单覆盖仓库里的所有普通文件，排除清单自身、缓存目录与运行时产物；符号链接不入清单。

取内容的优先级：
1. **git 索引里的 blob**（首选）——校验的是「仓库内容」而不是某个工作副本，
   这样 Windows（autocrlf=true）与 Linux 上算出的清单一致，升级链路不会因为换行符误报；
2. **直接读工作树**（兜底）——没有 git 元数据时（离线包、tar 解包目录、CI 产物）也能生成，
   此时按文件当前字节计算。

用法：
    python3 tools/gen_sha256sums.py           # 重新生成 SHA256SUMS
    python3 tools/gen_sha256sums.py --check   # 校验仓库内容是否与清单一致
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "SHA256SUMS"
MANIFEST_NAME = MANIFEST.name

# 工作树兜底扫描时跳过的东西（与 .gitignore 的运行时产物保持一致）
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
             "node_modules", ".venv", "venv", ".idea", ".vscode"}
SKIP_NAMES = {"VERSION", "update.lock", ".supervisor.pid", ".supervisor.lock",
              "config.json", ".env", ".DS_Store"}
SKIP_SUFFIXES = (".pyc", ".pyo", ".log", ".log.1")


def _git_names() -> list[str] | None:
    """git 索引中的普通文件名；没有 git（或不是仓库）返回 None。"""
    try:
        raw = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    names = [name for name in raw.decode("utf-8").split("\0")
             if name and name != MANIFEST_NAME]
    return names or None


def _git_blobs(names: list[str]) -> dict[str, bytes] | None:
    """一次性批量读 blob 内容（git cat-file --batch），避免逐文件起进程。"""
    request = "".join(f"{name}\n" for name in names).encode("utf-8")
    try:
        proc = subprocess.run(
            ["git", "cat-file", "--batch"], cwd=ROOT, input=request,
            capture_output=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    out = proc.stdout
    blobs: dict[str, bytes] = {}
    pos = 0
    for name in names:
        newline = out.find(b"\n", pos)
        if newline < 0:
            return None
        header = out[pos:newline].split()
        # 缺失对象时 header 形如 b"<name> missing"
        if len(header) < 3:
            pos = newline + 1
            continue
        size = int(header[2])
        blobs[name] = out[newline + 1:newline + 1 + size]
        pos = newline + 1 + size + 1
    return blobs


def _walk_tree() -> dict[str, bytes]:
    """兜底：直接扫工作树（没有 git 元数据时用）。"""
    blobs: dict[str, bytes] = {}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name in SKIP_NAMES or name == MANIFEST_NAME:
                continue
            if name.endswith(SKIP_SUFFIXES):
                continue
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(ROOT).as_posix()
            blobs[rel] = path.read_bytes()
    return blobs


def contents() -> dict[str, bytes]:
    names = _git_names()
    if names:
        blobs = _git_blobs(names)
        if blobs:
            return blobs
    return _walk_tree()


def render() -> str:
    lines = [f"{hashlib.sha256(data).hexdigest()}  {name}"
             for name, data in sorted(contents().items())]
    return "\n".join(lines) + "\n"


def main() -> int:
    content = render()
    if "--check" in sys.argv:
        try:
            current = MANIFEST.read_text("utf-8").replace("\r\n", "\n")
        except OSError:
            print("SHA256SUMS 不存在，请运行 python3 tools/gen_sha256sums.py", file=sys.stderr)
            return 1
        if current != content:
            print("SHA256SUMS 与仓库内容不一致，请重新生成后提交。", file=sys.stderr)
            return 1
        print(f"SHA256SUMS 校验通过（{content.count(chr(10))} 个文件）")
        return 0
    # 显式 LF：Windows 上默认文本模式会写 CRLF，导致设备端校验失败
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    print(f"已生成 {MANIFEST}（{content.count(chr(10))} 个文件）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
