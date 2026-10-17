"""回收站：覆盖写与删除前的自动备份，误操作可还原。

设计要点：

- **先搬家再动手**：覆盖写 / 删除执行前，把原文件（目录同理）整体移入回收站，
  移动是同一文件系统内的 rename，成本近乎为零；跨文件系统退化为复制。
- **索引落盘**：``index.json`` 记录原始路径、移入时间、大小、原因，原子替换；
  结构损坏时保留上一份（与 apps.json 同款策略）。
- **保留策略**：默认 30 天后自动清理（``SERVERPANEL_TRASH_RETENTION_DAYS``
  可覆盖，0 = 永不自动清理），列表与启动时都会触发一次清扫。
- **目录选址**：root 部署优先 ``/var/lib/serverpanel/trash``（回收站可能很大，
  不放 /etc），非 root 或不可写时退到配置目录旁；``SERVERPANEL_TRASH_DIR``
  可显式指定。测试环境随配置目录隔离。
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

_DEFAULT_RETENTION_DAYS = 30


def _retention_days() -> int:
    raw = os.environ.get("SERVERPANEL_TRASH_RETENTION_DAYS", "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_RETENTION_DAYS
    return max(0, min(value, 3650))


def _default_dir() -> Path:
    env = os.environ.get("SERVERPANEL_TRASH_DIR")
    if env:
        return Path(env).expanduser()
    from .config import config  # 延迟导入避免循环依赖

    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
        preferred = Path("/var/lib/serverpanel/trash")
        try:
            preferred.mkdir(parents=True, exist_ok=True)
            os.chmod(preferred.parent, 0o700)
            os.chmod(preferred, 0o700)
            return preferred
        except OSError:
            pass
    return Path(config.path).parent / "trash"


@dataclass
class TrashEntry:
    entry_id: str
    original: str
    stored: str
    size: int
    is_dir: bool
    reason: str
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.entry_id,
            "original": self.original,
            "name": os.path.basename(self.original.rstrip("/")) or self.original,
            "size": self.size,
            "is_dir": self.is_dir,
            "reason": self.reason,
            "time": int(self.ts),
        }


class Trash:
    """回收站：move / list / restore / purge，索引原子替换，线程安全。"""

    def __init__(self, directory: Path | None = None) -> None:
        self._dir = Path(directory) if directory else _default_dir()
        self._index_file = self._dir / "index.json"
        self._lock = threading.RLock()
        self._entries: list[TrashEntry] = []
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self._dir, 0o700)
        except OSError:
            pass
        self._load()
        self._cleanup_old()

    # ------------------------------------------------------------ 索引
    def _load(self) -> None:
        try:
            data = json.loads(self._index_file.read_text("utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return
        if not isinstance(data, list):
            return
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                self._entries.append(TrashEntry(
                    entry_id=str(item["id"]),
                    original=str(item["original"]),
                    stored=str(item["stored"]),
                    size=int(item.get("size", 0)),
                    is_dir=bool(item.get("is_dir", False)),
                    reason=str(item.get("reason", "")),
                    ts=float(item.get("ts", 0)),
                ))
            except (KeyError, TypeError, ValueError):
                continue  # 单条坏数据不拖垮整体

    def _save(self) -> None:
        tmp = self._index_file.with_name(f"index.json.{os.getpid()}.tmp")
        payload = [
            {
                "id": e.entry_id,
                "original": e.original,
                "stored": e.stored,
                "size": e.size,
                "is_dir": e.is_dir,
                "reason": e.reason,
                "ts": e.ts,
            }
            for e in self._entries
        ]
        try:
            tmp.write_text(json.dumps(payload, ensure_ascii=False), "utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._index_file)
        except OSError:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    # ------------------------------------------------------------ 操作
    def move(self, path: str, reason: str = "delete") -> TrashEntry:
        """把 path 移入回收站，返回索引条目。path 不存在时抛 FileNotFoundError。"""
        src = os.path.abspath(path)
        if not os.path.lexists(src):
            raise FileNotFoundError(src)
        with self._lock:
            entry_id = f"{int(time.time() * 1000):x}{os.urandom(3).hex()}"
            stored = self._dir / entry_id
            size = self._sizeof(src)
            is_dir = os.path.isdir(src) and not os.path.islink(src)
            # 同名文件夹批量移入时靠 entry_id 目录区分，不会互相覆盖
            os.makedirs(stored, exist_ok=True)
            dest = stored / (os.path.basename(src.rstrip("/")) or "root")
            try:
                os.rename(src, dest)  # 同盘 rename：瞬间完成
            except OSError as exc:
                # 只有跨文件系统（EXDEV）才值得退化为复制。磁盘满（ENOSPC）、
                # 权限不足时继续 copytree 只会留下索引外的半成品并掩盖真实原因
                if exc.errno != errno.EXDEV:
                    shutil.rmtree(stored, ignore_errors=True)
                    raise
                try:
                    if is_dir:
                        shutil.copytree(src, dest, symlinks=True)
                        shutil.rmtree(src)
                    else:
                        shutil.copy2(src, dest)
                        os.remove(src)
                except Exception:
                    # 复制中途失败：清掉半成品，别让回收站里出现无索引的残骸
                    shutil.rmtree(stored, ignore_errors=True)
                    raise
            entry = TrashEntry(entry_id=entry_id, original=src, stored=str(dest),
                               size=size, is_dir=is_dir, reason=reason)
            self._entries.insert(0, entry)
            self._save()
            return entry

    @staticmethod
    def _sizeof(path: str) -> int:
        try:
            if os.path.islink(path) or not os.path.isdir(path):
                return os.lstat(path).st_size
            total = 0
            for root, _dirs, files in os.walk(path):
                for name in files:
                    try:
                        total += os.lstat(os.path.join(root, name)).st_size
                    except OSError:
                        continue
            return total
        except OSError:
            return 0

    def list(self) -> list[dict]:
        with self._lock:
            self._cleanup_old()
            return [e.to_dict() for e in self._entries
                    if os.path.lexists(e.stored)]

    def restore(self, entry_id: str) -> str:
        """还原到原始路径；目标已存在时拒绝（不猜测用户想不想合并）。"""
        with self._lock:
            entry = next((e for e in self._entries if e.entry_id == entry_id), None)
            if entry is None:
                raise KeyError(entry_id)
            if not os.path.lexists(entry.stored):
                raise FileNotFoundError(entry.stored)
            if os.path.lexists(entry.original):
                raise FileExistsError(entry.original)
            os.makedirs(os.path.dirname(entry.original) or "/", exist_ok=True)
            try:
                os.rename(entry.stored, entry.original)
            except OSError:
                if entry.is_dir:
                    shutil.copytree(entry.stored, entry.original, symlinks=True)
                    shutil.rmtree(entry.stored, ignore_errors=True)
                else:
                    shutil.copy2(entry.stored, entry.original)
                    os.remove(entry.stored)
            self._entries = [e for e in self._entries if e.entry_id != entry_id]
            self._save()
            return entry.original

    def purge(self, entry_id: str) -> None:
        with self._lock:
            entry = next((e for e in self._entries if e.entry_id == entry_id), None)
            if entry is None:
                raise KeyError(entry_id)
            self._remove_stored(entry)
            self._entries = [e for e in self._entries if e.entry_id != entry_id]
            self._save()

    def purge_all(self) -> int:
        with self._lock:
            count = len(self._entries)
            for entry in self._entries:
                self._remove_stored(entry)
            self._entries = []
            self._save()
            return count

    @staticmethod
    def _remove_stored(entry: TrashEntry) -> None:
        try:
            if os.path.isdir(entry.stored) and not os.path.islink(entry.stored):
                shutil.rmtree(entry.stored, ignore_errors=True)
            else:
                os.remove(entry.stored)
        except OSError:
            pass

    def _cleanup_old(self) -> None:
        days = _retention_days()
        if days <= 0:
            return
        cutoff = time.time() - days * 86400
        stale = [e for e in self._entries if e.ts < cutoff]
        if not stale:
            return
        for entry in stale:
            self._remove_stored(entry)
        self._entries = [e for e in self._entries if e.ts >= cutoff]
        self._save()

    def usage(self) -> dict:
        with self._lock:
            total = sum(e.size for e in self._entries if os.path.lexists(e.stored))
            return {"count": len(self._entries), "bytes": total,
                    "retention_days": _retention_days()}


trash = Trash()
