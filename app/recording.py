"""终端会话录制（2.0 M5）：asciinema v2 JSONL。

格式（与 asciinema 兼容，可直接用 `asciinema play` 回放）：

- 首行 header：``{"version": 2, "width": 80, "height": 24, "timestamp": ...}``
- 之后每行：``[相对秒, "o" | "i", "数据"]``

默认关闭（prefs ``terminal.record_sessions``），目录在配置目录旁
``recordings/``。**任何写盘失败只停止录制，绝不影响终端本身**。
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import time
from pathlib import Path

# 只允许这类文件名被 API 读取/删除，防止路径穿越
NAME_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}\.cast$")

# 回放接口一次读入内存的上限：把 50MB 录制转成 JSON 事件数组要几百 MB 内存
MAX_REPLAY_BYTES = 32 * 1024 * 1024
# 录制文件保留策略（录制默认关闭，开启后必须防止磁盘只增不减）
RETENTION_DAYS = 30
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def recordings_dir() -> Path:
    from .config import config

    path = Path(config.path).parent / "recordings"
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700)
    return path


def cleanup_old(retention_days: int = RETENTION_DAYS,
                max_total: int = MAX_TOTAL_BYTES) -> int:
    """按天数 + 总体积清理录制文件，返回删除数量。

    录制开启后每次会话都会写一个新文件：没有清理策略时磁盘只增不减，
    直到写盘失败（``_write`` 会静默停录，界面上没有任何提示）。
    在每次开始录制时顺带执行一次，成本只是遍历一个小目录。
    """
    directory = recordings_dir()
    cutoff = time.time() - retention_days * 86400
    removed = 0
    try:
        items = []
        for path in directory.glob("*.cast"):
            try:
                stat = path.stat()
            except OSError:
                continue
            if stat.st_mtime < cutoff:
                with contextlib.suppress(OSError):
                    path.unlink()
                    removed += 1
                continue
            items.append((stat.st_mtime, stat.st_size, path))
        total = sum(size for _mtime, size, _path in items)
        for _mtime, size, path in sorted(items):  # 旧的先删
            if total <= max_total:
                break
            with contextlib.suppress(OSError):
                path.unlink()
                total -= size
                removed += 1
    except OSError:
        pass
    return removed


class Recorder:
    def __init__(self, max_bytes: int = 50 * 1024 * 1024) -> None:
        self._max = max(0, max_bytes)
        self._fh = None
        self._start = 0.0
        self._written = 0
        self.path: Path | None = None

    def start(self, width: int = 80, height: int = 24) -> "Recorder | None":
        try:
            name = f"{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}.cast"
            path = recordings_dir() / name
            fh = open(path, "w", encoding="utf-8")
        except OSError:
            return None
        self._start = time.time()
        self._fh = fh
        self.path = path
        self._write({"version": 2, "width": width, "height": height,
                     "timestamp": int(self._start)})
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
        # 顺带清理过期/超量录制（失败不影响本次录制）
        with contextlib.suppress(Exception):
            cleanup_old()
        return self

    def _write(self, payload) -> None:
        if self._fh is None:
            return
        if 0 < self._max and self._written >= self._max:
            self.close()
            return
        try:
            line = json.dumps(payload, ensure_ascii=False) + "\n"
            self._fh.write(line)
            self._written += len(line.encode("utf-8"))
        except (OSError, ValueError):
            self.close()

    def output(self, text: str) -> None:
        self._write([round(time.time() - self._start, 3), "o", text])

    def input(self, text: str) -> None:
        self._write([round(time.time() - self._start, 3), "i", text])

    def resize(self, cols: int, rows: int) -> None:
        """asciinema v2 的窗口尺寸事件，回放时按新尺寸换行。"""
        self._write([round(time.time() - self._start, 3), "r", f"{int(cols)}x{int(rows)}"])

    def close(self) -> None:
        if self._fh is not None:
            with contextlib.suppress(OSError):
                self._fh.close()
            self._fh = None


def load_events(name: str) -> list | None:
    """读取录制文件为事件数组；文件不存在或格式错误返回 None。"""
    if not NAME_RE.fullmatch(name or ""):
        return None
    path = recordings_dir() / name
    try:
        events = []
        with open(path, encoding="utf-8") as fh:
            for index, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                if index == 0 and isinstance(item, dict):
                    events.append({"header": item})
                elif isinstance(item, list) and len(item) == 3:
                    events.append({"time": item[0], "kind": item[1], "data": item[2]})
        return events
    except (OSError, json.JSONDecodeError, ValueError):
        return None
