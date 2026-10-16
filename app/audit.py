"""统一审计管道：所有敏感操作一条不落地记下来。

设计要点：

- **一条 JSONL 一行事件**，按天滚动（``audit-YYYYMMDD.jsonl``），权限 0600，
  与配置文件同目录（root 部署时即 ``/etc/serverpanel/audit/``）。
- **写不阻塞事件循环**：记录请求进内存队列，由独立守护线程落盘；进程被杀时
  队列里未落盘的事件会丢——审计的价值在于"绝大多数事件可追溯"，可用性优先。
- **读走文件**：查询时按日期范围读文件尾部，内存里只留最近若干条做面板速览。
- **CLI 也记**：``serverpanel --enable-internal`` 等本机命令同样算敏感操作，
  通过 :func:`record_cli` 直接追加（与 Web 操作同一套格式）。

事件字段：时间、来源（web 面板会话 / agent 令牌 / 本机 CLI / 系统）、来源 IP、
操作类型、目标、参数摘要、结果、耗时。参数摘要统一截断，防止超长命令/路径
把单行撑爆。
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# 单条事件各字段的截断上限
_MAX_SUMMARY = 2000
_MAX_TARGET = 1024

# 内存速览缓冲（面板「最近事件」直接读它，不碰盘）
_RECENT_MAX = 200

# 查询时的倒读粒度与单文件读取上限（避免 readlines() 把整天文件塞进内存）
_READ_CHUNK = 256 * 1024
_MAX_READ_BYTES = 8 * 1024 * 1024

# 默认保留天数；SERVERPANEL_AUDIT_RETENTION_DAYS 可覆盖
_DEFAULT_RETENTION_DAYS = 90


def _retention_days() -> int:
    raw = os.environ.get("SERVERPANEL_AUDIT_RETENTION_DAYS", "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_RETENTION_DAYS
    return max(1, min(value, 3650))


def _clip(value: Any, limit: int = _MAX_SUMMARY) -> str:
    text = str(value if value is not None else "")
    return text[:limit]


@dataclass
class AuditEvent:
    """一条审计事件。``summary`` 放操作参数摘要（命令、路径列表等）。"""

    action: str                     # 操作类型，如 exec / file_delete / power
    target: str = ""                # 操作对象（路径、服务名、PID…）
    summary: str = ""               # 参数摘要（命令全文、批量路径数等）
    source: str = "web"             # web / agent / cli / system
    ip: str = ""                    # 来源 IP（cli/system 为空）
    actor: str = ""                 # 令牌名称 / 会话标识（预留给多用户）
    ok: bool = True
    code: int | None = None         # 退出码（命令类操作）
    duration: float | None = None   # 耗时秒
    extra: dict | None = None       # 结构化附加字段（如 app_id / app 名）
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        data = {
            "ts": self.ts,
            "time": int(self.ts),
            "action": self.action,
            "target": _clip(self.target, _MAX_TARGET),
            "summary": _clip(self.summary),
            "source": self.source,
            "ip": self.ip,
            "actor": self.actor,
            "ok": bool(self.ok),
            "code": self.code,
            "duration": round(self.duration, 3) if self.duration is not None else None,
        }
        if self.extra:
            for key, value in self.extra.items():
                data[str(key)] = value
        return data


class AuditLog:
    """JSONL 审计日志：后台线程落盘 + 内存速览 + 按日期查询。"""

    def __init__(self, directory: Path | None = None) -> None:
        self._dir = Path(directory) if directory else self._default_dir()
        self._queue: queue.Queue[AuditEvent | None] = queue.Queue()
        # RLock：_append 持锁期间 _recent_lock_guard 会重入同一把锁
        self._lock = threading.RLock()
        self._recent: list[dict] = []
        self._stopped = False
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self._dir, 0o700)
        except OSError:
            # 目录建不了（只读文件系统等）：退化纯内存模式，不拖垮服务
            pass
        self._thread = threading.Thread(target=self._writer, name="audit-writer", daemon=True)
        self._thread.start()
        self._cleanup_old()

    # ------------------------------------------------------------ 基础设施
    @staticmethod
    def _default_dir() -> Path:
        # 与 sessions.json 同目录：配置在哪，审计就在哪
        from .config import config  # 延迟导入避免循环依赖

        return Path(config.path).parent / "audit"

    def _path_for(self, ts: float) -> Path:
        return self._dir / f"audit-{time.strftime('%Y%m%d', time.localtime(ts))}.jsonl"

    def _writer(self) -> None:
        while True:
            event = self._queue.get()
            if event is None:
                return
            try:
                self._append(event)
            except Exception:
                # 审计写失败绝不能影响业务；只往 stderr 留个痕迹
                try:
                    import sys
                    print(f"[audit] 写入失败: {event.action}", file=sys.stderr)
                except Exception:
                    pass

    def _append(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict(), ensure_ascii=False)
        path = self._path_for(event.ts)
        with self._lock:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            # 文件本身也要 0600（目录 0700 之外的第二道；文档原先声称
            # 0600 但只 chmod 了目录）
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
            with self._recent_lock_guard():
                self._recent.append(event.to_dict())
                if len(self._recent) > _RECENT_MAX:
                    del self._recent[: len(self._recent) - _RECENT_MAX]

    def _recent_lock_guard(self):
        return self._lock  # 落盘与内存速览共用一把锁：顺序一致，实现简单

    # ------------------------------------------------------------ 记录
    def record(self, event: AuditEvent) -> None:
        """记录一条事件（异步落盘，立即返回）。"""
        if self._stopped:
            return
        self._queue.put(event)

    def record_cli(self, action: str, target: str = "", summary: str = "",
                   ok: bool = True) -> None:
        """本机 CLI 命令（模式切换、令牌轮换等）直接同步落盘。

        CLI 是短命进程，没有后台线程可依赖，写失败就地忽略（屏幕已有输出）。
        """
        event = AuditEvent(action=action, target=target, summary=summary,
                           source="cli", ok=ok)
        try:
            self._append(event)
        except OSError:
            pass

    # ------------------------------------------------------------ 查询
    def recent(self, limit: int = 100) -> list[dict]:
        """内存速览（最近 _RECENT_MAX 条，新的在前）。"""
        with self._lock:
            items = list(reversed(self._recent))
        return items[: max(1, min(limit, 500))]

    @staticmethod
    def _tail_lines(path: Path, min_lines: int) -> list[str]:
        """从文件尾部倒读，返回最近若干行（保持原顺序）。

        1.4.1 起不再 ``readlines()`` 整文件：一次查询可能只要 500 条，
        却把几十上百 MB 读进内存（实测 44.6MB 文件峰值 51MB），
        在手机上直接把面板拖死。这里按块倒读，最多读
        :data:`_MAX_READ_BYTES`，读够 ``min_lines`` 就停。

        代价：单个文件超过该上限时更早的事件查不到（需要就看磁盘上的
        JSONL）。这是"面板可用性优先"的取舍，文档已写明。
        """
        lines: list[str] = []
        buf = b""
        read = 0
        reached_start = False
        try:
            with open(path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                pos = fh.tell()
                while pos > 0 and read < _MAX_READ_BYTES and len(lines) < min_lines + 1:
                    step = min(_READ_CHUNK, pos)
                    pos -= step
                    fh.seek(pos)
                    buf = fh.read(step) + buf
                    read += step
                    lines = buf.split(b"\n")
                reached_start = pos == 0
        except OSError:
            return []
        rows = buf.decode("utf-8", "replace").split("\n")
        if not reached_start and rows:
            rows = rows[1:]  # 首行可能被块边界截断，丢弃
        return [row for row in rows if row.strip()]

    def query(self, days: int = 7, action: str = "", source: str = "",
              q: str = "", limit: int = 500) -> list[dict]:
        """按条件查审计日志：读最近 N 天的文件，倒序返回。

        ``action`` / ``source`` 精确匹配；``q`` 对 target+summary 做大小写
       不敏感的子串匹配。查询从文件尾部倒读（不再全量载入内存），
       所以 limit 与 days 都有上限。
        """
        days = max(1, min(days, 90))
        limit = max(1, min(limit, 2000))
        now = time.time()
        events: list[dict] = []
        for offset in range(days):
            path = self._path_for(now - offset * 86400)
            if not path.exists():
                continue
            for line in reversed(self._tail_lines(path, limit)):
                item = self._parse_line(line)
                if item is None:
                    continue  # 空行或半行（写入中途被杀）
                if not self._match(item, action, source, q):
                    continue
                events.append(item)
                if len(events) >= limit:
                    return events
        return events

    @staticmethod
    def _parse_line(line: str) -> dict | None:
        line = line.strip()
        if not line:
            return None
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            return None
        return item if isinstance(item, dict) else None

    @staticmethod
    def _match(item: dict, action: str, source: str, q: str) -> bool:
        if action and item.get("action") != action:
            return False
        if source and item.get("source") != source:
            return False
        if q:
            haystack = f"{item.get('target', '')} {item.get('summary', '')}".lower()
            if q.lower() not in haystack:
                return False
        return True

    def actions_summary(self, days: int = 7) -> dict[str, int]:
        """各操作类型计数（面板概览小卡片用）。"""
        counts: dict[str, int] = {}
        for item in self.query(days=days, limit=2000):
            counts[item["action"]] = counts.get(item["action"], 0) + 1
        return counts

    # ------------------------------------------------------------ 维护
    def _cleanup_old(self) -> None:
        retention = _retention_days()
        cutoff = time.time() - retention * 86400
        try:
            for path in self._dir.glob("audit-*.jsonl"):
                try:
                    if path.stat().st_mtime < cutoff:
                        path.unlink()
                except OSError:
                    continue
        except OSError:
            pass

    def close(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        self._queue.put(None)
        if self._thread.is_alive():
            self._thread.join(timeout=2)


audit = AuditLog()
