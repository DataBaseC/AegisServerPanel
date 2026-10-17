"""指标持久化（2.0 M2）：SQLite 存采样，按时间范围降采样查询。

设计要点：

- **零新增依赖**：sqlite3 是标准库；单文件落在配置目录旁（``metrics.db``），
  可用 ``SERVERPANEL_METRICS_DB`` 覆盖（测试/多实例）。
- **省电**：WAL + ``synchronous=NORMAL``，写入是单条 INSERT；查询按下采样桶
  ``GROUP BY``，不会把 365 天的原始点全读出来。
- **可降级**：任何 SQLite 错误都只让"历史持久化"失效，采样与实时接口不受影响
  （日志里提示一次，之后静默）。
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
import time
from pathlib import Path

# range 键 -> (窗口秒数, 聚合桶秒数)
RANGES = {
    "1h": (3600, 10),
    "1d": (86400, 60),
    "30d": (30 * 86400, 3600),
    "365d": (365 * 86400, 86400),
}
RETENTION_SECONDS = 365 * 86400


class MetricsStore:
    """单连接 + 互斥锁的轻量 SQLite 存储（写少读少，够用）。"""

    def __init__(self, path: str | Path | None = None) -> None:
        env = os.environ.get("SERVERPANEL_METRICS_DB")
        if path is None and env:
            path = env
        if path is None:
            from .config import config

            path = Path(config.path).parent / "metrics.db"
        self.path = Path(path)
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._broken = False
        self._broken_at = 0.0
        self._last_prune = 0.0
        self._open()

    def _open(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS samples ("
                " ts INTEGER PRIMARY KEY,"
                " cpu REAL, mem REAL, swap REAL, disk REAL,"
                " disk_read REAL, disk_write REAL,"
                " net_sent REAL, net_recv REAL,"
                " load1 REAL, temp REAL)"
            )
            self._conn = conn
        except (sqlite3.Error, OSError):
            self._broken = True
            self._broken_at = time.time()
            self._conn = None

    def _retry_open(self) -> None:
        """磁盘满/临时锁不是永久故障：标记 broken 后每 5 分钟重试一次打开。

        原实现一次错误就永久停写，直到进程重启，用户只能看到历史曲线断在某一刻。
        """
        if not self._broken:
            return
        if time.time() - self._broken_at < 300:
            return
        self._broken = False
        self._open()

    def append(self, snapshot: dict) -> None:
        """写入一条采样；失败只标记存储不可用，不抛异常。"""
        if self._conn is None:
            if not self._broken:
                self._open()      # close() 之后（lifespan 重启/测试复用）重新打开
            self._retry_open()
        if self._broken or self._conn is None:
            return
        mem = snapshot.get("mem") or {}
        swap = snapshot.get("swap") or {}
        disk = snapshot.get("disk") or {}
        net = snapshot.get("net") or {}
        temps = snapshot.get("temps") or []
        temp = max((t.get("current") or 0) for t in temps) if temps else None
        load = snapshot.get("load") or [0, 0, 0]
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO samples VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (int(snapshot.get("time") or time.time()),
                     snapshot.get("cpu"), mem.get("percent"), swap.get("percent"),
                     disk.get("percent"), disk.get("disk_read"), disk.get("disk_write"),
                     net.get("net_sent"), net.get("net_recv"),
                     load[0] if load else 0, temp),
                )
                self._conn.commit()
                now = time.time()
                if now - self._last_prune > 3600:
                    self._last_prune = now
                    self._conn.execute("DELETE FROM samples WHERE ts < ?",
                                       (int(now) - RETENTION_SECONDS,))
                    self._conn.commit()
        except sqlite3.Error:
            self._broken = True
            self._broken_at = time.time()
            with self._lock:
                with contextlib.suppress(Exception):
                    if self._conn is not None:
                        self._conn.close()
            self._conn = None

    def query(self, range_key: str) -> list[dict]:
        """按范围返回降采样点；失败/无数据返回空列表（调用方回落到内存历史）。"""
        window, bucket = RANGES.get(range_key, RANGES["1h"])
        if not self.path.exists():
            return []
        since = int(time.time()) - window
        sql = (
            "SELECT (ts / ?) * ? AS t, AVG(cpu), AVG(mem), AVG(swap), AVG(disk),"
            " AVG(disk_read), AVG(disk_write), AVG(net_sent), AVG(net_recv),"
            " AVG(load1), AVG(temp)"
            " FROM samples WHERE ts >= ? GROUP BY t ORDER BY t"
        )
        try:
            # 只读连接 + 独立连接：365 天窗口的全表聚合可能要数百毫秒到数秒，
            # 不能持写入锁——否则采样线程被堵住，实时曲线出现空洞
            conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=2)
            try:
                rows = conn.execute(sql, (bucket, bucket, since)).fetchall()
            finally:
                conn.close()
        except sqlite3.Error:
            return []
        points = []
        for row in rows:
            if row[0] is None:
                continue
            points.append({
                "time": row[0],
                "cpu": _round(row[1]),
                "mem": _round(row[2]),
                "swap": _round(row[3]),
                "disk": _round(row[4]),
                "disk_read": _round(row[5]),
                "disk_write": _round(row[6]),
                "net_sent": _round(row[7]),
                "net_recv": _round(row[8]),
                "load1": _round(row[9]),
                "temp": _round(row[10]),
            })
        return points

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                with contextlib.suppress(Exception):
                    self._conn.close()
                self._conn = None


def _round(value) -> float | None:
    if value is None:
        return None
    try:
        return round(float(value), 1)
    except (TypeError, ValueError):
        return None


store = MetricsStore()
