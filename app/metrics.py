"""性能数据采集：CPU / 内存 / 磁盘 / 网络 / 负载 / 温度。"""

from __future__ import annotations

import platform
import socket
import threading
import time
from collections import deque

import psutil

HISTORY_SIZE = 120


class MetricsSampler:
    """周期性采样并维护一段历史，供前端图表初始化时回填。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: tuple[float, object, object] | None = None
        self._sample_count = 0
        self._cached_threads = 0
        # Android / PRoot 等环境可能屏蔽 /sys/block、/proc/net/dev，
        # 对应计数器读不到时降级为 0 并在快照里标记 io_limited
        self._io_limited = False
        self.history: deque[dict] = deque(maxlen=HISTORY_SIZE)
        # 首次调用只用于初始化基线
        psutil.cpu_percent(interval=None)
        psutil.cpu_percent(interval=None, percpu=True)

    @staticmethod
    def _safe(fn, default=None):
        """读系统计数器：Android / PRoot 可能屏蔽对应 /proc、/sys 文件。"""
        try:
            return fn()
        except (OSError, psutil.Error):
            return default

    def _rates(self, now: float) -> dict:
        disk = self._safe(psutil.disk_io_counters)
        net = self._safe(psutil.net_io_counters)
        self._io_limited = disk is None or net is None
        rates = {"disk_read": 0.0, "disk_write": 0.0, "net_sent": 0.0, "net_recv": 0.0}
        last = self._last
        self._last = (now, disk, net)
        if last is None:
            return rates  # 首次采样没有基线
        ts, last_disk, last_net = last
        delta = max(now - ts, 1e-6)
        if disk is not None and last_disk is not None:
            rates["disk_read"] = max(0.0, (disk.read_bytes - last_disk.read_bytes) / delta)
            rates["disk_write"] = max(0.0, (disk.write_bytes - last_disk.write_bytes) / delta)
        if net is not None and last_net is not None:
            rates["net_sent"] = max(0.0, (net.bytes_sent - last_net.bytes_sent) / delta)
            rates["net_recv"] = max(0.0, (net.bytes_recv - last_net.bytes_recv) / delta)
        return rates

    def sample(self) -> dict:
        now = time.time()
        cpu_total = psutil.cpu_percent(interval=None)
        cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
        memory = self._safe(psutil.virtual_memory)
        swap = self._safe(psutil.swap_memory)
        rates = self._rates(now)

        # 线程总数需要遍历整个进程表：在 PRoot 上每个 /proc 访问都是 ptrace 慢速
        # 调用，300 进程要数秒——io 受限（Android/PRoot）或首次采样直接跳过，
        # 否则采样线程会饿死整个事件循环（实测教训）。
        self._sample_count += 1
        if not self._io_limited and self._sample_count > 1 and self._sample_count % 10 == 1:
            try:
                self._cached_threads = sum(
                    p.info["num_threads"]
                    for p in psutil.process_iter(["num_threads"])
                    if p.info["num_threads"]
                )
            except (OSError, psutil.Error):
                pass

        try:
            load = list(psutil.getloadavg())
        except (AttributeError, OSError):
            load = [0.0, 0.0, 0.0]

        try:
            freq = psutil.cpu_freq()
            cpu_mhz = round(freq.current) if freq else None
        except (AttributeError, OSError):
            cpu_mhz = None

        temps = []
        try:
            for name, entries in (psutil.sensors_temperatures() or {}).items():
                for entry in entries:
                    if entry.current is None:
                        continue
                    temps.append(
                        {"label": entry.label or name, "current": round(entry.current, 1),
                         "high": entry.high, "critical": entry.critical}
                    )
        except (AttributeError, OSError):
            temps = []

        disk_usage = self._safe(lambda: psutil.disk_usage("/"))
        boot = self._safe(psutil.boot_time, 0.0)
        snapshot = {
            "time": now,
            "io_limited": self._io_limited,
            "cpu": round(cpu_total, 1),
            "cpu_per_core": [round(v, 1) for v in cpu_per_core],
            "cpu_mhz": cpu_mhz,
            "mem": {
                "total": memory.total if memory else 0,
                "used": (memory.total - memory.available) if memory else 0,
                "available": memory.available if memory else 0,
                "percent": round(memory.percent, 1) if memory else 0.0,
                "cached": getattr(memory, "cached", 0) if memory else 0,
            },
            "swap": {
                "total": swap.total if swap else 0,
                "used": swap.used if swap else 0,
                "percent": round(swap.percent, 1) if swap else 0.0,
            },
            "disk": {
                **{k: round(v) for k, v in rates.items() if k.startswith("disk")},
                "total": disk_usage.total if disk_usage else 0,
                "used": disk_usage.used if disk_usage else 0,
                "percent": round(disk_usage.percent, 1) if disk_usage else 0.0,
            },
            "net": {k: round(v) for k, v in rates.items() if k.startswith("net")},
            "load": [round(v, 2) for v in load],
            "uptime": int(now - boot) if boot else 0,
            "processes": len(self._safe(psutil.pids, [])),
            "threads": self._cached_threads,
            "temps": temps,
        }
        with self._lock:
            self.history.append({
                "t": round(now),
                "cpu": snapshot["cpu"],
                "mem": snapshot["mem"]["percent"],
                "net_recv": snapshot["net"]["net_recv"],
                "net_sent": snapshot["net"]["net_sent"],
                "disk_read": snapshot["disk"]["disk_read"],
                "disk_write": snapshot["disk"]["disk_write"],
            })
        return snapshot

    def history_list(self) -> list[dict]:
        with self._lock:
            return list(self.history)


metrics = MetricsSampler()


_FQDN_CACHE: str | None = None


def _fqdn() -> str:
    """socket.getfqdn 带缓存：它是同步反向 DNS 查询，坏 DNS 环境下能挂数秒，
    而 FQDN 在进程生命周期内基本不变，查一次就够。"""
    global _FQDN_CACHE
    if _FQDN_CACHE is None:
        try:
            _FQDN_CACHE = socket.getfqdn()
        except OSError:
            _FQDN_CACHE = socket.gethostname()
    return _FQDN_CACHE


def basic_info() -> dict:
    """静态系统信息。"""
    uname = platform.uname()
    os_release = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    key, _, value = line.strip().partition("=")
                    os_release[key] = value.strip('"')
    except OSError:
        pass

    cpu_model = uname.processor or ""
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass

    addresses = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    addresses.append({"interface": name, "address": addr.address})
    except (psutil.Error, OSError):
        pass

    def _safe(fn, default):
        # Android / PRoot 会把内核 PermissionError 直接抛出来（不是 psutil.Error）：
        # basic_info 是首屏依赖，任何一项读不到都不该让整页崩掉
        try:
            return fn()
        except (psutil.Error, OSError):
            return default

    boot = _safe(psutil.boot_time, time.time())
    return {
        "hostname": socket.gethostname(),
        "fqdn": _fqdn(),
        "distro": os_release.get("PRETTY_NAME", uname.system),
        "distro_id": os_release.get("ID", ""),
        "kernel": uname.release,
        "arch": uname.machine,
        "cpu_model": cpu_model or "未知",
        "cpu_cores_physical": _safe(lambda: psutil.cpu_count(logical=False), None),
        "cpu_cores_logical": _safe(lambda: psutil.cpu_count(logical=True), None),
        "mem_total": _safe(lambda: psutil.virtual_memory().total, 0),
        "swap_total": _safe(lambda: psutil.swap_memory().total, 0),
        "boot_time": int(boot),
        "uptime": int(time.time() - boot),
        "user": _safe(lambda: psutil.Process().username(), "-"),
        "python": platform.python_version(),
        "addresses": addresses,
        "is_root": psutil.Process().username() == "root",
    }


def top_processes(limit: int = 15, sort: str = "cpu") -> list[dict]:
    fields = ["pid", "name", "username", "cpu_percent", "memory_percent", "memory_info", "cmdline", "status", "create_time"]
    procs = []
    for proc in psutil.process_iter(fields, ad_value=None):
        info = proc.info
        try:
            mem_info = info.get("memory_info")
            procs.append({
                "pid": info["pid"],
                "name": info["name"] or "?",
                "user": info["username"] or "?",
                "cpu": round(info["cpu_percent"] or 0.0, 1),
                "mem": round(info["memory_percent"] or 0.0, 1),
                "rss": mem_info.rss if mem_info else 0,
                "status": info["status"] or "?",
                "create_time": int(info["create_time"] or 0),
                "cmdline": " ".join(info["cmdline"] or []) or info["name"] or "?",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    key = {"cpu": "cpu", "mem": "mem", "rss": "rss", "pid": "pid"}.get(sort, "cpu")
    procs.sort(key=lambda p: p[key], reverse=(key != "pid"))
    return procs[:limit]
