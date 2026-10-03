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
        self.history: deque[dict] = deque(maxlen=HISTORY_SIZE)
        # 首次调用只用于初始化基线
        psutil.cpu_percent(interval=None)
        psutil.cpu_percent(interval=None, percpu=True)

    def _rates(self, now: float) -> dict:
        disk = psutil.disk_io_counters()
        net = psutil.net_io_counters()
        rates = {"disk_read": 0.0, "disk_write": 0.0, "net_sent": 0.0, "net_recv": 0.0}
        if self._last is not None and disk is not None and net is not None:
            ts, last_disk, last_net = self._last
            delta = max(now - ts, 1e-6)
            if last_disk is not None:
                rates["disk_read"] = max(0.0, (disk.read_bytes - last_disk.read_bytes) / delta)
                rates["disk_write"] = max(0.0, (disk.write_bytes - last_disk.write_bytes) / delta)
            if last_net is not None:
                rates["net_sent"] = max(0.0, (net.bytes_sent - last_net.bytes_sent) / delta)
                rates["net_recv"] = max(0.0, (net.bytes_recv - last_net.bytes_recv) / delta)
        self._last = (now, disk, net)
        return rates

    def sample(self) -> dict:
        now = time.time()
        cpu_total = psutil.cpu_percent(interval=None)
        cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        rates = self._rates(now)

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

        disk_usage = psutil.disk_usage("/")
        snapshot = {
            "time": now,
            "cpu": round(cpu_total, 1),
            "cpu_per_core": [round(v, 1) for v in cpu_per_core],
            "cpu_mhz": cpu_mhz,
            "mem": {
                "total": memory.total,
                "used": memory.total - memory.available,
                "available": memory.available,
                "percent": round(memory.percent, 1),
                "cached": getattr(memory, "cached", 0),
            },
            "swap": {
                "total": swap.total,
                "used": swap.used,
                "percent": round(swap.percent, 1),
            },
            "disk": {
                **{k: round(v) for k, v in rates.items() if k.startswith("disk")},
                "total": disk_usage.total,
                "used": disk_usage.used,
                "percent": round(disk_usage.percent, 1),
            },
            "net": {k: round(v) for k, v in rates.items() if k.startswith("net")},
            "load": [round(v, 2) for v in load],
            "uptime": int(now - psutil.boot_time()),
            "processes": len(psutil.pids()),
            "threads": sum(p.num_threads() for p in psutil.process_iter(["num_threads"]) if p.info["num_threads"]),
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


def basic_info() -> dict:
    """静态系统信息。"""
    uname = platform.uname()
    os_release = {}
    try:
        for line in open("/etc/os-release", encoding="utf-8"):
            if "=" in line:
                key, _, value = line.strip().partition("=")
                os_release[key] = value.strip('"')
    except OSError:
        pass

    cpu_model = uname.processor or ""
    try:
        for line in open("/proc/cpuinfo", encoding="utf-8"):
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
    except OSError:
        pass

    boot = psutil.boot_time()
    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "distro": os_release.get("PRETTY_NAME", uname.system),
        "distro_id": os_release.get("ID", ""),
        "kernel": uname.release,
        "arch": uname.machine,
        "cpu_model": cpu_model or "未知",
        "cpu_cores_physical": psutil.cpu_count(logical=False),
        "cpu_cores_logical": psutil.cpu_count(logical=True),
        "mem_total": psutil.virtual_memory().total,
        "swap_total": psutil.swap_memory().total,
        "boot_time": int(boot),
        "uptime": int(time.time() - boot),
        "user": psutil.Process().username(),
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
