"""应用与端口发现：列出监听端口的应用，并生成可点击的访问链接。"""

from __future__ import annotations

import os

import psutil
from fastapi import APIRouter, Depends, HTTPException

from ..auth import require_internal
from ..metrics import basic_info

router = APIRouter(prefix="/api/apps", tags=["apps"])

# 明确不是网页服务的常见端口，避免生成无效的 http 链接
NON_WEB_PORTS = {
    21, 22, 23, 25, 53, 110, 111, 139, 143, 445, 465, 514, 587, 631,
    993, 995, 1080, 1194, 1433, 1521, 1883, 2049, 2181, 2375, 2376, 3306, 3389,
    5060, 5061, 5432, 5672, 5900, 5901, 5902, 6379, 8883, 9042, 9092, 9300,
    10250, 11211, 27017,
}
TLS_PORTS = {443, 4443, 6443, 8443, 9443, 10443}


def _safe(fn, default=None):
    try:
        return fn()
    except (psutil.Error, OSError):
        return default


def _port_entry(conn, lan: list[str]) -> dict:
    address = conn.laddr.ip
    port = conn.laddr.port
    if address in ("0.0.0.0", "::", "::0"):
        hosts, scope = lan, "all"
    elif address.startswith("127.") or address == "::1":
        hosts, scope = [], "local"
    else:
        hosts, scope = [address], "specific"

    non_web = port in NON_WEB_PORTS
    scheme = "https" if port in TLS_PORTS else "http"
    # 仅监听回环地址的服务无法从其他设备访问，不生成链接
    urls = [] if non_web or scope == "local" else [
        {"label": f"{scheme}://{host}:{port}", "url": f"{scheme}://{host}:{port}/"}
        for host in hosts
    ]
    return {
        "port": port,
        "address": address,
        "proto": "tcp6" if conn.family.name == "AF_INET6" else "tcp",
        "scope": scope,
        "non_web": non_web,
        "protocol": "非 Web 服务" if non_web else scheme.upper(),
        "urls": urls,
    }


@router.get("")
async def list_apps(_session: dict = Depends(require_internal)):
    """按进程聚合所有 TCP 监听端口，并给出可点击的访问地址。"""
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        raise HTTPException(403, "需要 root 权限才能枚举监听端口")
    except Exception as exc:  # psutil 在不同平台可能抛不同异常
        raise HTTPException(500, f"读取网络连接失败: {exc}")

    lan = [a["address"] for a in basic_info()["addresses"]]
    grouped: dict[int, list[dict]] = {}
    for conn in conns:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        grouped.setdefault(conn.pid or 0, []).append(_port_entry(conn, lan))

    self_pid = os.getpid()
    apps = []
    for pid, ports in grouped.items():
        # 同一进程可能同时监听 IPv4/IPv6 的同一端口，去重后展示
        unique = {(p["address"], p["port"]): p for p in ports}
        row = {
            "pid": pid,
            "name": "系统 / 未知进程",
            "user": "-",
            "exe": None,
            "cmdline": "",
            "cwd": None,
            "mem": 0.0,
            "rss": 0,
            "create_time": 0,
            "self": pid == self_pid,
            "ports": sorted(unique.values(), key=lambda p: p["port"]),
        }
        if pid:
            try:
                proc = psutil.Process(pid)
                row["name"] = proc.name()
                row["user"] = _safe(proc.username, "-")
                row["exe"] = _safe(proc.exe)
                cmdline = _safe(proc.cmdline, [])
                row["cmdline"] = " ".join(cmdline) or row["name"]
                row["mem"] = round(_safe(proc.memory_percent, 0.0), 2)
                mem_info = _safe(proc.memory_info)
                row["rss"] = mem_info.rss if mem_info else 0
                row["create_time"] = int(_safe(proc.create_time, 0))
                row["cwd"] = _safe(proc.cwd)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            if row["self"]:
                row["name"] = f"{row['name']}（本面板）"
        apps.append(row)

    apps.sort(key=lambda a: (-len(a["ports"]), a["name"].lower()))
    return {
        "total_apps": len(apps),
        "total_ports": sum(len(a["ports"]) for a in apps),
        "hosts": lan,
        "apps": apps,
    }
