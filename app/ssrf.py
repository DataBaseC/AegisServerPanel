"""SSRF 防护：URL 协议白名单 + DNS 解析结果不得落入私网。

1.6.0（F1）从 ``routes/file_routes.py`` **原样抽出**，供两处共用：

- 文件管理 → 从 URL 拉取（原调用方）；
- 事件通知 Webhook（新增）。

行为与 1.5.0 完全一致：协议只允许 http/https；解析出的任一地址落在回环 /
私网 / CGNAT / 链路本地 / 组播等网段即拒绝；``fetch_allow_private=true`` 时
统一放行内网目标（不为通知单独开后门）。
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse

from fastapi import HTTPException

from .config import config

# SSRF 防护（1.4.0）：默认拒绝解析到私网/回环/链路本地的目标。
# 面板以 root 运行， unrestricted fetch 可被用作探测/读取内网服务
# （含云元数据 169.254.169.254）的跳板，且响应会落盘成文件可被读回。
_BLOCKED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),     # 链路本地 / 云元数据
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),           # IPv6 唯一本地
    ipaddress.ip_network("fe80::/10"),          # IPv6 链路本地
]


def _ip_blocked(ip_text: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return True  # 解析不出来的地址一律按拒绝处理
    # IPv4-mapped IPv6（::ffff:127.0.0.1）在双栈上直通对应 IPv4 地址，但
    # IPv6Address.is_loopback/is_private 与 IPv4 网段的 in 判断都不认它，
    # 必须先归一成 IPv4 再判定，否则 SSRF 防护可被一个方括号字面量绕过。
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if (addr.is_link_local or addr.is_loopback or addr.is_unspecified
            or addr.is_multicast or addr.is_private or addr.is_reserved):
        return True
    return any(addr in net for net in _BLOCKED_NETS)


def assert_url_allowed(url: str) -> None:
    """URL 级 SSRF 校验：协议白名单 + 主机名解析后不得落入私网。

    配置 ``fetch_allow_private=true`` 可显式放行内网目标（内网运维场景）。

    **残余风险（1.4.1 起如实标注）**：这里是"解析→校验→交给 urllib 连接"，
    连接时 urllib 会**重新解析一次域名**，因此理论上存在 DNS rebinding 的
    TOCTOU 窗口；本函数不再声称"防住 rebinding"。真正消除它需要把连接
    固定到已校验的 IP（自定义 opener / 直连 IP + Host 头），代价与收益
    不成比例，这里只做"DNS 层拦截 + 重定向逐跳复核"。
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(400, "仅支持 http/https 直链")
    host = parsed.hostname or ""
    if not host:
        raise HTTPException(400, "URL 缺少主机名")
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise HTTPException(400, f"无法解析主机名 {host}: {exc}")
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise HTTPException(400, f"无法解析主机名 {host}")
    if config.fetch_allow_private:
        return
    for address in addresses:
        if _ip_blocked(address):
            raise HTTPException(400, f"目标地址 {address} 属于内网/回环/链路本地地址，"
                                     f"已被 SSRF 防护拦截（可在配置中放行私网）")
