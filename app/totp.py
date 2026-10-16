"""TOTP 二次认证（RFC 6238）——零依赖实现。

面板密码即 root shell，单因素不够。本模块用标准库完成 TOTP 全流程：

- ``generate_secret``：20 字节随机数 → Base32（与 Google Authenticator 等兼容）
- ``code`` / ``verify``：HMAC-SHA1、6 位、30 秒步长，容忍 ±1 步时钟漂移
- ``provisioning_uri``：otpauth:// URI，前端渲染成二维码即可扫码绑定
- 恢复码：10 个一次性随机码，只存 SHA-256，用一次即焚

安全边界：secret 与恢复码哈希都落在配置文件（0600）里，不落任何别处；
登录时先验密码再验 TOTP，两层都计入失败锁定（防 6 位动态码在线爆破）。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

_STEP = 30           # 秒
_DIGITS = 6
_WINDOW = 1          # 容忍 ±1 步（约 ±30s）时钟漂移
_RECOVERY_COUNT = 10


def generate_secret() -> str:
    """生成 Base32 密钥（32 字符，160 位熵）。"""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** _DIGITS)).zfill(_DIGITS)


def code(secret_b32: str, at: float | None = None) -> str:
    """当前时间的 TOTP 码。"""
    counter = int((at if at is not None else time.time()) // _STEP)
    return _hotp(secret_b32, counter)


def verify(secret_b32: str, candidate: str, at: float | None = None) -> bool:
    """校验动态码，容忍 ±1 步漂移；空码/格式错直接拒。"""
    candidate = (candidate or "").strip().replace(" ", "")
    if len(candidate) != _DIGITS or not candidate.isdigit():
        return False
    now = at if at is not None else time.time()
    counter = int(now // _STEP)
    for drift in range(-_WINDOW, _WINDOW + 1):
        if hmac.compare_digest(_hotp(secret_b32, counter + drift), candidate):
            return True
    return False


def provisioning_uri(secret_b32: str, account: str = "serverpanel",
                     issuer: str = "ServerPanel") -> str:
    """otpauth:// URI（供 authenticator App 扫码）。"""
    label = urllib.parse.quote(f"{issuer}:{account}")
    query = urllib.parse.urlencode({
        "secret": secret_b32,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": _DIGITS,
        "period": _STEP,
    })
    return f"otpauth://totp/{label}?{query}"


def generate_recovery_codes() -> list[str]:
    """生成 10 个一次性恢复码（xxxx-xxxx-xxxx 格式，便于抄录）。"""
    codes = []
    for _ in range(_RECOVERY_COUNT):
        raw = secrets.token_bytes(6).hex().upper()  # 12 位十六进制
        codes.append(f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}")
    return codes


def hash_recovery(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()


def consume_recovery(code: str, hashes: list[str]) -> int | None:
    """校验恢复码；命中返回其索引（调用方删除即焚），未命中返回 None。"""
    candidate = hash_recovery(code)
    for index, stored in enumerate(hashes):
        if isinstance(stored, str) and hmac.compare_digest(candidate, stored.lower()):
            return index
    return None
