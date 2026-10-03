"""跨平台小工具：权限判断等。

面板的主要运行环境是 Linux（含 PRoot / 容器），但保留对非 POSIX
平台的可导入性，便于开发与测试。
"""

from __future__ import annotations

import os


def is_root() -> bool:
    """当前进程是否以 root 运行。非 POSIX 平台（如 Windows）返回 False。"""
    return hasattr(os, "geteuid") and os.geteuid() == 0
