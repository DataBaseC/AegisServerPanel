"""跨平台小工具：权限判断等。

面板的主要运行环境是 Linux（含 PRoot / 容器），但保留对非 POSIX
平台的可导入性，便于开发与测试。
"""

from __future__ import annotations

import os


def is_root() -> bool:
    """当前进程是否以 root 运行。非 POSIX 平台（如 Windows）返回 False。"""
    return hasattr(os, "geteuid") and os.geteuid() == 0


# 日志白名单永远不能落的敏感目录：与这些目录存在任意包含关系都拒绝。
SENSITIVE_LOG_DIRS = (
    "/etc", "/root", "/proc", "/sys", "/dev", "/run", "/boot",
    "/var/lib", "/var/backups",
)

# 只允许精确相等的系统关键目录（/usr 下的常规日志目录仍可用）
SYSTEM_LOG_DIRS = ("/", "/usr")


def log_dir_reason(path: str) -> str | None:
    """把 ``path`` 当日志白名单目录是否安全；不安全时返回中文原因，安全返回 None。

    日志接口只要求登录（公网只读模式也可用），所以白名单本身就是读取边界：
    一旦把 /etc/ssh、/root/.ssh、面板配置目录放进去，只读用户就能读到私钥、
    密码哈希与 Agent 令牌。判定基于 realpath，尾随斜杠、``..``、符号链接都绕不过。

    这个函数是**唯一判定处**：写配置时（``boot.set_pref_with_check``）与配置
    导入时（``/api/panel/config/import``）都要调用，日志读取时还要再兜一层，
    避免任何一条写入路径漏掉。
    """
    real = os.path.realpath(os.path.abspath(path))
    if any(part.startswith(".") for part in real.split(os.sep) if part):
        return f"不能把隐藏目录加入日志白名单：{real}"
    for probe in SENSITIVE_LOG_DIRS:
        sensitive = os.path.realpath(probe)
        if (real == sensitive or real.startswith(sensitive + os.sep)
                or sensitive.startswith(real + os.sep)):
            return f"不能把 {real} 加入日志白名单：它与敏感目录 {probe} 存在包含关系"
    for probe in SYSTEM_LOG_DIRS:
        if real == os.path.realpath(probe):
            return f"不能把系统关键目录加入日志白名单：{probe}"
    return None
