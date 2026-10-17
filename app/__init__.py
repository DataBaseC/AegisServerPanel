"""ServerPanel —— 本地部署的 Ubuntu 系统控制台。"""

import sys

# 内容 = 外包 2.0.1（1.6.0 + 2.0.0 + 2.0.1 累积）；版本号按本仓库口径归一为 2.0
__version__ = "2.0"

# Pydantic 在运行时求值 `X | None` 形式的注解，Python 3.10 以下在导入阶段即崩溃。
# 门禁必须放在任何第三方 import 之前（本文件是包的入口）。
if sys.version_info < (3, 10):
    sys.stderr.write(
        f"ServerPanel 需要 Python 3.10 及以上，当前为 "
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}。\n"
        "请先升级 Python（Ubuntu 22.04+ 自带 3.10+），或使用 Docker 镜像部署。\n"
    )
    sys.exit(1)
