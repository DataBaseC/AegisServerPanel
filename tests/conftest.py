"""测试环境准备。

必须在导入 app 之前设置 SERVERPANEL_CONFIG，让配置单例落在临时文件上，
避免污染真实配置。
"""

from __future__ import annotations

import os
import tempfile

os.environ["SERVERPANEL_CONFIG"] = tempfile.mktemp(suffix=".json")
