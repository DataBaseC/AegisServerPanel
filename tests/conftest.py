"""测试环境准备。

必须在导入 app 之前设置 SERVERPANEL_CONFIG，让配置单例落在临时文件上，
避免污染真实配置；SERVERPANEL_APPS_DIR 把常驻应用注册表与日志也隔离到临时目录。
"""

from __future__ import annotations

import gc
import os
import tempfile
import warnings

import pytest

os.environ["SERVERPANEL_CONFIG"] = tempfile.mktemp(suffix=".json")
os.environ["SERVERPANEL_APPS_DIR"] = tempfile.mkdtemp(prefix="serverpanel-apps-")


@pytest.fixture(autouse=True)
def _settle_subprocesses():
    """每个用例结束后回收子进程引用。

    常驻应用相关用例会真的拉起子进程（尤其在 Windows 上用 Proactor 事件循环），
    asyncio 的管道 transport 在被 GC 回收时才会打印 "unclosed transport"。
    这里主动催一次回收，既让测试输出干净，也能更早暴露真正的 fd 泄漏。
    """
    yield
    gc.collect()


@pytest.fixture(autouse=True)
def _quiet_resource_warnings():
    """过滤 asyncio 管道 transport 的 ResourceWarning。

    它是解释器退出阶段的噪音：进程本身已经结束、管道也已关闭，只是 transport
    对象在被回收时才打印告警。真正的功能回归由断言覆盖，不靠这条警告。
    """
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=ResourceWarning)
        yield
