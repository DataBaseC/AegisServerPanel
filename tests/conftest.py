"""测试环境准备。

必须在导入 app 之前设置 SERVERPANEL_CONFIG，让配置单例落在临时文件上，
避免污染真实配置；SERVERPANEL_APPS_DIR 把常驻应用注册表与日志也隔离到临时目录。

注意：配置必须放在**每进程独立的临时目录**里。sessions.json / failures.json
等状态文件紧邻配置文件存放，若用裸 mktemp 落在 /tmp 根下，这些文件会跨
pytest 运行共享累积（1.4.0 起它们都是落盘的），导致用例间状态污染。
"""

from __future__ import annotations

import gc
import os
import tempfile
import warnings

import pytest

_STATE_DIR = tempfile.mkdtemp(prefix="serverpanel-test-")
os.environ["SERVERPANEL_CONFIG"] = os.path.join(_STATE_DIR, "config.json")
os.environ["SERVERPANEL_APPS_DIR"] = tempfile.mkdtemp(prefix="serverpanel-apps-")


@pytest.fixture(autouse=True)
def _reset_failure_tracker():
    """每个用例前重置登录失败计数。

    失败计数是进程级单例且落盘（1.4.0 起重启不清零），不加这道隔离，
    防爆破用例触发的锁定会污染后续所有用例。持久化行为由专门用例覆盖。
    """
    from app.auth import failures

    failures._ips = {}
    failures._global = []
    try:
        failures._file().unlink(missing_ok=True)
    except OSError:
        pass
    yield


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
