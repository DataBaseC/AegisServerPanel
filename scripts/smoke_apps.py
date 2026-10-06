"""常驻应用管理的本地冒烟脚本（开发机可跑，Windows/Linux 均可）。

用法：python scripts/smoke_apps.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("SERVERPANEL_CONFIG", str(Path(tempfile.mkdtemp()) / "config.json"))

from app import apps as apps_mod  # noqa: E402
from app.apps import AppError, normalize_definition, supervisor  # noqa: E402


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="sp-app-"))
    script = workdir / "tick.py"
    script.write_text(
        "import sys, time\n"
        "for i in range(1000):\n"
        "    print('tick', i, flush=True)\n"
        "    time.sleep(0.5)\n",
        "utf-8",
    )
    command = f'{Path(sys.executable).as_posix()} {script.as_posix()}'
    definition = normalize_definition({
        "name": "smoke-tick",
        "command": command,
        "cwd": str(workdir),
        "restart": "on-failure",
        "max_restarts": 3,
        "restart_delay": 0.5,
    })
    app = supervisor.registry.add(definition)
    print(f"注册：{app['name']}  id={app['id']}")
    print(f"注册表：{supervisor.registry.path}")

    async def scenario() -> None:
        await supervisor.serve()
        await asyncio.sleep(0.1)
        result = await supervisor.start(app["id"])
        pid = result["runtime"]["pid"]
        print(f"启动：PID {pid}  状态 {result['runtime']['status']}")
        await asyncio.sleep(2.5)
        data = supervisor.log_of(app["id"], tail_lines=20)
        lines = [ln for ln in data["content"].splitlines() if ln.strip()]
        print(f"日志（{len(lines)} 行，size={data['size']}）：")
        for line in lines[-6:]:
            print(f"    | {line}")
        if not lines:
            print(f"    内存缓冲：{[ln for ln in data['memory'][-5:]]}")
        assert lines, "日志为空，托管应用的输出没有被收集"
        assert any("tick" in ln for ln in lines), "没有看到应用输出"

        # 增量读取：offset 递增应拿到新增内容
        offset = data["next_offset"]
        await asyncio.sleep(1.5)
        delta = supervisor.log_of(app["id"], offset=offset)
        print(f"增量读取：{len(delta['content'])} 字节")

        # 进程隔离：托管进程不能与当前进程同组（否则面板重启会连带杀死它）
        if os.name == "posix":
            assert os.getpgid(pid) != os.getpgid(os.getpid()), "托管进程必须独立成组"
            print(f"进程组隔离：托管 pgid={os.getpgid(pid)}  面板 pgid={os.getpgid(os.getpid())}")

        # 崩溃拉起：杀掉进程后应被自动重启，且 PID 变化
        if os.name == "posix":
            os.kill(pid, 9)
            for _ in range(20):
                await asyncio.sleep(0.4)
                snapshot = supervisor.get(app["id"])["runtime"]
                if snapshot["status"] == "running" and snapshot["pid"] not in (None, pid):
                    print(f"崩溃拉起：新 PID {snapshot['pid']}（累计重启 {snapshot['restart_count']} 次）")
                    break
            else:
                raise AssertionError("进程被杀后没有被自动拉起")
        else:
            print("崩溃拉起：Windows 上跳过 POSIX 信号测试")

        stopped = await supervisor.stop(app["id"])
        print(f"停止：状态 {stopped['runtime']['status']}")
        await supervisor.shutdown()

    try:
        asyncio.run(scenario())
    finally:
        supervisor.registry.remove(app["id"])
    print("冒烟通过 ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
