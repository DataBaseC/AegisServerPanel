"""阈值告警（2.0 M2）：CPU / 内存 / 磁盘 / 温度 / 负载。

设计：

- 采样线程每轮调用 :meth:`AlertManager.evaluate`，只做纯计算并返回需要发送的
  文本，**不在这里发 HTTP**（由调用方下线程池，避免阻塞事件循环）。
- 去抖：超过阈值需持续 ``alerts.for_seconds`` 秒才触发；触发后静默
  ``alerts.silence_minutes`` 分钟，避免刷屏。
- 全部阈值来自 prefs（0 表示关闭该项），未启用 ``alerts.enabled`` 时不做任何事。
"""

from __future__ import annotations

import threading
import time

from .prefs import prefs


class AlertManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._breach_since: dict[str, float] = {}
        self._silent_until: dict[str, float] = {}

    def _reset(self) -> None:
        self._breach_since.clear()
        self._silent_until.clear()

    @staticmethod
    def _rules(snapshot: dict) -> list[tuple[str, float | None, float, str, str]]:
        mem = (snapshot.get("mem") or {}).get("percent")
        disk = (snapshot.get("disk") or {}).get("percent")
        temps = snapshot.get("temps") or []
        temp = max((t.get("current") or 0) for t in temps) if temps else None
        load = snapshot.get("load") or [0]
        return [
            ("cpu", snapshot.get("cpu"), prefs.get("alerts.cpu_percent"), "CPU 使用率", "%"),
            ("mem", mem, prefs.get("alerts.mem_percent"), "内存使用率", "%"),
            ("disk", disk, prefs.get("alerts.disk_percent"), "磁盘使用率", "%"),
            ("temp", temp, prefs.get("alerts.temp_c"), "最高温度", "°C"),
            ("load1", load[0], prefs.get("alerts.load1"), "1 分钟负载", ""),
        ]

    def evaluate(self, snapshot: dict) -> list[str]:
        """返回本轮需要发送的告警文本（可能为空）。"""
        if not prefs.get("alerts.enabled"):
            with self._lock:
                self._reset()
            return []

        now = time.time()
        hold = float(prefs.get("alerts.for_seconds") or 0)
        silence = float(prefs.get("alerts.silence_minutes") or 0) * 60
        messages: list[str] = []

        with self._lock:
            for key, value, limit, label, unit in self._rules(snapshot):
                if value is None or not limit or float(value) < float(limit):
                    self._breach_since.pop(key, None)
                    continue
                first = self._breach_since.setdefault(key, now)
                if now - first < hold:
                    continue
                if now < self._silent_until.get(key, 0):
                    continue
                self._silent_until[key] = now + silence
                messages.append(
                    f"{label} {value}{unit}，超过阈值 {limit}{unit}"
                    f"（已持续 {int(hold)} 秒）"
                )
        return messages


alerts = AlertManager()
