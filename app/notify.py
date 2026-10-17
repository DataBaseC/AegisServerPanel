"""事件通知出口（1.6.0 F1）：把任务失败、登录锁定等事件 POST 到配置的 Webhook。

设计底线：

- **通知故障不得影响主流程**：未配置 URL 或事件开关关闭时直接返回；任何异常
  （DNS 解析失败、SSRF 拦截、超时、非 2xx、连接被拒）只写审计
  ``notify_failed``，绝不向上抛。
- **同步实现**：``notify()`` 内部是阻塞 HTTP，调用方在异步路由里必须用
  ``await asyncio.to_thread(notify, ...)``，避免冻住事件循环。
- **SSRF 同源校验**：复用 :func:`app.ssrf.assert_url_allowed`（与文件远程拉取
  同一套判定）；私网需求由用户统一配置 ``fetch_allow_private`` 放行。
- **不跟随重定向**：3xx 一律按失败处理，防止"公网地址 302 到内网/云元数据"
  绕过初始 URL 的校验（与文件拉取"逐跳复核"的安全目标一致，这里取更保守的
  做法——直接不跟随）。
"""

from __future__ import annotations

import json
import time
import urllib.request

from .audit import AuditEvent, audit
from .prefs import prefs
from .ssrf import assert_url_allowed

TIMEOUT = 5
_EVENT_SWITCH = {
    "task_fail": "notify.on_task_fail",
    "lockout": "notify.on_lockout",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """关闭自动跳转：Webhook 的 3xx 直接当失败，不给 SSRF 留跳板。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def notify(event: str, text: str) -> None:
    """按配置推送一条通知；任何失败只记审计，不抛异常。"""
    url = ""
    try:
        url = str(prefs.get("notify.webhook_url") or "").strip()
        if not url:
            return
        switch = _EVENT_SWITCH.get(event)
        if switch and not prefs.get(switch):
            return
        assert_url_allowed(url)
        payload = json.dumps({
            "event": event,
            "text": text,
            "time": int(time.time()),
        }).encode("utf-8")
        request = urllib.request.Request(
            url, data=payload, method="POST",
            headers={"Content-Type": "application/json",
                     "User-Agent": "AegisServerPanel/1.6"},
        )
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(request, timeout=TIMEOUT) as response:
            response.read(1024)          # 读掉响应体，避免连接悬挂
    except Exception as exc:             # noqa: BLE001 —— 通知失败不能影响主流程
        _audit("notify_failed", event, text, ok=False, detail=str(exc)[:200])
        return
    _audit("notify_sent", event, text, ok=True)


def _audit(action: str, event: str, text: str, ok: bool, detail: str = "") -> None:
    summary = f"{event}: {text}"[:400]
    if detail:
        summary = f"{summary}（{detail}）"[:400]
    try:
        audit.record(AuditEvent(action=action, target=event, summary=summary,
                                source="system", ok=ok))
    except Exception:                    # noqa: BLE001 —— 审计写失败也不得外抛
        pass
