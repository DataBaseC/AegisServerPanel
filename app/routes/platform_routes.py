"""平台化配套接口（2.0 M4）：自诊断包、OpenAPI、自包含接口文档。

三条原则：

- **脱敏在前**：诊断包里的 ``config.json`` 先走与配置导出同一套
  :func:`_scrub`，再额外抹掉 ``users`` 里的密码哈希 / TOTP 密钥 / 恢复码哈希，
  宁可少给排障信息也不泄露凭据。
- **零外部资源**：接口文档是内联 CSS 的静态 HTML，**不引 Swagger UI CDN**
  （CSP 也不允许），离线内网环境照样能打开。
- **全部要求内网模式**：诊断包与接口清单都含部署细节，权限等级不低于设置页。
"""

from __future__ import annotations

import asyncio
import html
import io
import json
import platform
import time
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .. import __version__, shell
from ..audit import AuditEvent, audit
from ..auth import client_ip, require_internal
from ..config import config
from ..metrics import metrics
from ..utils import is_root
from .panel_routes import _scrub

router = APIRouter(tags=["platform"])

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# 诊断包里需要探测的 CLI（与「设置 → 运行环境」的能力探测口径一致，另加运维常用项）
PROBED_CLIS = (
    "systemctl", "journalctl", "crontab", "dmesg", "lsblk", "du", "mount", "smartctl",
    "ufw", "iptables", "nft", "docker", "podman", "nginx", "certbot", "rclone",
    "psql", "mysql", "sqlite3", "ssh-keygen", "timedatectl", "git", "curl",
)

USER_SECRET_KEYS = ("password_hash", "totp_secret", "totp_enabled", "recovery_hashes")


def _build_version() -> dict:
    build = None
    version_file = BASE_DIR / "VERSION"
    if version_file.exists():
        try:
            build = version_file.read_text("utf-8").strip() or None
        except OSError:
            build = None
    return {
        "version": __version__,
        "build": build,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "mode": config.mode,
        "mode_label": config.mode_label,
        "multi_user": config.has_users,
        "generated_at": int(time.time()),
    }


def _scrubbed_config() -> tuple[dict, list[str]]:
    """配置脱敏：先走导出用的 _scrub，再抹掉用户记录里的凭据字段。"""
    data = json.loads(json.dumps(config.data))  # 深拷贝，绝不改动内存里的真实配置
    data, removed = _scrub(data, False)
    users = data.get("users")
    if isinstance(users, list):
        for user in users:
            if not isinstance(user, dict):
                continue
            for key in USER_SECRET_KEYS:
                if key in user:
                    user.pop(key)
                    removed.append(f"users.{key}")
    return data, removed


def _capabilities() -> dict:
    return {
        "cli": {name: shell.available(name) for name in PROBED_CLIS},
        "systemd": Path("/run/systemd/system").is_dir() and shell.available("systemctl"),
        "is_root": is_root(),
        "mode": config.mode,
    }


def _diagnostics_zip() -> io.BytesIO:
    buffer = io.BytesIO()
    scrubbed, removed = _scrubbed_config()
    samples = metrics.history_list()[-60:]  # 最近 60 个内存采样点（约 2 分钟）
    recent = audit.query(days=7, limit=50)
    readme = (
        "ServerPanel 自诊断包\n"
        "====================\n\n"
        "生成时间: %s\n版本: %s\n\n"
        "包含文件:\n"
        "  version.json          版本 / 构建 / 平台 / 内核 / 运行模式\n"
        "  config.scrubbed.json  已脱敏的配置（见下）\n"
        "  capabilities.json     本机 CLI 与能力探测结果\n"
        "  metrics.json          最近 60 个内存采样点\n"
        "  audit_recent.json     最近 50 条审计事件\n\n"
        "脱敏范围（以下内容**不会**出现在包里）:\n"
        "  - 面板密码哈希（password_hash）与弱口令标记\n"
        "  - 多用户记录中的 password_hash / totp_secret / totp_enabled / recovery_hashes\n"
        "  - Agent 接入令牌（含哈希、名称、创建时间）\n"
        "  - 全局 TOTP 密钥与恢复码哈希\n"
        "本次实际剔除的键: %s\n\n"
        "注意: 审计事件里保留了来源 IP、操作对象与命令摘要，转发给他人前请自行评估。\n"
        % (time.strftime("%Y-%m-%d %H:%M:%S"), __version__, ", ".join(removed) or "（无）")
    )
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("version.json", json.dumps(_build_version(), ensure_ascii=False, indent=2))
        bundle.writestr("config.scrubbed.json", json.dumps(scrubbed, ensure_ascii=False, indent=2))
        bundle.writestr("capabilities.json",
                        json.dumps(_capabilities(), ensure_ascii=False, indent=2))
        bundle.writestr("metrics.json", json.dumps(samples, ensure_ascii=False, indent=2))
        bundle.writestr("audit_recent.json", json.dumps(recent, ensure_ascii=False, indent=2))
        bundle.writestr("README.txt", readme)
    buffer.seek(0)
    return buffer


@router.get("/api/panel/diagnostics")
async def diagnostics(request: Request, _session: dict = Depends(require_internal)):
    """下载自诊断包（zip，内存生成，不落临时文件）。"""
    buffer = await asyncio.to_thread(_diagnostics_zip)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    audit.record(AuditEvent(action="diagnostics_export", summary="导出自诊断包",
                            source="web", ip=client_ip(request)))
    return StreamingResponse(
        buffer, media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="serverpanel-diag-{stamp}.zip"'},
    )


@router.get("/api/openapi.json")
async def openapi_spec(request: Request, _session: dict = Depends(require_internal)):
    """OpenAPI 描述（内置文档被关闭，只能从这里取）。"""
    return JSONResponse(request.app.openapi())


METHOD_ORDER = ("get", "post", "put", "patch", "delete")


def _docs_html(spec: dict) -> str:
    """把 OpenAPI 描述渲染成一页自包含 HTML（无 JS、无外部资源）。"""
    groups: dict[str, list[tuple[str, str, str]]] = {}
    for path, item in sorted(spec.get("paths", {}).items()):
        if not isinstance(item, dict):
            continue
        for method in METHOD_ORDER:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            tags = operation.get("tags") or ["default"]
            tag = str(tags[0])
            summary = str(operation.get("summary") or operation.get("operationId") or "")
            groups.setdefault(tag, []).append((method.upper(), path, summary))

    sections = []
    for tag in sorted(groups):
        rows = "".join(
            f'<tr><td><span class="m m-{method.lower()}">{method}</span></td>'
            f'<td class="p">{html.escape(path)}</td>'
            f'<td>{html.escape(summary)}</td></tr>'
            for method, path, summary in groups[tag]
        )
        sections.append(
            f'<section><h2>{html.escape(tag)} <span class="n">{len(groups[tag])}</span></h2>'
            f'<table><thead><tr><th>方法</th><th>路径</th><th>说明</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></section>'
        )

    total = sum(len(v) for v in groups.values())
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ServerPanel 接口文档</title>
<style>
:root {{ color-scheme: dark; }}
body {{ margin:0; background:#12151a; color:#d7dce3;
  font:14px/1.6 -apple-system, "Segoe UI", "Noto Sans SC", sans-serif; }}
header {{ padding:26px 28px 18px; border-bottom:1px solid #242a33; }}
header h1 {{ margin:0 0 6px; font-size:20px; letter-spacing:.5px; }}
header div {{ color:#8d97a5; font-size:12.5px; }}
main {{ padding:18px 28px 60px; }}
section {{ margin-bottom:26px; }}
section h2 {{ font-size:15px; margin:0 0 10px; color:#ffd802;
  letter-spacing:.4px; text-transform:uppercase; }}
section h2 .n {{ color:#8d97a5; font-weight:400; font-size:12px; }}
table {{ width:100%; border-collapse:collapse; background:#171b21;
  border:1px solid #242a33; border-radius:6px; overflow:hidden; }}
th, td {{ text-align:left; padding:7px 10px; border-bottom:1px solid #1f242c;
  vertical-align:top; }}
th {{ font-size:11.5px; color:#8d97a5; text-transform:uppercase;
  letter-spacing:.6px; background:#141821; }}
tr:last-child td {{ border-bottom:none; }}
td.p {{ font-family:ui-monospace, "SF Mono", Menlo, monospace; font-size:12.5px;
  color:#c9d3e0; }}
.m {{ display:inline-block; min-width:52px; text-align:center; padding:1px 6px;
  border-radius:3px; font-size:11px; font-weight:700; letter-spacing:.5px; }}
.m-get {{ background:#12321f; color:#5ad17e; }}
.m-post {{ background:#33290c; color:#ffd802; }}
.m-put {{ background:#10283a; color:#5aa9ff; }}
.m-patch {{ background:#2a1f3a; color:#b48cff; }}
.m-delete {{ background:#3a1418; color:#ff6b6b; }}
footer {{ padding:0 28px 40px; color:#6f7885; font-size:12px; }}
code {{ background:#1c212a; padding:1px 5px; border-radius:3px; }}
</style></head>
<body>
<header>
  <h1>ServerPanel 接口文档</h1>
  <div>版本 {html.escape(str(spec.get("info", {}).get("version", "")))}
    · 共 {total} 个端点 · {len(groups)} 个分组
    · 本页为静态渲染，交互式调试请用
    <code>/api/openapi.json</code></div>
</header>
<main>{"".join(sections)}</main>
<footer>所有接口都需要登录会话（Cookie 或 Authorization: Bearer）；
除鉴权类接口外，绝大多数要求内网模式。高危操作另需
<code>X-Confirm-Token</code> 确认令牌。</footer>
</body></html>"""


@router.get("/api/docs")
async def docs(request: Request, _session: dict = Depends(require_internal)):
    """自包含的接口文档页（内联 CSS，无 JS，无 CDN）。"""
    page = await asyncio.to_thread(lambda: _docs_html(request.app.openapi()))
    return Response(content=page, media_type="text/html; charset=utf-8")
