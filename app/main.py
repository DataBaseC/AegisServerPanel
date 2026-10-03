"""ServerPanel 应用入口与命令行启动逻辑。"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import socket
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import MODE_INTERNAL, MODE_LABELS, MODE_PUBLIC, config
from .metrics import metrics
from .routes import (
    agent_routes,
    app_routes,
    auth_routes,
    file_routes,
    log_routes,
    process_routes,
    service_routes,
    storage_routes,
    system_routes,
    terminal_routes,
)

logger = logging.getLogger("serverpanel")
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


async def _sampler() -> None:
    """每 2 秒采集一次性能数据，供历史图表使用。"""
    last_error: tuple[str, float] | None = None
    while True:
        try:
            await asyncio.to_thread(metrics.sample)
        except Exception as exc:  # 采集失败不应影响服务，但要留下线索（限频防日志洪水）
            now = asyncio.get_running_loop().time()
            if last_error is None or last_error[0] != repr(exc) or now - last_error[1] > 300:
                logger.warning("性能采样失败: %r", exc)
                last_error = (repr(exc), now)
        await asyncio.sleep(2)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # 清扫历史遗留的下载打包临时目录（进程上次被杀时的残留）
    await asyncio.to_thread(file_routes.cleanup_stale_archives)
    task = asyncio.create_task(_sampler())
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


app = FastAPI(
    title="ServerPanel",
    version=__version__,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,  # 不对外暴露接口文档
)


CSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = CSP
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    # 内部细节只进日志不回传给客户端；本地调试可设 SERVERPANEL_DEBUG=1
    logger.exception("未处理异常 %s %s", request.method, request.url.path)
    detail = f"服务器内部错误: {exc}" if os.environ.get("SERVERPANEL_DEBUG") else "服务器内部错误"
    return JSONResponse(status_code=500, content={"detail": detail})


for module in (
    auth_routes,
    system_routes,
    storage_routes,
    process_routes,
    service_routes,
    log_routes,
    file_routes,
    terminal_routes,
    app_routes,
    agent_routes,
):
    app.include_router(module.router)


@app.get("/healthz")
async def healthz():
    build = None
    version_file = BASE_DIR / "VERSION"
    if version_file.exists():
        build = version_file.read_text("utf-8").strip() or None
    return {"ok": True, "version": __version__, "build": build, "initialized": config.initialized}


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/favicon.ico")
async def favicon():
    icon = STATIC_DIR / "favicon.svg"
    if icon.exists():
        return FileResponse(icon, media_type="image/svg+xml")
    return Response(status_code=204)


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def local_addresses() -> list[str]:
    addresses = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addresses.add(info[4][0])
    except OSError:
        pass
    with contextlib.suppress(OSError):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        addresses.add(sock.getsockname()[0])
        sock.close()
    return sorted(a for a in addresses if not a.startswith("127."))


def banner(host: str, port: int) -> None:
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    internal = config.mode == MODE_INTERNAL
    try:
        print("\n  ServerPanel %s 已启动" % __version__)
        print("  本机访问:   http://%s:%d" % (shown, port))
        for address in local_addresses():
            print("  局域网访问: http://%s:%d" % (address, port))
        print("  当前模式:   %s" % MODE_LABELS.get(config.mode, config.mode))
        if internal:
            print("              （已解锁终端、文件管理与全部控制功能）")
            agent = "已启用" if config.agent_token else "未启用"
            print("  Agent 接入: %s（serverpanel --agent-token 生成令牌）" % agent)
        else:
            print("              （只读监控；执行 serverpanel --enable-internal 解锁全部功能）")
        if not config.initialized:
            print("  首次使用：打开上面的地址，设置面板密码")
        print("  配置文件:   %s" % config.path)
        print("  按 Ctrl+C 停止\n")
    finally:
        sys.stdout.flush()  # 保证在 systemd / 重定向场景下也能立即看到地址


def main() -> int:
    parser = argparse.ArgumentParser(prog="serverpanel", description="ServerPanel — 本地部署的 Ubuntu 系统控制台")
    parser.add_argument("--host", default=os.environ.get("SERVERPANEL_HOST", "0.0.0.0"),
                        help="监听地址，默认 0.0.0.0（局域网可访问）")
    parser.add_argument("--port", type=int, default=int(os.environ.get("SERVERPANEL_PORT", "8787")),
                        help="监听端口，默认 8787")
    parser.add_argument("--config", help="配置文件路径，默认 /etc/serverpanel/config.json")
    parser.add_argument("--ssl-certfile", help="HTTPS 证书路径（可选）")
    parser.add_argument("--ssl-keyfile", help="HTTPS 私钥路径（可选）")

    # 以下命令用于在服务器本机管理面板，执行后立即退出。
    # 内网模式只能通过这些命令切换，面板界面不提供切换入口。
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--set-password", metavar="PASSWORD", help="直接设置/重置面板密码后退出")
    action.add_argument("--enable-internal", action="store_true",
                        help="激活内网模式：解锁终端、文件管理、电源等全部功能")
    action.add_argument("--disable-internal", action="store_true",
                        help="关闭内网模式，回到公网只读模式")
    action.add_argument("--show-mode", action="store_true", help="显示当前运行模式后退出")
    action.add_argument("--agent-token", action="store_true",
                        help="生成（轮换）Agent 接入令牌并打印后退出")
    action.add_argument("--show-agent-token", action="store_true",
                        help="显示当前 Agent 接入令牌后退出")
    action.add_argument("--revoke-agent-token", action="store_true",
                        help="吊销 Agent 接入令牌后退出")

    # ---- 生命周期管理：安装 / 启停 / 升级（替代手工维护 systemd unit 与守护脚本）----
    action.add_argument("--install", action="store_true",
                        help="安装：生成启动命令、VERSION 标记与守护（systemd 或内置 supervisor）并启动")
    action.add_argument("--start", action="store_true", help="启动面板服务")
    action.add_argument("--stop", action="store_true", help="停止面板服务")
    action.add_argument("--restart", action="store_true", help="重启面板服务")
    action.add_argument("--status", action="store_true", help="查看运行状态与健康检查")
    action.add_argument("--update", action="store_true",
                        help="git 升级：备份配置 → fetch → 切换目标版本 → 装依赖 → 重启 → 健康检查，失败自动回滚")
    action.add_argument("--show-version", action="store_true", help="显示版本与部署来源后退出")

    parser.add_argument("--app-dir", default=str(BASE_DIR),
                        help="应用目录（install/update/start/stop 使用，默认为代码所在目录）")
    parser.add_argument("--update-ref", default=os.environ.get("SERVERPANEL_UPDATE_REF", "origin/main"),
                        help="update 目标分支/标签/commit，默认 origin/main")
    parser.add_argument("--update-force", action="store_true",
                        help="update 时容忍本地改动（自动 stash）")
    args = parser.parse_args()

    if args.config:
        config.path = Path(args.config).expanduser()
        config.load()

    # ---- 生命周期命令 ----
    if any((args.install, args.start, args.stop, args.restart, args.status, args.update)):
        from . import manage  # 延迟导入，常规启动路径不付出额外开销

        target_dir = Path(args.app_dir).expanduser().resolve()
        if args.install:
            return manage.cmd_install(target_dir, args.host, args.port)
        if args.start:
            return manage.cmd_start(target_dir)
        if args.stop:
            return manage.cmd_stop(target_dir)
        if args.restart:
            return manage.cmd_restart(target_dir)
        if args.status:
            return manage.cmd_status(target_dir)
        return manage.cmd_update(target_dir, args.update_ref, args.update_force)

    if args.show_version:
        print(f"ServerPanel {__version__}")
        version_file = Path(args.app_dir) / "VERSION"
        if version_file.exists():
            print(f"部署来源: {version_file.read_text().strip()}")
        if (Path(args.app_dir) / ".git").exists():
            import subprocess
            r = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                               cwd=args.app_dir, capture_output=True, text=True)
            if r.returncode == 0:
                print(f"代码版本: {r.stdout.strip()}")
        print(f"配置文件: {config.path}")
        return 0

    if args.set_password:
        try:
            config.set_password(args.set_password)
        except ValueError as exc:
            print(f"设置失败: {exc}", file=sys.stderr)
            return 1
        print(f"面板密码已更新，配置文件: {config.path}")
        return 0

    if args.show_mode:
        print(f"当前模式: {MODE_LABELS.get(config.mode, config.mode)}")
        print(f"配置文件: {config.path}")
        return 0

    if args.agent_token:
        token = config.issue_agent_token()
        print("Agent 接入令牌已生成（旧令牌立即失效）：")
        print(f"  {token}")
        print("  使用方式：POST /api/terminal/exec，请求头 X-Agent-Token: <令牌>")
        print("  生效条件：仅在【内网模式】下有效；关闭内网模式后立即失效。")
        return 0

    if args.show_agent_token:
        token = config.agent_token
        if token:
            print(f"当前 Agent 接入令牌:\n  {token}")
        else:
            print("尚未生成 Agent 接入令牌，执行 serverpanel --agent-token 生成。")
        return 0

    if args.revoke_agent_token:
        config.revoke_agent_token()
        print("Agent 接入令牌已吊销，旧令牌立即失效。")
        return 0

    if args.enable_internal:
        config.set_mode(MODE_INTERNAL)
        print("已激活内网模式（完全控制）")
        print("  已解锁：网页终端、文件读写、进程信号、服务启停、挂载/卸载、开关机")
        print("  生效说明：正在运行的面板会在数秒内自动识别，无需重启服务")
        print("  安全提醒：请关闭后执行 serverpanel --disable-internal")
        return 0

    if args.disable_internal:
        config.set_mode(MODE_PUBLIC)
        print("已关闭内网模式，回到公网模式（只读监控）")
        print("  终端、文件管理、电源等敏感功能已锁定")
        return 0

    banner(args.host, args.port)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level="info",
        access_log=False,
        ssl_certfile=args.ssl_certfile,
        ssl_keyfile=args.ssl_keyfile,
        # 优雅关闭限时：默认无限等待，一个未完成的 WebSocket 就能把重启
        # 卡成几分钟甚至永久（实测教训），守护脚本会被它堵死
        timeout_graceful_shutdown=10,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
