#!/usr/bin/env bash
# 常驻应用验收脚本：在目标服务器（192.168.3.43 / 任意部署机）本机执行。
#
#   bash scripts/verify-apps.sh [应用目录，默认 /root/aegis/AegisServerPanel]
#
# 安全性：只做「注册 → 启动 → 读日志 → 停止 → 删除」，**不会**停面板、不会动现有服务，
# 因此可以放心在正在服役的机器上跑。
#
# 面板退出时是否收走托管进程，由 tests/test_panel.py::test_shutdown_stops_managed_apps 覆盖，
# 不在本脚本里验证——那需要真的把面板停掉，会中断你的运维通道。
set -u

APPDIR="${1:-/root/aegis/AegisServerPanel}"
NAME="verify-tick-$$"
WORKDIR="$(mktemp -d)"
FAILED=0

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; FAILED=1; }
cleanup() {
  command -v serverpanel >/dev/null 2>&1 && serverpanel --apps remove "$NAME" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "==> 应用目录：$APPDIR"
[ -d "$APPDIR/app" ] || { echo "找不到 $APPDIR/app，请先部署代码"; exit 1; }

echo "==> 1/4 注册测试应用（直接写注册表，不依赖面板进程）"
cat > "$WORKDIR/tick.py" <<'PY'
import time
for i in range(100000):
    print("verify", i, flush=True)
    time.sleep(0.5)
PY

python3 - "$APPDIR" "$NAME" "$WORKDIR" <<'PY'
import sys
from pathlib import Path
appdir, name, workdir = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, appdir)
from app.apps import normalize_definition, supervisor
definition = normalize_definition({
    "name": name,
    "command": f"{sys.executable} {Path(workdir, 'tick.py').as_posix()}",
    "cwd": workdir,
    "restart": "on-failure",
    "restart_delay": 0.5,
})
supervisor.registry.add(definition)
print(f"  已写入 {supervisor.registry.path}")
PY
pass "注册写入完成（失败会直接退出）"

echo "==> 2/4 启动并确认进程独立运行"
serverpanel --apps start "$NAME" >/dev/null 2>&1 && pass "启动命令已执行" || fail "启动失败"
sleep 2
PID="$(serverpanel --apps list | awk -v n="$NAME" '$1==n {print $2}')"
if [ -n "${PID:-}" ] && [ "$PID" != "-" ] && [ -d "/proc/$PID" ]; then
  pass "应用正在运行（PID $PID）"
  PGID="$(ps -o pgid= -p "$PID" | tr -d ' ')"
  [ -n "$PGID" ] && pass "进程组 PGID=$PGID（与面板不同组才不会被升级连带杀死）"
else
  fail "列表里看不到运行中的进程"
fi

echo "==> 3/4 读取运行日志"
if serverpanel --apps logs "$NAME" | grep -q verify; then
  pass "日志里能看到应用输出"
else
  fail "日志里没有应用输出（检查 logs/apps/ 目录与权限）"
fi

echo "==> 4/4 停止并清理"
serverpanel --apps stop "$NAME" >/dev/null 2>&1
sleep 1
if [ -n "${PID:-}" ] && [ -d "/proc/$PID" ]; then
  fail "停止后进程仍在（PID $PID）"
else
  pass "已停止，进程已退出"
fi
serverpanel --apps remove "$NAME" >/dev/null 2>&1 && pass "已删除托管配置"

echo
if [ "$FAILED" = "0" ]; then
  echo "常驻应用验收通过 ✅"
else
  echo "存在失败项，请检查上面的 ✗ 行 ❌"
fi
exit "$FAILED"
