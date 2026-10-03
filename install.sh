#!/usr/bin/env bash
# ServerPanel 安装脚本 —— 引导阶段：检查环境、建虚拟环境、装依赖；
# 之后的安装动作（启动命令 / VERSION 标记 / systemd 单元或守护脚本 / 启动）
# 全部由 serverpanel --install 完成，保证与升级路径（serverpanel --update）行为一致。
#
# 用法：
#   sudo bash install.sh                          # 默认监听 0.0.0.0:8787
#   sudo SERVERPANEL_HOST=0.0.0.0 SERVERPANEL_PORT=9000 bash install.sh
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${SERVERPANEL_PORT:-8787}"
HOST="${SERVERPANEL_HOST:-0.0.0.0}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 权限运行：sudo bash install.sh" >&2
  exit 1
fi

echo "==> 应用目录：${APP_DIR}"

command -v python3 >/dev/null 2>&1 || {
  echo "缺少 python3，请先执行：apt install -y python3 python3-venv python3-pip" >&2
  exit 1
}
python3 -c 'import venv' >/dev/null 2>&1 || {
  echo "缺少 python3-venv，请先执行：apt install -y python3-venv" >&2
  exit 1
}
python3 - <<'EOF' || {
  echo "需要 Python >= 3.10（项目注解由 Pydantic 运行时求值，3.9 及以下导入即崩）" >&2
  exit 1
}
import sys
sys.exit(0 if sys.version_info >= (3, 10) else 1)
EOF

echo "==> 创建虚拟环境并安装依赖"
if [[ ! -x "${APP_DIR}/.venv/bin/python" ]]; then
  python3 -m venv "${APP_DIR}/.venv"
fi
"${APP_DIR}/.venv/bin/pip" install --quiet --upgrade pip
PIP_ARGS=(install --quiet -r "${APP_DIR}/requirements.txt")
[[ -f "${APP_DIR}/constraints.txt" ]] && PIP_ARGS+=(-c "${APP_DIR}/constraints.txt")
"${APP_DIR}/.venv/bin/pip" "${PIP_ARGS[@]}"

echo "==> 执行安装（启动命令 / VERSION / 守护 / 启动 / 健康检查）"
cd "${APP_DIR}"
exec "${APP_DIR}/.venv/bin/python" -m app.main --install --app-dir "${APP_DIR}" \
  --host "${HOST}" --port "${PORT}"
