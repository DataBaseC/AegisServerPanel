#!/usr/bin/env bash
# 前台快速启动（不安装 systemd 服务），适合调试
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -x "${APP_DIR}/.venv/bin/python" ]]; then
  echo "==> 首次运行，创建虚拟环境并安装依赖"
  python3 -m venv "${APP_DIR}/.venv"
  "${APP_DIR}/.venv/bin/pip" install --quiet --upgrade pip
  "${APP_DIR}/.venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"
fi

cd "${APP_DIR}"
exec "${APP_DIR}/.venv/bin/python" -m app.main "$@"
