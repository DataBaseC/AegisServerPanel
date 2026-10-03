#!/usr/bin/env bash
# 前台快速启动（不安装任何守护），适合调试；正式运行请用 install.sh / serverpanel --install
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -x "${APP_DIR}/.venv/bin/python" ]]; then
  echo "==> 首次运行，创建虚拟环境并安装依赖"
  python3 -m venv "${APP_DIR}/.venv"
  "${APP_DIR}/.venv/bin/pip" install --quiet --upgrade pip
  PIP_ARGS=(install --quiet -r "${APP_DIR}/requirements.txt")
  [[ -f "${APP_DIR}/constraints.txt" ]] && PIP_ARGS+=(-c "${APP_DIR}/constraints.txt")
  "${APP_DIR}/.venv/bin/pip" "${PIP_ARGS[@]}"
fi

cd "${APP_DIR}"
exec "${APP_DIR}/.venv/bin/python" -m app.main "$@"
