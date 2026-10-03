#!/usr/bin/env bash
# ServerPanel 安装脚本 —— 在 Ubuntu 上部署本地系统控制台
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${SERVERPANEL_PORT:-8787}"
HOST="${SERVERPANEL_HOST:-0.0.0.0}"
BIN="/usr/local/bin/serverpanel"
UNIT="/etc/systemd/system/serverpanel.service"

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 权限运行：sudo bash install.sh" >&2
  exit 1
fi

echo "==> 应用目录：${APP_DIR}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "缺少 python3，请先执行：apt install -y python3 python3-venv python3-pip" >&2
  exit 1
fi
if ! python3 -c 'import venv' >/dev/null 2>&1; then
  echo "缺少 python3-venv，请先执行：apt install -y python3-venv" >&2
  exit 1
fi

echo "==> 创建虚拟环境并安装依赖"
python3 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/pip" install --quiet --upgrade pip
"${APP_DIR}/.venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"

echo "==> 生成启动命令 ${BIN}"
cat > "${BIN}" <<EOF
#!/usr/bin/env bash
cd "${APP_DIR}"
exec "${APP_DIR}/.venv/bin/python" -m app.main "\$@"
EOF
chmod 0755 "${BIN}"

if [[ -d /run/systemd/system ]]; then
  echo "==> 安装 systemd 服务"
  cat > "${UNIT}" <<EOF
[Unit]
Description=ServerPanel 本地系统控制台
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 面板需要 root 才能管理系统、读取日志与执行终端命令
User=root
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/python -m app.main --host ${HOST} --port ${PORT}
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=serverpanel

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now serverpanel.service
  sleep 1
  systemctl --no-pager --lines=5 status serverpanel.service || true
  echo
  echo "服务已启动并设置为开机自启。常用命令："
  echo "  systemctl status serverpanel      查看状态"
  echo "  systemctl restart serverpanel     重启"
  echo "  journalctl -u serverpanel -f      查看面板日志"
else
  echo "==> 未检测到 systemd，跳过服务安装。可手动前台启动："
  echo "    ${BIN}"
fi

echo
echo "==> 安装完成，访问地址："
for ip in $(hostname -I 2>/dev/null); do
  echo "    http://${ip}:${PORT}"
done
echo "    http://127.0.0.1:${PORT}"
echo
echo "首次访问时按提示设置面板密码。"
echo "若忘记密码，执行：serverpanel --set-password 新密码"
echo
echo "运行模式（默认公网模式，只读监控）："
echo "  serverpanel --show-mode          查看当前模式"
echo "  serverpanel --enable-internal    激活内网模式：解锁终端、文件管理、电源等全部功能"
echo "  serverpanel --disable-internal   关闭内网模式，回到只读"
echo "  说明：模式只能登录服务器本机执行上述命令切换，面板界面不提供切换入口。"
echo
echo "内网模式下的两项能力："
echo "  「应用与端口」页面：列出所有监听端口的应用，直接点击链接访问对应服务"
echo "  「Agent 接入」页面：生成令牌后，本地脚本 / AI Agent 可直接远程执行命令"
echo "  serverpanel --agent-token        生成（轮换）Agent 接入令牌"
echo "  serverpanel --show-agent-token   显示当前 Agent 令牌"
echo "  serverpanel --revoke-agent-token 吊销 Agent 令牌"
echo "  说明：Agent 令牌仅在内网模式下有效，关闭内网模式后立即失效。"
echo
echo "安全建议（只在可信网络使用）："
echo "  ufw allow from 192.168.0.0/16 to any port ${PORT} proto tcp"
