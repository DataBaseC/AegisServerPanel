#!/bin/bash
# 重置冒烟测试环境：清配置 → 设密码 → 切内网 → 重启面板（端口 8899）
# 用法：bash tests/smoke_reset.sh && python3 tests/smoke_frontend.py
set -e
cd "$(dirname "$0")/.."
pkill -f "app.main --port 8899" 2>/dev/null || true
sleep 1
rm -f /tmp/sp_smoke.json
export SERVERPANEL_CONFIG=/tmp/sp_smoke.json
python3 -m app.main --port 8899 --set-password "smoke-test-password-1234" >/dev/null 2>&1
python3 -m app.main --enable-internal >/dev/null 2>&1
SERVERPANEL_CONFIG=/tmp/sp_smoke.json nohup python3 -m app.main --port 8899 > /tmp/sp_smoke.log 2>&1 &
for i in $(seq 1 20); do
  curl -sf http://localhost:8899/healthz >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf http://localhost:8899/healthz && echo " 冒烟环境就绪"
