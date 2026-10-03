#!/usr/bin/env bash
# 在有网络的机器上制作离线安装包（代码 + 全部依赖 wheel）。
# 目标机拿到包后完全离线安装，见 README「离线安装」章节。
#
# 用法：
#   scripts/make-offline-bundle.sh                       # 为当前机器平台打包
#   scripts/make-offline-bundle.sh --platform manylinux2014_aarch64 \
#       --python-version 3.12 --implementation cp --abi cp312
#       # ^ 额外参数原样透传给 pip download，用于交叉打包（如 x86 机器为 aarch64 手机打包）
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OFFLINE_OUT:-AegisServerPanel-offline.tar.gz}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

command -v pip >/dev/null 2>&1 || { echo "缺少 pip"; exit 1; }

echo "==> 1/3 提取代码（不含 .git 与虚拟环境）"
mkdir -p "$STAGE/AegisServerPanel-offline"
if git -C "$APP_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  git -C "$APP_DIR" archive --format=tar HEAD | tar x -C "$STAGE/AegisServerPanel-offline"
else
  tar cf - -C "$APP_DIR" --exclude='.git' --exclude='.venv' --exclude='venv' \
      --exclude='__pycache__' --exclude='*.pyc' --exclude='panel.log*' \
      --exclude='.supervisor.*' . | tar xf - -C "$STAGE/AegisServerPanel-offline"
fi

echo "==> 2/3 下载依赖 wheels（透传参数: $*）"
# --only-binary=:all:：交叉打包(--platform 等)时 pip 强制要求，且本项目全部依赖均有官方 wheel
pip download --only-binary=:all: \
    -r "$APP_DIR/requirements.txt" -c "$APP_DIR/constraints.txt" \
    -d "$STAGE/AegisServerPanel-offline/wheels" "$@"

echo "==> 3/3 打包"
# wheels/ 的存在会让 install.sh 自动切换为 --no-index 本地安装
tar czf "$OUT" -C "$STAGE" AegisServerPanel-offline
echo
echo "离线包已生成: $OUT ($(du -h "$OUT" | cut -f1))"
cat <<'TIP'

目标机安装（无需任何网络）:
  tar xzf AegisServerPanel-offline.tar.gz
  cd AegisServerPanel-offline
  sudo bash install.sh

注意:
  - wheel 与平台绑定。为其他架构打包时用第二个用法示例透传 --platform 等
    参数（目标机 Python 版本也要一致，如 3.12）。
  - 目标机仍需预装 python3(>=3.10) 与 python3-venv（系统包，离线包不含）。
TIP
