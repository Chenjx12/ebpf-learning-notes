#!/bin/bash
# deploy.sh — 第十篇：容器逃逸防护系统生产化部署脚本
set -e

INSTALL_DIR="/opt/escape-defender"
LOG_DIR="/var/log/escape-defender"
SERVICE_NAME="escape-defender"

echo "=== 容器逃逸防护系统 生产化部署 ==="

# 1. 创建安装目录
echo "[1/5] 创建目录结构..."
sudo mkdir -p "$INSTALL_DIR" "$LOG_DIR"

# 2. 复制程序文件
echo "[2/5] 复制程序文件..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
sudo cp "$SCRIPT_DIR/../09-response/escape-respond.py" "$INSTALL_DIR/"
sudo cp "$SCRIPT_DIR/../09-response/responder.py" "$INSTALL_DIR/"
sudo cp "$SCRIPT_DIR/../09-response/detector.py" "$INSTALL_DIR/"
sudo cp "$SCRIPT_DIR/../09-response/escape-detect.c" "$INSTALL_DIR/"
sudo cp "$SCRIPT_DIR/../09-response/rules.yaml" "$INSTALL_DIR/"
sudo cp "$SCRIPT_DIR/../09-response/responses.yaml" "$INSTALL_DIR/"

# 3. 安装 systemd unit
echo "[3/5] 安装 systemd 服务..."
sudo cp "$SCRIPT_DIR/escape-defender.service" /etc/systemd/system/
sudo systemctl daemon-reload

# 4. 设置权限
echo "[4/5] 配置权限..."
sudo chown -R root:root "$INSTALL_DIR"
sudo chmod 755 "$INSTALL_DIR"
sudo chmod 644 "$INSTALL_DIR"/*.yaml
sudo chown -R root:root "$LOG_DIR"

# 5. 启动服务
echo "[5/5] 启动服务..."
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl start "$SERVICE_NAME"

echo ""
echo "=== 部署完成 ==="
echo "  查看状态: sudo systemctl status $SERVICE_NAME"
echo "  查看日志: sudo journalctl -u $SERVICE_NAME -f"
echo "  停止服务: sudo systemctl stop $SERVICE_NAME"
echo "  审计日志: $LOG_DIR/"
echo ""
echo "⚠️  首次运行前请确认:"
echo "  1. Docker 正在运行: docker ps"
echo "  2. Python 依赖已安装: pip3 install docker pyyaml"
echo "  3. eBPF 环境正常: sudo python3 -c 'from bcc import BPF; print(\"OK\")'"
