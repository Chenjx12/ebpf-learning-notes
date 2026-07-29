#!/bin/bash
# setup-k3s.sh — K8s 学习环境一键搭建
# 对应笔记: docs/Three-扩展/WEEK 1.md
#
# 用法: bash setup-k3s.sh
# 安装 k3s 轻量级 K8s 发行版 (单节点, 适合虚拟机学习)

set -e

echo "============================================"
echo "  k3s 单节点 K8s 环境搭建"
echo "============================================"

# 1. 安装 k3s
if command -v k3s &>/dev/null; then
    echo "[✓] k3s 已安装"
else
    echo "[*] 正在安装 k3s..."
    curl -sfL https://get.k3s.io | sh -
    echo "[✓] k3s 安装完成"
fi

# 2. 等待 k3s 就绪
echo "[*] 等待 k3s 就绪..."
sleep 5

# 3. 配置 kubectl
echo "[*] 配置 kubectl..."
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
chmod 600 ~/.kube/config

# 4. 验证
echo ""
echo "============================================"
echo "  验证环境"
echo "============================================"
echo ""
kubectl get nodes
echo ""
kubectl get pods -A
echo ""
echo "[✓] k3s 环境搭建完成!"
echo ""
echo "常用命令:"
echo "  kubectl get nodes          # 查看节点"
echo "  kubectl get pods -A        # 查看所有 Pod"
echo "  kubectl run test --image=nginx --restart=Never  # 创建测试 Pod"
