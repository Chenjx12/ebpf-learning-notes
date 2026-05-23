#!/bin/bash
# Ubuntu虚拟机快速初始化脚本
# 用途: 一键配置eBPF学习环境

set -e  # 遇到错误立即退出

echo "=========================================="
echo "  eBPF学习环境初始化脚本"
echo "=========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 步骤1: 系统更新
echo -e "${YELLOW}[1/7] 更新系统...${NC}"
sudo apt update && sudo apt upgrade -y
echo -e "${GREEN}✓ 系统更新完成${NC}"
echo ""

# 步骤2: 安装VMware Tools
echo -e "${YELLOW}[2/7] 安装VMware Tools...${NC}"
sudo apt install -y open-vm-tools-desktop
echo -e "${GREEN}✓ VMware Tools安装完成${NC}"
echo ""

# 步骤3: 安装开发工具
echo -e "${YELLOW}[3/7] 安装开发工具...${NC}"
sudo apt install -y build-essential git curl wget vim
echo -e "${GREEN}✓ 开发工具安装完成${NC}"
echo ""

# 步骤4: 安装eBPF依赖
echo -e "${YELLOW}[4/7] 安装eBPF依赖...${NC}"
sudo apt install -y \
    linux-headers-$(uname -r) \
    clang llvm libelf-dev libbpf-dev \
    bison flex libssl-dev pkg-config \
    cmake make gcc
echo -e "${GREEN}✓ eBPF依赖安装完成${NC}"
echo ""

# 步骤5: 安装Python
echo -e "${YELLOW}[5/7] 安装Python环境...${NC}"
sudo apt install -y python3 python3-pip python3-setuptools
echo -e "${GREEN}✓ Python环境安装完成${NC}"
echo ""

# 步骤6: 安装BCC
echo -e "${YELLOW}[6/7] 安装BCC框架...${NC}"
sudo apt install -y bpfcc-tools
echo -e "${GREEN}✓ BCC框架安装完成${NC}"
echo ""

# 步骤7: 克隆学习项目
echo -e "${YELLOW}[7/7] 克隆eBPF学习资料项目...${NC}"
cd ~
git clone https://github.com/binw666/learning-ebpf-translation.git learning-ebpf
echo -e "${GREEN}✓ 学习项目克隆完成${NC}"
echo ""

# 验证安装
echo "=========================================="
echo -e "${GREEN}  环境配置完成!${NC}"
echo "=========================================="
echo ""
echo "检查关键组件:"
echo "  内核版本: $(uname -r)"
echo "  Clang版本: $(clang --version | head -n 1)"
echo "  Git版本: $(git --version)"
echo "  Python版本: $(python3 --version)"
echo ""
echo "学习项目位置: ~/learning-ebpf/"
echo ""
echo "下一步:"
echo "  1. cd ~/learning-ebpf"
echo "  2. 阅读 Learning-eBPF-Full-book.pdf"
echo "  3. 运行第一个eBPF示例程序"
echo ""
echo -e "${YELLOW}提示: 重启系统使VMware Tools生效${NC}"
echo "  sudo reboot"
