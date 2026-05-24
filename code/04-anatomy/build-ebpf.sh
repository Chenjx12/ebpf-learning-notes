#!/bin/bash
# build-ebpf.sh - 手动编译eBPF程序脚本

set -e  # 遇到错误立即退出

echo "=========================================="
echo "  手动编译 eBPF 程序"
echo "=========================================="
echo ""

# 检查输入文件
if [ $# -eq 0 ]; then
    echo "用法: ./build-ebpf.sh <source.c> [output.o]"
    echo ""
    echo "示例:"
    echo "  ./build-ebpf.sh hello-debug.c"
    echo "  ./build-ebpf.sh hello-debug.c hello-debug.o"
    exit 1
fi

SOURCE_FILE=$1
OUTPUT_FILE=${2:-${SOURCE_FILE%.c}.o}

# 检查源文件是否存在
if [ ! -f "$SOURCE_FILE" ]; then
    echo "❌ 错误: 源文件 $SOURCE_FILE 不存在"
    exit 1
fi

echo "📄 源文件: $SOURCE_FILE"
echo "📦 输出文件: $OUTPUT_FILE"
echo ""

# 步骤1: 检查clang是否安装
echo "[1/3] 检查 clang..."
if ! command -v clang &> /dev/null; then
    echo "❌ clang 未安装,请先执行:"
    echo "   sudo apt install clang"
    exit 1
fi

CLANG_VERSION=$(clang --version | head -n 1)
echo "✅ clang 已安装: $CLANG_VERSION"
echo ""

# 步骤2: 检查内核头文件
echo "[2/3] 检查内核头文件..."
KERNEL_HEADERS="/usr/include/linux/bpf.h"
if [ ! -f "$KERNEL_HEADERS" ]; then
    echo "⚠️  警告: 未找到内核头文件 $KERNEL_HEADERS"
    echo "   可能需要安装:"
    echo "   sudo apt install linux-headers-\$(uname -r)"
else
    echo "✅ 找到内核头文件"
fi
echo ""

# 步骤3: 编译eBPF程序
echo "[3/3] 编译 eBPF 程序..."
echo "执行命令:"
echo "  clang -target bpf \\"
echo "        -O2 \\"
echo "        -g \\"
echo "        -c $SOURCE_FILE \\"
echo "        -o $OUTPUT_FILE"
echo ""

clang -target bpf \
      -O2 \
      -g \
      -c "$SOURCE_FILE" \
      -o "$OUTPUT_FILE"

echo "✅ 编译成功!"
echo ""

# 显示编译产物信息
echo "=========================================="
echo "  编译结果"
echo "=========================================="
ls -lh "$OUTPUT_FILE"
echo ""

# 使用readelf查看段结构
echo "=========================================="
echo "  段结构分析 (readelf -S)"
echo "=========================================="
readelf -S "$OUTPUT_FILE" || echo "readelf 不可用"
echo ""

# 使用objdump反汇编(如果可用)
if command -v objdump &> /dev/null; then
    echo "=========================================="
    echo "  反汇编 (objdump -d)"
    echo "=========================================="
    objdump -d "$OUTPUT_FILE" || echo "objdump 失败"
    echo ""
fi

echo "🎉 完成!"
echo ""
echo "下一步:"
echo "  1. 用 bpftool 加载: sudo bpftool prog load $OUTPUT_FILE /sys/fs/bpf/test_prog"
echo "  2. 查看程序: sudo bpftool prog list"
echo "  3. 清理: sudo rm /sys/fs/bpf/test_prog"
