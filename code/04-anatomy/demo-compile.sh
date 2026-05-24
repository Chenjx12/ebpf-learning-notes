#!/bin/bash
# demo-compile.sh - 演示 eBPF 编译全过程并展示中间产物

set -e

echo "=========================================="
echo "  eBPF 编译过程演示"
echo "=========================================="
echo ""

# 清理之前的编译产物
if [ -f "hello-debug.o" ]; then
    echo "🗑️  清理之前的编译产物..."
    rm hello-debug.o
fi

echo "📄 源代码文件: hello-debug.c"
echo ""
echo "--- 源代码内容 ---"
cat hello-debug.c
echo ""
echo "------------------"
echo ""

# 步骤1: 编译
echo "=========================================="
echo "  步骤 1: 编译 C 代码为 eBPF 字节码"
echo "=========================================="
echo ""
echo "执行命令:"
echo "  clang -target bpf -O2 -g \\"
echo "        -I/usr/include/x86_64-linux-gnu \\"
echo "        -c hello-debug.c \\"
echo "        -o hello-debug.o"
echo ""

clang -target bpf -O2 -g \
      -I/usr/include/x86_64-linux-gnu \
      -c hello-debug.c \
      -o hello-debug.o

echo "✅ 编译成功!"
echo ""

# 步骤2: 查看文件大小
echo "=========================================="
echo "  步骤 2: 查看编译产物大小"
echo "=========================================="
echo ""
ls -lh hello-debug.o
echo ""

# 步骤3: 查看 ELF 段结构
echo "=========================================="
echo "  步骤 3: 查看 ELF 段结构 (readelf -S)"
echo "=========================================="
echo ""
echo "关键段说明:"
echo "  - kprobe/sys_execve: eBPF 程序代码（将挂钩到 sys_execve）"
echo "  - license: 许可证字符串（必须是 GPL 兼容）"
echo "  - .rodata: 只读数据（字符串常量）"
echo ""
readelf -S hello-debug.o | grep -E "(kprobe|license|\.rodata|Name)"
echo ""

# 步骤4: 反汇编查看字节码
echo "=========================================="
echo "  步骤 4: 反汇编查看 eBPF 字节码"
echo "=========================================="
echo ""
echo "指令数: $(llvm-objdump-14 -d hello-debug.o | grep -E '^\s+[0-9]+:' | wc -l) 条"
echo ""
llvm-objdump-14 -d hello-debug.o
echo ""

# 步骤5: 总结
echo "=========================================="
echo "  总结"
echo "=========================================="
echo ""
echo "✅ 已生成 hello-debug.o（eBPF 字节码文件）"
echo ""
echo "下一步操作:"
echo "  1. 查看详细分析: cat COMPILE_OUTPUT.md"
echo "  2. 用 bpftool 加载: sudo bpftool prog load hello-debug.o /sys/fs/bpf/test"
echo "  3. 查看已加载程序: sudo bpftool prog list"
echo "  4. 清理: sudo rm /sys/fs/bpf/test"
echo ""
echo "🎉 完成!"
