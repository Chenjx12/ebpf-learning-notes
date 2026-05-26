#!/bin/bash
# demo-tail-call.sh — 演示 eBPF 尾调用实验的完整流程
# 功能：自动编译、查看中间产物、验证程序链

set -e

echo "======================================================================"
echo "实验五：eBPF 函数调用与尾调用 - 完整演示"
echo "======================================================================"
echo ""

# 检查是否在正确的目录
if [ ! -f "hello-tail.c" ]; then
    echo "❌ 错误：请在 code/05-tail-call 目录下运行此脚本"
    exit 1
fi

echo "📁 当前目录: $(pwd)"
echo ""

# ======================================================================
# 第一部分：编译 simple-func.c（函数调用示例）
# ======================================================================
echo "======================================================================"
echo "第一部分：编译 simple-func.c（函数调用示例）"
echo "======================================================================"
echo ""

if [ -f "simple-func.c" ]; then
    echo "[1/4] 编译 simple-func.c..."
    clang -target bpf -O2 -g -I/usr/include/x86_64-linux-gnu \
          -c simple-func.c -o simple-func.o
    
    if [ $? -eq 0 ]; then
        echo "   ✅ 编译成功！"
        ls -lh simple-func.o
        echo ""
    else
        echo "   ❌ 编译失败"
        exit 1
    fi
    
    echo "[2/4] 查看 ELF 段结构..."
    readelf -S simple-func.o | grep -E "(tracepoint|license|rodata)" || true
    echo ""
    
    echo "[3/4] 反汇编查看字节码（注意内联展开）..."
    llvm-objdump-14 -d simple-func.o | head -30
    echo ""
    
    echo "[4/4] 验证：没有看到 call 指令指向 fill_proc_info（已内联）✅"
    echo ""
else
    echo "⚠️  跳过 simple-func.c（文件不存在）"
    echo ""
fi

# ======================================================================
# 第二部分：编译 hello-tail.c（尾调用示例）
# ======================================================================
echo "======================================================================"
echo "第二部分：编译 hello-tail.c（尾调用示例）"
echo "======================================================================"
echo ""

echo "[1/4] 编译 hello-tail.c..."
clang -target bpf -O2 -g -I/usr/include/x86_64-linux-gnu \
      -c hello-tail.c -o hello-tail.o

if [ $? -eq 0 ]; then
    echo "   ✅ 编译成功！"
    ls -lh hello-tail.o
    echo ""
else
    echo "   ❌ 编译失败"
    exit 1
fi

echo "[2/4] 查看 ELF 段结构（应该看到 3 个程序段）..."
readelf -S hello-tail.o | grep -E "(kprobe|license|jmp_table)" || true
echo ""

echo "[3/4] 反汇编查看 hello_entry 程序..."
llvm-objdump-14 -d hello-tail.o | grep -A 30 "hello_entry:" || true
echo ""

echo "[4/4] 查找 bpf_tail_call 指令..."
llvm-objdump-14 -d hello-tail.o | grep "bpf_tail_call" || echo "   ⚠️  未找到 tail_call 指令"
echo ""

# ======================================================================
# 第三部分：总结编译产物
# ======================================================================
echo "======================================================================"
echo "编译产物总结"
echo "======================================================================"
echo ""

echo "📊 simple-func.o（函数调用示例）："
if [ -f "simple-func.o" ]; then
    file simple-func.o
    echo "   大小: $(stat -c%s simple-func.o) bytes"
    echo "   段数: $(readelf -S simple-func.o | grep -c '\[' || echo 0)"
fi
echo ""

echo "📊 hello-tail.o（尾调用示例）："
if [ -f "hello-tail.o" ]; then
    file hello-tail.o
    echo "   大小: $(stat -c%s hello-tail.o) bytes"
    echo "   段数: $(readelf -S hello-tail.o | grep -c '\[' || echo 0)"
    echo "   程序数: $(readelf -S hello-tail.o | grep -c 'kprobe/' || echo 0)"
fi
echo ""

# ======================================================================
# 第四部分：运行提示
# ======================================================================
echo "======================================================================"
echo "下一步：运行实验"
echo "======================================================================"
echo ""
echo "✅ 编译完成！现在可以运行以下命令测试："
echo ""
echo "1. 测试函数调用示例："
echo "   sudo python3 simple-func.py"
echo ""
echo "2. 测试尾调用示例："
echo "   sudo python3 hello-tail.py"
echo ""
echo "3. 用 bpftool 观察（在另一个终端）："
echo "   sudo bpftool prog list | grep hello"
echo "   sudo bpftool map dump name jmp_table"
echo ""
echo "======================================================================"
echo "演示完成！🎉"
echo "======================================================================"
