#!/usr/bin/python3
"""
手动编译的eBPF程序加载器

功能: 演示如何用Python加载手动clang编译的.o文件
对比: 这与BCC的BPF(text=program)完全等价,但是分成了两步

步骤:
  1. clang -target bpf hello-debug.c -o hello-debug.o  (手动编译)
  2. python3 load-compiled.py                           (加载运行)
"""

from bcc import BPF

print("正在加载已编译的 eBPF 程序...")
print("=" * 60)

# 关键: 用 src_file 加载已编译的 .o 文件
# 这与 BPF(text=program) 完全等价,但 C 代码已经预先编译好了
try:
    b = BPF(src_file="hello-debug.o")
except Exception as e:
    print(f"❌ 加载失败: {e}")
    print("\n提示: 请先运行 ./build-ebpf.sh hello-debug.c 编译程序")
    exit(1)

# 获取系统调用名称并附加探针
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

print(f"✅ 成功加载并附加到 {syscall}")
print("=" * 60)
print("\n开始监控 execve 事件...")
print("在新终端执行 ls, ps 等命令,按 Ctrl-C 退出\n")

# 输出跟踪信息
b.trace_print()
