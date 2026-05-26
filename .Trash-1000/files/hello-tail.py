#!/usr/bin/python3
# hello-tail.py — eBPF 尾调用实验加载器
# 功能：加载 hello-tail.c，配置 prog_array 跳转表，构建 3 级程序链
# 用法：sudo python3 hello-tail.py

import ctypes as ct
import os
import sys
from bcc import BPF

if os.geteuid() != 0:
    print("需要 root 权限：sudo python3 hello-tail.py")
    sys.exit(1)

print("=" * 60)
print("实验 2: eBPF 尾调用 (Tail Call)")
print("=" * 60)

# ============================================================
# 步骤 1: 加载 eBPF 程序
# ============================================================
print("\n[1/4] 加载 eBPF 程序...")
b = BPF(src_file="hello-tail.c")

# ============================================================
# 步骤 2: 获取各函数 fd
# ============================================================
print("[2/4] 获取函数文件描述符...")
entry_fn = b.load_func("hello_entry", BPF.KPROBE)
handler1_fn = b.load_func("hello_handler1", BPF.KPROBE)
handler2_fn = b.load_func("hello_handler2", BPF.KPROBE)

print(f"   entry.fd    = {entry_fn.fd}")
print(f"   handler1.fd = {handler1_fn.fd}")
print(f"   handler2.fd = {handler2_fn.fd}")

# ============================================================
# 步骤 3: 配置 prog_array (jmp_table)
# ============================================================
print("[3/4] 配置尾调用跳转表...")
jmp_table = b.get_table("jmp_table")

jmp_table[ct.c_uint32(1)] = ct.c_uint32(handler1_fn.fd)
print("   jmp_table[1] = handler1 ✅")
jmp_table[ct.c_uint32(2)] = ct.c_uint32(handler2_fn.fd)
print("   jmp_table[2] = handler2 ✅")

# ============================================================
# 步骤 4: 附加到 kprobe
# ============================================================
print("[4/4] 附加 kprobe...")
b.attach_kprobe(
    event=b.get_syscall_fnname("execve"),
    fn_name="hello_entry"
)
print("   已附加到 sys_execve")

print("\n" + "=" * 60)
print("运行中！在另一个终端执行命令观察 tail call")
print("   如: ls, cat /etc/passwd, ps aux")
print()
print("观察方法:")
print("   终端2: sudo cat /sys/kernel/debug/tracing/trace_pipe")
print("   终端3: sudo bpftool prog list | grep hello")
print("   终端3: sudo bpftool map dump name jmp_table")
print()
print("按 Ctrl+C 停止")
print("=" * 60)

try:
    b.trace_print()
except KeyboardInterrupt:
    print("\n\n清理中...")
    print("   分离 kprobe...")
    print("   程序已卸载，实验结束。")
