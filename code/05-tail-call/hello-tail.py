#!/usr/bin/python3
# hello-tail.py — eBPF 尾调用实验加载器
#
# 演示:
#   1. 加载多个 eBPF 程序到内核
#   2. 用 prog_array 建立程序链
#   3. 动态切换尾调用目标
#   4. bpftool 观察尾调用状态
#
# 用法:
#   sudo python3 hello-tail.py              # 完整 3 级链
#   sudo python3 hello-tail.py --chain=2    # 只链 2 级（观察 fallback）
#   sudo python3 hello-tail.py --no-fallback # 不加载 fallback（观察错误行为）

import sys
import subprocess
import os
from bcc import BPF

# 确保以 root 运行
if os.geteuid() != 0:
    print("❌ 需要 root 权限运行: sudo python3 hello-tail.py")
    sys.exit(1)

# 解析参数
CHAIN_LEN = 3  # 默认完整链: entry -> handler1 -> handler2
LOAD_FALLBACK = True

for arg in sys.argv[1:]:
    if arg.startswith("--chain="):
        try:
            CHAIN_LEN = int(arg.split("=")[1])
            if CHAIN_LEN < 1 or CHAIN_LEN > 3:
                print("⚠️  chain 长度必须为 1-3，使用默认值 3")
                CHAIN_LEN = 3
        except ValueError:
            print("⚠️  参数格式错误，使用默认值")
    elif arg == "--no-fallback":
        LOAD_FALLBACK = False

print("=" * 60)
print("🧪 实验 2: eBPF 尾调用 (Tail Call)")
print("=" * 60)
print(f"   链长度: {CHAIN_LEN} 级")
print(f"   降级程序: {'✅' if LOAD_FALLBACK else '❌'}")
print()

# ============================================================
# 步骤 1: 加载 eBPF 程序
# ============================================================
print("[1/4] 加载 eBPF 程序...")

# 方法: 用 BCC 加载 C 源码
b = BPF(src_file="hello-tail.c")

# ============================================================
# 步骤 2: 获取各函数 fd
# ============================================================
print("[2/4] 获取函数文件描述符...")

entry_fn = b.load_func("hello_entry", BPF.KPROBE)
handler1_fn = b.load_func("hello_handler1", BPF.KPROBE)
handler2_fn = b.load_func("hello_handler2", BPF.KPROBE)
fallback_fn = b.load_func("hello_fallback", BPF.KPROBE)

print(f"   entry.fd    = {entry_fn.fd}")
print(f"   handler1.fd = {handler1_fn.fd}")
print(f"   handler2.fd = {handler2_fn.fd}")
print(f"   fallback.fd = {fallback_fn.fd}")

# ============================================================
# 步骤 3: 配置 prog_array (jmp_table)
# ============================================================
print("[3/4] 配置尾调用跳转表...")

jmp_table = b.get_table("jmp_table")

# 清空跳转表（BCC 初始化后默认全 0）
# 注意: BCC 的 prog_array 需要设置值

# 索引 0: 保留给 entry 自身（BCC 的 kprobe 附加用）
# 索引 1: handler1
jmp_table[ct.c_int(1)] = ct.c_int(handler1_fn.fd)
print("   jmp_table[1] = handler1 ✅")

# 索引 2: handler2（如果链长度 >= 2）
if CHAIN_LEN >= 2:
    jmp_table[ct.c_int(2)] = ct.c_int(handler2_fn.fd)
    print("   jmp_table[2] = handler2 ✅")
else:
    print("   jmp_table[2] = (空) — 将触发 fallback")

# 索引 3: fallback（可选）
if LOAD_FALLBACK:
    jmp_table[ct.c_int(3)] = ct.c_int(fallback_fn.fd)
    print("   jmp_table[3] = fallback ✅")

# ============================================================
# 步骤 4: 附加到 kprobe
# ============================================================
print("[4/4] 附加 kprobe...")

b.attach_kprobe(
    event=b.get_syscall_fnname("execve"),
    fn_name="hello_entry"
)
print("   已附加到 sys_execve\n")

print("=" * 60)
print("🚀 运行中! 在另一个终端执行命令观察 tail call")
print("   (如: ls, cat /etc/passwd, ps aux)")
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
    print("\n\n🧹 清理中...")

# 清理时倒序卸载
print("   分离 kprobe...")
b.detach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello_entry")

print("   程序已卸载，实验结束。")
print()
print("📖 实验回顾:")
print("   修改 --chain 参数重新运行，观察 fallback 行为:")
print(f"   sudo python3 hello-tail.py --chain=2")
print(f"   sudo python3 hello-tail.py --chain=1")