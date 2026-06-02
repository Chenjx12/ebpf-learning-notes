#!/usr/bin/env python3
# ex2-multi-probe.py — Ch2 练习2: 多个系统调用访问同一个 map
# 将 eBPF 程序附加到 execve, openat, write 三个系统调用, 共享一个统计 map

from bcc import BPF
import time

bpf_code = """
#include <uapi/linux/ptrace.h>

// 计数 key: 0=execve, 1=openat, 2=write
BPF_HASH(syscall_count, u32, u64, 3);

int count_execve(struct pt_regs *ctx) {
    u32 key = 0;  // execve
    u64 *val = syscall_count.lookup(&key);
    if (val) (*val)++; else { u64 one = 1; syscall_count.update(&key, &one); }
    return 0;
}

int count_openat(struct pt_regs *ctx) {
    u32 key = 1;  // openat
    u64 *val = syscall_count.lookup(&key);
    if (val) (*val)++; else { u64 one = 1; syscall_count.update(&key, &one); }
    return 0;
}

int count_write(struct pt_regs *ctx) {
    u32 key = 2;  // write
    u64 *val = syscall_count.lookup(&key);
    if (val) (*val)++; else { u64 one = 1; syscall_count.update(&key, &one); }
    return 0;
}
"""

b = BPF(text=bpf_code)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="count_execve")
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="count_openat")
b.attach_kprobe(event=b.get_syscall_fnname("write"),  fn_name="count_write")

syscalls = {0: "execve", 1: "openat", 2: "write"}
print("[*] 多系统调用监控已启动 (execve+openat+write), Ctrl-C 退出")
print(f"{'Syscall':>10s}  {'Count':>10s}")
print("-" * 25)

while True:
    try:
        time.sleep(2)
        for k, name in syscalls.items():
            val = b["syscall_count"][k]
            print(f"{name:>10s}  {val.value:>10d}")
        print("---")
    except KeyboardInterrupt:
        print("\n[*] 退出")
        break
