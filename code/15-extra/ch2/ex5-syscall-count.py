#!/usr/bin/env python3
# ex5-syscall-count.py — Ch2 练习5: 按系统调用类型统计 (key=syscall_id 而非 UID)
# 展示"改变 map key 即可改变统计维度"的灵活性

from bcc import BPF
import time

bpf_code = """
#include <uapi/linux/ptrace.h>

struct data_t {
    long syscall_id;
    u64 count;
};

BPF_HASH(syscall_counter, long, u64);

int on_sys_enter(struct pt_regs *ctx) {
    // 用 ctx->orig_ax (x86) 获取系统调用号
    long id = PT_REGS_SYSCALL(ctx);
    u64 *val = syscall_counter.lookup(&id);
    if (val) {
        (*val)++;
    } else {
        u64 one = 1;
        syscall_counter.update(&id, &one);
    }
    return 0;
}
"""

# 系统调用号 → 名称映射 (x86_64 常见)
syscall_names = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
    7: "poll", 9: "mmap", 10: "mprotect",
    14: "rt_sigaction", 21: "access",
    56: "clone", 57: "fork", 59: "execve", 60: "exit",
    61: "wait4", 62: "kill",
    202: "futex", 217: "getdents64",
    231: "exit_group", 232: "epoll_wait",
    257: "openat", 262: "newfstatat",
    281: "execveat",
}

b = BPF(text=bpf_code)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="on_sys_enter")
# 也可以改为 raw tracepoint sys_enter 来覆盖所有系统调用

print("[*] 按系统调用类型统计已启动, Ctrl-C 退出")
print(f"{'Name':>14s} (ID)  {'Count':>10s}")
print("-" * 35)

while True:
    try:
        time.sleep(2)
        print("\033[2J\033[H")
        print(f"{'Name':>14s} (ID)  {'Count':>10s}")
        print("-" * 35)
        for syscall_id, count in sorted(b["syscall_counter"].items(),
                                        key=lambda x: x[1].value, reverse=True)[:15]:
            name = syscall_names.get(syscall_id.value, f"???({syscall_id.value})")
            print(f"{name:>14s} ({syscall_id.value:>3d}) {count.value:>10d}")
    except KeyboardInterrupt:
        print("\n[*] 退出")
        break
