#!/usr/bin/env python3
# ex3-sys-enter.py — Ch2 练习3: 附加到 sys_enter raw tracepoint, 统计每个UID的总系统调用数
# raw tracepoint 在每次系统调用入口触发, 比 kprobe 更高效

from bcc import BPF
import time

bpf_code = """
#include <uapi/linux/ptrace.h>

struct sys_enter_args {
    u64 __unused;
    long id;  // 系统调用号
    u64 args[6];
};

BPF_HASH(uid_count, u32, u64);

int on_sys_enter(struct sys_enter_args *ctx) {
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u64 *val = uid_count.lookup(&uid);
    if (val) {
        (*val)++;
    } else {
        u64 one = 1;
        uid_count.update(&uid, &one);
    }
    return 0;
}
"""

b = BPF(text=bpf_code)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="on_sys_enter")

print("[*] UID 系统调用统计已启动 (sys_enter raw tracepoint), Ctrl-C 退出")
print(f"{'UID':>8s}  {'Syscall Count':>14s}")
print("-" * 30)

while True:
    try:
        time.sleep(2)
        print("\033[2J\033[H")  # 清屏
        print(f"{'UID':>8s}  {'Syscall Count':>14s}")
        print("-" * 30)
        for uid, count in sorted(b["uid_count"].items(), key=lambda x: x[1].value, reverse=True):
            print(f"{uid.value:>8d}  {count.value:>14d}")
    except KeyboardInterrupt:
        print("\n[*] 退出")
        break
