#!/usr/bin/env python3
# ex4-raw-tp-macro.py — Ch2 练习4: 使用 RAW_TRACEPOINT_PROBE 宏简化附加
# 无需在 Python 中显式调用 attach_raw_tracepoint(), BCC 自动处理

from bcc import BPF
import time

bpf_code = """
#include <uapi/linux/ptrace.h>

struct sys_enter_args {
    u64 __unused;
    long id;
    u64 args[6];
};

BPF_HASH(syscall_freq, long, u64);

// RAW_TRACEPOINT_PROBE 自动附加到 sys_enter, 无需 Python 侧 attach
RAW_TRACEPOINT_PROBE(sys_enter) {
    long id = ctx->id;
    u64 *val = syscall_freq.lookup(&id);
    if (val) {
        (*val)++;
    } else {
        u64 one = 1;
        syscall_freq.update(&id, &one);
    }
    return 0;
}
"""

# 注意: 不需要 b.attach_raw_tracepoint(), BCC 自动处理!
b = BPF(text=bpf_code)

print("[*] syscall 频率统计已启动 (RAW_TRACEPOINT_PROBE), Ctrl-C 退出")
print(f"{'Syscall#':>10s}  {'Count':>10s}")
print("-" * 25)

while True:
    try:
        time.sleep(2)
        print("\033[2J\033[H")
        print(f"{'Syscall#':>10s}  {'Count':>10s}")
        print("-" * 25)
        for syscall_id, count in sorted(b["syscall_freq"].items(),
                                        key=lambda x: x[1].value, reverse=True)[:10]:
            print(f"{syscall_id.value:>10d}  {count.value:>10d}")
    except KeyboardInterrupt:
        print("\n[*] 退出")
        break
