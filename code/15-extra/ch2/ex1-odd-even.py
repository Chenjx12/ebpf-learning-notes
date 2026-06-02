#!/usr/bin/env python3
# ex1-odd-even.py — Ch2 练习1: 区分奇偶 PID 输出不同消息
# 基于 hello-buffer.py 修改, 对奇数和偶数进程 ID 输出不同的跟踪消息

from bcc import BPF

bpf_code = """
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    char comm[16];
};

BPF_PERF_OUTPUT(output);

int on_execve(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    output.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=bpf_code)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="on_execve")

def handle_event(cpu, data, size):
    e = b["output"].event(data)
    if e.pid % 2 == 0:
        print(f"🟢 [EVEN] PID={e.pid:6d} COMM={e.comm.decode():16s}")
    else:
        print(f"🟡 [ODD ] PID={e.pid:6d} COMM={e.comm.decode():16s}")

b["output"].open_perf_buffer(handle_event)
print("[*] 奇偶 PID 区分监控已启动, Ctrl-C 退出")
print(f"{'':6s} {'PID':>6s}  {'COMM':16s}")
print("-" * 40)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[*] 退出")
        break
