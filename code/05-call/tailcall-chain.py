#!/usr/bin/python3
"""尾调用扩展C：链式跳转"""
from bcc import BPF
import ctypes as ct

program = r"""
#include <uapi/linux/ptrace.h>

BPF_PROG_ARRAY(table_a, 2);
BPF_PROG_ARRAY(table_b, 2);

int stage_2(struct pt_regs *ctx) {
    bpf_trace_printk("[STAGE 2] final\n");
    return 0;
}

int stage_1(struct pt_regs *ctx) {
    bpf_trace_printk("[STAGE 1] jumping...\n");
    table_b.call(ctx, 0);   // 继续跳到 stage_2
    return 0;
}

int hello(struct pt_regs *ctx) {
    bpf_trace_printk("[STAGE 0] start\n");
    table_a.call(ctx, 0);   // 跳到 stage_1
    return 0;
}
"""

b = BPF(text=program)

# 链式设置：hello -> stage_1 -> stage_2
b["table_a"][ct.c_int(0)] = ct.c_int(b.load_func("stage_1", BPF.KPROBE).fd)
b["table_b"][ct.c_int(0)] = ct.c_int(b.load_func("stage_2", BPF.KPROBE).fd)

b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello")
print("Chained tail call (2 levels). Try: ls")
b.trace_print()
