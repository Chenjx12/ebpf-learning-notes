#!/usr/bin/python3
"""尾调用扩展B：多探针共享映射表（只打印 UID 1000）"""
from bcc import BPF
import ctypes as ct

program = r"""
#include <uapi/linux/ptrace.h>

BPF_PROG_ARRAY(tail_call_table, 4);

int handle_execve(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid() >> 32;
    if (uid != 1000) return 0;          //  只关注普通用户
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("[EXECVE] pid=%d uid=%d\n", pid, uid);
    return 0;
}

int handle_openat(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid() >> 32;
    if (uid != 1000) return 0;          //  过滤掉系统进程
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("[OPENAT] pid=%d uid=%d\n", pid, uid);
    return 0;
}

int hello_execve(struct pt_regs *ctx) {
    tail_call_table.call(ctx, 0);
    return 0;
}

int hello_openat(struct pt_regs *ctx) {
    tail_call_table.call(ctx, 1);
    return 0;
}
"""

b = BPF(text=program)

b["tail_call_table"][ct.c_int(0)] = ct.c_int(b.load_func("handle_execve", BPF.KPROBE).fd)
b["tail_call_table"][ct.c_int(1)] = ct.c_int(b.load_func("handle_openat", BPF.KPROBE).fd)

b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello_execve")
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="hello_openat")

print("Filtered multi-probe demo (UID=1000 only). Try: ls / sudo ls / cat /etc/passwd")
b.trace_print()
