#!/usr/bin/python3
"""尾调用扩展A：策略路由 - 根据UID分发"""
from bcc import BPF
import ctypes as ct

program = r"""
#include <uapi/linux/ptrace.h>

BPF_PROG_ARRAY(tail_call_table, 3);

int handle_system(struct pt_regs *ctx) {
    bpf_trace_printk("[SYSTEM] sys user execve\n");
    return 0;
}

int handle_root(struct pt_regs *ctx) {
    bpf_trace_printk("[ROOT] root execve detected!\n");
    return 0;
}

int handle_normal(struct pt_regs *ctx) {
    bpf_trace_printk("[NORMAL] regular user execve\n");
    return 0;
}

int hello(struct pt_regs *ctx) {
    u32 uid = bpf_get_current_uid_gid() >> 32;
    
    if (uid == 0) {
        tail_call_table.call(ctx, 1);   // root -> 索引1
    } else if (uid < 1000) {
        tail_call_table.call(ctx, 0);   // 系统用户 -> 索引0
    } else {
        tail_call_table.call(ctx, 2);   // 普通用户 -> 索引2
    }
    
    bpf_trace_printk("TC MISS uid=%d\n", uid);
    return 0;
}
"""

b = BPF(text=program)

# 加载所有子程序并填入映射表
# 映射表绑定：系统用户(0) / root(1) / 普通用户(2)
for name, idx in [
    ("handle_system", 0),
    ("handle_root", 1),
    ("handle_normal", 2),
]:
    fn = b.load_func(name, BPF.KPROBE)
    b["tail_call_table"][ct.c_int(idx)] = ct.c_int(fn.fd)

syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

print("Policy routing demo. Try: sudo ls  vs  ls")
b.trace_print()
