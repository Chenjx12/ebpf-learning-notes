#!/usr/bin/python3
"""最简单的尾调用演示 - 验证机制"""
from bcc import BPF
import ctypes as ct

program = r"""
#include <uapi/linux/ptrace.h>

// 1. 定义尾调用映射表（大小为 2）
BPF_PROG_ARRAY(tail_call_table, 2);

// 2. 子程序：被尾调用跳转的目标
//    注意：程序类型必须和主程序一致（都是 KPROBE）
int handle_execve(struct pt_regs *ctx) {
    bpf_trace_printk("TC OK!\\n");
    return 0;
}

// 3. 主程序：发起尾调用
int hello(struct pt_regs *ctx) {
    bpf_trace_printk("Before TC\\n");

    // 🔥 关键修复：使用 BCC 的 .call() 语法，而不是手写 bpf_tail_call()
    tail_call_table.call(ctx, 0);

    // 4. 降级逻辑：只有尾调用失败（索引不存在）才会执行到这里
    bpf_trace_printk("TC FAIL!\\n");
    return 0;
}
"""

# 编译 BPF 程序
b = BPF(text=program)

# 5. 先加载子程序，获取其 fd
handle_fn = b.load_func("handle_execve", BPF.KPROBE)

# 6. 将子程序 fd 填入尾调用映射表的索引 0 位置
b["tail_call_table"][ct.c_int(0)] = ct.c_int(handle_fn.fd)

# 7. 附加主程序到 execve 系统调用
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

print("Simple tail call demo, hit Ctrl-C to stop.")
print("Open another terminal and type: ls")
b.trace_print()
