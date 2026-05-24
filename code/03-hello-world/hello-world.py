#!/usr/bin/python3
"""
eBPF Hello World 示例 - 监控 execve 系统调用

功能: 当系统中任何进程调用 execve 时,在内核 trace_pipe 中输出 "Hello World!"

使用方法:
    sudo python3 hello-world.py
    
然后在新终端执行 ls, ps 等命令观察输出

预期输出:
    在 /sys/kernel/debug/tracing/trace_pipe 中看到 Hello World!
"""

from bcc import BPF

# eBPF C 程序代码
program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

# 编译并加载 eBPF 程序
b = BPF(text=program)

# 获取当前架构上 execve 的内核函数名 (如 __x64_sys_execve)
syscall = b.get_syscall_fnname("execve")

# 将 hello() 函数挂钩到 execve 系统调用的 kprobe
b.attach_kprobe(event=syscall, fn_name="hello")

print(f"已附加到 {syscall},等待 execve 事件...")
print("在新终端执行 ls, ps 等命令,按 Ctrl-C 退出")

# 持续读取 trace_pipe 并打印输出
b.trace_print()
