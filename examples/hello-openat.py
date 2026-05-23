#!/usr/bin/python3
"""
eBPF Hello World 示例 - 监控 openat 系统调用

功能: 监控文件打开操作,比 execve 更频繁

使用方法:
    sudo python3 hello-openat.py
    
预期输出:
    在 trace_pipe 中看到大量 "Hello World from openat!" 消息
"""

from bcc import BPF

# eBPF C 程序代码
program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World from openat!");
    return 0;
}
"""

# 编译并加载 eBPF 程序
b = BPF(text=program)

# 获取 openat 系统调用的内核函数名
syscall = b.get_syscall_fnname("openat")

# 将 hello() 函数挂钩到 openat 系统调用
b.attach_kprobe(event=syscall, fn_name="hello")

print(f"已附加到 {syscall},等待文件打开事件...")
print("执行任何文件操作都会触发输出,按 Ctrl-C 退出")

# 持续读取 trace_pipe 并打印输出
b.trace_print()
