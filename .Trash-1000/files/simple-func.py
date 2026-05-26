#!/usr/bin/python3
# simple-func.py — eBPF 函数调用实验加载器
# 功能：加载 simple-func.c，监控 execve 事件，打印 PID 和进程名
# 用法：sudo python3 simple-func.py

from bcc import BPF

b = BPF(src_file="simple-func.c")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID={event.pid:6d} COMM={event.comm.decode():16s}")

b["events"].open_perf_buffer(print_event)

print("实验 1: eBPF 函数调用实验")
print("监控中... 在另一个终端执行命令观察输出")
print("按 Ctrl+C 退出\n")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n退出。eBPF 程序已随进程自动卸载。")
    print("\n💡 如果想用 bpftool 观察字节码，请在程序运行时另开终端执行：")
    print("   sudo bpftool prog list | grep execve")
    print("   sudo bpftool prog dump xlated id <ID>")
