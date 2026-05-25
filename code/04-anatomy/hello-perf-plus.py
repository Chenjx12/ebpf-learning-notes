#!/usr/bin/python3
"""
eBPF Tracepoint 示例(C/Python 分离版) - 获取被执行的完整命令路径
功能: 使用 tracepoint 监控 execve,显示完整命令路径
改进: C 代码和 Python 代码分离,提升可维护性
使用方法: sudo python3 hello-perf-plus.py
"""
from bcc import BPF

# 🔥 关键改动：用 src_file 替代 text！
b = BPF(src_file="hello-perf-plus.c")

# 用户态回调函数
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID={event.pid:6d} UID={event.uid:5d} "
          f"CALLER={event.comm.decode():16s} → "
          f"CMD={event.filename.decode()}")

# 打开 perf buffer
b["events"].open_perf_buffer(print_event)

print("通过 Tracepoint 监控 execve (C/Python 分离版)，按 Ctrl-C 退出...")
print("\n示例:")
print(" ls → CALLER=bash → CMD=/usr/bin/ls")
print(" sudo su → CALLER=bash → CMD=/usr/bin/sudo")
print(" → CALLER=sudo → CMD=/usr/bin/su\n")

# 持续轮询
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
