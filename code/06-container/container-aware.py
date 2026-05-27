#!/usr/bin/python3
from bcc import BPF

#  C/Python 分离加载
b = BPF(src_file="container-aware.c")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    # 把 64 位 ID 格式化为十六进制输出
    cg_id = hex(event.cgroup_id)
    print(f"CG={cg_id:18s} PID={event.pid:6d} UID={event.uid:5d} "
          f"COMM={event.comm.decode():16s} → CMD={event.filename.decode()}")

b["events"].open_perf_buffer(print_event)

print("Tracing execve with Cgroup ID, hit Ctrl-C to stop.")
print("Try: ls (host) vs docker run ubuntu ls")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
