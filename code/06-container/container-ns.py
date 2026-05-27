#!/usr/bin/python3
from bcc import BPF

# 加载带有 Namespace 获取的 C 代码
b = BPF(src_file="container-ns.c")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    
    # 格式化输出
    cg_id = hex(event.cgroup_id)
    ns_inum = hex(event.pid_ns_inum) if event.pid_ns_inum else "0x0"
    
    print(f"CG={cg_id:18s} NS={ns_inum:18s} PID={event.pid:6d} UID={event.uid:5d} "
          f"COMM={event.comm.decode():16s} → CMD={event.filename.decode()}")

b["events"].open_perf_buffer(print_event)

print("Tracing execve with Cgroup ID & PID Namespace, hit Ctrl-C to stop.")
print("Try: ls (host) vs docker exec test_ns ls")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
