#!/usr/bin/python3
from bcc import BPF
import docker
import os
import ctypes as ct

# 定义与 C 语言对应的用户态结构体
class ContainerInfo(ct.Structure):
    _fields_ = [("name", ct.c_char * 64)]

# 注意这里加载的是 container-map.c
b = BPF(src_file="container-map.c")

# 核心：扫描 Docker 容器，构建映射表
def sync_container_map():
    client = docker.from_env()
    for container in client.containers.list():
        long_id = container.id
        name = container.name
        
        # 拼接 cgroup v2 路径
        cgroup_path = f"/sys/fs/cgroup/system.slice/docker-{long_id}.scope"
        
        # 有些容器可能还没完全启动
        if not os.path.exists(cgroup_path):
            continue
            
        # 获取 inode
        inode = os.stat(cgroup_path).st_ino
        
        # 写入 eBPF Map
        key = ct.c_uint64(inode)
        value = ContainerInfo()
        value.name = name.encode('utf-8')
        b["container_map"][key] = value
        print(f"[Sync] {name} -> inode {inode} (0x{inode:x})")

# 启动时全量同步一次
sync_container_map()

def print_event(cpu, data, size):
    event = b["events"].event(data)
    cg_name = event.container_name.decode()
    print(f"CG={cg_name:16s} PID={event.pid:6d} UID={event.uid:5d} "
          f"COMM={event.comm.decode():16s} → CMD={event.filename.decode()}")

b["events"].open_perf_buffer(print_event)

print("\nTracing execve with Container Identity, hit Ctrl-C to stop.")
print("Try: ls (host) vs docker exec -it test_ns bash :cat /etc/hostname")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
