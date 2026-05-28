#!/usr/bin/python3
from bcc import BPF
import docker
import os
import ctypes as ct
import threading
import time
from socket import htons

# ==================== 0. ctypes 结构体定义 ====================
class ContainerInfo(ct.Structure):
    _fields_ = [("name", ct.c_char * 64)]

class DataUnion(ct.Union):
    _fields_ = [
        ("filename", ct.c_char * 128),
        ("daddr", ct.c_uint32),
        ("dport", ct.c_uint16)
    ]

class DataT(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("cgroup_id", ct.c_uint64),
        ("container_name", ct.c_char * 64),
        ("type", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("data", DataUnion)
    ]

# ==================== 1. 加载 eBPF 程序 ====================
b = BPF(src_file="container-monitor.c")

# ==================== 2. 映射表操作 ====================
def add_container_to_map(container, max_retries=10, interval=0.5):
    long_id = container.id
    name = container.name
    cgroup_path = f"/sys/fs/cgroup/system.slice/docker-{long_id}.scope"

    for attempt in range(max_retries):
        if os.path.exists(cgroup_path):
            break
        if attempt < max_retries - 1:
            print(f"\033[93m[Retry] 等待 cgroup 就绪: {name} (第{attempt+1}次)\033[0m")
            time.sleep(interval)
    else:
        print(f"\033[91m[Error] cgroup 路径不存在: {cgroup_path}，映射添加失败！\033[0m")
        return

    inode = os.stat(cgroup_path).st_ino
    key = ct.c_uint64(inode)
    value = ContainerInfo()
    value.name = name.encode('utf-8')
    b["container_map"][key] = value
    print(f"\033[92m[Sync+] 容器启动: {name} -> inode {inode} (0x{inode:x})\033[0m")

def del_container_by_name(name):
    deleted = False
    for key in list(b["container_map"].keys()):
        val = b["container_map"].get(key)
        if val is None:
            continue
        try:
            val_name = bytes(val.name).split(b'\x00')[0].decode('utf-8')
        except Exception:
            continue
        if val_name == name:
            del b["container_map"][key]
            print(f"\033[91m[Sync-] 容器停止: {name} -> inode {key.value} (0x{key.value:x})\033[0m")
            deleted = True
            break
    return deleted

# ==================== 3. 启动时全量同步 ====================
def sync_container_map():
    client = docker.from_env()
    for container in client.containers.list():
        long_id = container.id
        name = container.name
        cgroup_path = f"/sys/fs/cgroup/system.slice/docker-{long_id}.scope"
        if not os.path.exists(cgroup_path):
            continue
        inode = os.stat(cgroup_path).st_ino
        key = ct.c_uint64(inode)
        value = ContainerInfo()
        value.name = name.encode('utf-8')
        b["container_map"][key] = value
        print(f"\033[92m[Sync] {name} -> inode {inode} (0x{inode:x})\033[0m")

# ==================== 4. 后台线程：监听 Docker Event ====================
def listen_docker_events():
    client = docker.from_env()
    print("[*] 开始监听 Docker 事件...")
    for event in client.events(decode=True):
        if event.get('Type') != 'container':
            continue

        # 关键修复：兼容不同 docker-py / API 版本（status vs Action）
        status = event.get('status') or event.get('Action')
        if not status:
            continue

        actor = event.get('Actor', {})
        cid = actor.get('ID', '')
        attrs = actor.get('Attributes', {})
        name = attrs.get('name', 'unknown')

        if status in ('start', 'restart'):
            try:
                container = client.containers.get(cid)
                add_container_to_map(container)
            except Exception as e:
                print(f"\033[91m[Error] 处理 {status} 事件失败 ({name}): {e}\033[0m")

        elif status in ('die', 'destroy', 'stop'):
            del_container_by_name(name)

# ==================== 5. 启动 ====================
sync_container_map()
event_thread = threading.Thread(target=listen_docker_events, daemon=True)
event_thread.start()

# ==================== 6. 面板输出 ====================
EVENT_EXECVE = 1
EVENT_OPENAT = 2
EVENT_CONNECT = 3

def ip_int_to_str(ip_int):
    return f"{(ip_int>>24)&0xFF}.{(ip_int>>16)&0xFF}.{(ip_int>>8)&0xFF}.{ip_int&0xFF}"

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(DataT)).contents
    try:
        cg_name = event.container_name.decode()
        if cg_name != "[HOST]":
            cg_color = "\033[92m"
        else:
            cg_color = "\033[94m"
        base_info = f"{cg_color}{cg_name:16s}\033[0m PID={event.pid:6d} UID={event.uid:5d}"

        if event.type == EVENT_EXECVE:
            cmd = event.data.filename.decode('utf-8', errors='ignore')
            cmd_name = cmd.split('/')[-1]
            if cmd_name in ['nc', 'curl', 'wget', 'nmap', 'chmod']:
                print(f"{base_info} \033[91mCOMM={event.comm.decode('utf-8', errors='ignore'):16s} → CMD={cmd} ⚠️ SUSPICIOUS\033[0m")
            else:
                print(f"{base_info} COMM={event.comm.decode('utf-8', errors='ignore'):16s} → CMD={cmd}")
        elif event.type == EVENT_OPENAT:
            path = event.data.filename.decode('utf-8', errors='ignore')
            if any(x in path for x in ['shadow', 'passwd', 'id_rsa', 'kcore']):
                print(f"{base_info} \033[91mCOMM={event.comm.decode('utf-8', errors='ignore'):16s} → OPEN={path} ⚠️ SENSITIVE\033[0m")
            else:
                print(f"{base_info} COMM={event.comm.decode('utf-8', errors='ignore'):16s} → OPEN={path}")
        elif event.type == EVENT_CONNECT:
            daddr = ip_int_to_str(event.data.daddr)
            dport = htons(event.data.dport)
            print(f"{base_info} COMM={event.comm.decode('utf-8', errors='ignore'):16s} → CONNECT={daddr}:{dport}")
    except Exception as e:
        print(f"\033[91m[Error] 解析事件失败: {e}\033[0m")

b["events"].open_perf_buffer(print_event)
print("\n🛡️ 容器运行时安全监控已启动，按 Ctrl-C 停止")
print("="*60)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
