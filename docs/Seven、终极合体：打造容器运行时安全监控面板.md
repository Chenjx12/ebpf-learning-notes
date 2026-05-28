# Seven、终极合体：打造容器运行时安全监控面板

date: 2026.5.28

上篇我们拿到了容器的“身份证”，但留下了一个致命的定时炸弹：**容器一重启，Cgroup Inode 变了，映射表瞬间过期，探针再次变瞎。**

真正的安全监控，必须能感知业务的生命周期。这篇，我们把第四篇的分离架构、第五篇的尾调用多探针、第六篇的容器身份全部整合，再加上**Docker Event 动态感知**，打造一个真正的云原生运行时安全监控 MVP！

## 核心内容结构

```text
1. 架构演进：从“单兵”到“联合作战”
2. 内核态大融合：多探针 + 容器身份
3. 动态生命线：基于 Docker Event 的映射表热更新
4. 面板升级：终端彩色高亮与告警分级
5. 攻防演练：动态捕获容器的异常行为
```

## 一、架构演进：从“单兵”到“联合作战”

我们的架构经历了三次演进：

- **v1.0 (第四篇)**：单探针，C/Python 分离，只能看 `execve`。
- **v2.0 (第五篇)**：多探针尾调用，能看 `execve/openat/connect`，但不知道是谁。
- **v3.0 (第六篇)**：加了 Cgroup 映射，知道是哪个容器了，但映射表会过期。

**v4.0 终极架构**：

```text
┌───────────────────────────────────────────────────┐
│                   用户态 Python                     │
│                                                   │
│  [Docker Event 监听线程] ──(容器启停)──> 更新 eBPF Map │
│                                                   │
│  [Perf Buffer 消费线程] ──(读取事件)──> 终端输出   │
└───────────────────────────────────────────────────┘
                       ↕ (BPF Map / Perf Buffer)
┌───────────────────────────────────────────────────┐
│                   内核态 eBPF                       │
│                                                   │
│  [Entry 探针] ──(尾调用分发)──> [execve 处理器]     │
│                            ──> [openat 处理器]     │
│                            ──> [connect 处理器]    │
│  (所有处理器共享 container_map，查不到就是 [HOST])    │
└───────────────────────────────────────────────────┘
```

## 二、内核态大融合：多探针 + 容器身份

为了实现多探针监控，我最初尝试了 eBPF 理论上最优雅的架构：**尾调用分发**。

### 2.1 尝试架构：尾调用分发（踩坑实录）

基于第五篇的经验，我设计了如下的尾调用架构：入口探针只做分发，具体逻辑由 `PROBE_INDEX` 指定的子函数处理。

为了简化加载逻辑，我们把所有探针逻辑写在一个 C 文件里，用尾调用分发。

`container-tail.c`：

```c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

// 1. 容器身份映射表 (与第六篇一致)
struct container_info {
    char name[64];
};
BPF_HASH(container_map, u64, struct container_info);

// 2. 尾调用映射表
BPF_PROG_ARRAY(prog_array, 10);

// 3. 统一事件结构体 (用枚举区分类型)
enum event_type { EVENT_EXECVE = 1, EVENT_OPENAT = 2, EVENT_CONNECT = 3 };

struct data_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    char container_name[64];
    enum event_type type;
    
    // 联合体节省内存，每次只传一种数据
    union {
        char filename[128];     // for execve & openat
        u32 daddr;              // for connect
        u16 dport;              // for connect
    } data;
};

BPF_PERF_OUTPUT(events);

// 4. 公共函数：打容器标签
static inline void fill_container_info(struct data_t *data) {
    data->cgroup_id = bpf_get_current_cgroup_id();
    struct container_info *info = container_map.lookup(&data->cgroup_id);
    if (info) {
        bpf_probe_read_kernel_str(&data->container_name, sizeof(data->container_name), info->name);
    } else {
        char host[] = "[HOST]";
        bpf_probe_read_kernel_str(&data->container_name, sizeof(host), host);
    }
}

// 5. Entry 探针：只做分发
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.type = EVENT_EXECVE;
    // 尾调用跳转到具体处理器，索引为 1
    prog_array.call(data, 1);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.type = EVENT_OPENAT;
    prog_array.call(data, 2);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct data_t data = {};
    data.type = EVENT_CONNECT;
    prog_array.call(data, 3);
    return 0;
}

// 6. 具体处理器 (注意 BCC 的尾调用处理方式)
PROBE_INDEX(1) // 对应 execve
int handle_execve(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_EXECVE;
    fill_container_info(&data);
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.data.filename, sizeof(data.data.filename), (void *)ctx->si);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

PROBE_INDEX(2) // 对应 openat
int handle_openat(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_OPENAT;
    fill_container_info(&data);

    bpf_probe_read_user_str(&data.data.filename, sizeof(data.data.filename), (void *)ctx->si);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

PROBE_INDEX(3) // 对应 connect
int handle_connect(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_CONNECT;
    fill_container_info(&data);

    struct sock *sk = (struct sock *)ctx->di;
    struct sockaddr_in *sin = (struct sockaddr_in *)ctx->si;
    
    bpf_probe_read_kernel(&data.data.daddr, sizeof(data.data.daddr), &sin->sin_addr.s_addr);
    bpf_probe_read_kernel(&data.data.dport, sizeof(data.data.dport), &sin->sin_port);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
```



**预期很丰满，现实很骨感。** 运行时直接遭遇了 BCC 的编译报错：

```
/virtual/main.c:62:21: error: passing 'struct data_t' to parameter of incompatible type 'void *'
    prog_array.call(data, 1);

/virtual/main.c:104:13: error: expected parameter declarator
PROBE_INDEX(1) // 对应 execve
```

### 2.2 填坑分析：BCC 尾调用的三个天坑

通过查阅 BCC 源码和内核文档，我发现了 BCC 尾调用在当前版本下的致命限制：

1. **上下文传递错误**：底层 `bpf_tail_call()` 的原型要求第二个参数是上下文指针 `ctx`，而 BCC 封装的 `prog_array.call()` 也需要传入 `ctx`。如果错误地传入了自定义的 `data` 结构体，就会触发 `incompatible type 'void *'` 报错。
2. **宏定义缺失**：BCC 在编译期会动态重写函数签名（比如自动插入 `ctx`），但 `PROBE_INDEX` 这个宏在很多发行版的 BCC 中并没有原生支持，导致编译器无法识别，报语法错误。
3. **参数丢失风险**：即使强行绕过编译，由于尾调用是**替换当前栈帧**，入口探针里提取的 `data` 数据，在跳转到子函数后**会全部丢失**！子函数必须重新从 `ctx`（即 `pt_regs` 寄存器）里提取参数，这在 BCC 里极其容易触发 Verifier 报错。

**核心结论**：在 BCC 框架下，尾调用更多是给网络层（XDP/TC）做包转发用的，对于安全监控这种需要提取大量上下文的 tracepoint/kprobe 场景，**尾调用不仅坑多，而且得不偿失。**

### 2.3 最终方案：多探针平铺（最终采用）

既然尾调用在 BCC 里是个大坑，我决定回归最务实的方案：**多探针平铺**。

在安全监控场景下，系统调用的频率（每秒几千次）远未达到内核瓶颈。平铺和尾调用的性能差异几乎测不出来，但代码可读性和开发效率却天差地别。

 `container-monitor.c` ：

```c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

// 1. 容器身份映射表 (与第六篇一致)
struct container_info {
    char name[64];
};
BPF_HASH(container_map, u64, struct container_info);

// 2. 统一事件结构体 (用枚举区分类型)
enum event_type {
    EVENT_EXECVE = 1,
    EVENT_OPENAT = 2,
    EVENT_CONNECT = 3
};

struct data_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    char container_name[64];
    enum event_type type;
    char comm[16];
    // 联合体节省内存，每次只传一种数据
    union {
        char filename[128]; // for execve & openat
        u32 daddr;          // for connect
        u16 dport;          // for connect
    } data;
};

BPF_PERF_OUTPUT(events);

// 3. 公共函数：打容器标签
static inline void fill_container_info(struct data_t *data)
{
    data->cgroup_id = bpf_get_current_cgroup_id();
    struct container_info *info = container_map.lookup(&data->cgroup_id);
    if (info) {
        bpf_probe_read_kernel_str(&data->container_name, sizeof(data->container_name), info->name);
    } else {
        char host[] = "[HOST]";
        bpf_probe_read_kernel_str(&data->container_name, sizeof(host), host);
    }
}

// ========================================================
// 4. 平铺版：直接在探针里处理逻辑，不用尾调用！
// ========================================================

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_EXECVE;
    fill_container_info(&data);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // HOST execve 保留（低频，安全相关）
    // 容器 execve 也保留

    bpf_probe_read_user_str(&data.data.filename, sizeof(data.data.filename), (void *)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_OPENAT;
    fill_container_info(&data);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 内核态过滤：HOST 的 openat 直接丢弃！
    // HOST openat 每秒数万次，是 Perf Buffer 溢出的元凶
    // container_name[0]=='[' 说明是 "[HOST]"，不是容器名
    if (data.container_name[0] == '[') {
        return 0;
    }

    bpf_probe_read_user_str(&data.data.filename, sizeof(data.data.filename), (void *)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_CONNECT;
    fill_container_info(&data);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 内核态过滤：HOST 的 connect 也直接丢弃！
    if (data.container_name[0] == '[') {
        return 0;
    }

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), (void *)args->uservaddr);
    data.data.daddr = sin.sin_addr.s_addr;
    data.data.dport = sin.sin_port;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

```



## 三、动态生命线：基于 Docker Event 的映射表热更新

这是本篇最核心的 Python 代码。我们用后台线程监听 Docker 事件，实现映射表的**增删改**。

`container-monitor.py`：

```python
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
```

## 四、攻防演练：动态捕获异常

现在，见证奇迹的时刻。

**终端 A：启动监控**

```bash
sudo python3 container-monitor.py

# 输出：
[Sync] test_ns -> inode 17556 (0x4494)
🛡️ 容器运行时安全监控已启动，按 Ctrl-C 停止
============================================================
[HOST]           PID= 14898 UID=    0 COMM=dockerd          → CMD=/usr/libexec/docker/docker-init
[*] 开始监听 Docker 事件...
```

**终端 B：重启容器（测试动态更新）**

```bash
docker restart test_ns
# 终端 A 打印：
[HOST]           PID= 14899 UID= 1000 COMM=bash             → CMD=/usr/bin/docker
[HOST]           PID= 14908 UID=    0 COMM=containerd-shim  → CMD=/usr/bin/runc
[HOST]           PID= 14916 UID=    0 COMM=containerd-shim  → CMD=/usr/bin/runc
[HOST]           PID= 14924 UID=    0 COMM=containerd-shim  → CMD=/usr/bin/runc
[HOST]           PID= 14931 UID=    0 COMM=containerd       → CMD=/usr/bin/containerd-shim-runc-v2
[HOST]           PID= 14939 UID=    0 COMM=containerd-shim  → CMD=/usr/bin/runc
[HOST]           PID= 14945 UID=    0 COMM=dockerd          → CMD=/usr/sbin/iptables
[HOST]           PID= 14946 UID=    0 COMM=(spawn)          → CMD=/lib/systemd/systemd-sysctl
[HOST]           PID= 14947 UID=    0 COMM=dockerd          → CMD=/usr/sbin/iptables
[Sync-] 容器停止: test_ns -> inode 17556 (0x4494)
[HOST]           PID= 14953 UID=    0 COMM=containerd       → CMD=/usr/bin/containerd-shim-runc-v2
[HOST]           PID= 14962 UID=    0 COMM=containerd-shim  → CMD=/usr/bin/containerd-shim-runc-v2
[HOST]           PID= 14973 UID=    0 COMM=containerd-shim  → CMD=/usr/bin/runc
[HOST]           PID= 14982 UID=    0 COMM=runc             → CMD=/proc/self/fd/7
[HOST]           PID= 14994 UID=    0 COMM=dockerd          → CMD=/usr/sbin/iptables
[HOST]           PID= 14995 UID=    0 COMM=(spawn)          → CMD=/lib/systemd/systemd-sysctl
[HOST]           PID= 14996 UID=    0 COMM=dockerd          → CMD=/usr/sbin/iptables
[HOST]           PID= 15019 UID=    0 COMM=containerd-shim  → CMD=/usr/bin/runc
[HOST]           PID= 14986 UID=    0 COMM=runc:[2:INIT]    → CMD=/usr/bin/bash
[HOST]           PID= 15024 UID=    0 COMM=bash             → CMD=/usr/bin/groups
[HOST]           PID= 15025 UID=    0 COMM=bash             → CMD=/usr/bin/dircolors
[Sync+] 容器启动: test_ns -> inode 17714 (0x4532)
test_ns          PID= 14986 UID=    0 COMM=bash             → OPEN=/root/.bash_history
test_ns          PID= 14986 UID=    0 COMM=bash             → OPEN=/root/.bash_history
test_ns          PID= 14986 UID=    0 COMM=bash             → OPEN=/root/.inputrc
test_ns          PID= 14986 UID=    0 COMM=bash             → OPEN=/etc/inputrc
[Sync+] 容器启动: test_ns -> inode 17714 (0x4532)
```

**终端 C：在容器内模拟攻击**

```bash
docker exec -it test_ns bash
# 在容器内执行：
cat /etc/shadow
curl http://evil.com
```

**终端 A：监控输出**

```bash
[HOST]           PID= 15257 UID= 1000 COMM=bash             → CMD=/usr/bin/docker
[HOST]           PID= 15266 UID=    0 COMM=containerd-shim  → CMD=/usr/bin/runc
[HOST]           PID= 15276 UID=    0 COMM=runc             → CMD=/proc/self/fd/7
test_ns          PID= 15279 UID=    0 COMM=runc:[2:INIT]    → OPEN=/proc/filesystems
test_ns          PID= 15279 UID=    0 COMM=runc:[2:INIT]    → OPEN=/dev/pts/ptmx
test_ns          PID= 15279 UID=    0 COMM=runc:[2:INIT]    → OPEN=8
test_ns          PID= 15279 UID=    0 COMM=runc:[2:INIT]    → OPEN=/etc/passwd ⚠️ SENSITIVE
test_ns          PID= 15279 UID=    0 COMM=runc:[2:INIT]    → OPEN=/proc/sys/kernel/cap_last_cap
test_ns          PID= 15279 UID=    0 COMM=runc:[2:INIT]    → OPEN=3
test_ns          PID= 15279 UID=    0 COMM=runc:[2:INIT]    → OPEN=3
test_ns          PID= 15279 UID=    0 COMM=runc:[2:INIT]    → OPEN=3
test_ns          PID= 15279 UID=    0 COMM=runc:[2:INIT]    → CMD=/usr/bin/bash
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/etc/ld.so.cache
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/lib/x86_64-linux-gnu/libtinfo.so.6
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/lib/x86_64-linux-gnu/libc.so.6
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=
test_ns          PID= 15279 UID=    0 COMM=bash             → CONNECT=114.47.118.47:12150
test_ns          PID= 15279 UID=    0 COMM=bash             → CONNECT=114.47.118.47:12150
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/etc/nsswitch.conf
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/etc/passwd ⚠️ SENSITIVE
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/lib/terminfo/x/xterm
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/etc/bash.bashrc
test_ns          PID= 15285 UID=    0 COMM=bash             → CMD=/usr/bin/groups
test_ns          PID= 15285 UID=    0 COMM=groups           → OPEN=/etc/ld.so.cache
test_ns          PID= 15285 UID=    0 COMM=groups           → OPEN=/lib/x86_64-linux-gnu/libc.so.6
test_ns          PID= 15285 UID=    0 COMM=groups           → CONNECT=114.47.118.47:12150
test_ns          PID= 15285 UID=    0 COMM=groups           → CONNECT=114.47.118.47:12150
test_ns          PID= 15285 UID=    0 COMM=groups           → OPEN=/etc/nsswitch.conf
test_ns          PID= 15285 UID=    0 COMM=groups           → OPEN=/etc/group
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/root/.bashrc
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/root/.bash_history
test_ns          PID= 15286 UID=    0 COMM=bash             → CMD=/usr/bin/dircolors
test_ns          PID= 15286 UID=    0 COMM=dircolors        → OPEN=/etc/ld.so.cache
test_ns          PID= 15286 UID=    0 COMM=dircolors        → OPEN=/lib/x86_64-linux-gnu/libc.so.6
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/root/.bash_history
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/root/.bash_history
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/root/.inputrc
test_ns          PID= 15279 UID=    0 COMM=bash             → OPEN=/etc/inputrc
test_ns          PID= 15287 UID=    0 COMM=bash             → CMD=/usr/bin/cat
test_ns          PID= 15287 UID=    0 COMM=cat              → OPEN=/etc/ld.so.cache
test_ns          PID= 15287 UID=    0 COMM=cat              → OPEN=/lib/x86_64-linux-gnu/libc.so.6
test_ns          PID= 15287 UID=    0 COMM=cat              → OPEN=/etc/shadow ⚠️ SENSITIVE
test_ns          PID= 15288 UID=    0 COMM=bash             → CMD=/usr/bin/curl ⚠️ SUSPICIOUS
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/etc/ld.so.cache
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libcurl.so.4
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libz.so.1
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libc.so.6
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libnghttp2.so.14
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libidn2.so.0
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/librtmp.so.1
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libssh.so.4
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libpsl.so.5
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libssl.so.3
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libcrypto.so.3
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libgssapi_krb5.so.2
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libldap-2.5.so.0
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/liblber-2.5.so.0
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libzstd.so.1
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libbrotlidec.so.1
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libunistring.so.2
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libgnutls.so.30
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libhogweed.so.6
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libnettle.so.8
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libgmp.so.10
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libkrb5.so.3
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libk5crypto.so.3
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libcom_err.so.2
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libkrb5support.so.0
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libsasl2.so.2
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libbrotlicommon.so.1
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libp11-kit.so.0
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libtasn1.so.6
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libkeyutils.so.1
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libresolv.so.2
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/lib/x86_64-linux-gnu/libffi.so.8
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/usr/lib/ssl/openssl.cnf
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/root/.curlrc
test_ns          PID= 15288 UID=    0 COMM=curl             → CONNECT=114.47.118.47:12150
test_ns          PID= 15288 UID=    0 COMM=curl             → CONNECT=114.47.118.47:12150
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/etc/nsswitch.conf
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/etc/passwd ⚠️ SENSITIVE
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/root/.curlrc
test_ns          PID= 15288 UID=    0 COMM=curl             → CONNECT=114.47.118.47:12150
test_ns          PID= 15288 UID=    0 COMM=curl             → CONNECT=114.47.118.47:12150
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/etc/host.conf
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/etc/resolv.conf
test_ns          PID= 15288 UID=    0 COMM=curl             → OPEN=/etc/hosts
test_ns          PID= 15288 UID=    0 COMM=curl             → CONNECT=2.65.53.0:53
test_ns          PID= 15288 UID=    0 COMM=curl             → CONNECT=2.65.53.0:53
test_ns          PID= 15288 UID=    0 COMM=curl             → CONNECT=2.65.53.0:53
test_ns          PID= 15288 UID=    0 COMM=curl             → CONNECT=2.65.53.0:53
```

**即使容器经历了重启，探针依然精准地打上了 `test_ns` 的标签，并且对敏感文件读取和黑客工具发起了红色告警！**

## 第七篇的关键点与避坑指南

1. **BCC 尾调用传参**：BCC 的尾调用传参是个大坑，由于上下文切换，`args->filename` 不能直接在子程序用，必须用 `pt_regs` 从寄存器里取。如果 Verifier 疯狂报错，**最务实的做法是放弃尾调用，把三个探针的逻辑平铺写在一个 C 文件里**（性能损失微乎其微，代码可读性反而更高）。
2. **Docker Event 延迟**：`die` 事件触发时，Cgroup 目录可能已经被内核删了，所以删除 Map 时，**不能靠 `stat` 算 inode，必须靠容器名匹配**，这是上面代码用遍历删除的原因。
3. **字节序问题**：网络事件中的 IP 和端口，IP 用移位转成字符串，端口记得用 `htons()` 转字节序，否则端口会错位（比如 80 变成 20480）。

这篇代码量是最大的，跑通之后，我们就拥有了一个可以写进简历的"云原生运行时安全监控 MVP"！

---

## 🔗 相关链接与下一步

**相关代码示例:**
- [`container-monitor.c`](../code/07-monitor/container-monitor.c) - 完整监控面板C代码
- [`container-monitor.py`](../code/07-monitor/container-monitor.py) - 完整监控面板Python加载器
- [`container-tail.c`](../code/07-monitor/container-tail.c) - Tail Call版本监控
- [`container-monitor-broken-sdk.py`](../code/07-monitor/container-monitor-broken-sdk.py) - SDK问题演示

**学习笔记:**
- **上一篇**: [Six、容器感知与身份识别：从内核到云原生](./Six、容器感知与身份识别：从内核到云原生.md)
- **下一篇**: 待规划(第八篇及后续方向)

**相关文档**: 
- [docker 容器环境准备](./docker%20容器环境准备.md)
- [eBPF 常用字典](./eBPFBPF%20常用字典.md)

**常见问题:**
- [FAQ](../FAQ.md) - 包含监控面板相关问题解答
- [项目环境](./项目环境.md) - Ubuntu环境配置

---

*最后更新: 2026-05-27*
