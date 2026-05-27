# Six、容器感知与身份识别：从内核 Cgroup 到 Docker 映射

date: 2026.5.27

上篇结尾，我们用尾调用搭建了多探针架构，解决了“代码怎么拆”的问题。但留下了一个致命的盲区：**当探针在内核里抓到一条 `execve` 时，它根本不知道这条命令是宿主机发出的，还是某个容器发出的。**

在云原生环境里，没有身份归属的事件，就是无效告警。这就好比监控录像拍到了小偷，但画面全是马赛克——没用。

这篇，我们放慢脚步，给 eBPF 探针装上“夜视仪”。**不碰 K8s，不碰 runc，就用你最熟悉的 Docker，从内核底层把容器的“身份证”给扒出来。**

## 核心内容结构

```text
1. 容器隔离的内核解剖：Namespace 与 Cgroup
2. eBPF 第一把钥匙：bpf_get_current_cgroup_id()
3. eBPF 第二把钥匙：获取 Namespace ID（伏笔）
4. 工程化：构建“Cgroup ID -> 容器名”的映射表
5. 实战：带容器身份的 execve 监控
```

## 一、用 Pwn 手的思维看容器：隔离的边界

以前玩 Pwn，我们关心的是怎么越界；现在搞容器安全，我们得先搞清楚**边界在哪**。

### 1. Namespace：视图的隔离（chroot 的究极加强版）

容器觉得自己是独立的主机，全靠 Namespace 骗它。

**实验：对比 Namespace ID**

打开宿主机终端：

```bash
ls -la /proc/self/ns
```

![image-20260527121457790](https://raw.githubusercontent.com/Chenjx12/PicGO/main/img/20260527121506803.png)

启动一个 Docker 容器并查看：

```bash
docker run -itd --name test_ns ubuntu:22.04
docker exec test_ns ls -la /proc/self/ns
```

![image-20260527121542006](https://raw.githubusercontent.com/Chenjx12/PicGO/main/img/20260527121543727.png)

发现了吗？`pid:[...]` 里的数字完全不同！这就是容器隔离的本质——**在内核里给进程分配了不同的虚拟空间 ID**。

但是，`user:[4026531837]` 宿主机和容器完全一样！

这意味着 **User Namespace 没有被隔离**。容器里的 UID 0 (root)，在内核的权限检查中，等同于宿主机的 UID 0。

不过，容器内的 root ≠ 宿主机的全知全能 root。

Docker 在创建容器时，虽然进程 UID 是 0，但**剥夺了大部分 Linux Capabilities**（如 `CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`）。你可以验证：

```bash
# 宿主机 PID 1 的 capabilities（几乎全开）
chenjx12@learning-ebpf:~/Desktop$ cat /proc/1/status | grep Cap
CapInh:	0000000000000000
CapPrm:	000001ffffffffff
CapEff:	000001ffffffffff  ← 41 个 capability，几乎全开
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000

# 容器内 PID 1 的 capabilities（被大幅削减）
chenjx12@learning-ebpf:~/Desktop$ docker exec test_ns cat /proc/1/status | grep Cap
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb   ← 14 个 capability，被砍了 66%
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

解码对比：

| Capability           | 宿主机 | 容器 | 含义                     |
| -------------------- | ------ | ---- | ------------------------ |
| CAP_CHOWN            | ✅      | ✅    | 修改文件所有者           |
| CAP_SETUID           | ✅      | ✅    | 切换用户身份             |
| CAP_NET_BIND_SERVICE | ✅      | ✅    | 绑定 1024 以下端口       |
| **CAP_SYS_ADMIN**    | ✅      | ❌    | **内核管理的"万能钥匙"** |
| **CAP_SYS_PTRACE**   | ✅      | ❌    | **进程注入/调试**        |
| **CAP_SYS_MODULE**   | ✅      | ❌    | **加载内核模块**         |
| **CAP_NET_ADMIN**    | ✅      | ❌    | **修改网络配置**         |
| **CAP_SYS_RAWIO**    | ✅      | ❌    | **直接操作硬件端口**     |
| **CAP_SYS_BOOT**     | ✅      | ❌    | **重启系统**             |
| CAP_BPF              | ✅      | ❌    | **加载 eBPF 程序**       |

所以，**准确的说法是**：

- **身份上**：容器进程在内核眼里是 UID 0，文件权限检查当 root 对待。
- **权限上**：能力被阉割，做不了挂载、内核模块操作等高危动作。
- **逃逸后**：攻击者如果突破 Namespace 限制，他带出来的身份是 **UID 0 + 受限的 Capabilities**。虽然不是完整的 root，但权限依然极高，且可通过其他漏洞恢复能力。

#### 暗门：`docker` 组等于 root 组

我们刚才说了，容器内的 root 受 Capabilities 限制，权限被阉割。但有一个更隐蔽的特权：如果你把普通用户加入了 `docker` 组，那他虽然 UID 还是 1000，但实际上已经拥有了系统的最高控制权。

**原因**：Docker 守护进程是以 root (UID 0) 身份运行的。加入 docker 组，意味着你可以通过套接字指挥这个 root 进程做任何事。

**验证**：只需一条命令，普通用户就能拿到 root shell：

```bash
docker run -it -v /:/host ubuntu:22.04 chroot /host
```

在安全评估中，`docker` 组等价于无密码的 `sudo`。

**正因为这种“身份高但权限受限”的脆弱平衡，我们才需要 eBPF 在内核层做更细粒度的监控——不能只看 UID，还要看它到底干了什么。**

此时，eBPF 探针抓到的“凶手”是容器内的 UID 0 进程，而不是发起命令的 UID 1000 用户！

这就是云原生安全监控的“幽暗地带”：**传统的基于 UID 的审计失效了，我们需要把“宿主机用户的指令”和“容器进程的行为”关联起来。** 这正是我们构建后续 Cgroup ID 映射表的意义——给每一个内核事件打上“容器身份”的标签，才能顺藤摸瓜揪出幕后黑手。



### 2. Cgroup：资源的限制与“绝对坐标”

Namespace 是“你只能看这些”，Cgroup 则是“你只能用这些”。但对我们做监控来说，Cgroup 有一个更致命的诱惑：**它是容器在内核文件系统里的“绝对坐标”。**

**实验：解剖 Docker 的 Cgroup 路径**

1. 查看容器的长 ID：

```bash
docker inspect test_ns | grep Id
# 输出： "Id": "a3e2f1...7c8",
chenjx12@learning-ebpf:~/Desktop$ docker inspect test_ns | grep Id
        "Id": "af153cfbefba9f435068572ffd9483a620ff057b375397d7eb2f505a825a2338",
```

2. 在宿主机的 Cgroup 树里找它（Ubuntu 22.04 默认是 Cgroup v2）：

```bash
ls /sys/fs/cgroup/system.slice/docker-a3e2f1...7c8.scope/
# 你会看到 cgroup.procs, cpu.max 等文件
注意！docker-后面跟的一长串是刚刚命令得到的 <长ID>
```

![image-20260527122339392](https://raw.githubusercontent.com/Chenjx12/PicGO/main/img/20260527122342160.png)

**核心洞察**：每个 Docker 容器，在内核的 Cgroup 树上，都挂着一个唯一的 `.scope` 节点。只要我们能拿到当前进程挂载在哪个节点，就能反推出它是哪个容器！

至于具体怎么用，咱往后看。

## 二、eBPF 第一把钥匙：`bpf_get_current_cgroup_id()`

有了坐标，怎么让 eBPF 看见？内核提供了一个专门看 Cgroup 的 Helper 函数。

### 1. 原理与坑点

`bpf_get_current_cgroup_id()` 返回当前进程所在 Cgroup 的 **Inode ID**（一个 `u64` 数字）。

**⚠️ Cgroup v1 vs v2 的天坑：**

- Cgroup v1：按控制器分家（cpu 一棵树，memory 一棵树），同一个容器在不同树里的 Inode 不一样，极其难搞。
- **Cgroup v2**：大一统！所有控制器在一棵树下，一个容器只有一个 Inode。**Ubuntu 22.04 默认就是 v2，简直是天赐良机！**

### 2. 实验：给 execve 探针加上 Cgroup ID

基于第四篇 C/Python 分离的架构，我们修改 C 代码。

**创建 `06-container/container-aware.c`：**

```c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 1. 事件结构体：新增 cgroup_id
struct data_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;  //  容器的“身份证号”
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};
    
    // 2. 获取公共信息
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    
    // 3. 获取当前进程的 Cgroup ID
    data.cgroup_id = bpf_get_current_cgroup_id();
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
```

**创建 `06-container/container-aware.py`：**

```python
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
```

### 3. 运行与验证

准备三个终端

**终端 A：运行监控**

```bash
sudo python3 container-aware.py
```

**终端 B：宿主机执行命令**

```bash
ls
# 预期输出：CG=0x...fa01 PID=12345 UID=1000 COMM=bash → CMD=/usr/bin/ls
CG=0x3716             PID=  7392 UID= 1000 COMM=bash             → CMD=/usr/bin/ls
```

**终端 C：Docker 容器执行命令**

```bash
docker exec test_ns ls
# 预期输出：CG=0x...1234 PID=54321 UID=0    COMM=docker → CMD=/bin/ls
CG=0x3a56             PID=  7365 UID= 1000 COMM=bash             → CMD=/usr/bin/docker
CG=0x1516             PID=  7373 UID=    0 COMM=containerd-shim  → CMD=/usr/bin/runc
CG=0x1516             PID=  7382 UID=    0 COMM=runc             → CMD=/proc/self/fd/6
CG=0x3740             PID=  7385 UID=    0 COMM=runc:[2:INIT]    → CMD=/usr/bin/ls
```

**为什么一行 `docker exec` 会产生四条事件？**

这四行就是一条**容器进程诞生链**：

```bash
bash (UID 1000, 宿主机 cgroup)
  └→ docker 客户端 (UID 1000, 宿主机 cgroup)
      └→ containerd-shim (UID 0, 系统服务 cgroup)
          └→ runc (UID 0, 系统服务 cgroup)
              └→ runc:[2:INIT] (UID 0, 容器 cgroup ← 0x3740!)
```

因为 eBPF 抓的是**内核级别**的 `execve`，每一步进程切换都逃不掉：

1. `bash → docker`：你的 shell 调用了 docker 客户端（UID 1000，宿主机 Cgroup）
2. `containerd-shim → runc`：Docker 后台服务接管（UID 0，系统服务 Cgroup `0x1516`）
3. `runc:[2:INIT] → ls`：容器内进程正式启动（UID 0，**容器专属 Cgroup `0x3740`**）

只有最后这一行，才是真正在容器内执行的命令。而它的 Cgroup ID `0x3740`，正好等于宿主机 Cgroup 文件系统里该容器 `.scope` 目录的 Inode 号！

**🔍 交叉验证：这串数字到底是啥？**
在终端 B 获取刚才那个 docker 容器的长 ID（比如 `a3e2...`），然后在宿主机执行：

```bash
stat /sys/fs/cgroup/system.slice/docker-<长ID>.scope
# 输出：
#   File: .../docker-a3e2...7c8.scope
#   Size: 0          Blocks: 0          IO Blocks: 4096  directory
# Device: 8,2        Inode: 4663        Links: 1
chenjx12@learning-ebpf:~/Desktop$ stat /sys/fs/cgroup/system.slice/docker-af153cfbefba9f435068572ffd9483a620ff057b375397d7eb2f505a825a2338.scope
  文件：/sys/fs/cgroup/system.slice/docker-af153cfbefba9f435068572ffd9483a620ff057b375397d7eb2f505a825a2338.scope
  大小：0         	块：0          IO 块大小：4096   目录
设备：1ch/28d	Inode：14144       硬链接：2
权限：(0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)
访问时间：2026-05-27 11:28:56.451463566 +0800
修改时间：2026-05-27 11:28:56.451463566 +0800
变更时间：2026-05-27 11:28:56.451463566 +0800
创建时间：-
```

看！`Inode: 14144` 的十六进制 `0x3740`，**正好和 eBPF 抓到的 `CG` 一模一样！** 证据确凿！



## 三、eBPF 第二把钥匙：获取 Namespace ID（为逃逸检测埋伏笔）

只认出容器还不够。**容器逃逸的本质，就是进程打破了 Namespace 的边界。** 我们需要在抓取事件时，顺带记录发起者的 Namespace ID。

内核 5.7+ 提供了一个强大的 Helper：`bpf_get_ns_current_pid_tgid()`。

### 1. 创建 `container-ns.c`

在 `06-container/` 目录下新建文件，把第一把钥匙的代码完整拷过来，再加上 Namespace 获取逻辑：

```
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>        // 补全 nsproxy 结构体定义
#include <linux/pid_namespace.h>  // 补全 pid_namespace 结构体定义

// 1. 事件结构体：新增 pid_ns_inum
struct data_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    u32 pid_ns_inum;  // PID Namespace 的 Inode 号
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};

    // 获取公共信息
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.cgroup_id = bpf_get_current_cgroup_id();

    // 通过 task_struct 深入内核获取 PID Namespace Inode
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // 第1步：读取 nsproxy 指针
    struct nsproxy *nsproxy = NULL;
    bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    if (!nsproxy) goto out;

    // 第2步：读取 pid_namespace 指针
    struct pid_namespace *pid_ns = NULL;
    bpf_probe_read_kernel(&pid_ns, sizeof(pid_ns), &nsproxy->pid_ns_for_children);
    if (!pid_ns) goto out;

    // 第3步：读取 ns.inum (Namespace 的 Inode 号)
    unsigned int inum = 0;
    bpf_probe_read_kernel(&inum, sizeof(inum), &pid_ns->ns.inum);
    data.pid_ns_inum = inum;

out:
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
```

### 2. 创建 `container-ns.py`

同样新建文件，在打印时把 `pid_ns` 也格式化输出：

```
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
```

### 3. 运行与验证

还是三个终端

**终端 A：运行新监控**

```
sudo python3 container-ns.py
```

**终端 B：宿主机执行命令**

```
ls
# 预期输出类似：CG=0x...fa01 NS=0x...e8f1 PID=12345 UID=1000 COMM=bash → CMD=/usr/bin/ls
CG=0x29b6             NS=0xeffffffc         PID=  3648 UID= 1000 COMM=bash             → CMD=/usr/bin/ls
```

**终端 C：Docker 容器执行命令**

```
docker exec test_ns ls
# 预期输出类似：CG=0x3740 NS=0x...a2c3 PID=7385 UID=0 COMM=runc:[2:INIT] → CMD=/usr/bin/ls
CG=0x29e0             NS=0xeffffffc         PID=  3649 UID= 1000 COMM=bash             → CMD=/usr/bin/docker
CG=0x1516             NS=0xeffffffc         PID=  3657 UID=    0 COMM=containerd-shim  → CMD=/usr/bin/runc
CG=0x1516             NS=0xeffffffc         PID=  3665 UID=    0 COMM=runc             → CMD=/proc/self/fd/6
CG=0x2a82             NS=0xf000036f         PID=  3670 UID=    0 COMM=runc:[2:INIT]    → CMD=/usr/bin/ls
```

**🔍 关键观察点：**

对比宿主机和容器的 `NS=` 值：

- 宿主机的 `NS` 值是一个固定的数字（比如 `0xe8f1`）
- 容器内进程的 `NS` 值是**另一个完全不同的数字**（比如 `0xa2c3`）

这就是 Namespace 隔离在 eBPF 眼里的直观体现！

有细心的同学可能会发现，诶，这里的 docker 和容器的 CG 怎么和上面实验不一样了？

因为刚刚我重启了一下虚拟机：

> 重启后的容器会获得一个**新的 Cgroup Inode**！之前第一把钥匙验证的 `0x3740`（Inode: 14144）已经失效了，需要重新 `stat` 一次获取新的值。这也是我们下一篇将要解决"映射表过期"问题的现实原因。



**🔍 交叉验证：这串 Namespace 数字又是啥？**

和 Cgroup 一样，我们也可以在系统里找到这串数字的根源。Namespace 在 Linux 里也是以文件形式存在的（伪文件系统 nsfs）。

在终端 C 执行：

```
# 查看容器内 PID 1 的 PID Namespace
docker exec test_ns ls -la /proc/1/ns/pid
# 输出：
chenjx12@learning-ebpf:~/Desktop$ docker exec test_ns ls -la /proc/1/ns/pid
lrwxrwxrwx 1 root root 0 May 27 06:09 /proc/1/ns/pid -> pid:[4026532719]
```

记住这个数字 `4026532719`，转成十六进制：

```
F000 036F
```

看！`0xf000036f`，**正好和 eBPF 抓到的容器 `NS=` 值一模一样！**

这就是 Namespace 隔离在内核文件系统里的绝对坐标。如果有一天，一个本来应该在 `0xf000036f` 里的进程，它的 `NS` 突然变成了宿主机的 `0xeffffffc`，那不用怀疑——**它越狱（逃逸）了！**



## 四、工程化：构建“Cgroup ID -> 容器名”的映射表

我们拿到了 Inode，但 `0x3740` 给人看毫无意义。eBPF 内核态不能读文件系统，不能调 API，怎么办？

**经典架构：用户态同步状态，内核态高效查询。**

### 1. 内核态：定义映射 Map

在 C 代码里新增一个 Hash Map：

编写 `container-map.c` ：

```
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 容器身份信息
struct container_info {
    char name[64]; // 容器名，如 "happy_nginx"
};

// 键是 cgroup_id (u64)，值是 container_info
BPF_HASH(container_map, u64, struct container_info);

// 修改 data_t，用人类可读的名字代替长字符串
struct data_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    char container_name[64]; // 替换原来的 cgroup_id 展示
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};

    // 1. 获取公共信息
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.cgroup_id = bpf_get_current_cgroup_id();

    // 2. 查询容器身份映射表
    struct container_info *info = container_map.lookup(&data.cgroup_id);
    if (info) {
        // 查到了：打上容器名标签
        bpf_probe_read_kernel_str(&data.container_name, sizeof(data.container_name), info->name);
    } else {
        // 查不到的，就是宿主机进程
        char host[] = "[HOST]";
        bpf_probe_read_kernel_str(&data.container_name, sizeof(host), host);
    }

    // 3. 获取进程名和执行的命令
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);

    // 4. 提交事件到用户态
    events.perf_submit(args, &data, sizeof(data));

    return 0;
}
```

### 2. 用户态：用 Docker SDK 填充 Map

这是本篇最硬核的 Python 代码。我们需要遍历当前运行的 Docker 容器，算出它们的 Cgroup Inode，然后写入 eBPF Map。

**安装 Docker SDK：**

```bash
sudo pip3 install docker
# 注意要 sudo ，这样使用 root 权限执行 py 时才能够找到对应的 SDK
```

对应的 `container-map.py` ：

```
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
```

## 五、实战：带容器身份的 execve 监控

### 完整运行

**终端 A：启动监控**

```
sudo python3 container-map.py
# 预期输出：
# [Sync] test_ns -> inode 4663 (0x1237)
[Sync] test_ns -> inode 10882 (0x2a82)   ← 映射表同步成功！
```

**终端 B：宿主机操作**

```
ls
# 预期输出：CG=[HOST]           PID=12345 UID=1000 COMM=bash → CMD=/usr/bin/ls
CG=[HOST]           PID=  4100 UID= 1000 COMM=bash             → CMD=/usr/bin/ls
```

宿主机的 `bash` 发起了 `ls`，正确标注为 `[HOST]`。

**终端 C：Docker 容器操作**

```
docker exec -it test_ns bash
# 在容器内输入：
cat /etc/hostname
# 预期输出：CG=test_ns          PID=54321 UID=0    COMM=bash → CMD=/bin/cat

CG=[HOST]           PID=  4102 UID= 1000 COMM=bash             → CMD=/usr/bin/docker
CG=[HOST]  PID=4110  UID=0  COMM=containerd-shim  → CMD=/usr/bin/runc
CG=[HOST]  PID=4121  UID=0  COMM=runc             → CMD=/proc/self/fd/7
CG=test_ns PID=4124  UID=0  COMM=runc:[2:INIT]    → CMD=/usr/bin/bash   ← 关键行！
CG=test_ns PID=4131  UID=0  COMM=bash             → CMD=/usr/bin/groups
CG=test_ns PID=4133  UID=0  COMM=bash             → CMD=/usr/bin/dircolors
CG=test_ns PID=4134  UID=0  COMM=bash             → CMD=/usr/bin/cat
```

看到了吗？从 `runc:[2:INIT]` 开始，身份**瞬间切换**成了 `test_ns`！而 `containerd-shim` 和 `runc` 虽然也是 UID 0，但它们属于系统服务 Cgroup，不在容器的 scope 里，所以正确地显示为 `[HOST]`。

### 容器初始化的三条命令

```
CG=test_ns PID=4131  COMM=bash → CMD=/usr/bin/groups
CG=test_ns PID=4133  COMM=bash → CMD=/usr/bin/dircolors
CG=test_ns PID=4134  COMM=bash → CMD=/usr/bin/cat
```

这三条是 `docker exec -it test_ns bash` 启动时，容器内的 `.bashrc` 自动执行的初始化命令。**全被 eBPF 抓得死死的。**

**你的 eBPF 探针，终于不再是个瞎子了！**

## 🔍 交叉验证

我们的映射表说 `test_ns` 的 inode 是 `0x2a82`（十进制 10882），可以验证一下：

```bash
# 确认 inode 一致
stat /sys/fs/cgroup/system.slice/docker-af153cfbefba9f435068572ffd9483a620ff057b375397d7eb2f505a825a2338.scope | grep Inode
```

应该输出 `Inode: 10882`，和 `[Sync]` 里打印的一模一样！

![image-20260527155905826](https://raw.githubusercontent.com/Chenjx12/PicGO/main/img/20260527155907866.png)



## 小结与预告

### 本篇核心收获

1. **内核视角看容器**：Namespace 控制视图，Cgroup 提供绝对坐标。
2. **身份获取双钥匙**：`bpf_get_current_cgroup_id()` 定位容器，`bpf_get_ns_current_pid_tgid()` 追踪隔离边界。
3. **经典工程架构**：用户态调 API 写映射表，内核态查 Map 做标注。

### 第七篇预告

第七篇我们将把第四篇、第五篇和第六篇的能力**全部整合**：

- 用 C/Python 分离架构
- 用尾调用多探针（`execve` / `openat` / `connect`）
- 加入用户态 Docker Event 动态更新（解决重启容器后映射表过期的问题）
- **打造真正的"容器运行时安全监控面板"**

---

## 🔗 相关链接与下一步

**相关代码示例:**
- [`container-aware.c`](../code/06-container/container-aware.c) - 基础Namespace检测
- [`container-aware.py`](../code/06-container/container-aware.py) - Namespace检测Python加载器
- [`container-ns.c`](../code/06-container/container-ns.c) - 完整Namespace ID获取
- [`container-ns.py`](../code/06-container/container-ns.py) - Namespace ID Python加载器
- [`container-map.c`](../code/06-container/container-map.c) - Cgroup Map映射
- [`container-map.py`](../code/06-container/container-map.py) - Cgroup Map Python加载器

**学习笔记:**
- **上一篇**: [Five、eBPF 程序的拆分与组合](./Five、eBPF%20程序的拆分与组合.md)
- **下一篇**: 第七篇(待完成) - 容器运行时安全监控面板
- **相关文档**: [docker 容器环境准备](./docker%20容器环境准备.md)

**常见问题:**
- [FAQ](../FAQ.md) - 包含Namespace编译问题解答(Q14, Q15)
- [项目环境](./项目环境.md) - Ubuntu环境配置

---

*最后更新: 2026-05-27*
