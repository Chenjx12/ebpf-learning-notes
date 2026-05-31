# eBPF 示例代码 (第三篇: Hello World)

本目录包含从学习笔记中提取的可运行 eBPF 示例代码。

**对应笔记**: [Three、eBPF 的 Hello World](../../docs/One-实践/三、eBPF%20的%20Hello%20%20World.md)

## 📂 文件列表

| 文件名 | 说明 | 难度 | 推荐顺序 |
|--------|------|------|---------|
| [hello-world.py](./hello-world.py) | ⭐ [基础Hello World,监控execve](./hello-world.py) | ⭐ | 1️⃣ |
| [hello-openat.py](./hello-openat.py) | ⭐ [监控openat系统调用](./hello-openat.py) | ⭐ | 2️⃣ |
| [hello-map.py](./hello-map.py) | ⭐⭐ [使用Hash Map统计UID执行次数](./hello-map.py) | ⭐⭐ | 3️⃣ |
| [hello-perf.py](./hello-perf.py) | ⭐⭐⭐ [使用Perf Buffer传递结构化事件](./hello-perf.py) | ⭐⭐⭐ | 4️⃣ |
| [hello-ring.py](./hello-ring.py) | ⭐⭐⭐ [使用Ring Buffer(推荐)](./hello-ring.py) | ⭐⭐⭐ | 5️⃣ |
| [hello-perf-plus.py](./hello-perf-plus.py) | ⭐⭐⭐⭐ [使用Tracepoint获取完整命令路径](./hello-perf-plus.py) | ⭐⭐⭐⭐ | 6️⃣ |

## 🚀 快速开始

### 前置要求

```bash
# 确认 BCC 已安装
sudo python3 -c "from bcc import BPF; print('BCC OK')"

# 如果未安装,参考项目根目录的 setup.sh
```

### 运行示例

```bash
# 1. 从最简单的开始
sudo python3 hello-world.py

# 2. 在新终端执行一些命令观察输出
ls
ps aux

# 3. 按 Ctrl-C 停止监控
```

## 📖 详细说明

### 1. hello-world.py - 基础 Hello World

**功能**: 监控 execve 系统调用,在内核 trace_pipe 中输出消息

**核心概念**:
- kprobe (内核函数探针)
- bpf_trace_printk (内核调试输出)
- attach_kprobe (挂钩系统调用)

**运行方式**:
```bash
sudo python3 hello-world.py
```

---

### 2. hello-openat.py - 监控文件打开操作

**功能**: 监控 openat 系统调用,比 execve 更频繁

**核心概念**:
- 不同系统调用的监控
- 理解系统调用频率差异

**运行方式**:
```bash
sudo python3 hello-openat.py
```

---

### 3. hello-map.py - 使用 Hash Map 统计

**功能**: 在内核中维护 uid -> count 哈希表,每2秒轮询一次

**核心概念**:
- BPF_HASH (哈希表映射)
- 用户态与内核态数据交换
- 轮询机制

**运行方式**:
```bash
sudo python3 hello-map.py
```

**预期输出**（仅示例）:

```
ID 1000: 8        ← UID 1000 执行了 8 次 execve
ID 1000: 14       ← 2秒后变成 14 次
ID 1000: 16  ID 0: 1   ← 出现 root (UID 0)
```

---

### 4. hello-perf.py - 使用 Perf Buffer

**功能**: 实时推送完整的事件信息(PID, UID, 进程名, 时间戳)

**核心概念**:
- BPF_PERF_OUTPUT (性能缓冲区)
- perf_submit (推送事件)
- 回调函数处理
- 结构化数据传输

**运行方式**:
```bash
sudo python3 hello-perf.py
```

**预期输出**（仅示例）:

```
PID=  4571 UID= 1000 COMM=bash             TS=8483481047509
PID=  4572 UID= 1000 COMM=bash             TS=8492034938577
```

---

### 5. hello-ring.py - 使用 Ring Buffer (推荐)

**功能**: 与 Perf Buffer 类似,但所有 CPU 共享缓冲区,保证全局有序

**核心概念**:
- BPF_RINGBUF_OUTPUT (环形缓冲区)
- ringbuf_output (推送事件)
- 全局事件顺序保证
- 内存效率优化

**运行方式**:
```bash
sudo python3 hello-ring.py
```

**优势**:
- ✅ 全局有序
- ✅ 内存更高效
- ✅ 支持检测数据丢失
- ✅ 新项目首选

---

### 6. hello-perf-plus.py - 使用 Tracepoint

**功能**: 使用 tracepoint 获取被执行的完整命令路径

**核心概念**:
- TRACEPOINT_PROBE (静态追踪点)
- bpf_probe_read_user_str (安全读取用户态字符串)
- 区分"谁发起的"(comm)和"执行了什么"(filename)

**运行方式**:
```bash
sudo python3 hello-perf-plus.py
```

**预期输出**（仅示例）:
```
PID=  4762 UID= 1000 CALLER=bash             → CMD=/usr/bin/ls
PID=  4766 UID= 1000 CALLER=bash             → CMD=/usr/bin/sudo
PID=  4768 UID=    0 CALLER=sudo             → CMD=/usr/bin/su
```

---

## 🔍 常见问题

### Q1: 为什么需要 sudo 权限?

eBPF 程序运行在内核态,需要 root 权限才能加载和执行。

### Q2: 如何查看 trace_pipe 输出?

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Q3: Perf Buffer 和 Ring Buffer 有什么区别?

| 特性 | Perf Buffer | Ring Buffer |
|------|-------------|-------------|
| 内核版本要求 | 4.4+ | 5.8+ |
| 缓冲区结构 | 每CPU各一个 | 所有CPU共享一个 |
| 事件顺序 | 可能乱序 | 全局有序 |
| 推荐度 | 老内核兼容 | 新项目首选 |

### Q4: 为什么有些程序的 COMM 显示的是 bash?

kprobe 挂钩在 execve 入口时,子进程的 comm 还未被替换,仍显示为父进程的名称(bash)。要获取被执行的命令,需要使用 tracepoint 并读取 filename 参数。

---

## 📖 相关文档

- **学习笔记**: [Three、eBPF 的 Hello World](../../docs/One-实践/三、eBPF%20的%20Hello%20%20World.md)
- **常见问题**: [FAQ](../../FAQ.md)
- **环境配置**: [项目环境](../../docs/项目环境.md)
- **第四篇笔记**: [Four、eBPF 程序的解剖与工程化](../../docs/One-实践/四、eBPF%20程序的解剖与工程化.md) (C/Python分离)

---

*最后更新: 2026-05-24*

## 💡 学习建议

1. **循序渐进**: 从 hello-world.py 开始,逐步深入
2. **动手实践**: 每个示例都亲自运行一遍
3. **观察输出**: 对比不同示例的输出特点
4. **修改代码**: 尝试修改参数,观察变化
5. **阅读源码**: 理解 BCC 框架的工作原理

---

*祝学习愉快! 🚀*
