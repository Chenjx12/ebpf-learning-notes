# eBPF 容器运行时安全监控面板 (第七篇)

本目录包含第七篇文章相关的实验代码,展示如何整合前面所有知识,**打造完整的容器运行时安全监控系统**。

**对应笔记**: [Seven、终极合体:打造容器运行时安全监控面板](../../docs/One-实践/七、终极合体：打造容器运行时安全监控面板.md)

## 📂 文件列表

| 文件名 | 说明 | 难度 | 推荐顺序 |
|--------|------|------|---------|
| [container-monitor.c](./container-monitor.c) | 🔥 [完整监控面板C代码](./container-monitor.c) | ⭐⭐⭐⭐⭐ | 1️⃣ |
| [container-monitor.py](./container-monitor.py) | 🐍 [完整监控面板Python加载器](./container-monitor.py) | ⭐⭐⭐⭐⭐ | 1️⃣ |
| [container-tail.c](./container-tail.c) | 🔥 [Tail Call版本监控](./container-tail.c) | ⭐⭐⭐⭐⭐ | 2️⃣ |
| [container-monitor-broken-sdk.py](./container-monitor-broken-sdk.py) | 🐛 [SDK问题演示](./container-monitor-broken-sdk.py) | ⭐⭐⭐ | 3️⃣ |

---

## 🚀 快速开始

### 前置要求

```bash
# 确认 BCC 已安装
sudo python3 -c "from bcc import BPF; print('BCC OK')"

# 确认 Docker 已安装并运行
docker ps

# 确认内核版本支持所有特性 (≥ 5.8 推荐)
uname -r
```

---

### 运行示例

#### **1. 完整监控面板(推荐)**

```bash
# 启动完整版本的容器监控面板
sudo python3 container-monitor.py
```

**核心功能**:
- ✅ 多探针整合(execve/openat/connect)
- ✅ 动态Docker事件监听
- ✅ 自动更新容器映射表
- ✅ Ring Buffer全局有序传递
- ✅ 实时显示和过滤
- ✅ 容器身份精准识别

**观察输出**:
```
=================================================================
         容器运行时安全监控面板 v1.0
=================================================================
[INFO] 启动 Docker 事件监听器...
[INFO] 检测到容器: nginx-container (ID: af153cfbefba...)
[INFO] 映射表更新: Cgroup 10882 -> nginx-container
[INFO] 开始监控容器活动...

TIME                 CONTAINER          PID    EVENT     DETAILS
2026-05-27 16:00:01  nginx-container    4567   execve    /usr/bin/bash
2026-05-27 16:00:02  nginx-container    4567   openat    /etc/nginx/nginx.conf
2026-05-27 16:00:03  redis-container    5678   connect   10.0.0.1:6379
```

---

#### **2. Tail Call 版本(高级特性)**

```bash
# 使用Tail Call实现程序链式调用
sudo python3 -c "
from bcc import BPF
b = BPF(src_file='container-tail.c')
# ... 配置Tail Call映射表
"
```

**特点**:
- ✅ 使用Tail Call实现模块化
- ✅ 程序间通过tail_call跳转
- ✅ 避免栈深度限制
- ✅ 更灵活的架构

---

#### **3. Broken SDK 演示(学习调试)**

```bash
# 查看常见错误示例
python3 container-monitor-broken-sdk.py
```

**教学目的**:
- ❌ 演示常见的SDK使用错误
- ❌ 展示Map访问的陷阱
- ❌ 帮助理解底层机制

---

## 📖 核心架构

### **整体设计**

```
┌─────────────────────────────────────────────────────────┐
│                   用户态控制平面                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Docker SDK   │  │ 映射表管理   │  │ 显示引擎     │  │
│  │ 事件监听     │→ │ 动态更新     │→ │ 实时刷新     │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                          ↕ Map 同步
┌─────────────────────────────────────────────────────────┐
│                   内核态数据平面                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ execve探针   │  │ openat探针   │  │ connect探针  │  │
│  │ kprobe       │  │ kprobe       │  │ kprobe       │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│         ↓                ↓                ↓              │
│  ┌──────────────────────────────────────────────────┐   │
│  │         Ring Buffer (全局有序)                    │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

### **关键技术点**

#### **1. 多探针整合**

**execve探针**:
```c
// 捕获进程启动
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    // 提取命令路径和参数
    // 识别容器身份
    // 发送到Ring Buffer
}
```

**openat探针**:
```c
// 捕获文件访问
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    // 提取文件路径
    // 检测敏感文件访问
    // 关联容器身份
}
```

**connect探针**:
```c
// 捕获网络连接
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    // 提取目标IP和端口
    // 检测异常连接
    // 关联容器身份
}
```

---

#### **2. 动态映射表管理**

**Docker事件监听**:
```python
import docker
client = docker.from_env()

# 监听容器启动/停止事件
for event in client.events(decode=True):
    if event['Action'] == 'start':
        # 获取容器信息
        container = client.containers.get(event['id'])
        # 提取Cgroup Inode
        # 更新BPF Map
```

**Map更新**:
```python
# 建立 Cgroup ID -> 容器名 映射
bpf_map[ct.c_ulonglong(cgroup_inode)] = container_name.encode()
```

---

#### **3. Ring Buffer事件传递**

**优势**:
- ✅ 全局有序(单生产者单消费者)
- ✅ 内存高效(环形缓冲区)
- ✅ 低延迟(无锁设计)

**使用**:
```c
struct ring_buffer *rb;
rb = ring_buffer__new(bpf_map_fd, event_callback, NULL, NULL);
while (1) {
    ring_buffer__poll(rb, 1000);  // 1秒超时
}
```

---

## 💡 学习建议

1. **先理解架构**: 这是前面六篇知识的集大成者
2. **重点看整合**: 如何将Namespace、Cgroup、多探针组合
3. **实践动态映射**: Docker事件监听是核心创新点
4. **对比Tail Call**: 理解两种实现方式的优劣

---

## 🔗 相关文档

- **学习笔记**: [Seven、终极合体:打造容器运行时安全监控面板](../../docs/One-实践/七、终极合体：打造容器运行时安全监控面板.md)
- **第六篇笔记**: [Six、容器感知与身份识别](../../docs/One-实践/六、容器感知与身份识别：从内核到云原生.md) (前置知识)
- **第五篇笔记**: [Five、eBPF 程序的拆分与组合](../../docs/One-实践/五、eBPF%20程序的拆分与组合.md) (Tail Call基础)
- **常见问题**: [FAQ](../FAQ.md)
- **Docker环境**: [docker 容器环境准备](../../docs/docker%20容器环境准备.md)

---

*最后更新: 2026-05-27*
