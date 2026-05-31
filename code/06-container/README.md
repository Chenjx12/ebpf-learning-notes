# eBPF 容器感知与身份识别示例代码 (第六篇)

本目录包含第六篇文章相关的实验代码，重点展示 **Namespace 检测**、**Cgroup 映射** 和 **容器身份识别** 的实现。

**对应笔记**: [Six、容器感知与身份识别：从内核到云原生](../../docs/One-实践/六、容器感知与身份识别：从内核到云原生.md)

## 📂 文件列表

| 文件名 | 说明 | 难度 | 推荐顺序 |
|--------|------|------|---------|
| [container-aware.c](./container-aware.c) | 🔥 [基础Namespace检测C代码](./container-aware.c) | ⭐⭐ | 1️⃣ |
| [container-aware.py](./container-aware.py) | 🐍 [Namespace检测Python加载器](./container-aware.py) | ⭐⭐ | 1️⃣ |
| [container-ns.c](./container-ns.c) | 🔥 [完整Namespace ID获取](./container-ns.c) | ⭐⭐⭐ | 2️⃣ |
| [container-ns.py](./container-ns.py) | 🐍 [Namespace ID Python加载器](./container-ns.py) | ⭐⭐⭐ | 2️⃣ |
| [container-map.c](./container-map.c) | 🔥 [Cgroup Map映射C代码](./container-map.c) | ⭐⭐⭐⭐ | 3️⃣ |
| [container-map.py](./container-map.py) | 🐍 [Cgroup Map Python加载器](./container-map.py) | ⭐⭐⭐⭐ | 3️⃣ |

---

## 🚀 快速开始

### 前置要求

```bash
# 确认 BCC 已安装
sudo python3 -c "from bcc import BPF; print('BCC OK')"

# 确认 Docker 已安装并运行(用于容器实验)
docker ps

# 确认内核版本支持 Cgroup v2 (≥ 5.8 推荐)
uname -r
```

---

### 运行示例

#### **1. 基础 Namespace 检测(入门)**

```bash
# 方法A: 直接运行Python脚本
sudo python3 container-aware.py

# 方法B: 手动编译后加载
clang -target bpf -O2 -g \
      -I/usr/include/x86_64-linux-gnu \
      -c container-aware.c \
      -o container-aware.o

sudo python3 -c "
from bcc import BPF
b = BPF(src_file='container-aware.o')
b.attach_kprobe(event='sys_execve', fn_name='detect_container')
b.trace_print()
"
```

**观察输出**（仅示例）:
```
CPU-0    [000] d...  PID 1234 in namespace 4026531836
CPU-0    [000] d...  PID 1235 in namespace 4026531836
```

---

#### **2. 完整 Namespace ID 获取(进阶)**

```bash
# 运行完整Namespace ID获取程序
sudo python3 container-ns.py
```

**核心功能**:
- ✅ 深入 `task_struct` 结构体
- ✅ 读取 `nsproxy->pid_ns_for_children`
- ✅ 获取 `ns.inum` (Namespace Inode号)
- ✅ 区分宿主机和容器环境

**观察输出**（仅示例）:

```
CPU-0    [000] d...  Container process: PID=5678, NS_INUM=4026532401
CPU-0    [000] d...  Host process: PID=9012, NS_INUM=4026531836
```

---

#### **3. Cgroup Map 映射(实战)**

```bash
# 运行Cgroup Map映射程序
sudo python3 container-map.py
```

**核心功能**:

- ✅ 使用 `bpf_get_current_cgroup_id()` 获取 Cgroup Inode
- ✅ 在用户态建立 `Cgroup ID ↔ 容器名` 映射
- ✅ 自动识别进程所属容器
- ✅ 支持多容器并发监控

**观察输出**（仅示例）:

```
TIME                 CONTAINER_NAME    PID    EVENT
2026-05-24 23:00:01  nginx-container   3456   execve
2026-05-24 23:00:02  redis-container   4567   openat
2026-05-24 23:00:03  nginx-container   3456   connect
```

---

## 📖 核心概念

### **Namespace (命名空间)**

**特点**:
- ✅ Linux 容器隔离的核心机制
- ✅ 每个容器有独立的 PID、Mount、Network 等 Namespace
- ✅ Namespace ID 是进程的"身份证号码"

**关键结构体**:
```c
struct task_struct {
    struct nsproxy *nsproxy;  // 指向 Namespace 代理
};

struct nsproxy {
    struct pid_namespace *pid_ns_for_children;  // PID Namespace
};

struct pid_namespace {
    struct ns_common ns;  // 包含 inum 字段
};
```

**访问链路**:
```
task_struct → nsproxy → pid_ns_for_children → ns.inum
```

---

### **Cgroup (控制组)**

**特点**:
- ✅ 资源限制和统计的核心机制
- ✅ Cgroup v2 下每个容器对应唯一 `.scope` 目录
- ✅ Cgroup Inode 是容器的"门牌号"

**Cgroup v2 优势**:
- ✅ 大一统设计(所有控制器在同一棵树)
- ✅ 一个容器只有一个 Cgroup Inode
- ✅ 一一对应关系稳定可靠

**Helper 函数**:
```c
u64 bpf_get_current_cgroup_id(void);
// 返回当前进程的 Cgroup Inode 号
```

---

### **容器身份识别策略**

**方案对比**:

| 维度 | Namespace ID | Cgroup Inode |
|------|-------------|--------------|
| **稳定性** | 高(重启前不变) | **极高**(持久存在) |
| **唯一性** | 高 | **极高**(v2下一一对应) |
| **获取难度** | 中(需深入结构体) | **简单**(一个Helper) |
| **适用场景** | 进程隔离检测 | **容器归属识别** |

**最佳实践**: 
- **组合使用**: Namespace + Cgroup 双重验证
- **优先 Cgroup**: 在容器识别场景中作为主键
- **Namespace 辅助**: 用于异常检测和逃逸识别

---

## 💡 学习建议

1. **先理解 Namespace**: 这是容器隔离的基础
2. **再掌握 Cgroup**: 这是资源控制和身份识别的关键
3. **对比两种方案**: 理解各自的适用场景
4. **实践组合使用**: 在复杂场景中混合使用两种技术

---

## 🔗 相关文档

- **学习笔记**: [Six、容器感知与身份识别：从内核到云原生](../../docs/One-实践/六、容器感知与身份识别：从内核到云原生.md)
- **第五篇笔记**: [Five、eBPF 程序的拆分与组合](../../docs/One-实践/五、eBPF%20程序的拆分与组合.md) (前置知识)
- **常见问题**: [FAQ](../../FAQ.md) (包含Namespace编译问题解答)
- **环境配置**: [项目环境](../../docs/项目环境.md)
- **Docker环境**: [docker 容器环境准备](../../docs/docker%20容器环境准备.md)

---

*最后更新: 2026-05-24*
