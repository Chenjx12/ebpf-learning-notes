# eBPF 函数调用与组合示例代码 (第五篇)

本目录包含第五篇文章相关的实验代码，重点展示 **BPF-to-BPF 函数调用** 和 **Tail Call 链式调用** 的实现。

**对应笔记**: [Five、eBPF 程序的拆分与组合](../../docs/One-实践/五、eBPF%20程序的拆分与组合.md)

## 📂 文件列表

| 文件名 | 说明 | 难度 | 推荐顺序 |
|--------|------|------|---------|
| [common.h](./common.h) | 🔧 [公共头文件定义](./common.h) | ⭐ | 必读 |
| [bpf2bpf.c](./bpf2bpf.c) | 🔥 [BPF-to-BPF函数调用C代码](./bpf2bpf.c) | ⭐⭐ | 1️⃣ |
| [bpf2bpf.o](./bpf2bpf.o) | 📦 BPF-to-BPF编译产物 | - | - |
| [hello-bpf2bpf.c](./hello-bpf2bpf.c) | 🔥 [完整BPF-to-BPF示例](./hello-bpf2bpf.c) | ⭐⭐⭐ | 2️⃣ |
| [hello-bpf2bpf.py](./hello-bpf2bpf.py) | 🐍 [BPF-to-BPF Python加载器](./hello-bpf2bpf.py) | ⭐⭐⭐ | 2️⃣ |
| [hello-tail-simple.py](./hello-tail-simple.py) | ⭐ [简单Tail Call示例](./hello-tail-simple.py) | ⭐⭐⭐ | 3️⃣ |
| [tailcall-chain.py](./tailcall-chain.py) | 🔥 [Tail Call链式调用](./tailcall-chain.py) | ⭐⭐⭐⭐ | 4️⃣ |
| [tailcall-multi-probe.py](./tailcall-multi-probe.py) | 🔥 [Tail Call多探针组合](./tailcall-multi-probe.py) | ⭐⭐⭐⭐ | 5️⃣ |
| [tailcall-policy-route.py](./tailcall-policy-route.py) | 🔥 [Tail Call策略路由](./tailcall-policy-route.py) | ⭐⭐⭐⭐⭐ | 6️⃣ |
| [load.py](./load.py) | 🛠️ [通用加载工具](./load.py) | ⭐⭐ | 辅助 |

---

## 🚀 快速开始

### 前置要求

```bash
# 确认 BCC 已安装
sudo python3 -c "from bcc import BPF; print('BCC OK')"

# 确认内核版本支持 Tail Call (≥ 5.8 推荐)
uname -r
```

### 运行示例

#### **1. BPF-to-BPF 函数调用(基础)**

```bash
# 方法A: 直接运行Python脚本(使用BPF text=方式)
sudo python3 hello-bpf2bpf.py

# 方法B: 手动编译后加载
clang -target bpf -O2 -g \
      -I/usr/include/x86_64-linux-gnu \
      -c hello-bpf2bpf.c \
      -o hello-bpf2bpf.o

sudo python3 -c "
from bcc import BPF
b = BPF(src_file='hello-bpf2bpf.o')
b.attach_kprobe(event='sys_execve', fn_name='syscall__execve')
b.trace_print()
"
```

**观察输出**（仅示例）:
```
CPU-0    [000] d...  Hello from helper function!
CPU-0    [000] d...  Hello from main function!
```

---

#### **2. Tail Call 链式调用(进阶)**

```bash
# 运行简单的Tail Call示例
sudo python3 hello-tail-simple.py

# 运行链式调用示例
sudo python3 tailcall-chain.py

# 运行多探针组合示例
sudo python3 tailcall-multi-probe.py

# 运行策略路由示例(最复杂)
sudo python3 tailcall-policy-route.py
```

**观察输出**（仅示例）:

```
CPU-0    [000] d...  Tail call chain: prog0 -> prog1 -> prog2
CPU-0    [000] d...  Chain completed successfully!
```

---

## 📖 核心概念

### **BPF-to-BPF 函数调用**

**特点**:
- ✅ 像普通C函数一样调用其他BPF程序
- ✅ 共享调用栈,可以传递参数
- ✅ 返回后可以继续执行
- ⚠️ 受内核调用深度限制(通常≤16层)

**适用场景**:
- 代码模块化,提取公共逻辑
- 避免重复代码
- 提高可维护性

---

### **Tail Call (尾调用)**

**特点**:
- ✅ 完全替换当前执行的BPF程序
- ✅ 不增加调用栈深度
- ✅ 可以跳转到另一个程序
- ⚠️ 需要预先创建程序数组(Program Array)
- ⚠️ 跳转后原程序不再返回

**适用场景**:
- 超长处理链(超过BPF-to-BPF深度限制)
- 动态路由/策略切换
- 多阶段处理管道

---

## 💡 学习建议

1. **先理解BPF-to-BPF**: 这是基础的函数调用机制
2. **再学习Tail Call**: 理解程序数组和动态跳转
3. **对比两种方案**: 理解各自的适用场景
4. **实践组合使用**: 在复杂场景中混合使用两种技术

---

## 🔗 相关文档

- **学习笔记**: [Five、eBPF 程序的拆分与组合](../../docs/One-实践/五、eBPF%20程序的拆分与组合.md)
- **第四篇笔记**: [Four、eBPF 程序的解剖与工程化](../../docs/One-实践/四、eBPF%20程序的解剖与工程化.md) (手动编译基础)
- **常见问题**: [FAQ](../FAQ.md)
- **环境配置**: [项目环境](../../docs/项目环境.md)
- **基础示例**: [code/03-hello-world](../code/03-hello-world/)

---

*最后更新: 2026-05-24*
