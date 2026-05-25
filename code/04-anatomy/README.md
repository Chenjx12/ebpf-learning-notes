# eBPF 程序解剖与编译过程

本目录包含第四篇文章相关的实验代码，重点展示 **手动编译 eBPF 程序** 和 **查看编译中间产物** 的过程。

**对应笔记**: [Four、eBPF 程序的解剖与工程化](../docs/Four、eBPF%20程序的解剖与工程化.md)

## 📂 文件列表

| 文件名                                     | 说明                                                 | 用途                          |
| ------------------------------------------ | ---------------------------------------------------- | ----------------------------- |
| [hello-debug.c](./hello-debug.c)           | 🔧 [独立的eBPF C源代码](./hello-debug.c)             | 用于手动编译测试              |
| [hello-debug.o](./hello-debug.o)           | 📦 [编译生成的eBPF字节码](./hello-debug.o)           | 编译产物（ELF格式）           |
| [build-ebpf.sh](./build-ebpf.sh)           | 🛠️ [自动化编译脚本](./build-ebpf.sh)                 | 一键完成编译和分析            |
| [load-compiled.py](./load-compiled.py)     | 🐍 [Python加载器示例](./load-compiled.py)            | 演示如何用BCC加载已编译的程序 |
| [hello-perf-plus.c](./hello-perf-plus.c)   | 🔥 [C/Python分离-C代码](./hello-perf-plus.c)         | 完整示例的C部分               |
| [hello-perf-plus.py](./hello-perf-plus.py) | 🔥 [C/Python分离-Python加载器](./hello-perf-plus.py) | 完整示例的Python部分          |
| [COMPILE_OUTPUT.md](./COMPILE_OUTPUT.md)   | 📖 **[编译过程详解](./COMPILE_OUTPUT.md)**           | 详细文档，展示所有中间产物    |

## 与第三篇示例的关系

code/03-hello-world/hello-perf-plus.py：第三篇的混合版（C 在 Python 字符串里）
code/04-anatomy/hello-perf-plus.c + hello-perf-plus.py：本篇的分离版（C 独立文件）
功能完全一致，但分离版更易维护，适合正式项目。

---

## 🚀 快速开始

### 1. 手动编译 eBPF 程序

```bash
# 进入目录
cd /home/chenjx12/Desktop/u/hgfs/code/04-anatomy

# 方法A: 使用自动化脚本
chmod +x build-ebpf.sh
./build-ebpf.sh hello-debug.c

# 方法B: 手动执行编译命令
clang -target bpf -O2 -g \
      -I/usr/include/x86_64-linux-gnu \
      -c hello-debug.c \
      -o hello-debug.o
```

### 2. 查看编译产物

```bash
# 查看文件大小
ls -lh hello-debug.o

# 查看 ELF 段结构（关键！）
readelf -S hello-debug.o

# 反汇编查看 eBPF 字节码
llvm-objdump-14 -d hello-debug.o
```

### 3. 查看详细文档

所有编译过程的详细分析都在 [`COMPILE_OUTPUT.md`](./COMPILE_OUTPUT.md) 中，包括：

- ✅ 完整的编译命令和参数解释
- ✅ ELF 段结构分析（`kprobe/sys_execve`、`license` 等）
- ✅ eBPF 字节码逐条指令解析
- ✅ 使用 bpftool 加载和查看程序的方法

---

## 🔍 核心知识点

### 为什么需要手动编译？

在之前的学习中，我们使用 `BPF(text=program)`，BCC 帮我们在后台悄悄调用了 `clang`。手动编译的目的是：

1. **打开黑盒**: 理解 BCC 背后做了什么
2. **完全可控**: 清楚知道每一个编译参数
3. **标准化流程**: 这是生产环境和 libbpf 的标准工作流
4. **调试友好**: 可以独立于 Python 测试 C 代码

### 编译链路

```
C 源代码 (hello-debug.c)
    ↓
clang -target bpf -O2 -g
    ↓
ELF 对象文件 (hello-debug.o)
    ├─ kprobe/sys_execve 段 (eBPF 字节码)
    ├─ license 段 ("GPL")
    └─ .rodata 段 (字符串常量)
    ↓
bpf() 系统调用 → 内核加载
    ↓
Verifier 验证 → JIT 编译
    ↓
附加到 kprobe → 运行
```

### ELF 段名的重要性

eBPF 程序通过 **ELF 段名** 来声明自己的类型和挂载点：

```c
SEC("kprobe/sys_execve")
int hello(struct pt_regs *ctx) { ... }
```

这告诉加载器："把 `hello` 函数挂钩到 `sys_execve` 的 kprobe 上"。

---

## 🛠️ 常见问题

### Q1: 编译时报错 `asm/types.h file not found`

**原因**: clang 默认不包含 x86_64-linux-gnu 的头文件路径

**解决**: 添加 `-I/usr/include/x86_64-linux-gnu` 参数

### Q2: 报错 `too few arguments to function call`

**原因**: 新版 libbpf 中 `bpf_trace_printk` 需要两个参数

**解决**: 改为 `bpf_trace_printk(fmt, sizeof(fmt))`

### Q3: `objdump -d` 无法识别架构

**原因**: 标准 objdump 不支持 eBPF 架构

**解决**: 使用 `llvm-objdump-14 -d`（专门用于 LLVM/Clang 生成的代码）

---

## 📚 相关文档

- **学习笔记**: [Four、eBPF 程序的解剖与工程化](../docs/Four、eBPF%20程序的解剖与工程化.md)
- **第三篇笔记**: [Three、eBPF 的 Hello World](../docs/Three、eBPF%20的%20Hello%20%20World.md)
- **常见问题**: [FAQ](../FAQ.md)
- **环境配置**: [项目环境](../docs/项目环境.md)
- **基础示例**: [code/03-hello-world](../code/03-hello-world/)

---

_最后更新: 2026-05-24_
