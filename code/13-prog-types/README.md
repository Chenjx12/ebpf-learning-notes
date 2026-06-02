# eBPF 示例代码 (第七篇: 程序类型与附加点)

> 《Learning eBPF》第 7 章练习

**对应笔记**: [三、eBPF 程序类型与附加点](../../docs/Two-回顾/三、eBPF%20程序类型与附加点.md)

## 📂 文件列表

| 文件名 | 说明 | 难度 |
|--------|------|------|
| hello.bpf.c | 多程序类型演示 (kprobe/fentry/tp/tp_btf/XDP/uprobe) | ⭐⭐⭐⭐ |
| hello.c | 用户态加载器 (Skeleton 自动附加) | ⭐⭐⭐ |
| hello-single.c | 练习2: 只加载单个程序 | ⭐⭐⭐⭐ |
| hello-kprobe.bpf.c | 练习3: 自定义 kprobe/fentry | ⭐⭐⭐ |
| hello-tp.bpf.c | 练习4: 自定义 tracepoint | ⭐⭐⭐ |
| Makefile | 编译脚本 | ⭐⭐ |

## 🚀 快速开始

```bash
make
sudo ./hello
# strace 观察 bpf() 系统调用 (练习1)
sudo strace -e bpf -o outfile ./hello
```

## 📝 练习

### 练习 1: strace 观察 prog_type
```bash
strace -e bpf -o outfile ./hello
```
在 `outfile` 中搜索 `BPF_PROG_LOAD`，观察不同程序的 `prog_type` 字段，匹配到 `hello.bpf.c` 中的 SEC() 定义。

### 练习 2: 只加载单个程序
修改用户态代码，从 `hello.bpf.o` 中只加载和附加**一个** eBPF 程序（不删除 `hello.bpf.c` 中的其他程序）。

### 练习 3: 自定义 kprobe/fentry
从 `/proc/kallsyms` 中找一个内核函数，写 kprobe 或 fentry 程序挂上去。

### 练习 4: 自定义 tracepoint
从 `/sys/kernel/tracing/available_events` 找一个 tracepoint，用 regular / raw / BTF-enabled 三种方式之一挂上去。

### 练习 5: XDP 独占性验证
尝试在同一个网口上附加两个 XDP 程序 → 观察 `Device or resource busy`。

## 📖 关键程序类型

| 类型 | SEC() 示例 | 能力要求 |
|------|-----------|---------|
| Kprobe | `SEC("ksyscall/execve")` | CAP_PERFMON + CAP_BPF |
| Fentry | `SEC("fentry/do_execve")` | 同上 |
| Tracepoint | `SEC("tp/syscalls/sys_enter_execve")` | 同上 |
| tp_btf | `SEC("tp_btf/sched_process_exec")` | 同上 |
| LSM | `SEC("lsm/path_chmod")` | 同上 |
| XDP | `SEC("xdp")` | CAP_NET_ADMIN + CAP_BPF |
| Uprobe | `SEC("uprobe/...")` | CAP_PERFMON + CAP_BPF |

## 📖 相关文档

- **上一篇**: [eBPF 验证器](../12-verifier/)
- **下一篇**: [用于安全的 eBPF](../14-security/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)
