# eBPF 示例代码 (第七篇: 程序类型与附加点)

> 《Learning eBPF》第 7 章练习

**对应笔记**: [三、eBPF 程序类型与附加点](../../docs/Two-回顾/三、eBPF%20程序类型与附加点.md)

## 📂 文件列表

| 文件名 | 说明 | 练习 |
|--------|------|:--:|
| `prog_types.bpf.c` | 3 种不同类型程序 (kprobe + tp + raw_tp) | 1, 2 |
| `kprobe_custom.bpf.c` | 通用 kprobe 程序 (无指定函数名) | 3 |
| `tp_custom.bpf.c` | 通用 tracepoint 程序 (无指定 category/name) | 4 |
| `ex1_list.c` | 列出 .bpf.o 中所有程序的类型 | 1 |
| `ex2_selective.c` | 选择性加载单个程序 (autoload 控制) | 2 |
| `ex3_kprobe.c` | 手动 kprobe 附加到任意内核函数 | 3 |
| `ex4_tracepoint.c` | 手动 tracepoint 附加到任意事件 | 4 |
| `Makefile` | 编译脚本 | — |

## 🚀 快速开始

```bash
# 生成/复制 vmlinux.h
cp ../11-libbpf/vmlinux.h .

# 编译
make

# 练习1: 查看程序类型
sudo ./ex1_list prog_types.bpf.o

# 练习2: 选择性加载
sudo ./ex2_selective prog_types.bpf.o kprobe_openat

# 练习3: 手动 kprobe (从 /proc/kallsyms 选函数)
sudo ./ex3_kprobe kprobe_custom.bpf.o                # 先看看有哪些函数
sudo ./ex3_kprobe kprobe_custom.bpf.o do_sys_openat2 # 挂上去

# 练习4: 手动 tracepoint (从 available_events 选)
sudo ./ex4_tracepoint tp_custom.bpf.o sched sched_process_exec

# 查看输出 (所有程序都用 bpf_printk)
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## 📖 关键 API 速查

| 操作 | API |
|------|-----|
| 遍历程序 | `bpf_object__for_each_program(pos, obj)` |
| 程序名 | `bpf_program__name(prog)` |
| 程序类型 | `bpf_program__type(prog)` → `BPF_PROG_TYPE_*` |
| 附加类型 | `bpf_program__expected_attach_type(prog)` |
| 禁/启 autoload | `bpf_program__set_autoload(prog, false/true)` |
| 手动 kprobe | `bpf_program__attach_kprobe(prog, false, func)` |
| 手动 tracepoint | `bpf_program__attach_tracepoint(prog, cat, name)` |

## 📖 关键程序类型

| 类型 | SEC() 示例 | 附加方式 |
|------|-----------|---------|
| Kprobe | `SEC("kprobe/do_sys_openat2")` | 自动 |
| Kprobe (通用) | `SEC("kprobe")` | 手动, 用户态指定函数 |
| Tracepoint | `SEC("tracepoint/sched/sched_process_exec")` | 自动 |
| Raw Tracepoint | `SEC("tp/syscalls/sys_enter_openat")` | 自动 (更高性能) |
| Tracepoint (通用) | `SEC("tp")` | 手动, 用户态指定 category/name |

## 📖 相关文档

- **上一篇**: [eBPF 验证器](../12-verifier/)
- **下一篇**: [用于安全的 eBPF](../14-security/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)

---

*最后更新: 2026-07-29*
