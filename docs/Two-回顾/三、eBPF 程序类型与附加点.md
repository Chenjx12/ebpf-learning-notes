# 三、eBPF 程序类型与附加点

> 《Learning eBPF》第 7 章精读笔记

---

## 笔记前置

前面我们几乎只用 kprobe 和 tracepoint。但实际上 eBPF 有**几十种程序类型**，每种有自己的上下文结构体、允许的 helper、附加方式。本章系统梳理，重点抓与安全项目相关的类型。

---

## 一、程序类型总览

### 1.1 追踪类 (需要 CAP_PERFMON + CAP_BPF)

| 类型 | SEC() 示例 | 特点 |
|------|-----------|------|
| Kprobe | `SEC("ksyscall/execve")` | 内核函数入口 |
| Kretprobe | `SEC("kretprobe/...")` | 内核函数返回, 可读返回值 |
| Fentry | `SEC("fentry/do_execve")` | 比 kprobe 高效, 通过 trampoline |
| Fexit | `SEC("fexit/...")` | 可访问函数输入参数 |
| Tracepoint | `SEC("tp/syscalls/sys_enter_execve")` | 稳定接口 |
| Raw Tracepoint | `SEC("raw_tp/...")` | 更高性能 |
| tp_btf | `SEC("tp_btf/sched_process_exec")` | 自动从 vmlinux.h 获取上下文 |
| Uprobe | `SEC("uprobe/...")` | 用户态函数 |
| USDT | — | 用户态预定义探测点 |
| **LSM** | `SEC("lsm/path_chmod")` | 🎯 **安全专用, 可阻断** |

### 1.2 网络类 (需要 CAP_NET_ADMIN + CAP_BPF)

| 类型 | 用途 |
|------|------|
| XDP | 驱动层数据包处理 |
| TC | 流量控制 ingress/egress |
| Socket Filter | 套接字数据复制 |
| Cgroup Skb | 按 cgroup 过滤 |
| Flow Dissector | 自定义包解析 |

---

## 二、重点类型深入

### 2.1 Kprobe → Fentry 的进化

```
Kprobe:   int 3 断点 → 慢, 可能被禁用
Fentry:  BPF trampoline → 快, 始终可用 (5.5+, x86)
```

Fentry 通过 BPF_PROG 宏接收与内核函数完全相同的参数，不需要 `pt_regs` 手动解析。

### 2.2 LSM (Linux Security Module)

**最关键的安全程序类型**。挂载到 LSM API，在参数已复制到内核内存后、操作执行前触发。

```c
SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path, umode_t mode)
{
    // 返回非零 = 拒绝操作
    return -EPERM;
}
```

与 tracepoint 的本质区别:
- Tracepoint: 只能观察, 参数在用户态 (TOCTOU 风险)
- LSM: 可以阻断, 参数在内核态 (无 TOCTOU)

### 2.3 Context 参数

每个程序类型的 context 结构体不同，验证器根据程序类型检查 context 访问:
- 访问未定义的字段 → `invalid bpf_context access`
- XDP 程序取 `xdp_md`，必须检查 data/data_end 边界

---

## 三、Helper 函数与 Kfuncs

**Helper**: UAPI 稳定接口, 约 200+ 个
**Kfunc**: 内核内部函数, **不保证兼容性**, 功能更强大

验证器检查: helper 是否允许该程序类型调用 + 参数类型是否匹配

---

## 四、实战: 程序类型与附加方式

本章配套代码在 `code/13-prog-types/`，包含 4 个练习 + 1 个思考实验。

### 4.1 练习1: 查看程序类型

```bash
sudo ./ex1_list prog_types.bpf.o
```

输出示例:
```
║ kprobe_openat        │ KPROBE             │ (none / auto)
║ tracepoint_exec      │ TRACEPOINT         │ (none / auto)
║ raw_tp_openat        │ TRACEPOINT         │ (none / auto)
```

**关键 API**: `bpf_object__for_each_program()`, `bpf_program__name()`, `bpf_program__type()`

### 4.2 练习2: 选择性加载

从多程序 `.bpf.o` 中只加载一个程序, 其余用 `bpf_program__set_autoload(false)` 禁用:

```bash
sudo ./ex2_selective prog_types.bpf.o kprobe_openat
# 输出: ⏭️ 跳过 tracepoint_exec / 跳过 raw_tp_openat / ✅ 加载 kprobe_openat
```

**关键 API**: `bpf_program__set_autoload(prog, false)`

### 4.3 练习3: 手动 Kprobe 附加

程序使用通用 `SEC("kprobe")` (不指定函数), 从用户态动态选择目标:

```bash
# 不指定函数名 → 列出 /proc/kallsyms 供参考
sudo ./ex3_kprobe kprobe_custom.bpf.o

# 手动指定目标函数
sudo ./ex3_kprobe kprobe_custom.bpf.o do_sys_openat2
sudo ./ex3_kprobe kprobe_custom.bpf.o __x64_sys_execve
```

**关键 API**: `bpf_program__attach_kprobe(prog, false, func_name)`

### 4.4 练习4: 手动 Tracepoint 附加

从 `/sys/kernel/debug/tracing/available_events` 选任意 tracepoint:

```bash
sudo ./ex4_tracepoint tp_custom.bpf.o sched sched_process_exec
sudo ./ex4_tracepoint tp_custom.bpf.o syscalls sys_enter_openat
sudo ./ex4_tracepoint tp_custom.bpf.o syscalls sys_enter_execve
```

**关键 API**: `bpf_program__attach_tracepoint(prog, category, name)`

### 4.5 练习5: XDP 独占性 (思考实验)

XDP 同一网口只能附加一个程序。可验证:

```bash
# 使用 bpftool 加载第一个 XDP 程序
sudo bpftool prog load xdp_pass.bpf.o /sys/fs/bpf/xdp1
sudo bpftool net attach xdp pinned /sys/fs/bpf/xdp1 dev lo

# 尝试加载第二个 → Device or resource busy
sudo bpftool net attach xdp pinned /sys/fs/bpf/xdp2 dev lo
```

---

## 📝 练习

- [ ] **练习 1**: 用 `ex1_list` 查看 prog_types.bpf.o 中每个程序的类型
- [ ] **练习 2**: 用 `ex2_selective` 选择性加载一个程序，观察 autoload 控制
- [ ] **练习 3**: 用 `ex3_kprobe` 从 /proc/kallsyms 手动 kprobe 附加
- [ ] **练习 4**: 用 `ex4_tracepoint` 从 available_events 自定义 tracepoint
- [ ] **练习 5**: 验证 XDP 独占性 (同一网口只能一个 XDP)

---

## 📖 相关文档

- **上一篇**: [二、eBPF 验证器](./二、eBPF%20验证器.md)
- **下一篇**: [四、用于安全的 eBPF](./四、用于安全的%20eBPF.md)
- **代码目录**: [code/13-prog-types/](../../code/13-prog-types/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)

---

*最后更新: 2026-07-29*
