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

## 📝 练习

- [ ] **练习 1**: strace 观察不同程序的 prog_type
- [ ] **练习 2**: 只加载单个程序 (libbpf 用户态编程)
- [ ] **练习 3**: 自定义 kprobe/fentry (从 /proc/kallsyms 选函数)
- [ ] **练习 4**: 自定义 tracepoint (从 available_events 选)
- [ ] **练习 5**: 验证 XDP 独占性 (同一网口只能一个 XDP)

---

## 📖 相关文档

- **上一篇**: [二、eBPF 验证器](./二、eBPF%20验证器.md)
- **下一篇**: [四、用于安全的 eBPF](./四、用于安全的%20eBPF.md)
- **代码目录**: [code/13-prog-types/](../../code/13-prog-types/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)

---

*最后更新: 2026-06-02*
