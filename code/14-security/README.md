# eBPF 示例代码 (第八篇: 用于安全的 eBPF)

> 《Learning eBPF》第 9 章 — 本章无练习，以毕设项目为实践场

**对应笔记**: [四、用于安全的 eBPF](../../docs/Two-回顾/四、用于安全的%20eBPF.md)

## 📂 安全技术演进路线

```
Seccomp-bpf (静态过滤)
  → Falco (规则告警)
    → LSM eBPF (内核态阻断, 5.7+)
      → Cilium Tetragon (任意内核函数 + SIGKILL)
```

## 🔨 实践任务 (替代练习)

本章没有官方练习，以下任务直接服务于毕设项目：

### 任务 1: 用 BPF LSM 实现阻断 (替代 tracepoint 返回错误码)
- 当前第九篇的阻断方式: tracepoint 返回 `-EPERM`
- 升级方案: 用 `SEC("lsm/path_chmod")` 在内核态直接拒绝
- 要求内核 ≥ 5.7

### 任务 2: 学习 Falco 规则引擎设计
- 阅读 [Falco rules](https://github.com/falcosecurity/rules) 仓库
- 对比自己第八篇 `rules.yaml` 的设计差异
- Falco 的宏 (macros) 和列表 (lists) 机制

### 任务 3: 研究 Cilium Tetragon 的 TracingPolicy
- [Tetragon](https://github.com/cilium/tetragon) 的 `TracingPolicy` CRD
- 比较 Tetragon 的 `fd_install` hook 与自己项目的 kprobe 方式

### 任务 4: TOCTOU 防护
- 理解为什么 seccomp-unotify 不能用于安全策略执行
- 对比 LSM hook (参数已在内核内存) 和 syscall tracepoint (参数在用户态) 的安全差异

## 📖 关键工具对比

| 工具 | 机制 | 优势 | 劣势 |
|------|------|------|------|
| Seccomp-bpf | 每进程 syscall 过滤 | 最早支持 | 静态, 不能解引用指针 |
| Falco | syscall tracepoint + 规则 | 可对运行中容器应用 | 只能告警, 有 TOCTOU |
| BPF LSM | LSM hook 返回非零 | 内核态阻断, 无 TOCTOU | 需 5.7+, 企业发行版滞后 |
| Tetragon | 任意内核函数 + SIGKILL | 最灵活, 同步杀死进程 | 依赖非稳定内核函数 |

## 📖 相关文档

- **上一篇**: [eBPF 程序类型与附加点](../13-prog-types/)
- **下一篇**: [用于网络的 eBPF](../15-network/) (可选)
- **FAQ**: [../../FAQ.md](../../FAQ.md)

---

*最后更新: 2026-06-02*
