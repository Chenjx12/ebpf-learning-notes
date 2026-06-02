# eBPF 示例代码 (第十篇: eBPF 编程)

> 《Learning eBPF》第 10 章练习 — 多语言 eBPF 概述

## 📝 练习

### 练习 1: 用任意语言写 Hello World
用 Go (cilium/ebpf)、Rust (Aya)、或 C (libbpf) 输出一条 trace 信息。

### 练习 2: 对比字节码
`llvm-objdump -d` 对比你写的程序和第三章 "Hello World" 的字节码差异。

### 练习 3: strace 观察 bpf() 调用
`strace -e bpf` 运行你的程序，确认 `BPF_PROG_LOAD` 等系统调用符合预期。

## 📖 语言/库对比

| 语言 | 库 | 特点 |
|------|-----|------|
| C | libbpf | 官方标准, CO-RE 支持 |
| Go | cilium/ebpf | 纯 Go, 不依赖 libbpf |
| Go | libbpfgo | Aqua 开发, 包装 libbpf |
| Rust | Aya | 纯 Rust, 不依赖 libbpf |
| Rust | libbpf-rs | libbpf 绑定 |
| Python | BCC | 最简单, 运行时编译 |

## 📖 相关文档

- **上一篇**: [用于网络的 eBPF](../15-network/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)
