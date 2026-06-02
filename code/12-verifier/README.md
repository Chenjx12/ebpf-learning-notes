# eBPF 示例代码 (第六篇: eBPF 验证器)

> 《Learning eBPF》第 6 章练习

**对应笔记**: [二、eBPF 验证器](../../docs/Two-回顾/二、eBPF%20验证器.md)

## 📂 文件列表

| 文件名 | 说明 | 难度 |
|--------|------|------|
| hello-verifier.bpf.c | 验证器实验程序 (多个测试场景) | ⭐⭐⭐⭐ |
| hello-verifier.c | 用户态加载器 | ⭐⭐⭐ |
| Makefile | 编译脚本 | ⭐⭐ |

## 🚀 快速开始

```bash
# 生成 vmlinux.h (从 Ch5 延续)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
make
sudo ./hello-verifier
```

## 📝 练习

### 练习 1: 再现 off-by-one 错误
修改 `hello-verifier.bpf.c`，将 `data.message[c]` 的边界检查从 `<` 改为 `<=`，观察验证器报错:
```
invalid variable-offset read from stack R2
```

### 练习 2: 追踪循环变量寄存器
取消 xdp_hello 中有界循环 `for (int i=0; i < 10; i++)` 的注释。从验证器日志中找出跟踪循环变量 `i` 的寄存器。观察重复出现的 `last_idx` / `first_idx` 模式。

### 练习 3: 无界循环触发复杂度上限
将循环改为 `for (int i=0; i < c; i++)` (c 是全局变量)，验证器将因指令复杂度超限而拒绝:
```
BPF program is too large. Processed 1000001 insn
```

### 练习 4: 跟踪点上下文结构体
编写一个 tracepoint 程序，自定义 `struct tracepoint_ctx` (以 `common_type`, `common_flags`, `common_preempt_count`, `common_pid` 开头)。尝试直接访问这些字段 → 验证器报 `invalid bpf_context access`。

## 📖 核心知识点

- **验证器状态追踪**: 每个寄存器的类型 (NOT_INIT / SCALAR / PTR_TO_*) 和值范围
- **状态剪枝**: 等价路径缓存，避免重复探索
- **1M 指令限制**: 硬编码的复杂度上限
- **辅助函数许可**: 不同类型程序允许不同的 helper
- **GPL 限制**: `gpl_only = true` 的 helper 需要 GPL 兼容许可证
- **内存边界检查**: 数组越界、空指针解引用
- **有界循环**: 5.3+ 支持，需要明确的迭代上限

## 📖 相关文档

- **上一篇**: [CO-RE、BTF 与 Libbpf](../11-libbpf/)
- **下一篇**: [eBPF 程序类型与附加点](../13-prog-types/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)
