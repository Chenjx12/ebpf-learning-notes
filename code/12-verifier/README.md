# eBPF 示例代码 (第六篇: eBPF 验证器)

> 《Learning eBPF》第 6 章练习

**对应笔记**: [二、eBPF 验证器](../../docs/Two-回顾/二、eBPF%20验证器.md)

## 📂 文件列表

| 文件名 | 说明 | 预期结果 | 关键知识点 |
|--------|------|:--:|------|
| `ex1_boundary.bpf.c` | map 查找后未检查 NULL | ❌ 拒绝 | `map_value_or_null` |
| `ex2_bounded_loop.bpf.c` | 有界循环 `for(i<10)` | ✅ 通过 | 循环展开与状态剪枝 |
| `ex3_unbounded_loop.bpf.c` | 无界循环 `for(i<limit)` | ❌ 拒绝 | 1M 指令复杂度上限 |
| `ex4_wrong_helper.bpf.c` | kprobe 调用 XDP 专属 helper | ❌ 拒绝 | helper 白名单机制 |
| `loader.c` | 通用加载器 (带详细日志) | — | `bpf_object__open_file` + kernel log |
| `Makefile` | 编译脚本 | — | CO-RE 编译 + llvm-strip |

## 🚀 快速开始

```bash
# 生成 vmlinux.h (或从上一章复制)
cp ../11-libbpf/vmlinux.h .
# 或
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 编译
make

# 运行各练习 (全部用 sudo)
sudo ./loader ex1_boundary.bpf.o       # 练习1: 观察 "invalid mem access"
sudo ./loader ex2_bounded_loop.bpf.o   # 练习2: 观察 "processed 219 insns"
sudo ./loader ex3_unbounded_loop.bpf.o # 练习3: 观察 "1000001 insn" (日志很长!)
sudo ./loader ex4_wrong_helper.bpf.o   # 练习4: 观察 "unknown func"
```

## 📝 练习详解

### 练习 1: NULL 指针解引用

**错误**: 调用 `bpf_map_lookup_elem()` 后直接解引用返回值，未检查 NULL。

```
; u64 *val = bpf_map_lookup_elem(&counters, &key);
6: (85) call bpf_map_lookup_elem#1    ; R0_w=map_value_or_null(...)
; *val = *val + 1;
7: (79) r1 = *(u64 *)(r0 +0)
R0 invalid mem access 'map_value_or_null'
```

**关键观察**: R0 的类型是 `map_value_or_null`（包含 NULL 可能），直接解引用被拒绝。

**修复**: 在第 7 行前添加 `if (!val) return 0;`，验证器在 if 分支内将 R0 类型提升为 `map_value`。

### 练习 2: 有界循环 (通过)

**正确做法**: 循环上限是编译时常量 `i < 10`，验证器可以静态确定迭代次数。

```
processed 219 insns (limit 1000000) max_states_per_insn 1 total_states 20 peak_states 20
```

**关键观察**: 
- `total_states 20`: 验证器创建了 20 个状态（10 次迭代 × 每轮 2 个分支）
- `max_states_per_insn 1`: 每次最多 1 个状态，状态剪枝有效
- 远未达到 1M 上限

### 练习 3: 无界循环 (拒绝)

**错误**: 循环上限来自全局变量 `loop_limit`，验证器无法静态确定。

```
BPF program is too large. Processed 1000001 insn
processed 1000001 insns (limit 1000000) max_states_per_insn 4 total_states 9618
```

**关键观察**:
- 验证器逐次展开循环，每次都创建新状态
- 达到 1M 指令上限后拒绝
- 日志量巨大 (~1MB)，体现了验证器的穷举分析

### 练习 4: 跨程序类型调用 Helper

**错误**: kprobe 程序尝试调用 `bpf_xdp_adjust_head()`（仅限 XDP 程序）。

**关键观察**: 每个 BPF 程序类型有允许使用的 helper 白名单。可以通过内核 debugfs 查看:

```bash
# 需要先挂载 debugfs: sudo mount -t debugfs none /sys/kernel/debug
cat /sys/kernel/debug/bpf/bpf_prog_type_helper_whitelist
```

## 📖 核心知识点

- **寄存器状态追踪**: 验证器为每个寄存器维护类型 + 值范围 (smin/smax/umin/umax)
- **状态剪枝**: 等价路径缓存，避免重复探索 (total_states vs peak_states)
- **1M 指令限制**: 硬编码的复杂度上限，超过即拒绝
- **辅助函数白名单**: 程序类型决定了可用的 helper 集合
- **循环限制**: 有界循环通过，无界循环被复杂度上限截断

## 📖 相关文档

- **上一篇**: [CO-RE、BTF 与 Libbpf](../11-libbpf/)
- **下一篇**: [eBPF 程序类型与附加点](../13-prog-types/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)

---

*最后更新: 2026-07-29*
