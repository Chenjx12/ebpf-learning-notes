# 二、eBPF 验证器

> 《Learning eBPF》第 6 章精读笔记

---

## 笔记前置

验证器是 eBPF 区别于内核模块的**最核心安全机制**。它不运行程序，而是静态分析每一条可能的执行路径，确保：
1. 程序一定会终止（无死循环）
2. 所有内存访问都在边界内
3. 寄存器类型与指令操作匹配
4. 只调用该程序类型允许的 helper 函数

理解验证器 = 理解"为什么我的程序加载失败"。

---

## 一、验证流程

### 1.1 寄存器状态追踪

验证器为每个寄存器维护 `bpf_reg_state`，包含:
- **type**: NOT_INIT / SCALAR_VALUE / PTR_TO_CTX / PTR_TO_MAP_VALUE / PTR_TO_STACK ...
- **值范围**: umin_value, umax_value, smin_value, smax_value
- **偏移信息**: var_off (已知位和未知位的掩码)

遇到分支时，保存当前状态 → 探索一条路径 → 弹栈继续另一条 → 合并等价状态 (状态剪枝)。

### 1.2 1M 指令限制

每个程序最多执行 100 万条指令（历史: 4096 条）。达到上限 → `BPF program is too large`。

### 1.3 状态剪枝

验证器在特定指令处缓存寄存器状态。如果到达同一指令时状态等价于已缓存的状态，跳过重复探索。这是验证器能处理复杂程序的关键优化。

---

## 二、验证器检查清单

### 2.1 辅助函数许可

**错误示例**: XDP 程序调用 `bpf_get_current_pid_tgid()` → `unknown func bpf_get_current_pid_tgid#14`。每个程序类型有允许的 helper 白名单。

### 2.2 参数类型校验

Helper 函数注册了 `bpf_func_proto`，描述参数和返回值的类型约束。传错类型 → `R1 type=... expected=...`。

### 2.3 许可证检查

`gpl_only = true` 的 helper (如 `bpf_probe_read_kernel`) 只能在 GPL 兼容程序中使用。缺少 LICENSE 节 → `cannot call GPL-restricted function`。

### 2.4 内存访问边界

- **数组越界**: `message[c]` 当 `c` 可能 ≥ 12 → `invalid access to map value`
- **包边界**: XDP 程序必须检查 `data < data_end`
- **栈越界**: 局部变量 off-by-one → `invalid variable-offset read from stack`

### 2.5 空指针检查

`bpf_map_lookup_elem()` 可能返回 NULL。不解引用检查 → `invalid mem access 'map_value_or_null'`。

### 2.6 终止性

- 每条路径必须到达 return
- R0 (返回值) 必须在 return 前被初始化

### 2.7 循环限制

- \< 5.3: 禁止向后跳转 (用 `#pragma unroll`)
- ≥ 5.3: 允许有界循环
- 无界循环 → 复杂度上限

### 2.8 无效指令

新指令（如原子操作）在老内核上无法验证。

---

## 三、调试工具

### 验证器日志

```c
libbpf_set_print(libbpf_print_fn);  // 捕获验证器输出
```

日志包含:
- 每条指令的序号 + 字节码
- 执行该指令后的寄存器状态
- `last_idx` / `first_idx` 循环状态回溯

### 控制流可视化

```bash
bpftool prog dump xlated name <prog> visual > out.dot
dot -Tpng out.dot -o cfg.png
```

---

## 📝 练习

- [ ] **练习 1**: 再现 off-by-one (data.message[c] 边界检查)
- [ ] **练习 2**: 追踪有界循环的寄存器 (`for i<10`)
- [ ] **练习 3**: 触发无界循环报错 (`for i<c`)
- [ ] **练习 4**: tracepoint 上下文结构体 → `invalid bpf_context access`

---

## 📖 相关文档

- **上一篇**: [一、CO-RE、BTF 与 Libbpf](./一、CO-RE、BTF%20与%20Libbpf.md)
- **下一篇**: [三、eBPF 程序类型与附加点](./三、eBPF%20程序类型与附加点.md)
- **代码目录**: [code/12-verifier/](../../code/12-verifier/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)

---

*最后更新: 2026-06-02*
