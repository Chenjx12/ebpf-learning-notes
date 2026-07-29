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

## 八、实战: 验证器错误再现

本章配套代码在 `code/12-verifier/`，包含 4 个练习，每个练习对应一种典型的验证器拒绝场景。

### 8.1 练习1: NULL 指针解引用

**代码**: `ex1_boundary.bpf.c`  
**错误**: 调用 `bpf_map_lookup_elem()` 后未检查 NULL 就直接解引用

```c
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(ex1_boundary)
{
    u32 key = 0;
    u64 *val = bpf_map_lookup_elem(&counters, &key);
    // ❌ 没有检查 val 是否为 NULL!
    *val = *val + 1;
    return 0;
}
```

**验证器输出** (关键行):

```
6: (85) call bpf_map_lookup_elem#1    ; R0_w=map_value_or_null(id=1,map=counters,ks=4,vs=8)
7: (79) r1 = *(u64 *)(r0 +0)
R0 invalid mem access 'map_value_or_null'
```

**解读**: 
- 第 6 条指令后，R0 的类型是 `map_value_or_null` — 验证器标注了"可能为 NULL"
- 第 7 条指令尝试读取 R0+0 处的 8 字节 → 验证器发现: 如果 R0 是 NULL，这是非法内存访问
- 结论: 拒绝加载，返回 `-EACCES`

**修复**: 在解引用前添加 `if (!val) return 0;`

### 8.2 练习2: 有界循环 (验证器通过)

**代码**: `ex2_bounded_loop.bpf.c`  
**场景**: 循环上限是编译时常量

```c
for (int i = 0; i < 10; i++) {
    u32 key = i;
    val = bpf_map_lookup_elem(&counters, &key);
    if (val) { total += *val; prev = val; }
}
```

**验证器输出**:

```
processed 219 insns (limit 1000000) max_states_per_insn 1 total_states 20 peak_states 20 mark_read 10
```

**解读**:
- 验证器逐次展开 10 次迭代 (每轮创建 2 个状态: NULL/非NULL 分支)
- `total_states 20` = 10 次迭代 × 2 个分支
- `max_states_per_insn 1`: 状态剪枝有效，验证器不会重复探索等价路径
- 成功加载 ✅

### 8.3 练习3: 无界循环 (验证器拒绝)

**代码**: `ex3_unbounded_loop.bpf.c`  
**错误**: 循环上限来自全局变量 `loop_limit`

```c
volatile int loop_limit = 100;

for (int i = 0; i < loop_limit; i++) {
    // ...
}
```

**验证器输出** (截断):

```
BPF program is too large. Processed 1000001 insn
processed 1000001 insns (limit 1000000) max_states_per_insn 4 total_states 9618 peak_states 9618 mark_read 2
```

**解读**:
- 验证器无法静态确定 `loop_limit` 的值 → 逐次展开循环
- 每次迭代都创建新状态 → 连锁爆炸
- 达到 1M 指令上限 → 拒绝加载，返回 `-ENOSPC`

⚠️ **注意**: ex3 的验证器日志可达 ~1MB (100 万条指令)，运行时会明显卡顿。

### 8.4 练习4: 跨程序类型调用 Helper

**代码**: `ex4_wrong_helper.bpf.c`  
**错误**: kprobe 程序调用 XDP 专属 helper

```c
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(ex4_wrong_helper)
{
    bpf_xdp_adjust_head((struct xdp_md *)ctx, 0);  // ❌ XDP only!
    return 0;
}
```

**验证器输出**: 加载失败，返回 `-EINVAL`。`bpf_xdp_adjust_head` 不在 kprobe 程序类型的 helper 白名单中。

**扩展**: 查看各程序类型允许的 helper 列表:

```bash
sudo mount -t debugfs none /sys/kernel/debug  # 如果未挂载
cat /sys/kernel/debug/bpf/bpf_prog_type_helper_whitelist
```

### 8.5 运行方法

```bash
cd code/12-verifier
make
sudo ./loader ex1_boundary.bpf.o       # 预期: 验证器拒绝
sudo ./loader ex2_bounded_loop.bpf.o   # 预期: 验证器通过
sudo ./loader ex3_unbounded_loop.bpf.o # 预期: 验证器拒绝 (日志很长!)
sudo ./loader ex4_wrong_helper.bpf.o   # 预期: 验证器拒绝
```

---

## 📝 练习

- [ ] **练习 1**: 再现 NULL 指针解引用 → `R0 invalid mem access 'map_value_or_null'`
- [ ] **练习 2**: 有界循环 `for(i<10)` → 验证器通过，观察状态剪枝
- [ ] **练习 3**: 无界循环 `for(i<loop_limit)` → `Processed 1000001 insn`
- [ ] **练习 4**: 跨程序类型调用 helper → helper 白名单拒绝

---

## 📖 相关文档

- **上一篇**: [一、CO-RE、BTF 与 Libbpf](./一、CO-RE、BTF%20与%20Libbpf.md)
- **下一篇**: [三、eBPF 程序类型与附加点](./三、eBPF%20程序类型与附加点.md)
- **代码目录**: [code/12-verifier/](../../code/12-verifier/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)

---

*最后更新: 2026-07-29*
