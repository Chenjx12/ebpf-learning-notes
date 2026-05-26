# 🧪 实验五：eBPF 函数调用与尾调用

## 实验概要

| 项目 | 内容 |
|------|------|
| **实验目的** | 理解 eBPF 函数调用机制，掌握尾调用实现程序链的方法 |
| **难度** | ⭐⭐⭐ (中等) |
| **预计用时** | 2-3 小时 |
| **前置知识** | 第四篇（eBPF 程序结构、编译链路） |
| **环境要求** | Ubuntu 22.04+、BCC、Linux 5.4+ 内核 |

### 你会学到什么？

- ✅ eBPF 中函数调用的限制（512 字节栈、8 层深度）
- ✅ `__always_inline` vs 普通函数调用的区别
- ✅ 尾调用（Tail Call）的原理：不返回、复用栈帧
- ✅ 用 `prog_array` Map 实现程序动态跳转
- ✅ 构建可扩展的链式 eBPF 程序

---

## 📂 实验文件清单

```
code/05-tail-call/
├── README.md            ← 本实验指导书
├── simple-func.c        ← 实验 1: 函数调用示例（C 源码）
├── simple-func.py       ← 实验 1: Python 加载器 + 字节码观察
├── hello-tail.c         ← 实验 2: 尾调用示例（C 源码）
└── hello-tail.py        ← 实验 2: Python 加载器 + 链配置
```

---

## 🔬 实验 1：eBPF 中的函数调用

### 1.1 背景

在第四篇中，你的 eBPF 程序都是"一整坨"——一个函数干所有事。但当逻辑变复杂时，你需要函数调用来组织代码。

**eBPF 函数调用的特殊性：**

| 对比项 | 普通 C 函数 | eBPF 函数 |
|--------|-----------|-----------|
| 栈大小 | MB 级 | **512 字节** |
| 调用深度 | 无限制 | **最多 8 层** |
| 内联倾向 | 可选 | **强烈建议 `__always_inline`** |
| 函数指针 | 支持 | ❌ 不支持 |

### 1.2 动手实验

#### 步骤 1：运行程序

```bash
cd /mnt/hgfs/code/05-tail-call
sudo python3 simple-func.py
```

#### 步骤 2：在另一个终端触发事件

```bash
ls -la /tmp
cat /etc/passwd 2>/dev/null
ps aux
```

#### 预期输出

```
============================================================
实验 1: eBPF 函数调用实验
============================================================
监控中... 在另一个终端执行命令观察输出
按 Ctrl+C 退出

[EXEC] PID=12345 UID=1000 COMM=ls FILE=/usr/bin/ls
[EXEC] PID=12346 UID=1000 COMM=cat FILE=/usr/bin/cat
[EXEC] PID=12347 UID=1000 COMM=ps FILE=/usr/bin/ps
```

### 1.3 观察函数调用（核心实验）

不停程序，新开一个终端，用 bpftool 查看函数调用情况：

```bash
# 1. 列出加载的 BPF 程序
sudo bpftool prog list | grep -A 3 execve

# 输出类似:
# 452: kprobe  name syscalls__sys_enter_execve  tag a1b2c3d4e5f6...
#    loaded_at 2026-05-25 15:00:00  uid 0
#    xlated 456B  jited 320B  memlock 4096B
#    ...

# 2. 查看翻译后的字节码（重点关注 CALL 指令）
sudo bpftool prog dump xlated id <上面拿到的ID>

# 重点看有没有 call 指令
```

🧠 **思考问题：** 在输出中搜索 `call` 关键字——你能看到函数调用指令吗？为什么这里没有函数调用栈？

<details>
<summary>💡 点击查看答案</summary>

因为 `fill_proc_info` 被声明为 `__always_inline`，编译器会将它内联展开，不会产生真正的 `call` 指令。试试把 `__always_inline` 改成普通的 `static`，重新编译看看有什么区别。

修改 `simple-func.c` 中 `fill_proc_info` 的声明：
```c
// 把这一行:
static __always_inline void fill_proc_info(struct data_t *data) {

// 改成:
static void fill_proc_info(struct data_t *data) {
```

然后重新运行，再用 `bpftool prog dump xlated` 观察——你会看到 `call` 指令出现。
</details>

### 1.4 512 字节栈的感知实验

eBPF 只有 512 字节栈。写一个"坏"程序看看 verifier 的反应：

```c
// 文件: stack_overflow.c
// 不要运行这个——会 verifier 报错！
struct big_buf {
    char buf[256];
};

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct big_buf a = {};
    struct big_buf b = {};  // 两个 256 字节 = 512 字节
    struct big_buf c = {};  // 第三个已经越界

    // bpf_printk("hello");  // 这里就会触发 verifier 错误
    return 0;
}
```

**结论：** 512 字节的限制意味着你不能在函数调用中层层传大结构体——这就是尾调用存在的意义。

---

## 🔬 实验 2：尾调用（Tail Call）

### 2.1 核心概念

尾调用和普通调用的根本区别：

```
普通函数调用:               尾调用:
                          
main()                    entry()
  ├─> func1()               ├─> handler1() ← 复用 entry 的栈帧
  │    └─> return                └─> handler2() ← 继续复用
  └─> continue                              └─> 程序结束
       ↑ 回到这里继续
```

**尾调用的关键特征：**
- ✅ **不返回**——调用后原程序结束，不会回到调用点
- ✅ **复用栈帧**——不增加栈空间消耗，突破 512 字节限制
- ✅ **原子性**——调用成功则原程序立即终止
- ⚠️ **不能传参**——只能通过 Map 或上下文 `ctx` 传递数据

### 2.2 动手实验

#### 步骤 1：运行完整 3 级链

```bash
sudo python3 hello-tail.py
```

#### 步骤 2：观察输出

新开一个终端，查看 trace_pipe：

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

#### 预期输出（trace_pipe 中）

```
<...>-12345 [001] .... 123456.789012: [ENTRY] pid=12345, entering tail call chain
<...>-12345 [001] .... 123456.789013: [HANDLER1] pid=12345 comm=ls processing...
<...>-12345 [001] .... 123456.789014: [HANDLER2] pid=12345 comm=ls end of chain
```

注意三个输出来自**同一个 PID**，说明它们在同一个上下文链中依次执行。

#### 步骤 3：用 bpftool 观察跳转表

```bash
# 找到 jmp_table
sudo bpftool map list | grep jmp_table

# 假设 ID 是 48
sudo bpftool map dump id 48

# 预期输出:
# key: 01 00 00 00  value: <handler1_fd>
# key: 02 00 00 00  value: <handler2_fd>
# key: 03 00 00 00  value: <fallback_fd>
```

---

### 2.3 实验 2b：观察 Fallback 机制

尾调用的一个强大特性是：**如果目标程序未加载，尾调用静默失败，继续执行原程序**。

这就是 `hello-tail.c` 中 `hello_entry` 函数的结构设计：

```c
int hello_entry(struct pt_regs *ctx) {
    // 尝试尾调用
    bpf_tail_call(ctx, &jmp_table, 1);

    // 如果执行到这里，说明尾调用失败（handler1 没加载）
    // 执行降级逻辑
    bpf_trace_printk("[FALLBACK] tail call failed");
    return 0;
}
```

**动手试试：**

```bash
# 只链 2 级（entry -> handler1，handler2 留空）
sudo python3 hello-tail.py --chain=2
```

#### 预期输出（trace_pipe）：

```
<...>-12345 [001] .... 123456.789012: [ENTRY] pid=12345, entering tail call chain
<...>-12345 [001] .... 123456.789013: [HANDLER1] pid=12345 comm=ls processing...
<...>-12345 [001] .... 123456.789014: [HANDLER1] no handler2, completing
```

对比完整链的输出——`handler2` 没有加载，所以 `handler1` 的降级逻辑被执行。

---

### 2.4 实验 2c：1 级链（完全观察 fallback）

```bash
sudo python3 hello-tail.py --chain=1
```

#### 预期输出：

```
<...>-12345 [001] .... 123456.789012: [ENTRY] pid=12345, entering tail call chain
<...>-12345 [001] .... 123456.789013: [FALLBACK] tail call to handler1 failed
```

`entry` 尝试 `bpf_tail_call(ctx, &jmp_table, 1)`，索引 1 不存在，函数直接返回 `0`（失败），然后执行 `bpf_trace_printk("[FALLBACK] ...")`。

---

## 🧩 实验 3：程序链架构设计（思考 + 动手）

### 3.1 架构对比

| 架构 | 优点 | 缺点 |
|------|------|------|
| 单函数 | 简单、性能好 | 不可扩展、代码耦合 |
| 函数调用 | 代码复用 | 受 512 字节栈限制 |
| **尾调用链** | **突破栈限制、可动态扩展** | 调试困难、不能返回结果 |

### 3.2 设计一个模块化监控链

根据目前学到的知识，你可以这样设计一个容器安全监控程序的架构：

```
                  ┌────────────────────────────┐
                  │  入口程序 (dispatcher)      │
                  │  · 收集事件上下文           │
                  │  · 根据类型分派             │
                  └──────────┬─────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
      ┌────────────┐ ┌────────────┐ ┌────────────┐
      │ 文件监控    │ │ 网络监控    │ │ 进程监控    │
      │ 索引 1     │ │ 索引 2     │ │ 索引 3     │
      └────────────┘ └────────────┘ └────────────┘
              │              │              │
              ▼              ▼              ▼
      ┌────────────┐ ┌────────────┐ ┌────────────┐
      │ 告警输出    │ │ 日志记录    │ │ 审计追踪    │
      │ 索引 4     │ │ 索引 5     │ │ 索引 6     │
      └────────────┘ └────────────┘ └────────────┘
```

**动手挑战：** 修改 `hello-tail.c`，把 `kprobe/sys_execve` 改成通过索引分派到不同处理路径。例如：

```c
// 根据进程名分派到不同处理程序
char comm[16] = {};
bpf_get_current_comm(&comm, sizeof(comm));

if (comm[0] == 's' && comm[1] == 's') {    // sshd
    bpf_tail_call(ctx, &jmp_table, 1);       // 安全监控
} else if (comm[0] == 'n' && comm[1] == 'g') { // nginx
    bpf_tail_call(ctx, &jmp_table, 2);       // Web 监控
} else {
    bpf_tail_call(ctx, &jmp_table, 3);       // 通用监控
}
```

---

## 📊 实验总结

### 实验完成后，你应该理解：

| 概念 | 理解程度检查 |
|------|------------|
| eBPF 512 字节栈限制 | □ 知道为什么有 512B 限制 □ 知道函数调用叠加栈帧 |
| `__always_inline` | □ 知道它的作用 □ 能通过 bpftool 验证内联效果 |
| 尾调用原理 | □ 理解不返回、复用栈帧 □ 知道和普通调用的区别 |
| `prog_array` Map | □ 知道怎么配置 □ 能解释 key/value 含义 |
| Fallback 机制 | □ 知道尾调用失败会静默返回 □ 能利用它设计降级 |

### 排错指南

| 问题 | 原因 | 解决 |
|------|------|------|
| `tail_call` 没生效 | `prog_array` 配置错误 | `sudo bpftool map dump` 检查跳转表 |
| Verifier 报 `stack limit` | 栈使用超过 512B | 减少局部变量，或改用尾调用 |
| `call depth exceeded` | 函数调用超过 8 层 | 减少嵌套，改用 `__always_inline` |
| trace_pipe 无输出 | 没挂到正确的 kprobe | `sudo bpftool prog list` 检查程序是否加载 |
| 权限错误 | 需要 root | 用 `sudo` 运行 |

### 下一步

- **第六篇预告：** eBPF 网络监控（XDP 和 TC），原书第 4 章
- **动手延伸：** 尝试用尾调用重构第四篇的 `hello-perf-plus`，把不同类型的事件分派到不同处理程序

---

## 📖 参考资源

- [BCC Documentation: bpf_tail_call](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#8-bpf_tail_call)
- [内核文档: BPF Tail Calls](https://docs.kernel.org/bpf/classic_vs_extended.html#tail-calls)
- [原书: Learning eBPF Ch.3](https://github.com/lizrice/learning-ebpf)
- Kernel 源码: `include/uapi/linux/bpf.h` 中 `bpf_tail_call` helper 定义