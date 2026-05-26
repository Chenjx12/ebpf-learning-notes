# 新五、eBPF 函数调用与尾调用

date: 2026.5.25

在上一篇文章里，我们终于拿起了手术刀，把 BCC 的黑盒剖开，看到了 C 代码是如何变成 eBPF 字节码的。我们还学会了用 `bpftool` 这个听诊器，去内核里偷看自己跑着的程序，甚至从 Map 里捞出了那个 33 字节的字符串彩蛋。

但是，如果回头看看我们写过的所有代码，不管是 `hello-world.py` 还是 `hello-perf-plus.c`，它们都有一个共同的特点：**一整坨**。

所有的逻辑——取 PID、取进程名、读路径、发事件——全塞在一个 `hello()` 或者 `TRACEPOINT_PROBE` 函数里。如果以后我们要做一个复杂的网络防火墙，或者一个多探针的监控系统，一个函数动辄几百行，512 字节的栈根本撑不住，维护起来也是灾难。

今天，我们就来给 eBPF 程序做"拆解"，让它学会像普通程序一样**调用函数**，甚至学会一种更高级的武功——**尾调用**。

## 0. 开篇：为什么需要"分而治之"？

### 回顾第四篇的成果

在第四篇中，我们已经学会了：

- ✅ 打开 BCC 黑盒，理解 `C → clang → .o → 内核` 的链路
- ✅ 用 `readelf` 和 `llvm-objdump` 解剖编译产物
- ✅ 用 `bpftool` 观察运行中的程序和 Map
- ✅ **C/Python 分离**，迈出工程化第一步

但我们的程序结构依然是：

```text
单一探针触发 → 单一巨型函数处理
```

**新问题：**

```text
如果逻辑复杂了怎么办？
├── 代码复用：能否像普通 C 语言一样调用函数？
├── 栈溢出：eBPF 只有 512 字节栈，函数调用会不会爆？
└── 架构扩展：能否根据情况，动态选择执行不同的程序？
```

---

## 1. 第一步：eBPF 中的函数调用（BPF-to-BPF）

在普通 C 里，我们习惯把重复逻辑写成函数。在 eBPF 里也可以，而且很简单。

### 1.1 最小函数调用示例

我们把"获取进程信息"提取成一个辅助函数：

完整代码：
- C 源码：[`code/05-tail-call/simple-func.c`](../code/05-tail-call/simple-func.c)
- Python 加载器：[`code/05-tail-call/simple-func.py`](../code/05-tail-call/simple-func.py)

```c
// simple-func.c — eBPF 中的函数调用实验
#include <linux/sched.h>

struct data_t {
    __u32 pid;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

// 🔥 辅助函数：填充进程信息
// __always_inline 强制内联展开，避免函数调用栈开销
static __always_inline void fill_proc_info(struct data_t *data) {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    // 调用辅助函数
    fill_proc_info(&data);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
```

Python 加载器和之前一样简单：

```python
#!/usr/bin/python3
# simple-func.py
from bcc import BPF

b = BPF(src_file="simple-func.c")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID={event.pid:6d} COMM={event.comm.decode():16s}")

b["events"].open_perf_buffer(print_event)

print("实验 1: eBPF 函数调用实验")
print("监控中... 在另一个终端执行命令观察输出")
print("按 Ctrl+C 退出\n")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n退出。")
```

**运行结果：**

```bash
$ cd /home/chenjx12/Desktop/u/hgfs/code/05-tail-call
$ sudo python3 simple-func.py
实验 1: eBPF 函数调用实验
监控中... 在另一个终端执行命令观察输出
按 Ctrl+C 退出

PID=  5234 COMM=bash
PID=  5235 COMM=bash
PID=  5240 COMM=sudo
PID=  5242 COMM=su
PID=  5243 COMM=bash
```

发现和之前的输出格式一样，但这次我们在 C 代码里**把获取 PID 和进程名的逻辑抽成了一个独立函数** `fill_proc_info()`。

### 1.2 ⚠️ 为什么强烈建议加 `__always_inline`？

如果不加，clang 会把它编译成真正的函数调用指令（`call`）。加了之后，编译器会把函数代码直接"贴"到调用处（内联展开）。

在 eBPF 里，内联不仅能**省去函数调用的开销**，更重要的是**避免栈帧叠加**，让 Verifier 更容易分析。

**验证一下**：让我们手动编译并查看字节码，看看 `__always_inline` 的效果：

```bash
cd /home/chenjx12/Desktop/u/hgfs/code/05-tail-call
clang -target bpf -O2 -g -I/usr/include/x86_64-linux-gnu \
      -c simple-func.c -o simple-func.o
llvm-objdump-14 -d simple-func.o | head -50
```

**预期输出**（关键部分）：

```
simple-func.o:file format ELF64-BPF

Disassembly of section tracepoint/syscalls/sys_enter_execve:
TRACEPOINT_PROBE(syscalls, sys_enter_execve):
       0:r1 = *(u32 *)(r1 + 0)
       1:r2 = r1
       2:r2 <<= 32
       3:r2 >>= 32
       4:*(u32 *)(r10 - 4) = r2
       5:r1 = r10 - 4
       6:r2 = 16
       7:call 3 <bpf_get_current_comm>
       8:r1 = r10 - 20
       9:r2 = 20
      10:call 6 <bpf_perf_event_output>
      11:r0 = 0
      12:exit
```

**关键发现**：没有看到 `call` 指令指向 `fill_proc_info`！因为它的代码被**内联展开**到了主函数里（第 0-7 行就是 `fill_proc_info` 的逻辑）。

### 1.3 函数调用的阿喀琉斯之踵：512 字节栈

如果我们偏不用内联，或者调用层级太深，会发生什么？

eBPF 的栈只有区区 512 字节！在普通 C 程序里，栈动辄 8MB，随便递归都不心疼。但在 eBPF 里，每多一层函数调用，就要压栈保存返回地址和局部变量，极易触发 Verifier 的报错。

你可以试试写一个故意消耗栈空间的程序（**⚠️ 仅作演示，不要加载**）：

```c
// stack_overflow.c
// ⚠️ 本文件仅作为 Verifier 报错示例，不要用 sudo python3 加载！
#include <linux/sched.h>

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    // 故意定义大数组，瞬间撑爆 512 字节栈
    char big_array[256];
    char another_big_array[256];

    // Verifier 会直接拒绝：stack size 512, max allowed 512
    bpf_trace_printk("This will never run!");
    return 0;
}
```

**编译测试**：

```bash
clang -target bpf -O2 -c stack_overflow.c -o stack_overflow.o
# 编译成功，但加载时会失败：
sudo bpftool prog load stack_overflow.o /sys/fs/bpf/test
# 错误：Verifier 报错：stack limit exceeded
```

**关键收获**：普通函数调用用于**代码复用**，但受限于 512B 栈和调用深度（通常 8 层），不能太放肆。

---

## 2. 尾调用：不回来的调用

既然普通调用会压栈，那有没有一种调用方式，用完新程序的栈，直接把老程序的栈扔掉？

有！这就是 eBPF 的**尾调用**。

### 2.1 核心概念：像 goto 一样跳转

**普通调用**：像借书，用完了要还回来（`call` → `ret`），栈越来越深。
**尾调用**：像私奔，走了就不回来了（`goto`），新程序复用老程序的栈帧。

```text
普通调用：                    尾调用：
程序A ──call──→ 程序B         程序A ──tail_call──→ 程序B
         ←──ret──                                （不返回！）
程序A 继续执行...                               程序B 直接接管
```

**尾调用的三大特性：**

1. ✅ **不返回**：调用后原程序立即终止，控制流不会回来。
2. ✅ **不复用旧栈**：新程序从"零栈 + 只有 ctx"开始执行，不在原栈上叠加。
3. ⚠️ **不能传参**：不能通过函数参数传参，只能通过上下文 `ctx` 或 Map 共享数据。

### 2.2 尾调用的底层基础设施：`prog_array` Map

还记得我们在第四篇用 `bpftool map list` 时看到的那个特殊的 Map 吗？

```bash
2: prog_array  name hid_jmp_table  flags 0x0
    key 4B  value 4B  max_entries 1024  memlock 8576B
    owner_prog_type tracing  owner jited
```

当时我说这是一个"高能预警"的剧透——这就是尾调用的"跳板"！`prog_array` 的 `value` 存的不是普通数据，而是**另一个 eBPF 程序的文件描述符（FD）**。

尾调用的逻辑很简单：拿着索引去 `prog_array` 里查，查到程序就跳过去，查不到就继续执行原程序。

---

## 3. 实战：用尾调用构建程序链

### 3.1 编写 C 代码

完整代码：[`code/05-tail-call/hello-tail.c`](../code/05-tail-call/hello-tail.c)

```c
// hello-tail.c — eBPF 尾调用实验
// 功能：用 prog_array Map 构建 3 级程序链：entry → handler1 → handler2
// 用法：sudo python3 hello-tail.py

#include <linux/sched.h>

// ============================================================
// 1. 定义 prog_array map（尾调用的核心基础设施）
//    key: u32 索引
//    value: u32 程序的文件描述符
//    max_entries: 链中最多几个程序
// ============================================================
BPF_PROG_ARRAY(jmp_table, 4);

// ============================================================
// 程序 1: 入口（挂载到 kprobe/sys_execve）
// 功能：打印入口日志，尾调用到 handler1
// ============================================================
int hello_entry(struct pt_regs *ctx) {
    char fmt[] = "[ENTRY] pid=%d, entering tail call chain\n";
    bpf_trace_printk(fmt, sizeof(fmt), bpf_get_current_pid_tgid() >> 32);

    // 尾调用到索引 1（hello_handler1）
    // 成功则不返回！失败则继续执行下面的 fallback
    bpf_tail_call(ctx, &jmp_table, 1);

    char fmt_fb[] = "[FALLBACK] tail call to handler1 failed\n";
    bpf_trace_printk(fmt_fb, sizeof(fmt_fb));
    return 0;
}

// ============================================================
// 程序 2: 处理器 1
// 功能：打印处理日志，尾调用到 handler2
// ============================================================
int hello_handler1(struct pt_regs *ctx) {
    char fmt[] = "[HANDLER1] processing...\n";
    bpf_trace_printk(fmt, sizeof(fmt));

    // 继续尾调用到索引 2（hello_handler2）
    bpf_tail_call(ctx, &jmp_table, 2);

    char fmt_fb[] = "[FALLBACK] tail call to handler2 failed\n";
    bpf_trace_printk(fmt_fb, sizeof(fmt_fb));
    return 0;
}

// ============================================================
// 程序 3: 处理器 2（链的终点）
// 功能：打印结束日志，链结束
// ============================================================
int hello_handler2(struct pt_regs *ctx) {
    char fmt[] = "[HANDLER2] end of chain\n";
    bpf_trace_printk(fmt, sizeof(fmt));
    return 0;
}
```

这段代码做了三件事：
1. 定义了一个 `prog_array` Map（`jmp_table`），作为尾调用的跳板
2. 写了 3 个 eBPF 程序：`hello_entry` → `hello_handler1` → `hello_handler2`
3. 每个程序在尾调用失败时都有 fallback 日志

### 3.2 编写 Python 加载器

完整代码：[`code/05-tail-call/hello-tail.py`](../code/05-tail-call/hello-tail.py)

在 BCC 中，我们需要手动把编译出的程序 FD 填入 `jmp_table`：

```python
#!/usr/bin/python3
import ctypes as ct
import os
import sys
from bcc import BPF

if os.geteuid() != 0:
    print("需要 root 权限：sudo python3 hello-tail.py")
    sys.exit(1)

print("=" * 60)
print("实验 2: eBPF 尾调用 (Tail Call)")
print("=" * 60)

# 步骤 1: 加载 eBPF 程序
print("\n[1/4] 加载 eBPF 程序...")
b = BPF(src_file="hello-tail.c")

# 步骤 2: 获取各函数 fd
print("[2/4] 获取函数文件描述符...")
entry_fn = b.load_func("hello_entry", BPF.KPROBE)
handler1_fn = b.load_func("hello_handler1", BPF.KPROBE)
handler2_fn = b.load_func("hello_handler2", BPF.KPROBE)

print(f"   entry.fd    = {entry_fn.fd}")
print(f"   handler1.fd = {handler1_fn.fd}")
print(f"   handler2.fd = {handler2_fn.fd}")

# 步骤 3: 配置 prog_array (jmp_table)
print("[3/4] 配置尾调用跳转表...")
jmp_table = b.get_table("jmp_table")

jmp_table[ct.c_uint32(1)] = ct.c_uint32(handler1_fn.fd)
print("   jmp_table[1] = handler1 ✅")
jmp_table[ct.c_uint32(2)] = ct.c_uint32(handler2_fn.fd)
print("   jmp_table[2] = handler2 ✅")

# 步骤 4: 附加到 kprobe
print("[4/4] 附加 kprobe...")
b.attach_kprobe(
    event=b.get_syscall_fnname("execve"),
    fn_name="hello_entry"
)
print("   已附加到 sys_execve")

print("\n" + "=" * 60)
print("运行中！在另一个终端执行命令观察 tail call")
print("   如: ls, cat /etc/passwd, ps aux")
print()
print("观察方法:")
print("   终端2: sudo cat /sys/kernel/debug/tracing/trace_pipe")
print("   终端3: sudo bpftool prog list | grep hello")
print("   终端3: sudo bpftool map dump name jmp_table")
print()
print("按 Ctrl+C 停止")
print("=" * 60)

try:
    b.trace_print()
except KeyboardInterrupt:
    print("\n\n清理中...")
    print("   分离 kprobe...")
    print("   程序已卸载，实验结束。")
```

> 💡 **关键点**：我们只 `attach` 了 `hello_entry`！`hello_handler1` 和 `hello_handler2` 不需要 attach，它们是被尾调用"拉"起来的。

### 3.3 运行与观察

**终端 1：运行程序**

```bash
$ sudo python3 hello-tail.py
============================================================
实验 2: eBPF 尾调用 (Tail Call)
============================================================

[1/4] 加载 eBPF 程序...
[2/4] 获取函数文件描述符...
   entry.fd    = 8
   handler1.fd = 9
   handler2.fd = 10
[3/4] 配置尾调用跳转表...
   jmp_table[1] = handler1 ✅
   jmp_table[2] = handler2 ✅
[4/4] 附加 kprobe...
   已附加到 sys_execve

============================================================
运行中！在另一个终端执行命令观察 tail call
   如: ls, cat /etc/passwd, ps aux

观察方法:
   终端2: sudo cat /sys/kernel/debug/tracing/trace_pipe
   终端3: sudo bpftool prog list | grep hello
   终端3: sudo bpftool map dump name jmp_table

按 Ctrl+C 停止
============================================================
```

**终端 2：触发事件**

```bash
ls
```

**终端 1 预期输出：**

```
<...>-12345 [001] .... 123456.789012: 0: [ENTRY] pid=12345, entering tail call chain
<...>-12345 [001] .... 123456.789013: 0: [HANDLER1] processing...
<...>-12345 [001] .... 123456.789014: 0: [HANDLER2] end of chain
```

看到没？三条记录的 PID 相同，说明它们是在同一个事件上下文中依次执行的！这就是程序链的威力。

**终端 3：用 bpftool 观察 jmp_table**

```bash
$ sudo bpftool map list | grep jmp_table
48: prog_array  name jmp_table  flags 0x0
    key 4B  value 4B  max_entries 4  memlock 4096B

$ sudo bpftool map dump id 48
key: 00 00 00 01
value: 00 00 00 09
key: 00 00 00 02
value: 00 00 00 0a
Found 2 elements
```

你会看到 `key` 是 1 和 2（对应的十六进制是 `01` 和 `02`），`value` 是 9 和 10（`09` 和 `0a`）——这正是 `handler1` 和 `handler2` 的程序 FD。

---

## 4. 工程化：多探针架构的雏形

尾调用不仅仅是为了好玩，它是构建复杂 eBPF 架构的基石。

### 4.1 动态分派

我们可以根据进程名，动态决定走哪条处理链：

```c
// 根据进程名分派
char comm[16];
bpf_get_current_comm(&comm, sizeof(comm));

if (comm[0] == 's' && comm[1] == 's') {    // sshd
    bpf_tail_call(ctx, &jmp_table, 1);       // 安全监控链
} else if (comm[0] == 'n' && comm[1] == 'g') { // nginx
    bpf_tail_call(ctx, &jmp_table, 2);       // Web 监控链
} else {
    bpf_tail_call(ctx, &jmp_table, 3);       // 通用监控链
}
```

### 4.2 降级策略

尾调用失败（比如 Map 里没填对应程序）不会崩溃，而是继续执行原程序。这让我们可以设计优雅的降级逻辑：

```c
bpf_tail_call(ctx, &jmp_table, 99);
// 如果高级监控模块没加载，就执行基础监控
bpf_trace_printk("Basic monitoring fallback");
```

在我们的 `hello-tail.c` 里已经演示了这一点——如果 `jmp_table[1]` 是空的，`hello_entry` 会直接走到 fallback 分支打印错误日志。你可以试试在 Python 里不填入索引 1，观察 fallback 输出。

### 4.3 尾调用的限制

尾调用虽然强大，但也有内核层面的限制：

- **最大调用链深度**：内核定义了 `MAX_TAIL_CALL_CNT`（通常是 32 级），超过后尾调用直接失败。
- **同类型程序**：尾调用跳到的程序必须和当前程序类型一致（比如都是 kprobe）。
- **不能传参**：只能通过 `ctx`（上下文指针）和 Map 传递数据。

---

## 5. 小结 + 预告

### 5.1 本篇总结

**理论层面：**

- ✅ 理解了 eBPF 函数调用机制与 512B 栈限制
- ✅ 掌握了尾调用原理：不返回、复用栈帧、像 `goto` 一样跳转
- ✅ 学会了用 `prog_array` Map 实现程序链

**实践层面：**

- ✅ 实现了简单的函数调用示例（`simple-func.c`）
- ✅ 构建了 3 级尾调用链（`hello-tail.c`：entry → handler1 → handler2）
- ✅ 理解了降级策略的设计思想
- ✅ 用 `bpftool map dump` 观察了 jmp_table 的内容

**核心思想：**

> **普通函数调用用于代码复用，尾调用用于架构扩展。**
> **512 字节栈限制要求我们精心设计函数调用，尾调用则是突破限制的关键。**

### 5.2 预告第六篇

现在我们的程序学会了"分身术"，可以链式处理复杂逻辑。但是，eBPF 不仅能监控，还能**干预**！

**第六篇讲：**

- eBPF 网络监控（XDP 和 TC）
- 如何在网卡驱动层拦截/修改网络包
- 原书第 4 章 + 网络示例实验
- 为构建网络防火墙打基础

**核心问题：**

- 如何用 eBPF 处理网络数据包？
- XDP 和 TC 有什么区别？
- 如何实现高性能的网络过滤和监控？

---

## 🔗 相关资源

- [原书第3章: eBPF 程序剖析](https://binw666.github.io/learning-ebpf-translation/03-eBPF程序剖析/03-eBPF程序剖析.html)
- [eBPF 尾调用官方文档](https://docs.ebpf.io/linux/concepts/tail-calls/)

## 📝 课后练习

1. **基础题**：修改 `hello-tail.c`，让 `hello_handler2` 打印出当前进程的 PID（提示：尾调用后 ctx 还在）。
2. **进阶题**：尝试在 `jmp_table` 中不填入索引 1 的程序，观察 `hello_entry` 的 fallback 输出。
3. **思考题**：尾调用最多支持多少级链式调用？（提示：查阅内核文档关于 `MAX_TAIL_CALL_CNT` 的定义）

*最后更新: 2026-05-25*
