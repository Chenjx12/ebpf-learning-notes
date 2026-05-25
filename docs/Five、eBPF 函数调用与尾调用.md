# Five、eBPF 函数调用与尾调用

> date: 2026.5.25

在上一篇文章里，我们终于拿起了手术刀，把 BCC 的黑盒剖开，看到了 C 代码是如何变成 eBPF 字节码的。我们还学会了用 `bpftool` 这个听诊器，去内核里偷看自己跑着的程序，甚至从 Map 里捞出了那个 33 字节的字符串彩蛋。

但是，如果你回头看看我们写过的所有代码，不管是 `hello-world.py` 还是 `hello-perf-plus.c`，它们都有一个共同的特点：**一整坨**。

所有的逻辑——取 PID、取进程名、读路径、发事件——全塞在一个 `hello()` 或者 `TRACEPOINT_PROBE` 函数里。如果以后我们要做一个复杂的网络防火墙，或者一个多探针的监控系统，一个函数动辄几百行，512 字节的栈根本撑不住，维护起来也是灾难。

今天，我们就来给 eBPF 程序做“拆解”，让它学会像普通程序一样**调用函数**，甚至学会一种更高级的武功——**尾调用**。

## 0. 开篇：为什么需要“分而治之”？

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

## 1. 尝试复用：eBPF 中的函数调用（BPF-to-BPF）

### 1.1 把重复逻辑提取成函数

在普通 C 里，我们习惯把重复逻辑写成函数。在 eBPF 里也可以，而且很简单。

我们基于第四篇的 `hello-perf-plus.c`，把“获取进程信息”提取出来：

```c
// simple-func.c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

// 🔥 提取的辅助函数
static __always_inline void get_proc_info(struct data_t *data) {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    
    // 调用辅助函数
    get_proc_info(&data);
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
```

**⚠️ 为什么强烈建议加 `__always_inline`？**

如果不加，clang 会把它编译成真正的函数调用指令（`call`）。加了之后，编译器会把函数代码直接“贴”到调用处（内联展开）。
在 eBPF 里，内联不仅能**省去函数调用的开销**，更重要的是**避免栈帧叠加**，让 Verifier 更容易分析。

### 1.2 函数调用的阿喀琉斯之踵：512 字节栈

如果我们偏不用内联，或者调用层级太深，会发生什么？

eBPF 的栈只有区区 512 字节！在普通 C 程序里，栈动辄 8MB，随便递归都不心疼。但在 eBPF 里，每多一层函数调用，就要压栈保存返回地址和局部变量，极易触发 Verifier 的报错。

你可以试试写一个故意消耗栈空间的程序（**⚠️ 仅作演示，不要加载**）：

```c
// stack_overflow.c
// ⚠️ 本文件仅作为 Verifier 报错示例，不要用 sudo python3 加载！
#include <uapi/linux/ptrace.h>

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    // 故意定义大数组，瞬间撑爆 512 字节栈
    char big_array[256];
    char another_big_array[256];
    
    // Verifier 会直接拒绝：stack size 512, max allowed 512
    bpf_trace_printk("This will never run!");
    return 0;
}
```

**关键收获**：普通函数调用用于**代码复用**，但受限于 512B 栈和调用深度（通常 8 层），不能太放肆。

## 2. 尾调用：不回来的调用

既然普通调用会压栈，那有没有一种调用方式，用完新程序的栈，直接把老程序的栈扔掉？

有！这就是 eBPF 的**尾调用**。

### 2.1 核心概念：像 goto 一样跳转

**普通调用**：像借书，用完了要还回来（`call` -> `ret`），栈越来越深。
**尾调用**：像私奔，走了就不回来了（`goto`），新程序复用老程序的栈帧。

bpf_tail_callbpf_tail_call不返回程序A程序B程序C结束

**尾调用的三大特性：**

1. ✅ **不返回**：调用后原程序立即终止，控制流不会回来。
2. ✅ **复用上下文**：新程序从“零栈 + 只有 ctx”开始执行，不在原栈上叠加。
3. ⚠️ **不能传参**：不能通过函数参数传参，只能通过上下文 `ctx` 或 Map 共享数据。

### 2.2 尾调用的底层基础设施：`prog_array` Map

还记得我们在第四篇用 `bpftool map list` 时看到的那个特殊的 Map 吗？

```bash
2: prog_array name hid_jmp_table flags 0x0
	key 4B  value 4B  max_entries 1024  memlock 8576B
```

当时我说这是一个彩蛋，这就是尾调用的“跳板”！`prog_array` 的 `value` 存的不是普通数据，而是**另一个 eBPF 程序的文件描述符（FD）**。

尾调用的逻辑很简单：拿着索引去 `prog_array` 里查，查到程序就跳过去，查不到就继续执行原程序。

## 3. 实战：用尾调用构建程序链

### 3.1 编写 C 代码 (`hello-tail.c`)

我们写一个入口程序，让它根据情况，尾调用到不同的处理程序：

```c
// hello-tail.c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 1. 定义 prog_array Map
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

// 许可证
char LICENSE[] SEC("license") = "GPL";

// 2. 入口程序
SEC("kprobe/sys_execve")
int hello_entry(struct pt_regs *ctx) {
    char fmt1[] = "[ENTRY] pid=%d, entering tail call chain\n";
    bpf_trace_printk(fmt1, sizeof(fmt1), bpf_get_current_pid_tgid() >> 32);
    
    // 🔥 关键：发起尾调用，跳转到索引 1 的程序
    bpf_tail_call(ctx, &jmp_table, 1);
    
    // 如果尾调用失败（比如索引 1 没有程序），会执行这里的降级逻辑
    char fmt_fallback[] = "[ENTRY Fallback] tail call failed!\n";
    bpf_trace_printk(fmt_fallback, sizeof(fmt_fallback));
    return 0;
}

// 3. 处理程序 1
SEC("kprobe/sys_execve")
int hello_handler1(struct pt_regs *ctx) {
    char fmt2[] = "[HANDLER1] processing...\n";
    bpf_trace_printk(fmt2, sizeof(fmt2));
    
    // 可以继续尾调用到下一个程序
    bpf_tail_call(ctx, &jmp_table, 2);
    return 0;
}

// 4. 处理程序 2
SEC("kprobe/sys_execve")
int hello_handler2(struct pt_regs *ctx) {
    char fmt3[] = "[HANDLER2] end of chain\n";
    bpf_trace_printk(fmt3, sizeof(fmt3));
    return 0;
}
```

### 3.2 编写 Python 加载器 (`hello-tail.py`)

在 BCC 中，我们需要手动把编译出的程序 FD 填入 `jmp_table`：

```python
#!/usr/bin/python3
from bcc import BPF

b = BPF(src_file="hello-tail.c")

# 1. 获取所有函数对象
entry_fn = b.load_func("hello_entry", BPF.KPROBE)
handler1_fn = b.load_func("hello_handler1", BPF.KPROBE)
handler2_fn = b.load_func("hello_handler2", BPF.KPROBE)

# 2. 获取 jmp_table 并填充跳板
jmp_table = b.get_table("jmp_table")
jmp_table[c_uint32(0)] = c_uint32(entry_fn.fd)   # 索引 0 (可选)
jmp_table[c_uint32(1)] = c_uint32(handler1_fn.fd) # 索引 1 -> handler1
jmp_table[c_uint32(2)] = c_uint32(handler2_fn.fd) # 索引 2 -> handler2

# 3. 只附加入口程序！后续程序由尾调用自动触发
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello_entry")

print("Tracing execve with tail calls... Hit Ctrl-C to end.")
b.trace_print()
```

> 💡 **关键点**：我们只 `attach` 了 `hello_entry`！`hello_handler1` 和 `hello_handler2` 不需要 attach，它们是被尾调用“拉”起来的。

### 3.3 运行与观察

**终端 1：运行程序**

```bash
sudo python3 hello-tail.py
```

**终端 2：触发事件**

```bash
ls
```

**终端 1 预期输出：**

```bash
<...>-12345 [001] .... 123456.789012: [ENTRY] pid=12345, entering tail call chain
<...>-12345 [001] .... 123456.789013: [HANDLER1] processing...
<...>-12345 [001] .... 123456.789014: [HANDLER2] end of chain
```

看到没？三条记录的 PID 相同，说明它们是在同一个事件上下文中依次执行的！这就是程序链的威力。

**终端 3：用 bpftool 观察 jmp_table**

```bash
sudo bpftool map list | grep jmp_table
# 假设 ID 是 48

sudo bpftool map dump id 48
```

你会看到 `key` 是 1 和 2，`value` 是一串数字（那是程序的 FD）。

## 4. 工程化：多探针架构的雏形

尾调用不仅仅是为了好玩，它是构建复杂 eBPF 架构的基石。

### 4.1 动态分派

我们可以根据包类型或进程名，动态决定走哪条处理链：

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

## 5. 小结 + 预告

### 5.1 本篇总结

**理论层面：**

- ✅ 理解了 eBPF 函数调用机制与 512B 栈限制
- ✅ 掌握了尾调用原理：不返回、不复用旧栈、像 `goto` 一样跳转
- ✅ 学会了用 `prog_array` Map 实现程序链

**实践层面：**

- ✅ 实现了简单的函数调用和尾调用示例
- ✅ 构建了可扩展的链式 eBPF 程序
- ✅ 理解了降级策略的设计思想

**核心思想：**

> **普通函数调用用于代码复用，尾调用用于架构扩展。**
> **512字节栈限制要求我们精心设计函数调用，尾调用则是突破限制的关键。**

### 5.2 预告第六篇

现在我们的程序学会了“分身术”，可以链式处理复杂逻辑。但是，eBPF 不仅能监控，还能**干预**！

**第六篇讲：**

- eBPF 网络监控（XDP 和 TC）
- 如何在网卡驱动层拦截/修改网络包
- 原书第 4 章 + 网络示例实验
- 为构建网络防火墙打基础

**核心问题：**

- 如何用 eBPF 处理网络数据包？
- XDP 和 TC 有什么区别？
- 如何实现高性能的网络过滤和监控？

## 🔗 相关资源

- [原书第3章: eBPF 程序剖析](https://binw666.github.io/learning-ebpf-translation/03-eBPF程序剖析/03-eBPF程序剖析.html)
- [eBPF 尾调用官方文档](https://docs.ebpf.io/linux/concepts/tail-calls/)

## 📝 课后练习

1. **基础题**：修改 `hello-tail.c`，让 `hello_handler2` 打印出当前进程的 PID（提示：尾调用后 ctx 还在）。
2. **进阶题**：尝试在 `jmp_table` 中不填入索引 1 的程序，观察 `hello_entry` 的 fallback 输出。
3. **思考题**：尾调用最多支持多少级链式调用？（提示：查阅内核文档关于 `MAX_TAIL_CALL_CNT` 的定义）

*最后更新: 2026-05-25*