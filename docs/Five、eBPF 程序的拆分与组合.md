# **Five、eBPF 程序的拆分与组合**

## 开篇

- 回顾第四篇：我们解剖了 BCC 的黑盒，学会了手动编译和 C/Python 分离

- 引出新问题：

  单函数程序如何应对复杂逻辑？

  - 安全检测需要多探针（execve / openat / connect）
  - 代码复用（公共数据提取逻辑）
  - 512字节栈限制下的函数调用问题

## 核心内容结构

```bash
1. 从“一坨代码”到“模块化”：为什么需要函数调用？
2. BPF-to-BPF 函数调用：有去有回的调用
3. 尾调用：不回来的跳转
4. 两种调用的实战对比
5. 工程化：用尾调用搭建多探针架构
```

## 核心知识点对比表



| 维度         | BPF-to-BPF 调用             | 尾调用                           |
| ------------ | --------------------------- | -------------------------------- |
| **本质**     | 函数级调用                  | 程序级跳转                       |
| **是否返回** | ✅ 会返回到调用点            | ❌ 不返回，复用栈帧               |
| **栈空间**   | 需要保存现场（压栈）        | 复用当前栈帧（不压栈）           |
| **调用层级** | 受 512B 栈限制，层级有限    | 最多 8 层（内核限制）            |
| **实现方式** | `__attribute__((noinline))` | `bpf_tail_call(ctx, map, index)` |
| **适用场景** | 抽取公共逻辑（工具函数）    | 程序分派、策略路由               |
| **BCC 支持** | 有限（内联处理）            | ✅ 完整支持                       |

## 代码比对案例1：BPF-to-BPF 调用（工具函数抽离）

### bpf2bpf：函数调用

通过 BCC，我们**永远看不到** BPF-to-BPF 的 `call` 指令。这是 BCC 的根本限制。

原书《Learning eBPF》第3章原文：

> “At the time of this writing, the BCC framework doesn’t support BPF-to-BPF calls. Any function you define gets inlined into the main program.”

但这不意味着我们**看不了** BPF-to-BPF 调用。解决方法是：**绕过 BCC，直接用 clang 编译。**

#### 一、为什么 BCC 看不到 BPF-to-BPF 调用？

```bash
BCC 的编译流程：
  C 代码 → BCC 预处理（强制内联所有函数）→ clang 编译 → 字节码（没有 call 指令）

直接 clang 的编译流程：
  C 代码 → clang 编译（尊重 noinline）→ 字节码（有 call 指令！）
```

BCC 在把 C 代码交给 clang 之前，会做一轮预处理：**把所有函数定义都内联展开**。所以无论我们加不加 `noinline`，BCC 的输出里都没有函数调用。

#### 二、用 clang 直接编译，看到真正的 BPF-to-BPF 调用

步骤 1：创建 C 文件 `bpf2bpf.c`

```c
// bpf2bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// 🔥 关键：noinline 让 clang 生成真正的函数调用
static __attribute__((noinline)) int get_pid(void) {
    return bpf_get_current_pid_tgid() >> 32;
}

SEC("kprobe/sys_execve")
int hello(struct pt_regs *ctx) {
    int pid = get_pid();  // 这里会生成 call 指令
    char fmt[] = "hello pid=%d";
    bpf_trace_printk(fmt, sizeof(fmt), pid);
    return 0;
}
```

步骤 2：用 clang 直接编译

```bash
clang -target bpf -O2 -g \
  -I/usr/include/x86_64-linux-gnu \
  -c bpf2bpf.c -o bpf2bpf.o
```

**注意：这里不会报 `__noinline__` 的错！** 因为直接用 clang 编译时，没有 BCC 注入的内核头文件冲突。`__attribute__((noinline))` 是 clang 原生支持的。

步骤 3：查看字节码

```bash
chenjx12@learning-ebpf:~/Desktop/u/hgfs/code/05-tail-call$ llvm-objdump-14 -d bpf2bpf.o

bpf2bpf.o:	file format elf64-bpf

Disassembly of section .text:

0000000000000000 <get_pid>:
       0:	85 00 00 00 0e 00 00 00	call 14        # 调用 helper #14 = bpf_get_current_pid_tgid
       1:	77 00 00 00 20 00 00 00	r0 >>= 32      # 右移32位取PID
       2:	95 00 00 00 00 00 00 00	exit           # 返回，结果在 r0

Disassembly of section kprobe/sys_execve:

0000000000000000 <hello>:
       0:	85 10 00 00 ff ff ff ff	call -1                     #  这就是关键
       1:	b7 01 00 00 64 3d 25 64	r1 = 1680162148
       2:	63 1a f8 ff 00 00 00 00	*(u32 *)(r10 - 8) = r1
       3:	18 01 00 00 68 65 6c 6c 00 00 00 00 6f 20 70 69	r1 = 7597608234306528616 ll
       5:	7b 1a f0 ff 00 00 00 00	*(u64 *)(r10 - 16) = r1
       6:	b7 01 00 00 00 00 00 00	r1 = 0
       7:	73 1a fc ff 00 00 00 00	*(u8 *)(r10 - 4) = r1
       8:	bf a1 00 00 00 00 00 00	r1 = r10
       9:	07 01 00 00 f0 ff ff ff	r1 += -16
      10:	b7 02 00 00 0d 00 00 00	r2 = 13
      11:	bf 03 00 00 00 00 00 00	r3 = r0                     # r0 = get_pid() 的返回值
      12:	85 00 00 00 06 00 00 00	call 6                      # 调用 bpf_trace_printk
      13:	b7 00 00 00 00 00 00 00	r0 = 0
      14:	95 00 00 00 00 00 00 00	exit
```

**我们可以看到真正的 BPF-to-BPF 调用！**

#### 逐行解释

指令 0：`call -1` —— BPF-to-BPF 的核心

```bash
0:  85 10 00 00 ff ff ff ff  call -1
```

**为什么是 `-1`？** 因为这是 `.o` 文件（编译产物），还没经过链接。`-1`（`0xffffffff`）是一个占位符，表示"目标地址待定"。当程序加载进内核时，加载器会把它**重定位**成 `get_pid` 的实际偏移地址。

**`0x10` 是什么意思？** 第二个字节的 `0x10` 表示这是一个 **BPF-to-BPF 调用**（而非 helper 函数调用）。这是区分两种 `call` 的关键：

| 指令      | 类型           | 目标                                           |
| --------- | -------------- | ---------------------------------------------- |
| `call 6`  | Helper 调用    | 内核白名单函数 #6（bpf_trace_printk）          |
| `call 14` | Helper 调用    | 内核白名单函数 #14（bpf_get_current_pid_tgid） |
| `call -1` | **BPF-to-BPF** | 你自己写的 `get_pid()` 函数                    |

指令 1-10：构建格式化字符串 + 准备参数

```
1:  r1 = 1680162148          # "d=%" 的部分（小端序）
2:  *(u32 *)(r10 - 8) = r1   # 存入栈
3:  r1 = 7597608234306528616  # "hello pi" 的部分
5:  *(u64 *)(r10 - 16) = r1   # 存入栈
6:  r1 = 0
7:  *(u8 *)(r10 - 4) = r1    # NULL 终止符
8:  r1 = r10
9:  r1 += -16                # r1 指向字符串起始
10: r2 = 13                   # 字符串长度
11: r3 = r0                   # 🔥 r0 = get_pid() 的返回值！作为 %d 的参数
12: call 6                    # bpf_trace_printk(fmt, size, pid)
```

**指令 11 是关键连接点**：`r3 = r0`，把 `get_pid()` 的返回值从 `r0` 拷贝到 `r3`，作为 `bpf_trace_printk` 的第三个参数（对应格式字符串里的 `%d`）。



### 内联代码：修改上一篇的hello-perf-plus

`05-calls/hello-bpf2bpf.c`

```c
// hello-bpf2bpf.c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(events);

// ✅ 用 __always_inline 内联它，但代码组织上仍然是"函数"
static __always_inline void get_common_info(struct data_t *data) {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() >> 32;
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    
    get_common_info(&data);
    
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

```

对应 Python 加载器：

`05-calls/hello-bpf2bpf.py`

```python
#!/usr/bin/python3
from bcc import BPF

b = BPF(src_file="hello-bpf2bpf.c")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID={event.pid:6d} UID={event.uid:5d} "
          f"CALLER={event.comm.decode():16s} → "
          f"CMD={event.filename.decode()}")

b["events"].open_perf_buffer(print_event)
print("BPF-to-BPF (inlined) demo, hit Ctrl-C to stop.")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

```

#### 📊 用 bpftool 验证函数内联

加载后运行：

```bash
sudo python3 hello-bpf2bpf.py
```

可以看到执行结果和前面篇章中的一致：

![image-20260526175953427](https://raw.githubusercontent.com/Chenjx12/PicGO/main/img/20260526180002773.png)

在另一个终端：

```bash
# 查看程序
sudo bpftool prog list | grep sys_enter_execve

chenjx12@learning-ebpf:~/Desktop/u/hgfs/code/05-tail-call$ sudo bpftool prog list | grep sys_enter_execve
104: tracepoint  name tracepoint__syscalls__sys_enter_execve  tag 68ffac92f86b0280  gpl


# 查看字节码（应该能看到 call 指令）
sudo bpftool prog dump xlated id <你的ID>

chenjx12@learning-ebpf:~/Desktop/u/hgfs/code/05-tail-call$ sudo bpftool prog dump xlated id 104
int tracepoint__syscalls__sys_enter_execve(struct tracepoint__syscalls__sys_enter_execve * args):
; TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
   0: (bf) r6 = r1
   1: (b7) r1 = 0
; struct data_t data = {};
   2: (7b) *(u64 *)(r10 -8) = r1
   3: (7b) *(u64 *)(r10 -16) = r1
   4: (7b) *(u64 *)(r10 -24) = r1
   5: (7b) *(u64 *)(r10 -32) = r1
   6: (7b) *(u64 *)(r10 -40) = r1
   7: (7b) *(u64 *)(r10 -48) = r1
   8: (7b) *(u64 *)(r10 -56) = r1
   9: (7b) *(u64 *)(r10 -64) = r1
  10: (7b) *(u64 *)(r10 -72) = r1
  11: (7b) *(u64 *)(r10 -80) = r1
  12: (7b) *(u64 *)(r10 -88) = r1
  13: (7b) *(u64 *)(r10 -96) = r1
  14: (7b) *(u64 *)(r10 -104) = r1
  15: (7b) *(u64 *)(r10 -112) = r1
  16: (7b) *(u64 *)(r10 -120) = r1
  17: (7b) *(u64 *)(r10 -128) = r1
  18: (7b) *(u64 *)(r10 -136) = r1
  19: (7b) *(u64 *)(r10 -144) = r1
; data->pid = bpf_get_current_pid_tgid() >> 32;
  20: (85) call bpf_get_current_pid_tgid#257360
; data->pid = bpf_get_current_pid_tgid() >> 32;
  21: (77) r0 >>= 32
; data->pid = bpf_get_current_pid_tgid() >> 32;
  22: (63) *(u32 *)(r10 -160) = r0
; data->uid = bpf_get_current_uid_gid() >> 32;
  23: (85) call bpf_get_current_uid_gid#257936
; data->uid = bpf_get_current_uid_gid() >> 32;
  24: (77) r0 >>= 32
; data->uid = bpf_get_current_uid_gid() >> 32;
  25: (63) *(u32 *)(r10 -156) = r0
; data->ts = bpf_ktime_get_ns();
  26: (85) call bpf_ktime_get_ns#257632
; data->ts = bpf_ktime_get_ns();
  27: (7b) *(u64 *)(r10 -152) = r0
; struct data_t data = {};
  28: (bf) r1 = r10
  29: (07) r1 += -144
; bpf_get_current_comm(&data->comm, sizeof(data->comm));
  30: (b7) r2 = 16
  31: (85) call bpf_get_current_comm#258080
; bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);
  32: (79) r3 = *(u64 *)(r6 +16)
; struct data_t data = {};
  33: (bf) r1 = r10
  34: (07) r1 += -128
; bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);
  35: (b7) r2 = 128
  36: (85) call bpf_probe_read_user_str#-128800
; bpf_perf_event_output(args, bpf_pseudo_fd(1, -1), CUR_CPU_IDENTIFIER, &data, sizeof(data));
  37: (18) r2 = map[id:13]
  39: (bf) r4 = r10
; 
  40: (07) r4 += -160
; bpf_perf_event_output(args, bpf_pseudo_fd(1, -1), CUR_CPU_IDENTIFIER, &data, sizeof(data));
  41: (bf) r1 = r6
  42: (18) r3 = 0xffffffff
  44: (b7) r5 = 160
  45: (85) call bpf_perf_event_output_tp#-111504
; return 0;
  46: (b7) r0 = 0
  47: (95) exit
```



这就是用 C/Python 分离后写的那个 `TRACEPOINT_PROBE(syscalls, sys_enter_execve)` 程序——**一整坨 48 条指令，全在一个函数里，没有任何函数调用**。

这正是第五篇要解决的问题，让我们逐段拆解：

#### 一、整体结构一览

```bash
指令 0-1:   保存上下文，初始化
指令 2-19:  把 struct data_t 清零（18条指令！）
指令 20-22: 获取 PID
指令 23-25: 获取 UID
指令 26-27: 获取时间戳
指令 28-31: 获取进程名
指令 32-36: 读取 filename
指令 37-45: 提交事件到 Perf Buffer
指令 46-47: 返回
```

**核心发现：光是清零 `struct data_t` 就占了 18/48 = 37.5% 的指令！**

#### 二、逐段拆解

阶段 0：保存上下文（指令 0-1）

```bash
   0: (bf) r6 = r1          # 把 ctx（tracepoint 参数指针）存到 r6
   1: (b7) r1 = 0           # r1 清零，后面用来初始化结构体
```

**为什么把 `r1` 存到 `r6`？**
因为 `r1-r5` 是参数寄存器，调用 helper 函数时会被覆盖。`r6-r9` 是被调用者保存寄存器——helper 函数执行完，`r6` 的值还在。后面指令 32 还要用到 `r6` 来读取 `args->filename`。

阶段 1：清零 `struct data_t`（指令 2-19）—— 最"浪费"的部分

```bash
   2: (7b) *(u64 *)(r10 - 8) = r1    # data 偏移 0-7
   3: (7b) *(u64 *)(r10 - 16) = r1   # data 偏移 8-15
   4: (7b) *(u64 *)(r10 - 24) = r1   # data 偏移 16-23
   5: (7b) *(u64 *)(r10 - 32) = r1   # data 偏移 24-31
   ...
  19: (7b) *(u64 *)(r10 -144) = r1   # data 偏移 136-143
```

**18 条指令，只为把 160 字节清零！**

为什么？因为 C 代码写了 `struct data_t data = {};`，这是零初始化，编译器必须保证每个字节都是 0。

**你的 `struct data_t` 长这样：**

```c
struct data_t {
    u32 pid;           // 4 字节
    u32 uid;           // 4 字节
    u64 ts;            // 8 字节
    char comm[16];     // 16 字节
    char filename[128]; // 128 字节
};                     // 总计 160 字节
```

160 字节 ÷ 8 字节/指令 = **正好 20 条**（实际是 18 条，因为后面直接覆盖了部分字段）。

阶段 2：获取 PID（指令 20-22）

```bash
  20: (85) call bpf_get_current_pid_tgid#257360   # 调用 helper
  21: (77) r0 >>= 32                               # 右移 32 位取 PID
  22: (63) *(u32 *)(r10 -160) = r0                # 存到 data.pid
```

**`(63)` 是什么操作码？** 这是 **STX32**——存 32 位到内存。因为 `pid` 是 `u32`，只需要存 4 字节。

**注意栈偏移：`r10 - 160`。** 这说明 `data` 结构体的起始位置在栈顶往下 160 字节处。

阶段 3：获取 UID（指令 23-25）

```bash
  23: (85) call bpf_get_current_uid_gid#257936
  24: (77) r0 >>= 32                               # 右移 32 位取 UID
  25: (63) *(u32 *)(r10 -156) = r0                # 存到 data.uid
```

偏移 `-156` = `-160 + 4`，正好是 `uid` 的位置（紧跟在 `pid` 后面）。

阶段 4：获取时间戳（指令 26-27）

```bash
  26: (85) call bpf_ktime_get_ns#257632
  27: (7b) *(u64 *)(r10 -152) = r0                # 存到 data.ts
```

偏移 `-152` = `-160 + 8`，`ts` 是 `u64`，用 `(7b)` 存 8 字节。

阶段 5：获取进程名（指令 28-31）

```bash
  28: (bf) r1 = r10           # r1 = 栈顶指针
  29: (07) r1 += -144         # r1 指向 data.comm 的位置
  30: (b7) r2 = 16            # 第二个参数：16 字节
  31: (85) call bpf_get_current_comm#258080
```

偏移 `-144` = `-160 + 16`，这是 `comm[16]` 的起始位置。

阶段 6：读取 filename（指令 32-36）——关键！

```bash
  32: (79) r3 = *(u64 *)(r6 +16)           # 从 tracepoint args 读 filename 指针
  33: (bf) r1 = r10                          # r1 = 栈顶指针
  34: (07) r1 += -128                        # r1 指向 data.filename
  35: (b7) r2 = 128                          # 第二个参数：128 字节
  36: (85) call bpf_probe_read_user_str#-128800
```

**关键指令：`32: (79) r3 = \*(u64 \*)(r6 +16)`**

- `(79)` 是 **LDX64**——从内存加载 64 位到寄存器
- `r6` 还记得吗？指令 0 存的 tracepoint 上下文指针
- `+16` 是 `args->filename` 字段在 tracepoint 参数结构体中的偏移量
- 这条指令把**用户态的 filename 指针**读到了 `r3`

然后 `bpf_probe_read_user_str(r1=&data.filename, r2=128, r3=filename_ptr)` 安全地从用户态读取字符串。

阶段 7：提交事件（指令 37-45）

```bash
  37: (18) r2 = map[id:13]                   # 加载 Perf Buffer 的 map 指针
  39: (bf) r4 = r10                           # r4 = 栈顶指针
  40: (07) r4 += -160                         # r4 指向 data 起始位置
  41: (bf) r1 = r6                            # r1 = tracepoint 上下文（必须传！）
  42: (18) r3 = 0xffffffff                    # r3 = BPF_F_CURRENT_CPU
  44: (b7) r5 = 160                           # r5 = sizeof(data) = 160
  45: (85) call bpf_perf_event_output_tp#-111504
```

这是 `events.perf_submit(args, &data, sizeof(data))` 的底层实现。

阶段 8：返回（指令 46-47）

```
  46: (b7) r0 = 0
  47: (95) exit
```

#### 三、这份字节码展示的"问题"

问题 1：没有函数调用，全是内联

整段 48 条指令，除了 `call` 到 helper 函数，**没有任何 `call` 到你写的其他函数**。这就是 BCC 的"内联一切"——所有逻辑都压在一个函数里。

问题 2：栈使用量巨大

```c
struct data_t = 160 字节
清零操作用掉了 r10-8 到 r10-160 的栈空间
```

加上 `r6` 保存的上下文指针，这个程序光是数据结构就占了 160+ 字节栈空间。eBPF 总共只有 **512 字节栈**，如果再嵌套几层函数调用，立刻爆栈。

问题 3：指令浪费严重

18 条指令只为了清零！如果能用 `__builtin_memset` 或其他优化，可以大幅减少。



## 代码案例2：尾调用（多探针动态分派）

### 目标

实现一个主程序 + 两个子程序的结构，用尾调用根据系统调用类型分发到不同处理逻辑。

### 完整代码：

`05-calls/hello-tailcall.c`

```c
// 05-calls/hello-tailcall.c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[16];
    char filename[128];  // execve 用
    int syscall_type;    // 1=execve, 2=openat
};

BPF_RINGBUF_OUTPUT(events, 1 << 4);

// ⚠️ 尾调用映射表：存储子程序的 fd
BPF_PROG_ARRAY(tail_call_table, 2);

// 主程序：提取公共信息后分发
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.syscall_type = 1;
    
    // ✅ 关键：尾调用分发到处理 execve 的子程序
    bpf_tail_call(args, &tail_call_table, 0);
    
    // 如果尾调用失败（子程序不存在），执行降级逻辑
    event.filename[0] = '\0';
    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

// 子程序1：处理 execve 的特定逻辑
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *event = ctx->args;  // 伪代码，实际需要重新构造
    
    // 从 tracepoint 参数读取 filename
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->args[0]);
    
    events.ringbuf_output(event, sizeof(*event), 0);
    return 0;
}
```

**⚠️ BCC 限制提示**：BCC 不支持多程序在同一文件，所以实际实现需要拆分。

### 实际可运行的 BCC 版本：

`05-calls/hello-tailcall.py`

```python
#!/usr/bin/python3
from bcc import BPF

# BCC 版本：模拟尾调用的分派逻辑
program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[16];
    char filename[128];
    int syscall_type;
};

BPF_RINGBUF_OUTPUT(events, 1 << 4);

// 尾调用映射表
BPF_PROG_ARRAY(tail_call_table, 2);

// 处理 execve 的逻辑
static __always_inline void handle_execve(struct event_t *event, void *ctx) {
    event->syscall_type = 1;
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), (void *)ctx);
}

// 处理 openat 的逻辑（预留）
static __always_inline void handle_openat(struct event_t *event) {
    event->syscall_type = 2;
    event->filename[0] = '\0';
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // ✅ 模拟尾调用的分派逻辑
    handle_execve(&event, (void *)args->filename);
    
    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}
"""

b = BPF(text=program)

def print_event(ctx, data, size):
    event = b["events"].event(data)
    syscall_name = "execve" if event.syscall_type == 1 else "openat"
    print(f"{syscall_name.upper():8s} PID={event.pid:6d} UID={event.uid:5d} "
          f"CALLER={event.comm.decode():16s} → CMD={event.filename.decode()}")

b["events"].open_ring_buffer(print_event)
print("Tail call demo (BCC simulation), hit Ctrl-C to stop.")

while True:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

## 实战对比实验设计

### 实验1：栈空间压力测试

**目标**：验证 BPF-to-BPF 调用的栈限制。

```c
// 测试用代码（不要在实际项目中用）
__attribute__((noinline))
static int func1(int x) {
    // 故意使用大局部变量
    char buf[200];  // 接近 512B 的一半
    return x + 1;
}

__attribute__((noinline))
static int func2(int x) {
    char buf[300];  // 再用 300B
    return x + 2;
}

int test(struct pt_regs *ctx) {
    // 嵌套调用：200 + 300 = 500B，接近极限
    int val = func1(0);
    val = func2(val);
    return val;
}
```

**观察点**：

- 编译时 Verifier 是否报错
- `bpftool prog dump xlated` 查看栈帧结构

### 实验2：尾调用层级测试

**目标**：验证尾调用的最大层级。



## 工程化建议：用尾调用搭建多探针架构

### 架构图

```
           主程序（提取公共信息）
                │
                ├─→ 尾调用[0] → execve_handler
                │
                ├─→ 尾调用[1] → openat_handler
                │
                ├─→ 尾调用[2] → connect_handler
                │
                └─→ 尾调用[3] → mount_handler
```

### 代码结构

```
05-calls/
├── common.h              # 公共结构体和工具函数
├── main.bpf.c            # 主程序
├── execve_handler.bpf.c  # execve 处理器
├── openat_handler.bpf.c  # openat 处理器
└── loader.py             # 统一加载器
```

## 与毕设的关联点

### 容器逃逸检测场景

1. **多探针组合**：
   - `execve` 捕获进程启动
   - `openat` 捕获文件访问
   - `ptrace` 捕获进程注入
   - `mount` 捕获挂载操作
2. **动态策略更新**：
   - 用尾调用实现“热插拔”检测模块
   - 无需重新加载主程序，只更新特定处理函数
3. **性能优化**：
   - 公共信息提取一次，多个处理器复用
   - 尾调用避免栈溢出

## 小结与预告

### 本篇核心收获

1. **两种调用机制的本质区别**：函数级 vs 程序级
2. **栈限制的实际影响**：为什么不能用深度递归
3. **工程化应用**：用尾调用搭建可扩展的检测架构
4. **BCC 的局限与绕过**：如何在内联限制下实现模块化

### 第六篇预告

**Six、容器感知与身份识别：从内核到云原生**

- 用 eBPF 获取 Cgroup ID 和容器标签
- 解析 `/proc` 中的容器信息
- 实战：识别命令来自哪个容器

## 可直接使用的代码片段

### 1. 公共信息提取宏（放在 common.h）

```c
#ifndef __COMMON_H
#define __COMMON_H

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 通用事件结构体
struct common_event {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[16];
};

// 提取公共信息的宏
#define EXTRACT_COMMON_INFO(event) do { \
    (event).pid = bpf_get_current_pid_tgid() >> 32; \
    (event).uid = bpf_get_current_uid_gid() >> 32; \
    (event).ts = bpf_ktime_get_ns(); \
    bpf_get_current_comm(&(event).comm, sizeof((event).comm)); \
} while(0)

#endif
```

### 2. 尾调用辅助函数（放在 loader.py）

```python
def setup_tail_calls(bpf_obj, program_map):
    """设置尾调用映射表"""
    for index, prog_name in program_map.items():
        # 查找子程序的 fd
        prog = bpf_obj.load_func(prog_name, BPF.TRACEPOINT)
        # 更新尾调用映射表
        bpf_obj["tail_call_table"][ct.c_int(index)] = ct.c_int(prog.fd)
```