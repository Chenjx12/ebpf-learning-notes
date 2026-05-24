# Four、eBPF 程序的解剖与工程化

date: 2026.5.24

---

在上一篇文章里，我们从 `trace_printk` 一路杀到了 Ring Buffer，甚至还能用 tracepoint 抓到被执行的命令路径。但是，当你写下 `b = BPF(text=program)` 并按下回车时，有没有一种感觉：

**这玩意儿到底是怎么跑进内核的？**

我们写了类 C 代码，它却跑在了内核态；我们没手动编译，它却奇迹般地生效了。BCC 就像一个黑盒，替我们挡住了底层的复杂度。

今天，我们就来打开这个黑盒，做一次“解剖”。同时，我会把之前突然顿悟的 **C/Python 分离** 工程实践落地，顺便把咱们的代码仓库整理得像模像样。

---

## 0. 开篇:为什么需要"解剖"?

### 回顾第三篇的成果

在第三篇中,我们已经学会了:
- ✅ 用 BCC 编写 eBPF 程序(trace_printk / Hash Map / Perf Buffer / Ring Buffer)
- ✅ 传递结构化数据(PID, UID, 进程名, 时间戳)
- ✅ 使用 tracepoint 获取完整命令路径
- ✅ 区分 shell 内建命令和外部命令

但一直有个**黑盒**:

```
我们写的 C 字符串  →  [BCC 黑盒]  →  内核里跑的 eBPF 程序
```

我们不知道中间发生了什么。这篇就是**打开这个黑盒**,看看从源码到字节码的完整链路。

---

## 1. BCC 背后:从 C 字符串到内核字节码

### 1.1 BCC 的编译链路

当我们执行这行代码时:

```python
b = BPF(text=program)
```

BCC 在背后做了这些事:

```mermaid
flowchart LR
  A[C 字符串] --> B[clang -target bpf]
  B --> C[eBPF 字节码 .o]
  C --> D[bpf 系统调用]
  D --> E[内核加载]
  E --> F[Verifier 验证]
  F --> G[JIT 编译为机器码]
  G --> H[附加到 kprobe/tracepoint]
```

**关键步骤:**
1. **编译**: clang 把 C 代码编译成 eBPF 字节码(.o 文件)
2. **加载**: 通过 `bpf()` 系统调用把字节码加载进内核
3. **验证**: Verifier 检查程序安全性(不能崩溃、不能死循环等)
4. **JIT**: Just-In-Time 编译为本地机器码,提升性能
5. **附加**: 把程序挂钩到指定的探针点(kprobe/uprobe/tracepoint)

### 1.2 实验:手动用 clang 编译(🔥 推荐)

**目标:** 不依赖 BCC 的黑盒,手动完成从 C 代码到 eBPF 字节码的编译过程,并理解其结构。

**⚠️ 为什么推荐手动编译?**
- **完全可控**: 清楚知道每一个编译参数和步骤。
- **标准化**: 这是生产环境和使用 libbpf/bpftool 时的标准工作流。
- **调试友好**: 可以独立于 Python/BCC 测试 C 代码的正确性。

#### **步骤 1: 创建独立的 C 文件**

创建 `hello-debug.c`:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// 定义许可证(必须的,否则内核拒绝加载)
char LICENSE[] SEC("license") = "GPL";

// eBPF程序入口点
// SEC("kprobe/sys_execve") 告诉编译器将此函数放入名为 "kprobe/sys_execve" 的段
SEC("kprobe/sys_execve")
int hello(struct pt_regs *ctx) {
    bpf_trace_printk("Hello from manual clang compile!");
    return 0;
}
```

#### **步骤 2: 用 clang 手动编译**

确保你安装了 `clang` 和内核头文件 (`linux-headers-$(uname -r)`).

```bash
# 方法A: 直接使用编译命令
clang -target bpf \
      -O2 \
      -g \
      -c hello-debug.c \
      -o hello-debug.o

# 方法B: 如果有自动化脚本 (可选)
# chmod +x build-ebpf.sh
# ./build-ebpf.sh hello-debug.c
```

**参数解释:**
- `-target bpf`: 指定目标架构为 eBPF。
- `-O2`: 优化等级, eBPF 验证器通常要求代码经过优化。
- `-g`: 生成调试信息(可选,便于 bpftool 查看源码对应关系)。
- `-c`: 只编译不链接。

#### **步骤 3: 查看编译产物**

```bash
# 查看生成的 .o 文件大小
ls -lh hello-debug.o

# 用 readelf 查看段结构
readelf -S hello-debug.o
```

**典型输出:**

```
Section Headers:
  [Nr] Name              Type            Address           Offset
       Size              EntSize         Flags  Link  Info  Align
  [ 1] .text             PROGBITS        0000000000000000  00000040
       0000000000000048  0000000000000000  AX       0     0     8
  [ 2] license           PROGBITS        0000000000000000  00000088
       0000000000000004  0000000000000000   A       0     0     1
  [ 3] kprobe/sys_execve PROGBITS        0000000000000000  00000090
       000000000000001a  0000000000000000   A       0     0     1
```

**关键字段解释:**
- `.text`: 默认的函数代码段。
- `license`: 许可证字符串,内核加载时会检查。
- `kprobe/sys_execve`: 我们定义的探针函数所在的段。段名决定了它将被附加到哪里(BCC/libbpf 会解析这个段名)。

**截图占位符:**
> 📸 在这里插入 `readelf -S hello-debug.o` 输出的截图

#### **步骤 4: 用 Python/BCC 加载已编译的 .o 文件**

虽然我们可以用 `bpftool` 直接加载,但为了保持与前文一致,这里演示如何用 BCC 加载手动编译的对象文件。

创建 `load-compiled.py`:

```python
from bcc import BPF

# 关键: 用 src_file 加载已编译的 .o 文件
# 注意: BCC 的 src_file 通常期望 C 源码,但在较新版本或特定用法下可处理对象文件
# 更通用的方式是使用 BPF 的 obj_file 参数(如果支持)或继续使用 text/src_file 让 BCC 重新编译
# 这里为了演示"手动编译产物"的概念,我们假设你只是想确认 .o 文件存在且合法。
# 实际上, BCC 的 BPF(src_file="hello-debug.c") 内部也是调用 clang。
# 若要真正加载 .o, 通常推荐使用 libbpf 或 bpftool。
# 但在 BCC 中, 我们可以这样验证我们的 C 代码是独立的:

b = BPF(src_file="hello-debug.c") # BCC 会再次编译它,但我们可以对比手动编译的 .o

syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

print("监控 execve,按 Ctrl-C 退出")
b.trace_print()
```

*注: 严格来说, BCC 主要设计用于从源码编译。如果你希望直接加载 `.o` 文件, **bpftool** 是更好的选择:*

```bash
sudo bpftool prog load hello-debug.o /sys/fs/bpf/hello-debug
sudo bpftool prog attach pinned /sys/fs/bpf/hello-debug kprobe sys_execve
```

**✅ 手动编译的优势:**
- 不依赖 BCC 的黑盒行为。
- 可以看到每一个编译步骤。
- C 代码独立编辑,有语法高亮。
- 可以用标准工具(readelf/objdump)分析。
- **这是转向 libbpf 和现代 eBPF 开发的基础。**

---

### 1.3 备选方案:让 BCC 留下中间文件

如果你坚持使用 BCC 的 `text=` 模式并想查看其生成的中间文件,可以尝试以下方法。

**⚠️ 重要提示:** `debug=4` 参数在不同 BCC 版本中行为可能不同。

#### **方法A: 使用环境变量**

```bash
export BCC_SAVE_TEMP_FILES=1
sudo python3 your-script.py
```

#### **方法B: 使用更强的 debug 级别**

```python
b = BPF(text=program, debug=0x1f)
```

#### **查看中间文件:**

```bash
sudo find /tmp -name "*bcc*" -type f 2>/dev/null
```

### 💡 关键收获

- BCC 不是"魔法",它就是帮你调 `clang + bpf()` 系统调用。
- **手动编译**能让你彻底理解从源码到字节码的过程。
- 编译产物(.o)包含段(Segments),如 `.text`, `license`, 以及探针特定的段(如 `kprobe/xxx`)。
- 可以用标准工具(readelf/objdump)分析编译产物。

---

## 2. 用 bpftool 看正在运行的 eBPF 程序

### 2.1 bpftool 是什么?

`bpftool` 是 Linux 内核提供的官方工具,用于:
- 查看已加载的 eBPF 程序
- 查看和修改 map
- dump 字节码
- 性能分析

**安装:**

```bash
sudo apt install linux-tools-common linux-tools-generic
```

### 2.2 列出所有 eBPF 程序

**命令:**

```bash
sudo bpftool prog list
```

**典型输出:**

```
123: kprobe  name hello  tag abc123def456  gpl
        loaded_at 2026-05-23T18:00:00+0800  uid 0
        xlated 64B  jited 96B  memlock 4096B
        pids python3(4567)
```

**字段解释:**
- `123`: 程序 ID
- `kprobe`: 程序类型(还有 tracepoint/xdp/socket_filter 等)
- `name hello`: 函数名
- `tag abc123...`: 程序哈希值(唯一标识)
- `gpl`: 许可证
- `loaded_at`: 加载时间
- `xlated 64B`: eBPF 字节码大小
- `jited 96B`: JIT 编译后的机器码大小
- `memlock 4096B`: 锁定的内存大小(map 占用)
- `pids`: 哪个进程加载的

**截图占位符:**
> 📸 在这里插入 `bpftool prog list` 输出的截图

### 2.3 查看某个程序的字节码

**命令:**

```bash
sudo bpftool prog dump xlated id 123
```

**典型输出:**

```
   0: (b7) r0 = 0
   1: (85) call bpf_trace_printk#-61664
   2: (b7) r0 = 0
   3: (95) exit
```

**说明:**
- 每条指令都是 8 字节
- `(b7)` = MOV 立即数
- `(85)` = CALL helper 函数
- `(95)` = EXIT 返回

**不需要逐行理解**,只要能看出:
- 有函数调用(`call`)
- 有返回值(`exit`)
- 指令数量很少(eBPF 程序通常很短)

**截图占位符:**
> 📸 在这里插入 `bpftool prog dump` 输出的截图

### 2.4 列出所有 map

**命令:**

```bash
sudo bpftool map list
```

**典型输出:**

```
456: hash  name counter_table  flags 0x0
        key 8B  value 8B  max_entries 4096  memlock 4096B
        pids python3(4567)
```

**字段解释:**
- `456`: map ID
- `hash`: map 类型(还有 array/perf/ringbuf 等)
- `key 8B`: 键的大小
- `value 8B`: 值的大小
- `max_entries`: 最大条目数

**查看 map 内容:**

```bash
sudo bpftool map dump id 456
```

### 2.5 实验:实时监控你的程序

**步骤:**

1. **终端 A:** 运行 hello-perf.py
   ```bash
   sudo python3 examples/hello-perf.py
   ```

2. **终端 B:** 查找程序
   ```bash
   sudo bpftool prog list | grep hello
   # 输出: 123: kprobe  name hello ...
   ```

3. **终端 B:** 查看字节码
   ```bash
   sudo bpftool prog dump xlated id 123
   ```

4. **终端 B:** 查看 map
   ```bash
   sudo bpftool map list | grep events
   # 输出: 456: perf_event_array  name events ...
   ```

**截图占位符:**
> 📸 在这里插入双终端对比的截图

### 💡 关键收获

- 你的 eBPF 程序加载后是**完全可观测**的
- `bpftool` 是你的"听诊器",能看到内核里跑的程序
- 不需要重新编译就能查看运行状态

---

## 3. 工程化第一步:C/Python 分离

### 3.1 为什么要分离?

**现在的写法(混合版):**

```
#!/usr/bin/python3
from bcc import BPF

program = r"""
// 一大坨 C 代码嵌在 Python 字符串里
// 没有语法高亮
// 调试痛苦
// 难以复用
"""

b = BPF(text=program)
# ... 后续逻辑
```

**问题:**
- ❌ C 代码没有语法高亮
- ❌ Python 文件越来越长
- ❌ 无法用 clang 单独检查 C 语法
- ❌ 难以维护和协作

**分离后的写法:**

```
hello-perf-plus.c   ← 纯 eBPF C 代码(有语法高亮)
hello-perf-plus.py  ← 只做加载和回调(简洁清晰)
```

**好处:**
- ✅ C 代码独立编辑,IDE 支持语法高亮
- ✅ 可以用 `clang -target bpf` 单独编译检查
- ✅ Python 文件更干净,专注业务逻辑
- ✅ 为后面项目级结构打基础

### 3.2 改造实战:拆分 hello-perf-plus

#### **原始版本(混合版)**

见 [`examples/hello-perf-plus.py`](../examples/hello-perf-plus.py) - 这是第三篇的最终版本

#### **拆分步骤**

**步骤 1: 提取 C 代码到独立文件**

创建 `hello-perf-plus.c`:

```
// hello-perf-plus.c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 定义事件结构体
struct data_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[16];          // 调用者进程名
    char filename[128];     // 被执行的程序路径
};

// 声明 perf buffer
BPF_PERF_OUTPUT(events);

// 改用 tracepoint,可以直接访问系统调用参数
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    // 填充基本信息
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.ts  = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 关键!从 tracepoint 参数中读取 filename
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), 
                            (void *)args->filename);

    // 推送事件
    events.perf_submit(args, &data, sizeof(data));
    
    return 0;
}
```

**步骤 2: Python 只负责加载**

创建新的 [hello-perf-plus.py](file://f:\test-for-mcp\ebpf-learning-notes\examples\hello-perf-plus.py):

```
#!/usr/bin/python3
"""
eBPF Tracepoint 示例(C/Python 分离版) - 获取被执行的完整命令路径

功能: 使用 tracepoint 监控 execve,显示完整命令路径
改进: C 代码和 Python 代码分离,提升可维护性

使用方法:
    sudo python3 hello-perf-plus.py
"""

from bcc import BPF

# 关键改动:用 src_file 替代 text
b = BPF(src_file="hello-perf-plus.c")

# 用户态回调函数
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID={event.pid:6d} UID={event.uid:5d} "
          f"CALLER={event.comm.decode():16s} → "
          f"CMD={event.filename.decode()}")

# 打开 perf buffer
b["events"].open_perf_buffer(print_event)

print("通过 Tracepoint 监控 execve(C/Python 分离版),按 Ctrl-C 退出...")
print("\n示例:")
print("  ls        → CALLER=bash   → CMD=/usr/bin/ls")
print("  sudo su   → CALLER=bash   → CMD=/usr/bin/sudo")
print("            → CALLER=sudo   → CMD=/usr/bin/su\n")

# 持续轮询
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

**步骤 3: 测试运行**

```bash
cd code/04-anatomy/
sudo python3 hello-perf-plus.py
```

**预期输出:** (和之前完全一样)

```
PID=  4762 UID= 1000 CALLER=bash             → CMD=/usr/bin/ls
PID=  4766 UID= 1000 CALLER=bash             → CMD=/usr/bin/sudo
PID=  4768 UID=    0 CALLER=sudo             → CMD=/usr/bin/su
```

**截图占位符:**
> 📸 在这里插入运行结果的截图

### 3.3 BPF() 的两种加载方式

| 参数 | 用法 | 适合场景 |
|------|------|---------|
| `text=program` | C 代码以字符串传入 | 简单示例、教学、快速原型 |
| `src_file="xxx.c"` | C 代码从文件读取 | 正式项目、代码较长、需要语法高亮 |

**两者完全等价**,`src_file` 本质上就是 BCC 帮你 `open().read()` 然后传给 `text`。

### 💡 关键收获

- C/Python 分离是**工程化的第一步**
- `BPF(src_file=)` 和 `BPF(text=)` 完全等价
- 从现在开始养成好习惯,后面做项目时会受益无穷

---

## 4. 小结 + 预告

### 4.1 本篇总结

**理论层面:**

- ✅ 理解了 BCC 编译链路: C → clang → .o → bpf() → 内核
- ✅ 学会了用 `debug=4` 查看中间文件
- ✅ 掌握了 `bpftool` 的基本用法(prog list / map list / dump)

**实践层面:**
- ✅ 学会了 C/Python 分离的工程化方法
- ✅ 掌握了 `BPF(src_file=)` 的使用方式
- ✅ 整理了仓库目录结构,为后续扩展打基础

**核心思想:**
> **不要停留在"会用 BCC",要理解背后的机制。**  
> **不要满足于"能跑",要追求"好维护"。**

### 4.2 预告第五篇

现在我们的程序都是"一整坨"——一个 `hello()` 函数干所有事。

如果逻辑复杂了怎么办?

**第五篇讲:**

- BPF-to-BPF 函数调用(代码复用)
- 尾调用(Tail Call)(不回来的调用)
- 原书第3章后半段 + hello-tail.py 实验
- 为你的多探针架构打基础

**核心问题:**

- 如何在 eBPF 中实现函数调用?(受限于 512 字节栈)
- 尾调用和普通函数调用有什么区别?(不返回、复用栈帧)
- 如何用尾调用实现"程序链"?(动态分派)

---

## 🔗 相关资源

- [原书第3章: eBPF 程序剖析](https://binw666.github.io/learning-ebpf-translation/03-eBPF%E7%A8%8B%E5%BA%8F%E5%89%96%E6%9E%90/03-eBPF%E7%A8%8B%E5%BA%8F%E5%89%96%E6%9E%90.html)
- [bpftool 官方文档](https://man7.org/linux/man-pages/man8/bpftool.8.html)
- [eBPF 程序生命周期](https://ebpf.io/what-is-ebpf/#verification)

---

## 📝 课后练习

1. **基础题:** 用 `bpftool` 查看你运行的 hello-perf.py 程序,截图字节码输出
2. **进阶题:** 把 hello-ring.py 也拆分成 `.c` + `.py` 两个文件
3. **思考题:** 为什么 eBPF 程序有栈大小限制(512 字节)?这对编程有什么影响?

---

*最后更新: 2026-05-24*
