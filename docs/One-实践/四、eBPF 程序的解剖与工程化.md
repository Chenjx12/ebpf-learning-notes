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

```text
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

#### **🔥 推荐方案:手动用clang编译(最可靠)**

与其依赖 BCC 的 debug 参数,不如直接用 clang 手动编译,这样能完全控制整个过程。

**完整代码示例:**
- C源码: [`code/04-anatomy/hello-debug.c`](../code/04-anatomy/hello-debug.c)
- 编译脚本: [`code/04-anatomy/build-ebpf.sh`](../code/04-anatomy/build-ebpf.sh)
- Python加载器: [`code/04-anatomy/load-compiled.py`](../code/04-anatomy/load-compiled.py)

**步骤 1: 创建独立的 C 文件**

创建 [`hello-debug.c`](../code/04-anatomy/hello-debug.c):

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
# 方法A: 直接使用编译命令(推荐)
clang -target bpf \
      -O2 \
      -g \
      -I/usr/include/x86_64-linux-gnu \
      -c hello-debug.c \
      -o hello-debug.o

# 方法B: 使用提供的自动化脚本
chmod +x build-ebpf.sh
./build-ebpf.sh hello-debug.c
```

**相关代码:**
- 自动化编译脚本: [`code/04-anatomy/build-ebpf.sh`](../code/04-anatomy/build-ebpf.sh)
- 编译输出示例: [`code/04-anatomy/COMPILE_OUTPUT.md`](../code/04-anatomy/COMPILE_OUTPUT.md)

**参数解释:**
- `-target bpf`: 指定目标架构为 eBPF。
- `-O2`: 优化等级, eBPF 验证器通常要求代码经过优化。
- `-g`: 生成调试信息(可选,便于 bpftool 查看源码对应关系)。
- `-c`: 只编译不链接。

#### **步骤 3: 查看编译产物**

让我们实际运行编译命令，看看真实的结果：

```bash
# 执行编译（注意：需要添加 -I 参数解决头文件问题）
clang -target bpf -O2 -g \
      -I/usr/include/x86_64-linux-gnu \
      -c hello-debug.c \
      -o hello-debug.o
```

**⚠️ 常见问题：头文件缺失**

在 Ubuntu 22.04 上首次编译时，你可能会遇到这个错误：

```bash
/usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found
#include <asm/types.h>
         ^~~~~~~~~~~~~
```

**原因**：`clang -target bpf` 默认不包含 `x86_64-linux-gnu` 的头文件路径。

**解决**：添加 `-I/usr/include/x86_64-linux-gnu` 参数。

另外，如果你使用最新版的 libbpf，可能还会遇到：

```bash
error: too few arguments to function call, expected at least 2, have 1
    bpf_trace_printk("Hello from manual clang compile!");
```

这是因为新版 `bpf_trace_printk` 需要两个参数。解决方法是修改 C 代码：

```c
char fmt[] = "Hello from manual clang compile!";
bpf_trace_printk(fmt, sizeof(fmt));  // ✅ 正确写法
```

---

##### 📊 实际编译结果

![image-20260524224339860](https://raw.githubusercontent.com/Chenjx12/PicGO/main/img/20260524224348848.png)

生成的 eBPF 字节码文件约 **4.6 KB**。

---

##### 🔍 用 readelf 查看段结构

```bash
$ readelf -S hello-debug.o
```

**典型输出如下：**

```bash
Section Headers:
  [Nr] Name       Type     Address          Offset   Size
  [ 1] .text      PROGBITS 0000000000000000 00000040 0000000000000048
  [ 2] license    PROGBITS 0000000000000000 00000088 0000000000000004
  [ 3] maps       PROGBITS 0000000000000000 00000090 000000000000001c
```

**实际输出**（只显示关键段）：

```bash
Section Headers:
  [Nr] Name              Type            Address           Offset
       Size              EntSize         Flags  Link  Info  Align
  
  [ 3] kprobe/sys_execve PROGBITS        0000000000000000  00000040
       00000000000000a0  0000000000000000  AX       0     0     8
  
  [ 4] license           PROGBITS        0000000000000000  000000e0
       0000000000000004  0000000000000000  WA       0     0     1
  
  [ 5] .rodata.str1.1    PROGBITS        0000000000000000  000000e4
       0000000000000021  0000000000000001 AMS       0     0     1
```

对比之前的"典型输出"，你会发现：
- **段号不同**：我们的是 `[3]`、`[4]`、`[5]`，因为我们的文件还包含了调试信息段
- **大小不同**：我们的 `kprobe/sys_execve` 段是 `0xa0` (160 字节)，比示例的 `0x1a` (26 字节) 大得多

**为什么我们的程序更大？**  
因为我们用了 `bpf_trace_printk(fmt, sizeof(fmt))`，需要在栈上构建 33 字节的格式化字符串，这需要多条指令来完成（后面会详细分析）。

---

##### 🔬 用 llvm-objdump 反汇编查看字节码

标准的 `objdump` 无法识别 eBPF 架构，我们需要使用 LLVM 提供的专用工具：

```bash
$ llvm-objdump-14 -d hello-debug.o
```

**执行结果**：

![image-20260524231136982](https://raw.githubusercontent.com/Chenjx12/PicGO/main/img/20260524231138781.png)

```bash
hello-debug.o:	file format elf64-bpf

Disassembly of section kprobe/sys_execve:

0000000000000000 <hello>:
       0:	18 01 00 00 63 6f 6d 70 00 00 00 00 69 6c 65 21	r1 = 2406448776012984163 ll
       2:	7b 1a f0 ff 00 00 00 00	*(u64 *)(r10 - 16) = r1
       3:	18 01 00 00 6c 20 63 6c 00 00 00 00 61 6e 67 20	r1 = 2334956296524210284 ll
       5:	7b 1a e8 ff 00 00 00 00	*(u64 *)(r10 - 24) = r1
       6:	18 01 00 00 6f 6d 20 6d 00 00 00 00 61 6e 75 61	r1 = 7022640558675881327 ll
       8:	7b 1a e0 ff 00 00 00 00	*(u64 *)(r10 - 32) = r1
       9:	18 01 00 00 48 65 6c 6c 00 00 00 00 6f 20 66 72	r1 = 8243311830880773448 ll
      11:	7b 1a d8 ff 00 00 00 00	*(u64 *)(r10 - 40) = r1
      12:	b7 01 00 00 00 00 00 00	r1 = 0
      13:	73 1a f8 ff 00 00 00 00	*(u8 *)(r10 - 8) = r1
      14:	bf a1 00 00 00 00 00 00	r1 = r10
      15:	07 01 00 00 d8 ff ff ff	r1 += -40
      16:	b7 02 00 00 21 00 00 00	r2 = 33
      17:	85 00 00 00 06 00 00 00	call 6
      18:	b7 00 00 00 00 00 00 00	r0 = 0
      19:	95 00 00 00 00 00 00 00	exit
```

**🎯 深度解析**

这个 eBPF 程序共 **20 条指令**，可以分为三个阶段：

**阶段 1：在栈上构建格式化字符串（指令 0-13）**

eBPF 运行在内核态，不能直接访问用户态的数据段，所以必须在栈上手动构建字符串：

```bash
指令 0-2:  将 8 字节 "!elpmoc gnilpm" 加载到 r1，存入栈 [r10-16]
指令 3-5:  将 8 字节 " clgnual" 加载到 r1，存入栈 [r10-24]
指令 6-8:  将 8 字节 "m manua" 加载到 r1，存入栈 [r10-32]
指令 9-11: 将 8 字节 "llor f" 加载到 r1，存入栈 [r10-40]
指令 12-13: 在栈 [r10-8] 写入 NULL 终止符 (0x00)
```

**为什么是反向的？**  
因为 x86_64 是小端序（Little-endian），字符串在内存中按 8 字节一组反向存储。

最终在栈上形成的完整字符串：`"Hello from manual clang compile!\0"`

**阶段 2：准备调用参数（指令 14-16）**

```bash
指令 14: r1 = r10          → r1 指向帧指针（栈顶）
指令 15: r1 += -40         → r1 向前偏移 40 字节，指向字符串起始位置
指令 16: r2 = 33           → r2 = 字符串长度（包括 NULL 终止符）
```

此时寄存器状态：
- `r1`: 指向格式化字符串 `"Hello from manual clang compile!"`
- `r2`: `33` (字符串大小)

这正好对应 `bpf_trace_printk(const char *fmt, u32 fmt_size)` 的两个参数。

**阶段 3：调用 helper 函数并返回（指令 17-19）**

```bash
指令 17: call 6            → 调用 eBPF helper #6，即 bpf_trace_printk
指令 18: r0 = 0            → 设置返回值
指令 19: exit              → 退出程序
```

**📊 指令统计**：

| 类别 | 数量 | 说明 |
|------|------|------|
| 总指令数 | 20 条 | eBPF 程序通常很短 |
| MOV 长立即数 (`18`) | 4 条 | 加载 64 位常量（字符串片段） |
| 存栈 (`7b`, `73`) | 5 条 | 将数据写入栈 |
| MOV 立即数 (`b7`) | 3 条 | 初始化寄存器 |
| MOV 寄存器 (`bf`) | 1 条 | 复制帧指针 |
| 算术运算 (`07`) | 1 条 | 调整指针偏移 |
| CALL (`85`) | 1 条 | 调用 helper 函数 |
| EXIT (`95`) | 1 条 | 程序退出 |

**程序大小**：20 条指令 × 8 字节/指令 = **160 字节**（与 readelf 显示的 `0xa0` 完全一致！）

**💡 核心发现**：通过真实的编译结果，我们看到了 eBPF 字节码的真实面貌——没有全局变量，所有数据必须在栈上构建；只能调用白名单里的 helper 函数；每条指令都有严格的语义。这正是 Verifier 要验证的内容！

#### **步骤 4: 用 Python 加载运行**

创建 [`load-compiled.py`](../code/04-anatomy/load-compiled.py):

```python
from bcc import BPF

# 关键: 用 src_file 加载已编译的 .o 文件
b = BPF(src_file="hello-debug.o")

syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

print("通过手动编译的 eBPF 程序监控 execve,按 Ctrl-C 退出")
b.trace_print()
```

**相关代码:**
- Python加载器: [`code/04-anatomy/load-compiled.py`](../code/04-anatomy/load-compiled.py)

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

**实际输出（Ubuntu 22.04 真实环境）:** 以下省略了部分 cgroup_* 的输出

```bash
2: tracing  name hid_tail_call  tag 7cc47bbf07148bfe  gpl
	loaded_at 2026-05-24T21:09:48+0800  uid 0
	xlated 56B  jited 138B  memlock 4096B  map_ids 2
	btf_id 2

5: cgroup_device  tag e3dbd137be8d6168  gpl
	loaded_at 2026-05-24T21:09:49+0800  uid 0
	xlated 504B  jited 314B  memlock 4096B

65: kprobe  name hello  tag ecfa78e68c90af07  gpl
	loaded_at 2026-05-24T22:00:49+0800  uid 0
	xlated 160B  jited 106B  memlock 4096B  map_ids 8
	btf_id 89
```

**💡 观察发现**：

1. **系统预装了很多 eBPF 程序**：你可能会惊讶地发现，即使什么都没做，系统里已经跑着几十个 eBPF 程序了！这些主要来自：
   - **Snap 容器运行时**：`s_snap_store_ub`、`s_snapd_desktop` 等（Ubuntu 使用 Snap 包管理器）
   - **HID 设备监控**：`hid_tail_call`（人机接口设备，如键盘鼠标）
   - **Cgroup 设备控制**：大量的 `cgroup_device` 和 `cgroup_skb`（用于容器资源隔离）

2. **我们的程序在哪里**：如果你运行了 `hello-debug.o`，会看到类似 `65: kprobe name hello` 这样的条目——这就是我们的程序！

---

**字段详解:**

| 字段 | 含义 | 示例解读 |
|------|------|----------|
| `65` | **程序 ID** | 内核给程序的唯一标识，后续操作都用这个 ID |
| `kprobe` | **程序类型** | 这是一个 kprobe 程序（还有 tracepoint/xdp/cgroup_skb/socket_filter 等） |
| `name hello` | **函数名** | C 代码中的 `int hello(...)` |
| `tag ecfa78...` | **程序哈希** | eBPF 字节码的唯一指纹（基于指令内容计算） |
| `gpl` | **许可证** | 必须是 GPL 兼容才能加载某些 helper 函数 |
| `loaded_at` | **加载时间** | 程序何时被加载到内核（ISO 8601 格式） |
| `uid 0` | **加载者 UID** | 0 表示 root 加载的，1000 表示普通用户 |
| `xlated 160B` | **字节码大小** | eBPF 字节码占 160 字节（与我们编译的一致！） |
| `jited 106B` | **JIT 机器码大小** | 编译后的 x86_64 原生代码大小 |
| `memlock 4096B` | **锁定内存** | 程序占用的不可交换内存（页对齐，通常 4KB） |
| `map_ids 8` | **关联的 Map ID** | 程序使用的 Map 的 ID 列表（如果有的话） |
| `btf_id 89` | **BTF 信息 ID** | BPF Type Format 信息（用于调试和内省） |

---

**🔍 有趣的现象**：

1. **为什么有些程序没有 `name`？**  
   匿名程序通常是系统自动生成的（如 cgroup 策略），它们不需要人类可读的名字。

2. **`xlated` vs `jited` 大小差异**：
   - 我们的程序：`xlated 160B` → `jited 106B`（缩小了 34%）
   - HID 程序：`xlated 56B` → `jited 138B`（反而变大了！）
   
   **为什么 JIT 后反而变大？**  
   某些 eBPF 指令需要多条 x86 指令来模拟（特别是复杂的算术运算）。JIT 编译器会权衡优化收益，有时保持简单翻译反而更高效。

3. **`map_ids` 的作用**：  
   如果你的程序使用了 Map（如 `BPF_HASH` 或 `BPF_RINGBUF_OUTPUT`），这里会显示 Map 的 ID。可以用 `bpftool map dump id <map_id>` 查看内容。

4. **`btf_id` 的意义**：  
   BTF（BPF Type Format）是 eBPF 的调试信息格式。如果你用 `-g` 参数编译，clang 会生成 BTF 信息，方便后续 introspection（内省）。

---

**💡 实际练习**：

在你的系统上执行以下命令，观察输出：

```bash
# 1. 列出所有程序
sudo bpftool prog list

# 2. 只看 kprobe 类型的程序
sudo bpftool prog list type kprobe

# 3. 查找我们加载的程序
sudo bpftool prog list | grep hello

# 4. 统计程序数量
sudo bpftool prog list | wc -l
```

**实际输出**：

```bash
$ sudo bpftool prog list | wc -l
65  # 我的系统上有 65 个 eBPF 程序在运行！
```

我们发现，即使是"干净"的 Ubuntu 系统，后台也跑着不少 eBPF 程序——这正是现代 Linux 内核的强大之处！

---

### 2.3 查看某个程序的字节码

**命令:** 注意，id 后跟的数字是你的 `hello` 程序真实的 ID ，上面看得到我这里是 65

```bash
sudo bpftool prog dump xlated id 65
```

**输出结果:** 注意哈，这里有注释的原因是我们前面编译的时候带上了调试信息

```asm
int hello(struct pt_regs * ctx):
; int hello(struct pt_regs *ctx) {
   0: (18) r1 = 0x21656c69706d6f63
; char fmt[] = "Hello from manual clang compile!";
   2: (7b) *(u64 *)(r10 -16) = r1
   3: (18) r1 = 0x20676e616c63206c
   5: (7b) *(u64 *)(r10 -24) = r1
   6: (18) r1 = 0x61756e616d206d6f
   8: (7b) *(u64 *)(r10 -32) = r1
   9: (18) r1 = 0x7266206f6c6c6548
  11: (7b) *(u64 *)(r10 -40) = r1
  12: (b7) r1 = 0
  13: (73) *(u8 *)(r10 -8) = r1
  14: (bf) r1 = r10
; 
  15: (07) r1 += -40
; bpf_trace_printk(fmt, sizeof(fmt));
  16: (b7) r2 = 33
  17: (85) call bpf_trace_printk#-116048
; return 0;
  18: (b7) r0 = 0
  19: (95) exit
```

这些十六进制代码（比如 `07`, `b7`, `18`）就是 eBPF 的**操作码（Opcodes）**，你可以把它们理解为 eBPF 虚拟机的“机言”。

就像 x86 汇编里的 `mov`、`add`、`call` 一样，eBPF 也有自己的一套指令集。

### 核心概念：eBPF 寄存器

在看指令前，先认识 eBPF 的 11 个寄存器（`r0` - `r10`）：

- `r0`：存放函数返回值（也是 eBPF 程序最终的返回值）。
- `r1` - `r5`：存放函数调用的参数。
- `r6` - `r9`：被调用者保存寄存器（函数执行前后值不变）。
- `r10`：**只读的栈帧指针**（指向当前 eBPF 程序的栈顶）。

### 逐行拆解：你的 Hello World 是怎么跑的

我们结合你的 C 代码和 `bpftool` 输出，一句句看：

#### C 代码 1：字符串定义与初始化

```c
char fmt[] = "Hello from manual clang compile!";
```

C 语言里的字符串，在机器层面就是一段连续的内存字节。因为 eBPF 指令一次最多只能操作 64 位（8 字节），所以 BCC 把 32 字节的字符串拆成了 4 块 8 字节塞进寄存器，然后存到栈上。

```bash
   0: (18) r1 = 0x21656c69706d6f63  // 加载 64 位立即数到 r1
   2: (7b) *(u64 *)(r10 -16) = r1   // 把 r1 存到栈上 (r10 - 16 的位置)
   3: (18) r1 = 0x20676e616c63206c
   5: (7b) *(u64 *)(r10 -24) = r1
   6: (18) r1 = 0x61756e616d206d6f
   8: (7b) *(u64 *)(r10 -32) = r1
   9: (18) r1 = 0x7266206f6c6c6548  // 这其实是字符串的开头 "Hello f"
  11: (7b) *(u64 *)(r10 -40) = r1   // 存到栈底 (r10 - 40)
```



**操作码解释：**

- **`(18)`**：**64位立即数加载**（Load 64-bit Immediate）。把一个超长的 64 位数字直接塞进寄存器。
- **`(7b)`**：**64位内存存储**（Store 64-bit to Memory）。格式是 `*(u64 *)(地址) = 寄存器`。这里用 `r10`（栈顶）减去偏移量，就是在**栈上分配空间**保存字符串。

> 💡 **彩蛋**：你可以把 `0x7266206f6c6c6548` 拿去转 ASCII 码。从右往左读（因为是小端序）：`48=H`, `65=e`, `6c=l`, `6c=l`, `6f=o`, `20=空格`, `66=f`, `72=r`。正好是 “Hello r”！这就是机器眼里的字符串。

#### C 代码 2：字符串结尾的 `\0`

```bash
// C 语言字符串默认以 \0 结尾
  12: (b7) r1 = 0               // 把 r1 清零
  13: (73) *(u8 *)(r10 -8) = r1 // 把 0 存到栈上某个位置
```

**操作码解释：**

- **`(b7)`**：**32位立即数加载**（Load 32-bit Immediate）。给寄存器赋一个比较小的值（0）时用这个，比 `(18)` 省空间。
- **`(73)`**：**8位内存存储**（Store 8-bit to Memory）。存一个字节（`\0`）。

#### C 代码 3：准备 `bpf_trace_printk` 的参数

在 C 里调用函数是 `bpf_trace_printk(fmt, sizeof(fmt))`，但在底层，你必须手动把参数放到寄存器里。eBPF 的调用约定是：**参数依次放在 `r1`, `r2`, `r3`, `r4`, `r5`**。

```bash
  14: (bf) r1 = r10      // 把栈顶指针赋给 r1
; 
  15: (07) r1 += -40     // r1 往下挪 40 字节，指向字符串开头 "H" 的位置
; bpf_trace_printk(fmt, sizeof(fmt));
  16: (b7) r2 = 33       // 第二个参数：字符串长度 33
```

**操作码解释：**

- **`(bf)`**：**64位寄存器拷贝**（Move 64-bit Register）。`r1 = r10`。
- **`(07)`**：**64位立即数加法**（Add 64-bit Immediate）。给寄存器加一个数字（这里是减 40，等价于加 -40）。这一步算出了字符串在栈上的起始地址，作为 `r1`（第一个参数）。
- **`(b7)`**：前面见过，把 33 赋给 `r2`（第二个参数）。

#### C 代码 4：调用与返回

```bash
  17: (85) call bpf_trace_printk#-116048  // 调用 helper 函数
; return 0;
  18: (b7) r0 = 0   // 设置返回值为 0
  19: (95) exit     // 程序结束
```

**操作码解释：**

- **`(85)`**：**函数调用**（Call）。这是 eBPF 最重要的指令之一，专门用来调用内核允许的 helper 函数（如 `bpf_trace_printk`）或者进行尾调用。
- **`(95)`**：**程序退出**（Exit）。eBPF 程序必须以 `exit` 结尾，返回值放在 `r0` 里。

### 总结：eBPF 指令速查表

你不需要背下来，只要有个印象就行：

| 操作码   | 助记符    | 含义           | 例子                    |
| :------- | :-------- | :------------- | :---------------------- |
| **`b7`** | MOV32     | 加载 32 位数字 | `r1 = 0`                |
| **`18`** | MOV64     | 加载 64 位数字 | `r1 = 0x726620...`      |
| **`bf`** | MOV64_REG | 复制寄存器     | `r1 = r10`              |
| **`07`** | ADD64     | 加法运算       | `r1 += -40`             |
| **`7b`** | STX64     | 存 64 位到内存 | `*(u64*)(r10-16) = r1`  |
| **`73`** | STX8      | 存 8 位到内存  | `*(u8*)(r10-8) = r1`    |
| **`85`** | CALL      | 调用函数       | `call bpf_trace_printk` |
| **`95`** | EXIT      | 退出程序       | `exit`                  |

### 关键收获

1. **C 代码不是魔法**：哪怕是一句简单的字符串打印，底层也要拆解成“分配栈空间 -> 一块块搬数据 -> 算地址 -> 设参数 -> 调用”的繁琐步骤。
2. **为什么 eBPF 程序有栈限制？** 你看，光存一个 33 字节的字符串，就占了栈上 40 字节的空间（还要考虑对齐），而 eBPF 总共只有 **512 字节**的栈！所以 eBPF 代码里绝不能定义大数组或大结构体，必须用 Map。
3. **BCC 的价值**：如果没有 `bpftool` 右边的 C 语言注释，纯看这些操作码，极其痛苦。BCC 自带调试信息，让我们能对着源码看汇编，这是学习 eBPF 内部机制的最佳方式！



但是我们大部分时间，**不需要逐行理解**,只要能看出:
- 有函数调用(`call`)
- 有返回值(`exit`)
- 指令数量很少(eBPF 程序通常很短)

**🔬 对比我们手动编译的程序**：

如果用 `bpftool` 加载并运行我们的 `hello-debug.o`，然后 dump 它的字节码，会看到类似这样的输出（但会更长，因为有 20 条指令）：

假设我们的程序 ID 是 66

```bash
sudo bpftool prog dump xlated id 66

0: (18) r1 = 2406448776012984163
; char fmt[] = "Hello from manual clang compile!"; # 加载字符串片段
   2: (7b) *(u64 *)(r10 - 16) = r1           # 存入栈
   3: (18) r1 = 2334956296524210284          # 加载字符串片段
   ...
  17: (85) call bpf_trace_printk#-116048     # 调用 helper
  18: (b7) r0 = 0                            # 返回值
  19: (95) exit                              # 退出
```

这与我们用 `llvm-objdump` 看到的完全一致！因为 `bpftool` 显示的是内核实际加载的字节码。

**🎯 进阶技巧：查看 JIT 编译后的原生代码**

```bash
sudo bpftool prog dump jited id 65
```

如果你的bpftool带有反汇编，那将会显示 x86_64 的原生汇编代码（JIT 编译后的结果）。你会发现它比 eBPF 字节码更短、更高效——这就是 JIT 优化的魔力！

那如果像我一样bpftool没有反汇编引擎，就会报错：

```bash
chenjx12@learning-ebpf:~/Desktop/u/hgfs/code/04-anatomy$ sudo bpftool prog dump jited id 65
Error: No JIT disassembly suppor
```

**实话实说，对于学习 eBPF 内部机制，看 `xlated` 已经完全足够了。**

因为 JIT 编译后的 x86_64 汇编非常底层，而且 `bpftool` 默认不带源码注释（不像 `xlated` 那样有 `; char fmt[]`），看起来极其痛苦。JIT 的核心目的是“跑得快”，而不是“让人懂”。



如果你就是想看一眼原生的 x86_64 汇编长什么样，可以自己编译带反汇编支持的 `bpftool`：

```bash
# 1. 安装依赖
sudo apt install -y binutils-dev libbfd-dev libopcodes-dev

# 2. 获取内核源码（以你当前的内核版本为准，比如 5.15）
# 如果找不到完全匹配的，用 mainline 也能编
apt source linux

# 3. 编译 bpftool
cd linux-*/tools/bpf/bpftool/
make clean
make -j$(nproc)

# 4. 替换系统自带的版本
sudo cp bpftool /usr/local/sbin/bpftool
```

编译成功后，再运行 `sudo bpftool prog dump jited id 65`，你就能看到一堆纯粹的 x86_64 汇编指令了（不过真的很难读懂，因为没有 C 源码对应）。

---

### 2.4 列出所有 map

**命令:**

```bash
sudo bpftool map list
```

**输出结果:**

```bash
chenjx12@learning-ebpf:~/Desktop/u/hgfs/code/04-anatomy$ sudo bpftool map list
2: prog_array  name hid_jmp_table  flags 0x0
	key 4B  value 4B  max_entries 1024  memlock 8576B
	owner_prog_type tracing  owner jited
3: hash  name s_snapd_desktop  flags 0x0
	key 9B  value 1B  max_entries 1000  memlock 103680B
4: hash  name s_snap_store_ub  flags 0x0
	key 9B  value 1B  max_entries 1000  memlock 103680B
5: hash  name s_firefox_firef  flags 0x0
	key 9B  value 1B  max_entries 1000  memlock 103680B
8: array  name .rodata.str1.1  flags 0x80
	key 4B  value 33B  max_entries 1  memlock 424B
	frozen
```

**字段解释:**

先看所有 Map 都有的公共字段：

| 字段                       | 含义       | 例子解析                                                     |
| :------------------------- | :--------- | :----------------------------------------------------------- |
| **`2:` / `8:`**            | Map ID     | 内核给这个 Map 分配的身份证号，全局唯一，和程序的 ID 一样是动态分配的。 |
| **`prog_array` / `hash`**  | Map 类型   | 这是 Map 的“物种”。`hash` 是哈希表（键值对），`array` 是数组（按索引存取），`prog_array` 是个特殊的物种（下面细说）。 |
| **`name xxx`**             | Map 名字   | 你在 C 代码里定义的变量名（比如 `counter_table`），或者编译器自动生成的名字。 |
| **`flags 0x0`**            | 标志位     | `0x0` 是默认；`0x80` 表示 `BPF_F_RDONLY_PROG`（eBPF 程序只能读，不能写）。 |
| **`key 4B` / `value 33B`** | 键值大小   | 这个 Map 里，键占几字节，值占几字节。                        |
| **`max_entries`**          | 最大条目数 | 这个 Map 最多能装多少个键值对。哈希表满了就插不进去了。      |
| **`memlock`**              | 锁定内存   | eBPF 的内存不会被 swap 到磁盘，这是它占用的**物理内存**大小。 |

#### 重点解析：你的系统里跑着哪些 Map？

##### 1. `prog_array`：尾调用的“跳板”（高能预警！）

```bash
2: prog_array  name hid_jmp_table  flags 0x0
	key 4B  value 4B  max_entries 1024  memlock 8576B
	owner_prog_type tracing  owner jited
```

这个 Map 非常特殊！它不是用来存数据的，而是用来**存 eBPF 程序的 ID**。

- **作用**：这是 eBPF **尾调用** 的底层实现。程序 A 可以通过这个 Map 查找到程序 B，然后跳过去执行，而且**不返回**（复用栈帧）。
- **`owner_prog_type tracing`**：限制只有 tracing 类型的 eBPF 程序才能放进来。
- **`owner jited`**：限制只有经过 JIT 编译的本地机器码程序才能放进来（因为跳转必须跳到本地机器码的地址）。

> 💡 **剧透**：这就是你大纲里第五篇要讲的核心内容！现在你已经在系统中看到它的真身了。

##### 2. `hash`：Snap 应用的安全沙箱

```bash
3: hash  name s_snapd_desktop  flags 0x0
	key 9B  value 1B  max_entries 1000  memlock 103680B
4: hash  name s_snap_store_ub  flags 0x0
...
5: hash  name s_firefox_firef  flags 0x0
...
```

这些不是你写的，是 Ubuntu 的 Snap 应用商店在背后跑的 eBPF 安全策略（AppArmor/lsm）。这也证明了：**你即使不写 eBPF，你的系统也已经在大量使用它了**。

##### 3. `array` + `frozen`：隐藏的字符串彩蛋！

```
8: array  name .rodata.str1.1  flags 0x80
	key 4B  value 33B  max_entries 1  memlock 424B
	frozen
```

这是全场最佳！我们来破案：

- **`.rodata.str1.1`**：这是编译器自动生成的名字。`.rodata` 代表 **Read-Only Data（只读数据）**。`str1.1` 说明这是字符串常量区。
- **`value 33B`**：**为什么是 33 字节？** 还记得你刚才那条 `bpf_trace_printk` 打印的字符串吗？
  `"Hello from manual clang compile!"`
  数一数：32 个字符 + 1 个结尾的 `\0` = **正好 33 字节**！
- **`frozen`**：表示这个 Map 已经被“冻结”了。内核启动后，任何 eBPF 程序都**不能修改**它里面的内容，这是严格只读的。

**底层原理：**
在早期的 eBPF 中，字符串是直接内嵌在指令里的（就像你之前看到的那一堆 `(18) r1 = 0x7266206f6c6c6548`）。
但在现代的 BCC/libbpf 编译中，为了优化，编译器会把字符串常量单独放在一个 `.rodata` 类型的只读 Map 里，然后 eBPF 程序只需要拿着这个 Map 的指针去读字符串就行了。这样指令会更短，也更安全。



### 2.4 查看 Map 内容：亲手从内核捞数据

纸上得来终觉浅。我们刚才发现 ID 为 8 的 `.rodata` Map 里有个 33 字节的神秘值，
不如直接把它 dump 出来看一眼？

```bash
sudo bpftool map dump id 8
```

得到的结果：

```bash
chenjx12@learning-ebpf:~/Desktop/u/hgfs/code/04-anatomy$ sudo bpftool map dump id 8
key:
00 00 00 00
value:
48 65 6c 6c 6f 20 66 72  6f 6d 20 6d 61 6e 75 61
6c 20 63 6c 61 6e 67 20  63 6f 6d 70 69 6c 65 21
00
Found 1 element
```



### 2.5 预留实验:实时监控你的程序

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



### 💡 关键收获

- 你的 eBPF 程序加载后是**完全可观测**的
- `bpftool` 是你的"听诊器",能看到内核里跑的程序
- 不需要重新编译就能查看运行状态

---

## 3. 工程化第一步:C/Python 分离

### 3.1 为什么要分离?

**现在的写法(混合版):**

```python
#!/usr/bin/python3
from bcc import BPF

program = r"""
"""

b = BPF(text=program)
# ... 后续逻辑
```

在第三篇中，我们所有的 C 代码都像上面的代码段一样，塞在 Python 的 `r""" ... """` 字符串里。虽然 BCC 帮我们屏蔽了编译细节，但写长了简直是一场灾难：
- ❌ C 代码没有语法高亮
- ❌ Python 文件越来越长
- ❌ 无法用 clang 单独检查 C 语法
- ❌ 难以维护和协作

**分离后的写法:**

```
hello-perf-plus.c  ← 纯 eBPF C 代码（VSCode/Clion 语法高亮爽飞）
hello-perf-plus.py ← 只做加载和回调（简洁清晰，专注业务逻辑）
```

**好处:**

- ✅ C 代码独立编辑,IDE 支持语法高亮
- ✅ 可以用 `clang -target bpf` 单独编译检查
- ✅ Python 文件更干净,专注业务逻辑
- ✅ 为后面项目级结构打基础

### 3.2 改造实战:拆分 hello-perf-plus

#### **原始版本(混合版)**

见 [`code/03-hello-world/hello-perf-plus.py`](../code/03-hello-world/hello-perf-plus.py) - 这是第三篇的最终版本,所有代码都在一个文件中。

#### **拆分步骤**

我们现在把第三篇最终的 `hello-perf-plus.py`（混合版）拆成两个独立的文件。

#### 步骤 1：提取 C 代码到独立文件

在你的 `04-anatomy` 目录下，创建 `hello-perf-plus.c`，把我们之前写在 Python 字符串里的 C 代码原封不动搬过来：

```c
// hello-perf-plus.c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 定义事件结构体
struct data_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[16];       // 调用者进程名
    char filename[128];  // 被执行的程序路径
};

// 声明 perf buffer
BPF_PERF_OUTPUT(events);

// 改用 tracepoint，可以直接访问系统调用参数
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    // 填充基本信息
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 关键！从 tracepoint 参数中读取 filename
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);

    // 推送事件
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
```

#### 步骤 2：重构 Python 代码，只负责加载

创建新的 [`hello-perf-plus.py`](../code/04-anatomy/hello-perf-plus.py)。注意看 `BPF()` 里面的参数变化：

```python
#!/usr/bin/python3
"""
eBPF Tracepoint 示例(C/Python 分离版) - 获取被执行的完整命令路径
功能: 使用 tracepoint 监控 execve,显示完整命令路径
改进: C 代码和 Python 代码分离,提升可维护性
使用方法: sudo python3 hello-perf-plus.py
"""
from bcc import BPF

# 关键改动：用 src_file 替代 text！
b = BPF(src_file="hello-perf-plus.c")

# 用户态回调函数
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID={event.pid:6d} UID={event.uid:5d} "
          f"CALLER={event.comm.decode():16s} → "
          f"CMD={event.filename.decode()}")

# 打开 perf buffer
b["events"].open_perf_buffer(print_event)

print("通过 Tracepoint 监控 execve (C/Python 分离版)，按 Ctrl-C 退出...")
print("\n示例:")
print(" ls → CALLER=bash → CMD=/usr/bin/ls")
print(" sudo su → CALLER=bash → CMD=/usr/bin/sudo")
print(" → CALLER=sudo → CMD=/usr/bin/su\n")

# 持续轮询
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

#### 步骤 3：测试运行

直接运行分离后的 Python 脚本：

```bash
sudo python3 hello-perf-plus.py
```

在另一个终端敲几个命令（比如 `ls` 或 `sudo su`），你会看到输出和之前**完全一样**：

![image-20260525150646674](https://raw.githubusercontent.com/Chenjx12/PicGO/main/img/20260525150655571.png)

### 3.3 BPF() 的两种加载方式对比

| 参数                   | 用法                 | 适合场景                             |
| ---------------------- | -------------------- | ------------------------------------ |
| `text=program`         | C 代码以字符串传入   | 简单示例、教学、快速原型             |
| **`src_file="xxx.c"`** | **C 代码从文件读取** | **正式项目、代码较长、需要语法高亮** |

**两者完全等价**，`src_file` 本质上就是 BCC 帮你 `open().read()` 然后传给 `text`。但就是这简单的一步分离，让你的 C 代码获得了 IDE 的语法高亮和跳转支持，维护体验直线上升！



### 💡 关键收获

经过前面的“解剖”，我们知道了 BCC 在背后调用了 `clang`。
而现在的 C/Python 分离，相当于我们把 C 代码**主动**交给了编辑器和 clang。

这不再仅仅是为了“好看”，而是为了**可维护**：
当你的 eBPF C 代码达到几百行时，你不可能在一个 Python 字符串里找 Bug。
分离是工程化的第一步，从现在开始养成好习惯，后面做项目时会受益无穷。

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

即使我们已经将 C 和 Python 做了分离，现在我们的程序还是"一整坨"——一个 `hello()` 函数干所有事。

如果逻辑复杂了怎么办?

**第五篇: eBPF 程序的拆分与组合** 已经发布! 🎉

**对应笔记**: [Five、eBPF 程序的拆分与组合](./五、eBPF%20程序的拆分与组合.md)  
**对应代码**: [`code/05-call/`](../code/05-call/)

**核心内容:**
- ✅ **BPF-to-BPF 函数调用**(代码复用) - [`bpf2bpf.c`](../code/05-call/bpf2bpf.c)
- ✅ **尾调用(Tail Call)**(不回来的调用) - [`tailcall-chain.py`](../code/05-call/tailcall-chain.py)
- ✅ **多探针组合架构** - [`tailcall-multi-probe.py`](../code/05-call/tailcall-multi-probe.py)
- ✅ **策略路由实现** - [`tailcall-policy-route.py`](../code/05-call/tailcall-policy-route.py)

**核心问题:**

- 如何在 eBPF 中实现函数调用?(受限于 512 字节栈)
- 尾调用和普通函数调用有什么区别?(不返回、复用栈帧)
- 如何用尾调用实现"程序链"?(动态分派)

---

## 🔗 相关链接

- **上一篇**: [Three、eBPF 的 Hello World](./三、eBPF%20的%20Hello%20%20World.md)
- **下一篇**: [Five、eBPF 程序的拆分与组合](./五、eBPF%20程序的拆分与组合.md)
- **再下一篇**: [Six、容器感知与身份识别：从内核到云原生](./六、容器感知与身份识别：从内核到云原生.md) - Namespace、Cgroup、容器身份识别
- **常见问题**: [FAQ](../FAQ.md) (包含程序卸载清理指南)
- **第四篇代码**: [`code/04-anatomy/`](../code/04-anatomy/)
- **第五篇代码**: [`code/05-call/`](../code/05-call/)
- **第六篇代码**: [`code/06-container/`](../code/06-container/)
