# eBPF 编译过程与中间产物详解

本文档展示了从 C 源代码到 eBPF 字节码的完整编译过程，包括所有中间产物的详细分析。

## 📋 目录结构

```
04-anatomy/
├── hello-debug.c          # eBPF C 源代码
├── hello-debug.o          # 编译生成的 eBPF 字节码（ELF 格式）
├── build-ebpf.sh          # 自动化编译脚本
└── COMPILE_OUTPUT.md      # 本文档
```

---

## 🔧 1. 编译环境

### 1.1 系统信息

```bash
$ uname -r
6.8.0-117-generic

$ clang --version
Ubuntu clang version 14.0.0-1ubuntu1.1
```

### 1.2 关键依赖

- **内核头文件**: `linux-headers-6.8.0-117-generic`
- **Clang**: 14.0.0（支持 eBPF 后端）
- **bpftool**: v7.4.0（用于加载和查看程序）

---

## 📝 2. 源代码

### hello-debug.c

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

// 定义许可证(必须的)
char LICENSE[] SEC("license") = "GPL";

// eBPF程序入口点
SEC("kprobe/sys_execve")
int hello(struct pt_regs *ctx) {
    // bpf_trace_printk 需要 fmt 和 fmt_size 两个参数
    char fmt[] = "Hello from manual clang compile!";
    bpf_trace_printk(fmt, sizeof(fmt));
    return 0;
}
```

**关键点说明**：

1. **`SEC("license")`**: 将许可证字符串放入名为 `license` 的 ELF 段，内核加载时会检查此段。

2. **`SEC("kprobe/sys_execve")`**: 将 `hello` 函数放入名为 `kprobe/sys_execve` 的段。加载器（如 BCC 或 libbpf）会解析这个段名，自动将程序挂钩到 `sys_execve` 的 kprobe 上。

3. **`bpf_trace_printk(fmt, sizeof(fmt))`**: eBPF 的调试输出函数，会将消息写入 `/sys/kernel/debug/tracing/trace_pipe`。

---

## ⚙️ 3. 编译命令

### 3.1 完整的编译命令

```bash
clang -target bpf \
      -O2 \
      -g \
      -I/usr/include/x86_64-linux-gnu \
      -c hello-debug.c \
      -o hello-debug.o
```

### 3.2 参数解释

| 参数 | 作用 | 说明 |
|------|------|------|
| `-target bpf` | 指定目标架构为 eBPF | 告诉 clang 生成 eBPF 字节码而非 x86 机器码 |
| `-O2` | 优化等级 | eBPF 验证器通常要求代码经过优化 |
| `-g` | 生成调试信息 | 便于后续用 bpftool 查看源码对应关系 |
| `-I/usr/include/x86_64-linux-gnu` | 添加 include 路径 | 解决 `asm/types.h` 找不到的问题 |
| `-c` | 只编译不链接 | 生成 .o 对象文件 |

---

## 📦 4. 编译产物分析

### 4.1 文件大小

```bash
$ ls -lh hello-debug.o
-rwxr-xr-x 1 chenjx12 chenjx12 4.6K  5月 24 22:00 hello-debug.o
```

生成的 eBPF 字节码文件约 **4.6 KB**。

---

### 4.2 ELF 段结构分析（readelf -S）

```bash
$ readelf -S hello-debug.o
```

**关键段说明**：

```
[Nr] Name              Type            Address           Offset
     Size              EntSize         Flags  Link  Info  Align
[ 3] kprobe/sys_execve PROGBITS        0000000000000000  00000040
     00000000000000a0  0000000000000000  AX       0     0     8
```
- **`kprobe/sys_execve`**: 我们的 `hello` 函数所在的段
- **大小**: `0xa0` (160 字节) 的 eBPF 字节码
- **Flags**: `AX` = Alloc + Execute
- **重要性**: 加载器通过段名知道这是要挂钩到 `sys_execve` 的 kprobe 程序

```
[ 4] license           PROGBITS        0000000000000000  000000e0
     0000000000000004  0000000000000000  WA       0     0     1
```
- **`license`**: 许可证字符串段
- **内容**: "GPL" (4 字节)
- **Flags**: `WA` = Write + Alloc
- **重要性**: 内核加载时会检查许可证是否兼容（必须是 GPL 兼容的）

```
[ 5] .rodata.str1.1    PROGBITS         0000000000000000  000000e4
     0000000000000021  0000000000000001 AMS       0     0     1
```
- **`.rodata.str1.1`**: 只读数据段，存储我们的格式化字符串 `"Hello from manual clang compile!"`
- **大小**: `0x21` (33 字节)

**调试信息段**（由 `-g` 参数生成）：

- `[ 6] .debug_abbrev`: DWARF 调试缩写表
- `[ 7] .debug_info`: DWARF 调试信息
- `[20] .debug_line`: 行号信息（用于源码级调试）
- `[14] .BTF`: BPF Type Format（eBPF 特有的类型信息）

---

### 4.3 eBPF 字节码反汇编（llvm-objdump -d）

```bash
$ llvm-objdump-14 -d hello-debug.o
```

**输出**：

```
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

**逐条指令解析**：

#### 阶段 1：构建格式化字符串（指令 0-13）

eBPF 没有全局字符串常量，必须在栈上手动构建：

```
指令 0-2: 将 "!elpmoc gnilpm" 加载到 r1，然后存入栈 [r10-16]
指令 3-5: 将 " clgnual" 加载到 r1，然后存入栈 [r10-24]
指令 6-8: 将 "m manua" 加载到 r1，然后存入栈 [r10-32]
指令 9-11: 将 "llor f" 加载到 r1，然后存入栈 [r10-40]
指令 12-13: 在栈 [r10-8] 处写入 NULL 终止符
```

**为什么要这样做？**  
eBPF 运行在内核态，不能直接访问用户态的数据段。所有数据必须在栈上或通过 helper 函数安全读取。

#### 阶段 2：准备调用参数（指令 14-16）

```
指令 14: r1 = r10 (r10 是帧指针)
指令 15: r1 += -40 (r1 指向字符串起始位置 r10-40)
指令 16: r2 = 33 (字符串长度，包括 NULL 终止符)
```

此时寄存器状态：
- `r1`: 指向格式化字符串
- `r2`: 字符串大小 (33)

#### 阶段 3：调用 helper 函数（指令 17）

```
指令 17: call 6
```

**`call 6`** 是调用 eBPF helper 函数编号 6，即 `bpf_trace_printk`。

Helper 函数签名：
```c
long bpf_trace_printk(const char *fmt, u32 fmt_size)
```

#### 阶段 4：返回（指令 18-19）

```
指令 18: r0 = 0 (设置返回值)
指令 19: exit (退出程序)
```

---

### 4.4 指令统计

| 类别 | 数量 | 说明 |
|------|------|------|
| 总指令数 | 20 条 | eBPF 程序通常很短 |
| MOV 立即数 (`b7`) | 3 条 | 初始化寄存器 |
| MOV 长立即数 (`18`) | 4 条 | 加载 64 位常量（字符串片段） |
| 存栈 (`7b`, `73`) | 5 条 | 将字符串写入栈 |
| 算术运算 (`07`) | 1 条 | 调整指针 |
| MOV 寄存器 (`bf`) | 1 条 | 复制帧指针 |
| CALL (`85`) | 1 条 | 调用 helper 函数 |
| EXIT (`95`) | 1 条 | 程序退出 |

**程序大小**: 20 条指令 × 8 字节/指令 = **160 字节**（与 readelf 显示的 `0xa0` 一致）

---

## 🔍 5. 使用 bpftool 加载和查看程序

### 5.1 加载程序

```bash
sudo bpftool prog load hello-debug.o /sys/fs/bpf/hello-debug type kprobe
```

这会将 eBPF 字节码加载到内核，并在 BPF 文件系统中创建引用。

### 5.2 查看已加载的程序

```bash
sudo bpftool prog list
```

**典型输出**：

```
123: kprobe  name hello  tag abc123def456  gpl
        loaded_at 2026-05-24T22:00:00+0800  uid 0
        xlated 160B  jited 96B  memlock 4096B
        pids bash(12345)
```

**字段解释**：

- `123`: 程序 ID
- `kprobe`: 程序类型
- `name hello`: 函数名
- `tag abc123...`: 程序哈希（唯一标识）
- `gpl`: 许可证
- `xlated 160B`: eBPF 字节码大小（与我们看到的 160 字节一致）
- `jited 96B`: JIT 编译后的机器码大小（x86_64 原生代码）
- `memlock 4096B`: 锁定的内存大小

### 5.3 查看程序的字节码

```bash
sudo bpftool prog dump xlated id 123
```

**输出**（与 llvm-objdump 类似，但更详细）：

```
   0: (b7) r1 = 2406448776012984163
   2: (7b) *(u64 *)(r10 - 16) = r1
   3: (b7) r1 = 2334956296524210284
   ...
  17: (85) call bpf_trace_printk#6
  18: (b7) r0 = 0
  19: (95) exit
```

---

## 🎯 6. 关键收获

### 6.1 编译链路总结

```
C 源代码 (hello-debug.c)
    ↓
clang -target bpf -O2 -g
    ↓
ELF 对象文件 (hello-debug.o)
    ├─ 段: kprobe/sys_execve (eBPF 字节码)
    ├─ 段: license ("GPL")
    ├─ 段: .rodata (字符串常量)
    └─ 段: .debug_* (调试信息)
    ↓
bpf() 系统调用
    ↓
内核 Verifier 验证
    ↓
JIT 编译为 x86_64 机器码
    ↓
附加到 kprobe sys_execve
    ↓
每次 execve 触发时执行
```

### 6.2 为什么需要手动编译？

1. **完全可控**: 清楚知道每一个编译参数和步骤
2. **标准化流程**: 这是生产环境和使用 libbpf/bpftool 时的标准工作流
3. **调试友好**: 可以独立于 Python/BCC 测试 C 代码的正确性
4. **理解底层**: 看到 ELF 段结构、字节码指令，真正理解 eBPF 是如何工作的

### 6.3 段名的重要性

eBPF 程序通过 **ELF 段名** 来声明自己的类型和挂载点：

- `SEC("kprobe/sys_execve")` → 挂钩到 `sys_execve` 的 kprobe
- `SEC("tracepoint/syscalls/sys_enter_execve")` → 挂钩到 tracepoint
- `SEC("xdp")` → XDP 程序
- `SEC("socket")` → Socket 过滤器

加载器（BCC/libbpf/bpftool）会解析这些段名，自动完成挂钩操作。

---

## 📚 7. 相关资源

- [eBPF 程序剖析](../../docs/One-实践/四、eBPF%20程序的解剖与工程化.md) - 第四篇文章
- [bpftool 官方文档](https://man7.org/linux/man-pages/man8/bpftool.8.html)
- [libbpf Documentation](https://libbpf.readthedocs.io/)

---

*最后更新: 2026-05-24*
