# Four、eBPF 程序的解剖与工程化

date: 2026.5.24

---

## 🎯 本篇目标

从"会写 BCC 代码"进化到"理解 eBPF 程序 internals",并学会工程化组织代码。

**核心问题:**
- BCC 的 `BPF(text=program)` 背后发生了什么?
- 如何查看内核中正在运行的 eBPF 程序?
- 如何把 C 代码和 Python 代码分离,提升可维护性?

**预计长度:** 中等偏短(比第三篇短 30-40%),因为偏动手验证而非学新 API

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
你写的 C 字符串  →  [BCC 黑盒]  →  内核里跑的 eBPF 程序
```

我们不知道中间发生了什么。这篇就是**打开这个黑盒**,看看从源码到字节码的完整链路。

同时,把你刚悟出来的 **C/Python 分离** 工程实践落地。

---

## 1. BCC 背后:从 C 字符串到内核字节码

### 1.1 BCC 的编译链路

当你执行这行代码时:

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

### 1.2 实验:让 BCC 留下中间文件

**目标:** 找到 BCC 编译过程中的 `.c` 和 `.o` 文件

**方法:** 在 Python 里加 `debug=4` 参数

```python
#!/usr/bin/python3
from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello from debug mode!");
    return 0;
}
"""

# 关键:添加 debug=4,BCC 会把中间文件写到 /tmp/
b = BPF(text=program, debug=4)

syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

print("运行中...请检查 /tmp/bcc_* 目录")
b.trace_print()
```

**运行后查看中间文件:**

```bash
# 新开终端
ls -lh /tmp/bcc_*
# 你会看到类似:
# /tmp/bcc_12345.c      ← BCC 生成的 C 代码
# /tmp/bcc_12345.o      ← 编译后的 eBPF 字节码
```

**截图占位符:** 
> 📸 在这里插入 `/tmp/bcc_*` 文件的截图

### 1.3 用 readelf 看编译产物

**目标:** 理解 eBPF 程序的"零件清单"

```bash
# 查看 .o 文件的段结构
readelf -S /tmp/bcc_12345.o
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
  [ 3] maps              PROGBITS        0000000000000000  00000090
       000000000000001c  0000000000000000   A       0     0     4
  [ 4] .strtab           STRTAB          0000000000000000  000000ac
       0000000000000050  0000000000000000           0     0     1
```

**关键字段解释:**
- `.text`: eBPF 程序的字节码指令
- `license`: 许可证(必须是 GPL 兼容的)
- `maps`: 定义的 map 结构(Hash/Perf/Ring Buffer)

**截图占位符:**
> 📸 在这里插入 `readelf` 输出的截图

### 💡 关键收获

- BCC 不是"魔法",它就是帮你调 `clang + bpf()` 系统调用
- 编译过程产生 `.c` → `.o` → 加载进内核
- 可以用标准工具(readelf/objdump)分析编译产物

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

```python
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

```c
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

```python
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
- 从现在开始养成好习惯,后面做毕设项目时会受益无穷

---

## 4. 整理你的仓库:目录结构规范化

### 4.1 当前问题

之前的结构:

```
ebpf-learning-notes/
├── README.md
├── FAQ.md
├── One、什么是 eBPF.md          ← 笔记和代码混在一起
├── Three、eBPF 的 Hello World.md
└── examples/                    ← 所有代码堆在一个目录
    ├── hello-world.py
    └── hello-perf-plus.py
```

**问题:**
- ❌ 笔记文件和代码文件混在根目录
- ❌ 无法区分哪篇笔记对应哪些代码
- ❌ 随着内容增多,根目录会越来越乱

### 4.2 推荐的新结构

```
ebpf-learning-notes/
├── README.md                     # 项目总览
├── FAQ.md                        # 常见问题
├── LICENSE                       # MIT协议
├── setup.sh                      # 环境搭建脚本
├── .gitignore                    # Git忽略配置
│
├── docs/                         # 📚 学习笔记目录
│   ├── One、什么是 eBPF.md
│   ├── Two、云原生下的 eBPF.md
│   ├── Three、eBPF 的 Hello World.md
│   ├── Four、eBPF 程序的解剖与工程化.md  ← 本篇
│   ├── 简章.md
│   └── 项目环境.md
│
└── code/                         # 💻 实验代码目录
    ├── 03-hello-world/           # 第三篇的代码
    │   ├── hello-world.py
    │   ├── hello-openat.py
    │   ├── hello-map.py
    │   ├── hello-perf.py
    │   ├── hello-ring.py
    │   └── hello-perf-plus.py    # 混合版(留作对比)
    │
    └── 04-anatomy/               # 第四篇的代码
        ├── hello-perf-plus.c     # ← 分离后的 C 代码
        └── hello-perf-plus.py    # ← 分离后的 Python
```

**优点:**
- ✅ 笔记和代码物理分离
- ✅ 每篇笔记对应一个代码目录,一目了然
- ✅ 根目录保持简洁
- ✅ 为后续扩展预留空间(如 `advanced/`, `research/` 等)

### 4.3 执行重构

**步骤 1: 创建新目录**

```bash
mkdir -p code/03-hello-world
mkdir -p code/04-anatomy
```

**步骤 2: 移动现有代码**

```bash
# 移动第三篇的代码
mv examples/hello-world.py code/03-hello-world/
mv examples/hello-openat.py code/03-hello-world/
mv examples/hello-map.py code/03-hello-world/
mv examples/hello-perf.py code/03-hello-world/
mv examples/hello-ring.py code/03-hello-world/
mv examples/hello-perf-plus.py code/03-hello-world/

# 移动第四篇的代码(等你拆分完成后)
# mv code/04-anatomy/hello-perf-plus.c code/04-anatomy/
# mv code/04-anatomy/hello-perf-plus.py code/04-anatomy/
```

**步骤 3: 更新 examples/README.md**

将 [`examples/README.md`](../examples/README.md) 移动到 [`code/03-hello-world/README.md`](../code/03-hello-world/README.md)

**步骤 4: 提交 commit**

```bash
git add .
git commit -m "Reorganize project structure: separate notes and code"
git push origin main
```

**截图占位符:**
> 📸 在这里插入 GitHub 仓库新结构的截图

### 💡 关键收获

- 好习惯从现在开始培养
- 后面代码量大了不用再重构
- 每篇笔记对应一个代码目录,便于复习和演示

---

## 5. 小结 + 预告

### 5.1 本篇总结

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

### 5.2 预告第五篇

现在你的程序都是"一整坨"——一个 `hello()` 函数干所有事。

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
