# 一、CO-RE、BTF 与 Libbpf

> 《Learning eBPF》第 5 章精读笔记

---

## 笔记前置

在动手之前，先搞清楚一件事：**为什么需要 CO-RE？**

前面十篇文章我们全用的 BCC。BCC 的做法是：在目标机器上**运行时**把 eBPF C 代码编译成字节码。这意味着：
- 每台机器都要装 clang/llvm 工具链
- 每台机器都要有内核头文件
- 每次启动都有编译延迟
- 不同内核版本可能导致编译失败

**CO-RE (Compile Once, Run Everywhere)** 的思路完全不同：在开发机上**预编译**好 `.bpf.o`，部署到任何机器上都能跑。内核版本不同？Libbpf 在加载时根据 BTF 自动修正数据结构偏移量。

这就是从"玩具"到"生产级"的关键跨越。

---

## 一、BCC 的可移植性问题

BCC 的可移植性依赖于在目标机器上编译。问题清单：

1. **编译工具链必须存在** — 嵌入式设备可能没有足够内存
2. **内核头文件必须存在** — 版本必须匹配
3. **启动延迟** — 每次运行都要编译一遍
4. **同质集群浪费** — 100 台相同机器重复编译 100 次

BCC 项目也意识到了这个问题，推出了 `libbpf-tools/` 目录，其中包含基于 libbpf 的 BCC 工具重写版本。

---

## 二、CO-RE 的五个要素

### 2.1 BTF (BPF Type Format)

BTF 描述数据结构和函数签名的内存布局。从 Linux 5.4 开始，内核编译时包含 BTF 信息，暴露在 `/sys/kernel/btf/vmlinux`。

**BTF 解决的三个关键问题**：
- **CO-RE 重定位** — 加载时修正字段偏移量
- **美化输出** — `bpftool map dump` 可以按结构体格式展示内容
- **源码交织** — JIT/xlated 转储中嵌入 C 源码行

### 2.2 内核头文件 (vmlinux.h)

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

这个命令从运行中内核的 BTF 信息生成一个**超级头文件**，包含所有内核数据结构定义。eBPF 程序只需要 `#include "vmlinux.h"` 就能访问任何内核类型。

### 2.3 编译器支持

Clang 增强了 `__builtin_preserve_access_index()`，在编译时生成 CO-RE 重定位记录。GCC 12+ 也支持。

vmlinux.h 中有这个 pragma：
```c
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
```
这意味着 vmlinux.h 中所有记录类型都会自动生成 CO-RE 重定位信息。

### 2.4 重定位库 (Libbpf)

Libbpf 在加载 eBPF 程序时：
1. 读取 `.bpf.o` 中的 CO-RE 重定位记录
2. 从运行中内核获取 BTF 信息
3. 比较结构体布局差异，自动修正偏移量
4. 将修正后的指令加载到内核

### 2.5 BPF Skeleton (骨架)

```bash
bpftool gen skeleton hello-buffer-config.bpf.o > hello-buffer-config.skel.h
```

骨架是一个自动生成的 C 头文件，提供：
- `__open()` — 读取 ELF 文件
- `__load()` — 加载 map 和程序到内核
- `__attach()` — 根据 SEC() 自动附加
- `__destroy()` — 清理所有资源

---

## 三、BPF 类型格式 (BTF) 深入

### 3.1 查看 BTF 信息

```bash
# 列出所有加载的 BTF 数据
bpftool btf list

# 查看 vmlinux BTF (ID 1)
bpftool btf dump id 1

# 查看特定 map 的 BTF
bpftool btf dump map name my_config

# 查看特定程序的 BTF
bpftool btf dump prog name hello
```

### 3.2 BTF 类型编码

BTF 将 C 类型编码为一组类型描述符。以 `struct user_msg_t { char message[12]; }` 为例：

```
[1] STRUCT 'user_msg_t' size=12 vlen=1
    'message' type_id=2 bits_offset=0
[2] ARRAY type_id=3 index_type_id=4 nr_elems=12
[3] INT 'char' size=1
[4] INT '__ARRAY_SIZE_TYPE__' size=4
```

### 3.3 Map 与 BTF

创建 Map 时传入 BTF 信息，内核就能理解 key/value 的类型，`bpftool map dump` 可以 pretty-print。

没有 BTF 时，key/value 只是不透明的字节数组。

### 3.4 函数和函数原型

BTF 不仅记录数据结构，还记录：
- 函数签名 (FUNC + FUNC_PROTO)
- 参数类型和返回值类型
- 这使 fentry/fexit 等程序类型能够直接访问参数

---

## 四、CO-RE 内存访问模式

### 4.1 bpf_core_read()

```c
// 底层 API: 安全读取内核内存 + CO-RE 重定位
bpf_core_read(dst, size, src);
```

等价于 `bpf_probe_read_kernel()` + `__builtin_preserve_access_index()`。

### 4.2 BPF_CORE_READ()

```c
// 链式读取: 相当于 d = a->b->c->d
BPF_CORE_READ(a, b, c, d);
```

对于深层嵌套的内核结构体，这个宏极大简化了代码。

### 4.3 为什么需要这些辅助函数？

eBPF 验证器通常不允许直接指针解引用。但对于某些 BTF-enabled 程序类型 (tp_btf, fentry, fexit)，可以直接访问指针——条件是 BTF 信息足够让验证器计算运行时越界检查。

---

## 五、编译 CO-RE eBPF 程序

### 5.1 编译标志解析

```makefile
clang \
    -target bpf \              # 生成 eBPF 字节码
    -D __TARGET_ARCH_x86 \     # 架构定义 (BPF_KPROBE 宏需要)
    -I/usr/include/x86_64-linux-gnu \
    -Wall \
    -O2 -g \                   # -O2 必须 (否则 callx 不支持); -g 生成 BTF
    -c hello-buffer-config.bpf.c -o hello-buffer-config.bpf.o
llvm-strip -g hello-buffer-config.bpf.o  # 剥离 DWARF，保留 BTF
```

### 5.2 为什么 -O2 是必须的？

没有优化时，Clang 可能生成 `callx <register>` 指令，而 eBPF 指令集不支持。`-O2` 消除了这些问题。

### 5.3 llvm-strip -g

`-g` 同时生成 DWARF 调试信息和 BTF 数据。DWARF 是给用户态调试器用的，eBPF 不需要。`llvm-strip -g` 移除 DWARF 而保留 BTF。

---

## 六、用户态 Libbpf 编程

### 6.1 Skeleton 生命周期

```c
// 1. 打开 ELF 文件
struct hello_buffer_config_bpf *skel = hello_buffer_config_bpf__open();

// 2. 可选: 在加载前设置初始配置
strcpy(skel->data->message, "Custom message");

// 3. 加载 map 和程序到内核 (CO-RE 重定位在此发生)
hello_buffer_config_bpf__load(skel);

// ⚠️ load() 之后的 data 修改不会影响内核态!

// 4. 附加到事件
hello_buffer_config_bpf__attach(skel);

// 5. 事件循环
while (running) {
    perf_buffer__poll(pb, 100);
}

// 6. 清理
hello_buffer_config_bpf__destroy(skel);
```

**关键坑**：`skel->data->` 的修改必须在 `__open()` 和 `__load()` 之间！
加载后内核已经读取了数据，后续修改无效。

### 6.2 SEC() 命名约定

| SEC() 名称 | 含义 | 自动附加 |
|-----------|------|---------|
| `SEC("ksyscall/execve")` | 系统调用 kprobe | ✅ |
| `SEC("kprobe/__arm64_sys_execve")` | 架构特定的 kprobe | ✅ |
| `SEC("kprobe")` | 通用 kprobe | ❌ (需手动) |
| `SEC("tracepoint/...")` | 跟踪点 | ✅ |
| `SEC("license")` | 许可证 | — |
| `SEC(".maps")` | Map 定义 | — |

### 6.3 访问已存在的 (Pinned) Map

```c
int fd = bpf_obj_get("/sys/fs/bpf/my_map");
bpf_map_update_elem(fd, &key, &value, BPF_ANY);
```

---

## 七、从 BCC 到 Libbpf 的迁移对照

| 概念 | BCC 写法 | Libbpf 写法 |
|------|---------|------------|
| 定义 Map | `BPF_PERF_OUTPUT(output);` | `SEC(".maps")` + `__uint(type, ...)` |
| 定义 Hash Map | `BPF_HASH(my_config, u32, struct user_msg_t);` | 同上 |
| 全局变量 | `char message[12] = "Hello";` | 同 (Libbpf 支持全局变量) |
| 探针宏 | `TRACEPOINT_PROBE(syscalls, sys_enter_execve)` | `SEC("tp/syscalls/...")` |
| 内核打印 | `bpf_trace_printk()` | `bpf_printk()` (同底层) |
| 用户态加载 | `b = BPF(src_file="xxx.c")` | `skel = xxx_bpf__open_and_load()` |

---

## 📝 练习

- [ ] **练习 1**: 用 `bpftool btf dump` 检查 map 和程序的 BTF 信息
- [ ] **练习 2**: 比较 ELF 文件 BTF 与加载后 BTF (应一致)
- [ ] **练习 3**: 用 `bpftool -d prog load` 观察加载调试输出
- [ ] **练习 4**: 从 BTFHub 下载不同内核的 vmlinux.h，验证 CO-RE 重定位
- [ ] **练习 5**: 实现用户态 map 配置 (不同 UID 不同消息)
- [ ] **练习 6**: 修改 SEC() 节名，实现手动附加

---

## 📖 相关文档

- **代码目录**: [code/11-libbpf/](../../code/11-libbpf/)
- **下一篇**: [二、eBPF 验证器](./二、eBPF%20验证器.md) (待完成)
- **常见问题**: [FAQ](../../FAQ.md)

---

*最后更新: 2026-06-02*
