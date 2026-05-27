# eBPF/BPF 常用字典

下面整理了**查 eBPF/BPF 函数和指令的几类“字典”**，从“内核 helper 函数”到“BCC 宏”再到“指令集”，按日常使用频率排序，并直接给链接和用法。

## 1. 内核 eBPF Helper 函数官方文档（最权威）

这是查 `bpf_get_current_pid_tgid()`、`bpf_probe_read()`、`bpf_tail_call()` 等内核 helper 的唯一权威来源。

### 1.1 内核文档：BPF Helpers

- 文档地址（5.15 版本，和实验环境接近）：
  - https://docs.kernel.org/bpf/helpers.html
- 内容包括：
  - 所有 helper 的函数原型、参数、返回值
  - 每个函数从哪个内核版本开始支持
  - 能在哪些 BPF 程序类型中使用（tracepoint / kprobe / XDP 等）

**建议用法：**

- 忘了某个 helper 的参数：直接搜 `bpf_get_current_pid_tgid` 或 `bpf_probe_read`。
- 想看新内核（5.19+/6.1+）新增了哪些 helper：看对应版本的同一路径文档。
- 想确认某个 helper 是否能在你的程序类型里用：文档里每个函数都有 “Context” 部分说明。

### 1.2 man 页面：bpf-helpers(7)

很多发行版提供了 man 页面，查起来比网页还快：

```bash
sudo apt install manpages-dev   # 如果没装的话
man 7 bpf-helpers
```

- 内容和内核文档基本一致，但适合在终端里快速翻。
- 你可以：
  - `/ bpf_get_current` 搜索某个函数
  - 按版本号查找（例如只看 5.15 支持的）

## 2. BCC 的 Helper 宏 / 函数参考

BCC 在 C 侧和 Python 侧都做了一层封装，直接看内核文档会“对不上号”，需要查 BCC 自己的映射。

### 2.1 BCC 官方参考文档

- BCC Python API：
  https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
- 里面关键章节：
  - `BPF()` 的各种参数（`text=` / `src_file=` / `debug=`）
  - `BPF_HASH` / `BPF_PERF_OUTPUT` / `BPF_RINGBUF_OUTPUT` 等 map 宏
  - `bpf_trace_printk` / `bpf_probe_read` 等 BCC 封装

**建议用法：**

- 忘了 `BPF_HASH` 的第三个参数是什么：搜 `BPF_HASH`。
- 忘了 `events.perf_submit(ctx, &data, size)` 的 Python 侧写法：搜 `perf_submit`。
- 想看 `bpf_trace_printk` 在 BCC 里要传几个参数：搜 `bpf_trace_printk`，注意 BCC 版本可能有差异。

### 2.2 BCC 源码里的 helper 定义

如果想从 C 侧看 BCC 到底怎么映射内核 helper：

- BCC 头文件（你本地装了 BCC 的话）：
  - `/usr/include/bcc/helpers.h`
  - `/usr/include/bcc/proto.h`

```bash
dpkg -L bpfcc-tools | grep helpers.h
# 或
find /usr -name helpers.h 2>/dev/null | head
```

- 里面有类似：
  - `bpf_get_current_pid_tgid()` → 内核 helper #14
  - `bpf_probe_read()` → 内核 helper #4
  - 以及 BCC 自己加的 `bpf_trace_printk` 封装等

## 3. eBPF 指令集 / 寄存器速查

之前用 `bpftool prog dump xlated` 看到一堆 `(18)`、`(7b)`、`(85)` 之类的操作码，想系统查指令集的话看这里：

### 3.1 内核文档：BPF Instruction Set

- 文档：https://docs.kernel.org/bpf/instruction-set.html
- 内容：
  - 指令格式（8 字节一条：op + dst_reg + src_reg + off + imm）
  - 所有操作码（`b7` = MOV32、`18` = MOV64、`85` = CALL 等）
  - 寄存器语义（`r0` 返回值 / `r1-r5` 参数 / `r10` 栈帧指针）

**建议用法：**

- 看字节码时遇到不认识的 opcode：

  - 直接在文档里搜 `7b` 或 `STX64`，就能看到语义。

- 想理解为什么

  ```bash
  call -1
  ```

  是 BPF-to-BPF 调用：

  - 看 `CALL` 指令的 `source_reg` 字段（`0x1` 表示 BPF-to-BPF）。

### 3.2 BPF 指令速查表

第四篇整理的表其实已经很好用了，下面精简成“日常查表版”：

| 操作码 | 助记符    | 含义                          | 例子                                |
| ------ | --------- | ----------------------------- | ----------------------------------- |
| `b7`   | MOV32     | 32 位立即数加载               | `r1 = 0`                            |
| `18`   | MOV64     | 64 位立即数加载               | `r1 = 0x726620...`（字符串片段）    |
| `bf`   | MOV64_REG | 64 位寄存器拷贝               | `r1 = r10`                          |
| `07`   | ADD64     | 64 位加法                     | `r1 += -40`                         |
| `7b`   | STX64     | 存 64 位到内存                | `*(u64*)(r10-16) = r1`              |
| `73`   | STX8      | 存 8 位到内存                 | `*(u8*)(r10-8) = r1`                |
| `85`   | CALL      | 调用函数（helper/BPF-to-BPF） | `call bpf_trace_printk` / `call -1` |
| `95`   | EXIT      | 退出程序                      | `exit`                              |

遇到不认识的操作码，就按这个表在内核文档里查，很快就能习惯。

## 4. 日常查表的小技巧

### 4.1 在虚拟机上本地查

1. **Helper 函数**

```bash
   man 7 bpf-helpers
   # 或
   grep -R "bpf_get_current_pid_tgid" /usr/include/bcc/ 2>/dev/null
```

2. **BCC 宏 / API**

```bash
   python3 -c "from bcc import BPF; help(BPF)" | less
   # 或直接看源码
   dpkg -L bpfcc-tools | grep '.py$' | xargs grep -n 'BPF_HASH'
```

3. **指令集**

```bash
   # 本地内核文档（如果装了 kernel-doc）
   ls /usr/share/doc/kernel-doc-*/Documentation/bpf/
   # 或直接在线看：https://docs.kernel.org/bpf/instruction-set.html
```

### 4.2 在线速查（推荐加书签）

按“从上到下”的使用频率排序：

1. **Helper 函数**
   - https://docs.kernel.org/bpf/helpers.html
   - 或 `man 7 bpf-helpers`
2. **BCC Python/C API**
   - https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
3. **BPF 指令集**
   - https://docs.kernel.org/bpf/instruction-set.html
4. **速查表**
   - 第四篇整理的指令表 + 本篇的 helper 表，复制到一个 `ebpf-cheatsheet.md` 里，写文章时直接翻。

