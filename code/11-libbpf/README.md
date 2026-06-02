# eBPF 示例代码 (第五篇: CO-RE、BTF 与 Libbpf)

本目录包含《Learning eBPF》第 5 章的学习笔记与配套练习代码。

**对应笔记**: [一、CO-RE、BTF 与 Libbpf](../../docs/Two-回顾/一、CO-RE、BTF%20与%20Libbpf.md)

## 📂 文件列表

| 文件名 | 说明 | 难度 | 推荐顺序 |
|--------|------|------|---------|
| [hello-buffer-config.bpf.c](./hello-buffer-config.bpf.c) | CO-RE 版 eBPF 内核程序 (Libbpf 风格) | ⭐⭐⭐⭐ | 1️⃣ |
| [hello-buffer-config.c](./hello-buffer-config.c) | 用户态 C 加载器 (Skeleton 模式) | ⭐⭐⭐⭐ | 2️⃣ |
| [hello-buffer-config.h](./hello-buffer-config.h) | 内核/用户态共享数据结构 | ⭐⭐⭐ | 3️⃣ |
| [Makefile](./Makefile) | CO-RE 编译脚本 | ⭐⭐ | 4️⃣ |

## 🚀 快速开始

### 前置要求

```bash
# 确认 libbpf 开发库已安装
sudo apt install libbpf-dev libelf-dev

# 确认 bpftool 可用
bpftool version

# 生成 vmlinux.h (CO-RE 依赖)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### 编译 & 运行

```bash
# 1. 编译 eBPF 程序
make

# 2. 运行
sudo ./hello-buffer-config

# 3. 在新终端触发 execve 事件
ls

# 4. 修改配置 (另一终端)
sudo bpftool map update name my_config key 0 0 0 0 value <你的消息>
```

## 📖 核心概念

### CO-RE (Compile Once, Run Everywhere)

BCC 在目标机器上**运行时编译** → 需要内核头文件 + clang/llvm 工具链。
Libbpf + CO-RE 在开发机上**预编译** → 只需一个 `.bpf.o` 文件，跨内核版本运行。

CO-RE 依赖五个要素:
1. **BTF** (BPF Type Format) — 描述数据结构布局
2. **vmlinux.h** — `bpftool btf dump` 从运行中内核生成
3. **Clang/GCC** — 编译器生成 CO-RE 重定位信息
4. **Libbpf 库** — 加载时根据 BTF 差异自动修正偏移量
5. **BPF Skeleton** — `bpftool gen skeleton` 自动生成，封装生命周期

### 关键差异: BCC vs Libbpf

| 维度 | BCC (旧) | Libbpf + CO-RE (新) |
|------|---------|---------------------|
| 编译时机 | 运行时 (每台机器) | 编译时 (开发机) |
| 部署依赖 | Python + clang + headers | 仅 .bpf.o 文件 |
| 启动速度 | 秒级 (含编译) | 毫秒级 |
| 内核兼容 | 需要匹配的 headers | CO-RE 自动适配 |
| 用户态语言 | Python | C / Go / Rust |

## 📝 练习

### 练习 1: BTF 信息检查

```bash
# 列出所有 BTF 数据块
bpftool btf list

# 查看 map 和 prog 的 BTF 信息
bpftool btf dump map name output
bpftool btf dump prog name hello
```

### 练习 2: 比较文件内与加载后的 BTF

```bash
# 比较 ELF 文件中的 BTF 和加载到内核后的 BTF
bpftool btf dump file hello-buffer-config.bpf.o
bpftool btf dump prog name hello
# 输出应该一致
```

### 练习 3: 调试加载过程

```bash
bpftool -d prog load hello-buffer-config.bpf.o /sys/fs/bpf/hello
# 观察: 加载的节、许可证检查、重定位、每条 BPF 指令
```

### 练习 4: 跨内核 CO-RE 重定位

从 [BTFHub](https://github.com/aquasecurity/btfhub) 下载不同内核版本的 `vmlinux.h`，重新编译后在另一台机器上加载，用 `bpftool -d` 观察偏移量变化。

### 练习 5: 实现用户态 map 配置

修改 `hello-buffer-config.c`，在加载 BPF 程序前写入 `my_config` map，使不同 UID 看到不同的问候消息。

### 练习 6: 修改 SEC() 节名

将 `SEC("ksyscall/execve")` 改为自定义名称，观察 libbpf 报错，然后手动用 `bpf_program__attach_kprobe()` 显式附加。

---

## 📖 相关文档

- **学习笔记**: [一、CO-RE、BTF 与 Libbpf](../../docs/Two-回顾/一、CO-RE、BTF%20与%20Libbpf.md)
- **常见问题**: [FAQ](../../FAQ.md)
- **上一章代码**: [10-perf](../10-perf/)

---

*最后更新: 2026-06-02*
