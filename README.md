# eBPF Learning Notes

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![eBPF](https://img.shields.io/badge/eBPF-Learning-green.svg)](https://ebpf.io/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04-orange.svg)](https://ubuntu.com/)

> 📚 从零开始学习 eBPF 的笔记与实践记录，聚焦云原生安全方向。

---

## 🎯 项目背景

本项目是 [Learning eBPF](https://binw666.github.io/learning-ebpf-translation/) 的学习笔记和代码实践，主要服务于：
- 🎓 本科毕业设计：《基于 eBPF 的容器运行时逃逸检测与防护系统》
- 💼 职业规划：云原生安全方向工程师
- 🧪 技术预研：eBPF 在容器安全中的应用

---

## 📖 学习笔记目录

| 章节 | 标题 | 核心内容 |
|------|------|----------|
| [One](./docs/One、什么是%20eBPF.md) | 什么是 eBPF | 核心概念、Verifier、JIT、Maps |
| [Two](./docs/Two、云原生下的%20eBPF.md) | 云原生下的 eBPF | 网络管理、可观测性、安全防护 |
| [Three](./docs/Three、eBPF%20的%20Hello%20%20World.md) | Hello World | BCC框架、kprobe、Perf/Ring Buffer |
| - | 简章 | 从 Pwn 手到云原生的逆旅 |
| - | 项目环境 | Ubuntu 22.04 虚拟机配置指南 |

---

## 🚀 快速开始

### 前置要求

- **操作系统**: Ubuntu 22.04 LTS (推荐 VMware 虚拟机)
- **内核版本**: ≥ 5.15 (支持 eBPF)
- **依赖工具**: BCC 框架、Python 3.8+
- **权限**: root 或 sudo

### 一键运行

```bash
# 1. 克隆仓库
git clone https://github.com/Chenjx12/ebpf-learning-notes.git
cd ebpf-learning-notes

# 2. 安装依赖 (参考 docs/项目环境.md)
sudo apt install bpfcc-tools linux-headers-$(uname -r)

# 3. 运行 Hello World 示例
sudo python3 examples/hello-world.py

# 4. 新开终端执行 ls, ps 等命令观察输出
```

### 环境搭建脚本

详见 [`setup.sh`](./setup.sh) - 一键配置 eBPF 学习环境

---

## 📂 项目结构

```
ebpf-learning-notes/
├── README.md              # 项目说明文档
├── setup.sh               # 环境搭建脚本
├── FAQ.md                 # 常见问题解答
├── docs/                  # 学习笔记
│   ├── One、什么是 eBPF.md
│   ├── Two、云原生下的 eBPF.md
│   ├── Three、eBPF 的 Hello  World.md
│   ├── 简章.md
│   └── 项目环境.md
└── examples/              # 示例代码
    ├── hello-world.py     # 基础 Hello World
    ├── hello-openat.py    # openat 监控
    ├── hello-perf.py      # Perf Buffer 示例
    └── hello-ring.py      # Ring Buffer 示例
```

---

## ❓ 常见问题 (FAQ)

### Q1: 为什么 execve 计数器初始值不是 0?

**现象**: 刚启动程序就看到计数已经是 8 了

**原因**: BCC 编译过程本身会 spawn 多个子进程：
1. `sudo` → execve +1
2. `python3` → execve +1  
3. clang 编译 eBPF 代码 → 可能产生 N 个子进程
4. 从 attach_kprobe 成功到第一次 print 之间的后台 execve

**验证方法**: 
```bash
# 在另一个终端监控
sudo /usr/share/bcc/tools/execsnoop
```

---

### Q2: 为什么 COMM 显示的是 bash 而不是 ls?

**现象**: 执行 ls 后，看到 COMM=bash

**原因**: kprobe 挂钩在 execve 入口，此时：
1. bash fork() 创建子进程（子进程继承 bash 名称）
2. 子进程调用 execve("/bin/ls") ← **探针在这里触发**
3. execve 成功后进程名才变成 ls ← **但已经过了探针点**

**解决方案**: 使用 tracepoint 并读取 filename 参数

---

### Q3: 为什么 exit 命令没有被捕获?

**原因**: exit 是 shell 内建命令，不触发 execve

**验证**:
```bash
type exit
# 输出: exit is a shell builtin
```

**安全启示**: 仅监控 execve 无法检测内建命令攻击，需要组合 openat 等探针

---

### Q4: Perf Buffer vs Ring Buffer 如何选择?

| 维度 | Perf Buffer | Ring Buffer |
|------|-------------|-------------|
| 内核版本要求 | 4.4+ | **5.8+** |
| 缓冲区结构 | 每 CPU 各一个 | **所有 CPU 共享一个** |
| 事件顺序 | 跨 CPU 可能乱序 | **全局有序** |
| 内存效率 | per-CPU 预留，可能浪费 | **按需使用，更节省** |
| 推荐度 | 老内核兼容 | **新项目首选** |

**结论**: 现代内核优先使用 Ring Buffer

---

查看更多问题 → [完整 FAQ](./FAQ.md)

---

## 🔬 实验环境

所有示例均在以下环境测试通过：

```yaml
OS: Ubuntu 22.04 LTS (VMware 虚拟机)
Kernel: 5.15.0-generic
CPU: 4 cores (2×2)
Memory: 8 GB
Disk: 80 GB
Network: NAT
BCC: 0.24.0
Python: 3.10.6
```

---

## 🛠️ 开发工具

### 必备工具

- **文本编辑器**: Vim / Nano
- **版本控制**: Git
- **包管理**: apt

### 可选工具

- **VS Code**: 远程连接虚拟机编辑代码
- **Docker**: 测试容器逃逸场景
- **Wireshark**: 分析网络流量

---

## 📊 性能对比

| 方式 | 10秒内事件数 | CPU占用 | 实现难度 |
|------|------------|---------|---------|
| trace_printk | ~50 | <1% | ⭐ |
| Perf Buffer | ~50 | 1-2% | ⭐⭐ |
| Ring Buffer | ~50 | 1-2% | ⭐⭐ |

**测试方法**: 手动执行 10 次 ls 命令，统计捕获数量

**结论**: 
- 三种方式在低负载下都能完整捕获
- trace_printk 最轻量，但不适合生产环境
- Ring Buffer 支持全局有序，推荐使用

---

## 🎓 学习路线

### 第 1 周：理论基础
- ✅ 阅读《Learning eBPF》第 1-2 章
- ✅ 理解 eBPF 工作原理
- ✅ 搭建 Ubuntu 开发环境

### 第 2 周：BCC 实践
- ✅ 运行现有工具 (execsnoop, opensnoop)
- ✅ 编写第一个 BCC 程序
- ✅ 理解不同 Maps 的使用场景

### 第 3 周：深入理解
- ✅ 学习不同探针类型 (kprobe, uprobe, tracepoint)
- ✅ 掌握 Ring Buffer 机制
- ✅ 研究容器逃逸案例

### 第 4 周：项目实战
- ✅ 设计简单的逃逸检测器
- ✅ 整合多个监控点
- ✅ 输出检测结果

---

## 🔗 相关资源

### 官方文档
- [eBPF.io](https://ebpf.io/) - 官方学习路径
- [BCC Tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial.md)
- [libbpf Documentation](https://libbpf.readthedocs.io/)

### 学习资源
- [Learning eBPF 中文翻译](https://binw666.github.io/learning-ebpf-translation/)
- [Brendan Gregg's Blog](http://www.brendangregg.com/bpf.html)
- [Falco Documentation](https://falco.org/docs/)

### 开源项目
- [Falco](https://falco.org/) - 云原生运行时安全
- [Tracee](https://github.com/aquasecurity/tracee) - eBPF 安全追踪
- [Cilium](https://cilium.io/) - eBPF 网络与安全

---

## 📝 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](./LICENSE) 文件

---

## 👤 关于作者

重庆邮电大学 · 网络空间安全系 · 信息安全专业 (2027届)

**职业方向**: 云原生安全工程师

**GitHub**: [@Chenjx12](https://github.com/Chenjx12)

---

## 🌟 Star History

如果这个项目对你有帮助，欢迎 Star ⭐️

---

*最后更新: 2026-05-24*
