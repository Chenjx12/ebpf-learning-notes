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

### 核心章节

| 章节                                                           | 标题            | 核心内容                                                       |
| -------------------------------------------------------------- | --------------- | -------------------------------------------------------------- |
| [One](./docs/One、什么是%20eBPF.md)                            | 什么是 eBPF     | 核心概念、Verifier、JIT、Maps                                  |
| [Two](./docs/Two、云原生下的%20eBPF.md)                        | 云原生下的 eBPF | 网络管理、可观测性、安全防护                                   |
| [Three](./docs/Three、eBPF%20的%20Hello%20%20World.md)         | Hello World     | BCC框架、kprobe、Perf/Ring Buffer                              |
| [Four](./docs/Four、eBPF%20程序的解剖与工程化.md)              | **程序解剖**    | **手动编译、ELF段结构、C/Python分离**                          |
| [Five](./docs/Five、eBPF%20程序的拆分与组合.md)                | **函数调用**    | **BPF-to-BPF、Tail Call、模块化设计**                          |
| [Six](./docs/Six、容器感知与身份识别：从内核到云原生.md)       | **容器感知**    | **Namespace、Cgroup、容器身份识别**                            |
| [Seven](./docs/Seven、终极合体：打造容器运行时安全监控面板.md) | **监控面板**    | **多探针整合、动态映射、完整监控系统**                         |
| [Eight](./docs/Eight、从监控到检测——构建容器逃逸规则引擎.md)   | **规则引擎**    | **YAML配置、三维检测模型(procfs挂载/ptrace注入/敏感文件访问)** |

### 辅助文档

| 文档名称                                               | 说明                               |
| ------------------------------------------------------ | ---------------------------------- |
| [简章](./docs/简章.md)                                 | 项目背景 - 从 Pwn 手到云原生的逆旅 |
| [项目环境](./docs/项目环境.md)                         | Ubuntu 22.04 虚拟机配置指南        |
| [Docker 容器环境准备](./docs/docker%20容器环境准备.md) | Docker安装与容器配置教程           |
| [eBPF 常用字典](./docs/eBPFBPF%20常用字典.md)          | eBPF术语表与API参考手册            |

---

## 🚀 快速开始

### 前置要求

- **操作系统**: Ubuntu 22.04 LTS (推荐 VMware 虚拟机)
- **内核版本**: ≥ 5.15 (支持 eBPF)
- **依赖工具**: BCC 框架、Python 3.8+
- **权限**: root 或 sudo

### 一键运行

```
# 1. 克隆仓库
git clone https://github.com/Chenjx12/ebpf-learning-notes.git
cd ebpf-learning-notes

# 2. 安装依赖 (参考 [docs/项目环境.md](./docs/项目环境.md))
sudo apt install bpfcc-tools linux-headers-$(uname -r)

# 3. 运行 Hello World 示例
# 基础版: [code/03-hello-world/hello-world.py](./code/03-hello-world/hello-world.py)
sudo python3 code/03-hello-world/hello-world.py

# 进阶版: [code/04-anatomy/hello-perf-plus.py](./code/04-anatomy/hello-perf-plus.py) (C/Python分离版)
sudo python3 code/04-anatomy/hello-perf-plus.py

# 函数调用示例: [code/05-call/bpf2bpf.py](./code/05-call/bpf2bpf.py) (BPF-to-BPF调用)
sudo python3 code/05-call/bpf2bpf.py

# 尾调用示例: [code/05-call/tailcall-chain.py](./code/05-call/tailcall-chain.py) (Tail Call链式调用)
sudo python3 code/05-call/tailcall-chain.py


# 容器感知示例（第六篇）[code/06-container](./code/06-container) (Namespace检测)
# 1）基础 Namespace 检测
sudo python3 code/06-container/container-aware.py

# 2）完整 Namespace ID 获取
sudo python3 code/06-container/container-ns.py

# 3）Cgroup Map + 容器名映射
sudo python3 code/06-container/container-map.py

# 监控面板示例（第七篇）[code/07-monitor](./code/07-monitor) (完整监控系统)
sudo python3 code/07-monitor/container-monitor.py

# 4. 新开终端执行 ls, ps 等命令观察输出


# 逃逸检测示例（第八篇）[code/08-detection](./code/08-detection) (YAML规则引擎)
# 1）启动检测系统
sudo python3 code/08-detection/escape-detect.py -r code/08-detection/rules.yaml

# 2）新开终端执行procfs挂载测试
bash code/08-detection/test-escape.sh

# 3）执行ptrace注入测试
bash code/08-detection/test-ptrace.sh

# 4）敏感文件访问测试（可选，当前已注释openat事件输出）
# bash code/08-detection/test-openat.sh

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
├── docs/                  # 📚 学习笔记
│   ├── One、什么是 eBPF.md                    ✅
│   ├── Two、云原生下的 eBPF.md                ✅
│   ├── Three、eBPF 的 Hello World.md          ✅
│   ├── Four、eBPF 程序的解剖与工程化.md       ✅
│   ├── Five、eBPF 程序的拆分与组合.md         ✅
│   ├── Six、容器感知与身份识别：从内核到云原生.md ✅
│   ├── Seven、终极合体：打造容器运行时安全监控面板.md ✅
│   ├── Eight、从监控到检测——构建容器逃逸规则引擎.md ✅
│   ├── 简章.md                                ✅
│   ├── 项目环境.md                            ✅
│   ├── docker 容器环境准备.md                 ✅ Docker配置教程
│   └── eBPFBPF 常用字典.md                    ✅ eBPF术语参考手册
└── code/                  # 💻 实验代码
    ├── 03-hello-world/    # 第三篇:基础示例
    │   ├── hello-world.py         # ⭐ [基础Hello World](./code/03-hello-world/hello-world.py)
    │   ├── hello-openat.py        # ⭐ [监控openat系统调用](./code/03-hello-world/hello-openat.py)
    │   ├── hello-map.py           # ⭐⭐ [Hash Map统计UID执行次数](./code/03-hello-world/hello-map.py)
    │   ├── hello-perf.py          # ⭐⭐⭐ [Perf Buffer传递事件](./code/03-hello-world/hello-perf.py)
    │   ├── hello-ring.py          # ⭐⭐⭐ [Ring Buffer(推荐)](./code/03-hello-world/hello-ring.py)
    │   └── hello-perf-plus.py     # ⭐⭐⭐⭐ [Tracepoint获取完整命令路径](./code/03-hello-world/hello-perf-plus.py)
    ├── 04-anatomy/        # 第四篇:程序解剖与工程化
    │   ├── README.md              # 📖 [目录说明](./code/04-anatomy/README.md)
    │   ├── hello-debug.c          # 🔧 [手动编译测试C代码](./code/04-anatomy/hello-debug.c)
    │   ├── build-ebpf.sh          # 🔨 [编译脚本](./code/04-anatomy/build-ebpf.sh)
    │   └── load-compiled.py       # 🔧 [加载已编译程序](./code/04-anatomy/load-compiled.py)
    ├── 05-call/           # 第五篇:函数调用
    │   ├── bpf2bpf.py             # ⭐⭐ [BPF-to-BPF调用](./code/05-call/bpf2bpf.py)
    │   └── tailcall-chain.py      # ⭐⭐⭐ [Tail Call链式调用](./code/05-call/tailcall-chain.py)
    ├── 06-container/      # 第六篇:容器感知
    │   ├── container-aware.py     # ⭐⭐⭐ [Namespace检测](./code/06-container/container-aware.py)
    │   └── cgroup-inode.py        # ⭐⭐⭐⭐ [Cgroup Inode映射](./code/06-container/cgroup-inode.py)
    ├── 07-monitor/        # 第七篇:监控面板
    │   ├── container-monitor.py   # ⭐⭐⭐⭐⭐ [完整监控面板](./code/07-monitor/container-monitor.py)
    │   ├── container-monitor.c    # ⭐⭐⭐⭐ [监控面板C代码](./code/07-monitor/container-monitor.c)
    │   └── container-tail.c       # ⭐⭐⭐ [Tail Call版本](./code/07-monitor/container-tail.c)
    └── 08-detection/      # 第八篇:规则引擎
        ├── escape-detect.c        # ⭐⭐⭐⭐ [逃逸检测C代码](./code/08-detection/escape-detect.c)
        ├── escape-detect.py       # ⭐⭐⭐⭐⭐ [Python加载器](./code/08-detection/escape-detect.py)
        ├── detector.py            # ⭐⭐⭐⭐ [YAML规则引擎](./code/08-detection/detector.py)
        ├── rules.yaml             # ⭐⭐⭐⭐ [检测规则配置](./code/08-detection/rules.yaml)
        ├── test-escape.sh         # ⭐⭐⭐ [procfs挂载测试](./code/08-detection/test-escape.sh)
        ├── test-ptrace.sh         # ⭐⭐⭐⭐ [ptrace注入测试](./code/08-detection/test-ptrace.sh)
        └── test-openat.sh         # ⭐⭐ [敏感文件访问测试(已注释)](./code/08-detection/test-openat.sh)
```

## Star History

<a href="https://www.star-history.com/?repos=Chenjx12%2Febpf-learning-notes&type=date&legend=bottom-right">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=Chenjx12/ebpf-learning-notes&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=Chenjx12/ebpf-learning-notes&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=Chenjx12/ebpf-learning-notes&type=date&legend=top-left" />
 </picture>
</a>
