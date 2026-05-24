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
| [Four](./docs/Four、eBPF%20程序的解剖与工程化.md) | **程序解剖** | **手动编译、ELF段结构、C/Python分离** |
| [简章](./docs/简章.md) | 项目背景 | 从 Pwn 手到云原生的逆旅 |
| [项目环境](./docs/项目环境.md) | 环境配置 | Ubuntu 22.04 虚拟机配置指南 |

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

# 2. 安装依赖 (参考 docs/项目环境.md)
sudo apt install bpfcc-tools linux-headers-$(uname -r)

# 3. 运行 Hello World 示例
sudo python3 code/03-hello-world/hello-world.py

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
│   ├── Three、eBPF 的 Hello World.md
│   ├── Four、eBPF 程序的解剖与工程化.md
│   ├── 简章.md
│   └── 项目环境.md
└── code/                  # 实验代码
    ├── 03-hello-world/    # 第三篇:基础示例
    │   ├── hello-world.py
    │   ├── hello-openat.py
    │   ├── hello-map.py
    │   ├── hello-perf.py
    │   ├── hello-ring.py
    │   └── hello-perf-plus.py
    └── 04-anatomy/        # 第四篇:程序解剖
        ├── README.md
        ├── hello-debug.c              # eBPF C 源代码
        ├── hello-debug.o              # 编译产物（eBPF 字节码）
        ├── build-ebpf.sh              # 自动化编译脚本
        ├── demo-compile.sh            # 编译过程演示脚本
        ├── load-compiled.py           # Python 加载器
        └── COMPILE_OUTPUT.md          # 📖 编译过程详解文档