# 10-Perf: 性能优化与生产级部署

对应笔记: [Ten、性能优化与生产级部署](../../docs/Ten、性能优化与生产级部署.md)

## 🎯 与第九篇的关系

第九篇完成了"检测→响应"全链路闭环，但系统以 `sudo python3 xxx.py` 跑在前台，缺少性能基准和生产化包装。
第十篇补上最后一块短板——**量化性能、优化瓶颈、systemd 部署**，让系统从"能跑"到"能上线"。

## 📁 目录结构

```
code/10-perf/
├── perf-ringbuf-bench.py      # 实验1: Ring Buffer 容量 vs 事件丢失率
├── perf-ringbuf-test.c        # 实验1: eBPF C 代码（openat 探针 + 内核计数）
├── perf-filter-bench.py       # 实验2&3: 内核态过滤降噪 + CPU 开销基准
├── perf-load-gen.c            # 受控 openat 负载生成器（C 实现，避免 IO 噪音）
├── perf-load-gen.sh           # openat 负载生成脚本（shell 版，备用）
├── escape-defender.service    # 实验4: systemd unit 文件
├── deploy.sh                  # 实验4: 一键部署脚本
└── README.md                  # 本文件
```

## 🚀 快速开始

### 实验1: Ring Buffer 容量压测

```bash
cd /mnt/hgfs/code/10-perf

# 安装依赖（如未安装）
sudo apt-get install -y stress-ng

# 运行压测（需要 sudo，eBPF 程序需要 root 权限）
sudo python3 perf-ringbuf-bench.py
```

**原理**: eBPF 内核态用 `BPF_ARRAY` 原子计数器记录"总生成事件数"，用户态 Poll Ring Buffer 记录"接收到的事件数"。两者对比 = 精确丢失率。

**结论**: 当前 VM (~1200 openat/s) 下 256 条目够用，但生产环境 (50K-100K/s) 下 256 条目仅提供 ~5ms 缓冲，推荐至少 4096 条目。

### 实验2&3: 内核态过滤 + CPU 开销

```bash
cd /mnt/hgfs/code/10-perf
sudo python3 perf-filter-bench.py
```

**实验2**: 对比"无过滤"vs"有路径前缀过滤（/host_*、/etc/shadow）"的 openat 事件量，量化过滤降噪效果。

**实验3**: 使用 `bpftool prog show` 读取各探针的运行时统计（运行次数、累计耗时），计算 CPU 开销。

### 实验4: systemd 生产化部署

```bash
cd /mnt/hgfs/code/10-perf
sudo bash deploy.sh
```

部署后可通过 systemctl 管理：
```bash
sudo systemctl start escape-defender    # 启动
sudo systemctl status escape-defender   # 查看状态
sudo systemctl stop escape-defender     # 停止
sudo journalctl -u escape-defender -f   # 查看日志
```

## 📊 实验数据速览

| 实验 | 核心发现 |
|------|---------|
| Ring Buffer | 256 条目在低负载下无丢失，生产环境需 4096+ |
| 内核态过滤 | 路径前缀过滤可挡 99%+ 噪音，比增大 Buffer 更治本 |
| CPU 开销 | 三维探针（mount/ptrace/openat）总体 < 3%，JIT 编译后接近内核原生速度 |
| systemd | 10 行 unit 文件完成生产化，支持自动重启和 journald 日志 |

## 🔧 与前九篇代码的关系

| 代码 | 来源 | 说明 |
|------|------|------|
| `perf-ringbuf-bench.py` | 🆕 新增 | 独立基准测试，不依赖 escape-respond.py |
| `perf-filter-bench.py` | 🆕 新增 | 独立基准测试，演示内核态过滤技术 |
| `perf-load-gen.c` | 🆕 新增 | 受控负载生成器，纯 open() 无 IO 噪音 |
| `escape-defender.service` | 🆕 新增 | 基于第九篇 escape-respond.py 的 systemd 包装 |

> 💡 这些脚本是**独立基准测试工具**，不会修改或影响前九篇的代码。内核态过滤（实验2）的技术可以直接移植到 `escape-detect.c` 中，方式是在 eBPF C 代码的 openat 探针里加 `if (filename starts with "/host_" || "/etc/shadow") { ringbuf_output(...); }`。

## ⚠️ 已知限制

1. **stress-ng 负载有限**: 当前 VM（4C8G）下 stress-ng --open 仅产生 ~1200 openat/s，远低于生产环境（50K-100K/s）。实验结论的综合分析部分是**计算推导**，而非实测。
2. **bpftool 统计精度**: `bpftool prog show` 的 run_time 是累计值，受内核调度影响，不适合做微秒级精度对比，但宏观开销比例可信。
3. **systemd 需要 root**: eBPF 程序加载和 Docker socket 访问都需要 root 权限，unit 文件里 `User=root` 是必须的。
