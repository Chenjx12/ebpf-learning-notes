# 20-MVP迭代：从假设可运行到真正可运行

> **对应笔记**: [MVP迭代记录](../../docs/Four-融合/MVP迭代记录.md)
> **日期**: 2026-08-08
> **状态**: v0.1.0 MVP 已修复并验证通过

---

## 📂 文件说明

| 文件 | 说明 |
|------|------|
| `main-broken.py` | ⚠️ v0.1.0 问题版本 — 从双仓库策略规划中"毕业"出来的代码，假设可运行，实际 import 全部不匹配 |
| (修复版) | 见 `../../ebpf-container-guard/main.py`，基于 `../code/09-response/escape-respond.py` 的已验证管线重写 |

---

## 🔍 问题诊断：为什么看起来能跑，实际不能跑？

### 表象

`main-broken.py` 看起来像一个完整的入口文件：
- ✅ 有 argparse CLI 参数解析
- ✅ 有配置文件验证
- ✅ 有 try/except 错误处理
- ✅ 代码风格整洁

### 真相

运行时第一行就会报错：

```
ImportError: cannot import name 'DetectionEngine' from 'detector.engine'
```

### 根本原因：双仓库策略的"复制即毕业"陷阱

```
ebpf-learning-notes/code/09-response/escape-respond.py
  → 这是可工作的端到端版本（BCC + 规则引擎 + Docker 响应）
  → 被"毕业"到 ebpf-container-guard/ 时：
    1. 目录结构重构了（扁平 → src/分层）
    2. 模块改名为"产品级"命名（DetectionEngine, DockerResponder）
    3. main.py 重新编写（但只写了骨架，管线完全缺失）
    4. 没有人实际跑过一次
```

---

## 📊 5 个集成缺口

| # | 缺口 | 严重度 | 具体表现 |
|---|------|--------|---------|
| 1 | import 名称不匹配 | 🔴 致命 | `DetectionEngine` → 实际是 `EscapeDetector`; `DockerResponder` → 实际是 `ResponseEngine` |
| 2 | eBPF 从未加载 | 🔴 致命 | 没有 `BPF(src_file=...)` 调用，3 个 tracepoint 探针从未附加到内核 |
| 3 | 管线未串联 | 🔴 致命 | `detector.start(responder.on_alert)` 这些方法根本不存在 |
| 4 | 容器身份映射缺失 | 🟡 严重 | 没有 PID→container_id 填充、cgroup inode 回退 |
| 5 | Makefile 工具链不匹配 | 🟡 中等 | Makefile 用 clang -target bpf 但代码是 BCC 宏风格 |

---

## 🔧 修复策略

**只改一个文件**: `main.py` 完全重写（80 行 → 240 行）

核心模块零改动:
- `src/ebpf/escape-detect.bpf.c` ✅ 无需改动
- `src/detector/engine.py` ✅ 无需改动
- `src/responder/docker_responder.py` ✅ 无需改动
- `config/rules.yaml` ✅ 无需改动
- `config/responses.yaml` ✅ 无需改动

修复参考: `code/09-response/escape-respond.py`（学习仓库中已验证的端到端版本）

---

## 📈 迭代对比

| 维度 | 问题版 (main-broken.py) | 修复版 (main.py) |
|------|------------------------|-------------------|
| 行数 | 80 | 257 |
| import 正确性 | ❌ 2 个类名错误 | ✅ EscapeDetector, ResponseEngine |
| eBPF 加载 | ❌ 缺失 | ✅ BPF(src_file=...) |
| Ring Buffer | ❌ 缺失 | ✅ open_ring_buffer + poll 循环 |
| 容器 ID 识别 | ❌ 缺失 | ✅ PID map + cgroup inode + /proc (3-tier) |
| 后台 map 刷新 | ❌ 缺失 | ✅ 5s 间隔后台线程 |
| PTRACE 常量映射 | ❌ 缺失 | ✅ 20+ 请求常量 |
| 检测→响应闭环 | ❌ 缺失 | ✅ check_event → print_alert → handle_alert |
| 版本 | v0.1.0 (不可用) | v0.1.1 (端到端验证通过) |

### v0.1.1 新增修复 (2026-08-08)

| 问题 | 发现方式 | 修复 |
|------|---------|------|
| openat 事件淹没 Ring Buffer | kprobe 测试时发现 0 事件 | 注释 openat 探针（高频调用，256 条目不够） |
| `docker exec` 进程容器 ID 为 "host" | 真实特权容器测试 | 后台线程每 5s 刷新 cgroup map |
| kprobe `PT_REGS_PARM` 在 kernel 6.8 失效 | 单独 kprobe 计数器测试 | 回退到 tracepoint（验证可行） |
| Docker `pause_container` 从未验证 | 端到端测试 | 确认容器被冻结（daemon 报 paused） |
| 容器映射 | ❌ 缺失 | ✅ PID map + cgroup inode + /proc fallback |
| PTRACE_MAP | ❌ 缺失 | ✅ 20+ 常量完整映射 |
| 检测-响应闭环 | ❌ 缺失 | ✅ check_event → print_alert → handle_alert |
| verbose 模式 | ❌ 参数定义但未使用 | ✅ 控制 INFO 日志输出 |
| 路径解析 | ❌ 硬编码相对路径 | ✅ 基于 __file__ 的绝对路径 |

---

## 💡 经验教训

1. **"复制"不等于"移植"**: 重构目录结构后，必须重新跑一遍完整启动流程
2. **模块改名要同步**: 改了类名就要同步改所有 import 和调用方
3. **管线不能只画在架构图上**: 每一环都要用代码实现并验证
4. **有已知工作参考时优先重写而非修补**: 从 `escape-respond.py` 重写比在 broken 版本上修补更快更稳

---

*最后更新: 2026-08-08*
