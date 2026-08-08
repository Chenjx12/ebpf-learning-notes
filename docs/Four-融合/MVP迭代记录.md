# MVP 迭代：从假设可运行到真正可运行

> **日期**: 2026-08-08
> **关联代码**: [`code/20-mvp-iteration/`](../code/20-mvp-iteration/)
> **关联项目**: [ebpf-container-guard](https://github.com/chenjx12/ebpf-container-guard) v0.1.0

---

## 背景

按照[双仓库策略规划](../双仓库策略规划.md)，2026-08-07 将学习仓库 `code/09-response/` 中的核心代码"毕业"到作品仓库 `ebpf-container-guard/`，期望得到一个开箱即用的 MVP。

代码复制完成、目录重构完成、README 撰写完成 — **但没有人实际跑过一次**。

2026-08-08 首次运行验证，发现 `main.py` 完全不可用。

---

## 问题发现过程

### Step 1: 代码通读

逐文件阅读 `ebpf-container-guard/` 下的所有源码，发现：

- `src/ebpf/escape-detect.bpf.c` — BCC 风格，3 个 tracepoint 探针，结构完整 ✅
- `src/detector/engine.py` — `EscapeDetector` 类，规则引擎完整 ✅
- `src/responder/docker_responder.py` — `ResponseEngine` 类，5 种响应动作完整 ✅
- `config/rules.yaml` / `config/responses.yaml` — YAML 配置有效 ✅
- `main.py` — import 名称与模块实际导出**全部不匹配** ❌

### Step 2: 对比参考实现

对比学习仓库中已知可工作的 `code/09-response/escape-respond.py`：

| 功能 | escape-respond.py (参考) | main.py (问题版) |
|------|-------------------------|-------------------|
| eBPF 编译加载 | `BPF(src_file="escape-detect.c")` | ❌ 缺失 |
| 规则引擎初始化 | `EscapeDetector(rules_file)` | `DetectionEngine(...)` ❌ |
| 响应引擎初始化 | `ResponseEngine(responses_file)` | `DockerResponder(...)` ❌ |
| 容器映射 | PID map + cgroup inode 双层映射 | ❌ 缺失 |
| Ring Buffer 消费 | `open_ring_buffer(handle_event)` | ❌ 缺失 |
| 事件解析 | event_type_map + fstype/target_pid 处理 | ❌ 缺失 |
| 管线串联 | check_event → print_alert → handle_alert | `detector.start(responder.on_alert)` ❌ |

### Step 3: 验证假设

```bash
$ cd ebpf-container-guard && sudo python3 main.py
ImportError: cannot import name 'DetectionEngine' from 'detector.engine'
```

第一行就崩溃。确认**代码从未被运行过**。

---

## 根本原因：重构 ≠ 移植

从学习仓库到作品仓库，经历了 3 个"看似无害"的变化：

```
学习仓库 (code/09-response/)          作品仓库 (ebpf-container-guard/)
─────────────────────────            ─────────────────────────────
扁平目录                              分层目录 (src/ebpf, src/detector, src/responder)
escape-respond.py (管主线)           main.py (重新编写，只写了骨架)
detector.py → EscapeDetector         engine.py → 类名构想为 DetectionEngine
responder.py → ResponseEngine        docker_responder.py → 类名构想为 DockerResponder
```

每一步单独看都合理，但**合成起来导致整个管线断裂**：
- 管主线 (`escape-respond.py` → `main.py`) 被重写而非移植
- 模块类名被改了但没有同步 import

---

## 修复：单文件重写

策略：不修补问题版的 80 行骨架，而是基于已知工作参考 `escape-respond.py`**直接重写**。

改动范围：
```
ebpf-container-guard/
├── main.py                  ← 🔧 重写（80行 → 240行）
├── src/ebpf/                ← ✅ 未改动
├── src/detector/             ← ✅ 未改动
├── src/responder/            ← ✅ 未改动
└── config/                   ← ✅ 未改动
```

修复后验证结果：

| 验证项 | 结果 |
|--------|------|
| import 正确性 | ✅ |
| eBPF 编译加载 | ✅ (3 harmless clang warnings) |
| Docker 连接 | ✅ |
| 容器映射 | ✅ |
| 规则引擎 4/4 用例 | ✅ |
| 响应引擎审计日志 | ✅ |
| 完整启停流程 | ✅ |

详见 [MVP运行验证报告 (ebpf-container-guard/docs/)](../../ebpf-container-guard/docs/MVP-运行验证报告.md)

---

## 经验教训

### 1. 双仓库策略的盲区

双仓库策略解决了"学习 vs 展示"的定位冲突，但引入了新风险：**代码移植后可能无人验证**。

对策：毕业流程增加"烟雾测试"步骤：
```bash
# 移植完成后必须执行
cd <作品仓库> && sudo python3 main.py --help   # 至少确认能启动
```

### 2. "看起来完整"≠"能跑"

`main-broken.py` 有 80 行代码、argparse、错误处理、类型注解 — 看起来像一个完整的入口文件。但核心的 eBPF 加载管线完全没有，这是静态代码审查容易漏掉的。

对策：运行时验证是唯一的真相来源。

### 3. 已知工作参考的价值

`escape-respond.py` 是经过多次调试、修复了 ptrace 参数映射陷阱、容器 ID 竞态等问题的成熟代码。重写时直接复用其模式，比自己从零写更可靠。

### 4. 单文件修复 > 多文件修补

识别出 3 个核心模块已正确后，只修 `main.py`，不碰其他文件。范围越小，风险越低。

---

## 下一步

- [ ] v0.2.0: DeepSeek AI 威胁研判集成（9月）
- [ ] 将 MVP 烟雾测试加入 Makefile (`make check` 或 `make test`)
- [ ] 补全 `deploy/` 和 `docs/` 空目录

---

## v0.1.1 迭代 (2026-08-08)

### 修复内容

在 v0.1.0 修复基础上，通过真实特权容器测试发现并修复了 3 个额外问题：

| # | 问题 | 发现方式 | 修复 | 验证 |
|---|------|---------|------|------|
| 1 | `docker exec` 进程容器 ID 解析为 "host" | 端到端测试中 CRITICAL 告警显示 `容器: host` | 添加后台线程每 5s 刷新 cgroup map + PID map | ✅ 告警正确显示 `容器: 2287bfc722b9` |
| 2 | openat 事件淹没 Ring Buffer | 切换到 kprobe 后 0 事件输出（Ring Buffer 满） | 注释 openat 探针（原 tracepoint 版已注释，转 kprobe 时遗漏） | ✅ 事件流正常 |
| 3 | kprobe `PT_REGS_PARM` 在 kernel 6.8 syscall wrapper 下失效 | 单独 kprobe 计数器测试（计数正常但字符串全空） | 回退到 tracepoint（已验证可行） | ✅ fstype=proc 正确捕获 |

### 端到端验证

```
🚨 安全告警 - CRITICAL 级别
规则: procfs_mount_escape
容器: 2287bfc722b9                    ← 容器 ID 正确
文件系统: proc -> 目标: /tmp/host_proc  ← fstype 正确

🛡️ [RESPONSE] 自动防御: CRITICAL → pause_container
✅ Container 2287bfc722b9 PAUSED       ← Docker 响应执行成功
```

Docker daemon 确认: `Container test_esc is paused, unpause the container before exec`

### 版本路线更新

```
v0.1.0 (8/7):  代码复制到作品仓库，但无法运行 ❌
v0.1.1 (8/8):  MVP 可运行，端到端验证通过 ✅           ← 当前位置
v0.2.0 (9月):  接入 K8s？待定。Docker 版需先稳定
v0.3.0 (10月): Streamlit 仪表盘
v1.0.0 (12月): 稳定版，毕设答辩前发布
```

---

## 相关文件

- [双仓库策略规划](../双仓库策略规划.md)
- [`code/20-mvp-iteration/main-broken.py`](../code/20-mvp-iteration/main-broken.py) — 问题版代码
- [`code/09-response/escape-respond.py`](../code/09-response/escape-respond.py) — 参考实现
- [ebpf-container-guard/main.py](../../ebpf-container-guard/main.py) — 修复版代码

---

*创建时间: 2026-08-08*
*作者: chenjx12*
