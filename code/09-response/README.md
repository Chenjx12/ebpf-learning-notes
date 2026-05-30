# 09-Response: 主动防御系统

对应笔记: [Nine、主动防御：从检测到自动响应](../../docs/Nine、主动防御：从检测到自动响应.md)

## 🎯 与第八篇的关系

第八篇实现了"检测"——eBPF 探针 + YAML 规则引擎，能识别逃逸行为并打印红色告警。
第九篇在此基础上增加了"响应"——告警触发后，**自动执行防御动作**，形成完整闭环：

```
eBPF 事件 → 规则引擎匹配 → 🚨告警 → 🛡️自动响应(pause/disconnect/kill)
```

## 📁 目录结构

```
code/09-response/
├── escape-respond.py      # 主程序(检测 + 响应闭环)
├── responder.py           # 🆕 响应引擎实现
├── detector.py            # 检测引擎(与 08-detection 相同)
├── escape-detect.c        # eBPF 探针代码(三维探针:mount/ptrace/openat)
├── rules.yaml             # 检测规则配置
├── responses.yaml         # 🆕 响应策略配置
├── test-ptrace-simple.sh  # ptrace 注入测试
├── test-escape.sh         # procfs 挂载逃逸测试
├── test-openat.sh         # 敏感文件读取测试(已知限制)
└── README.md              # 本文件
```

## 🚀 快速开始（宿主机直接运行，与前八篇一致）

### 1. 安装依赖

```bash
pip3 install docker pyyaml
```

### 2. 准备测试容器

**ptrace-test**（用于 ptrace 注入测试）：

```bash
docker run -d --name ptrace-test \
  --cap-add=SYS_PTRACE \
  --pid=host \
  ubuntu:22.04 sleep 3600

# 安装 strace（首次运行需要，后续重启容器不需要重复安装）
docker exec ptrace-test bash -c "apt-get update && apt-get install -y strace"
```

### 3. 启动主动防御系统

```bash
cd /mnt/hgfs/code/09-response
sudo python3 escape-respond.py -r rules.yaml -s responses.yaml
```

看到以下输出表示启动成功：
```
[1] 编译并加载eBPF程序...
[2] 加载检测规则...
[Detector] 已加载 3 条规则
[3] 加载响应策略...
[ResponseEngine] 已加载 4 条响应策略
[4] 连接Docker守护进程...
[5] 初始化容器ID映射...
[✓] 已映射 N 个容器的进程ID

[✓] 容器逃逸检测与主动防御系统启动成功!
[i] 按Ctrl+C停止监控
```

### 4. 执行测试

**新开一个终端**，依次执行：

```bash
cd /mnt/hgfs/code/09-response

# 测试 1: ptrace 注入（HIGH → isolate_network）
bash test-ptrace-simple.sh

# 测试 2: procfs 挂载逃逸（CRITICAL → pause_container）
bash test-escape.sh

# 测试 3: 敏感文件读取（可选，已知 openat 噪音限制）
bash test-openat.sh
```

### 5. 观察自动响应

监控终端应显示：

```
# ptrace 测试输出:
🚨 安全告警 - HIGH 级别
规则: dangerous_ptrace
Ptrace请求: PTRACE_SECCOMP_GET_FILTER -> 目标PID: 1

🛡️  [RESPONSE] 触发自动防御: HIGH → isolate_network
✅ Container xxxxxxxxxxxx DISCONNECTED from bridge

# procfs 挂载测试输出:
🚨 安全告警 - CRITICAL 级别
规则: procfs_mount_escape
文件系统: proc -> 目标: /tmp/host_proc

🛡️  [RESPONSE] 触发自动防御: CRITICAL → pause_container
✅ Container xxxxxxxxxxxx PAUSED - 已冻结,等待人工取证
```

## 📋 响应策略说明

| 威胁等级 | 触发条件示例 | 自动响应动作 | 说明 |
|---------|------------|------------|------|
| **CRITICAL** | procfs 挂载逃逸 | `pause_container` | 冻结容器，保留内存现场供取证 |
| **HIGH** | ptrace 对 PID 1 注入 | `isolate_network` | 断开所有网络，阻止 C2 回连或横向移动 |
| **MEDIUM** | 敏感文件访问 | `kill_process` | 在宿主机上发 SIGKILL 终止恶意进程 |
| **LOW** | 异常命令 | `log_only` | 仅写入 audit.log，不自动处置 |

### 冷却时间

同一容器 **10 分钟内只执行一次自动响应**，避免重复处置。冷却期内的事件仍会告警，但不会重复执行响应动作。

### 宿主机事件

来自宿主机（非容器）的告警**不会触发自动响应**，仅输出红色告警信息。这是为了防止误杀宿主机上的正常进程。

## 🔧 与第八篇代码的差异

| 文件 | 08-detection | 09-response | 说明 |
|------|-------------|-------------|------|
| `escape-detect.c` | openat 探针注释 | openat 探针启用 | 第九篇启用了三维探针 |
| `escape-respond.py` | 无 | 新增响应引擎集成 | 在告警后调用 `responder.handle_alert()` |
| `responder.py` | 无 | 🆕 新增 | Docker SDK + os.kill 实现容器/进程级响应 |
| `responses.yaml` | 无 | 🆕 新增 | 威胁等级 → 响应动作映射 |
| `detector.py` | 相同 | 相同 | 规则引擎逻辑不变 |
| `rules.yaml` | 相同 | 相同 | 检测规则不变 |

## ⚠️ 已知限制

1. **openat 噪音**: openat 是最高频系统调用，256 条目的 Ring Buffer 可能溢出导致敏感文件读取事件丢失。ptrace 和 mount 不受影响（低频调用）。
2. **容器映射**: 系统启动时全量同步一次容器 PID 映射，后续不动态更新（与第七篇不同，这里是简化版）。
3. **网络隔离**: `isolate_network` 只断开当前网络，攻击者如果在隔离前已建立反向 shell，连接不会自动中断。

## 🧹 清理

```bash
# 仅清理测试产生的日志文件，容器保留复用
rm -f audit.log response_audit.log detection.log
```

> 💡 测试容器（`ptrace-test`、`escape_test`）保留不用删。下次测试只需 `docker start ptrace-test`，无需重新创建和安装软件。
