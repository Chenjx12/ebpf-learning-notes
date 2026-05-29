# 第八篇：从监控到检测——构建容器逃逸规则引擎

本目录包含第八篇实验的完整代码,实现了基于 YAML 规则引擎的容器逃逸检测系统。

## 📁 文件说明

### 核心代码

| 文件 | 说明 | 对应章节 |
|------|------|---------|
| [`escape-detect.c`](./escape-detect.c) | eBPF探针C代码(mount + ptrace) | 第四节、第五节 |
| [`escape-detect.py`](./escape-detect.py) | Python加载器和事件处理 | 第三节 |
| [`detector.py`](./detector.py) | YAML规则引擎实现 | 第三节 |
| [`rules.yaml`](./rules.yaml) | 检测规则配置 | 第二节 |

### 测试脚本

| 文件 | 说明 | 测试场景 |
|------|------|---------|
| [`test-escape.sh`](./test-escape.sh) | procfs挂载逃逸测试 | 第四节 |
| [`test-ptrace.sh`](./test-ptrace.sh) | ptrace注入检测测试 | 第五节 |
| [`test-openat.sh`](./test-openat.sh) | 敏感文件访问测试(已注释) | 第六节(可选) |
| [`test-rule-match.py`](./test-rule-match.py) | 规则引擎单元测试 | 调试工具 |

## 🚀 快速开始

### 1. 启动检测系统

```bash
sudo python3 escape-detect.py -r rules.yaml
```

**预期输出:**
```
[1] 编译并加载eBPF程序...
[2] 加载检测规则...
[Detector] 已加载 2 条规则
[3] 连接Docker守护进程...
[4] 初始化容器ID映射...
[✓] 已映射 0 个容器的进程ID

[✓] 容器逃逸检测系统启动成功!
[i] 按Ctrl+C停止监控
```

### 2. 执行procfs挂载测试

新开一个终端:

```bash
bash test-escape.sh
```

**预期告警:**
```
🚨 安全告警 - CRITICAL 级别 
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
规则: procfs_mount_escape
描述: 检测容器内挂载宿主机procfs文件系统
容器: xxxxxxxxxxxx
进程: 12345 (mount)
文件系统: proc -> 目标: /tmp/host_proc
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 3. 执行ptrace注入测试

``bash
bash test-ptrace.sh
```

**预期告警:**
```
🚨 安全告警 - HIGH 级别 
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
规则: dangerous_ptrace
描述: 检测容器内尝试ptrace宿主机1号进程(systemd/init)
容器: host
进程: 17726 (strace)
Ptrace请求: PTRACE_SECCOMP_GET_FILTER -> 目标PID: 1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## 📊 架构设计

```text
┌───────────────────────────────────────────────────┐
│                 用户态 Python                       │
│                                                   │
│  [eBPF 事件] → [规则引擎] → [匹配成功] → [告警]    │
│                   ↕                               │
│            [rules.yaml 配置文件]                   │
│            - procfs_mount_escape                  │
│            - dangerous_ptrace                     │
└───────────────────────────────────────────────────┘
                       ↕ (BPF Ring Buffer)
┌───────────────────────────────────────────────────┐
│                 内核态 eBPF                         │
│                                                   │
│  [mount 探针] ──→ Ring Buffer ──→ 事件上报        │
│  [ptrace 探针] ──→ Ring Buffer ──→ 事件上报       │
└───────────────────────────────────────────────────┘
```

## 🎯 核心特性

### 1. YAML规则引擎

- ✅ 声明式安全策略
- ✅ 热加载无需重启
- ✅ 支持AND/OR/排除条件
- ✅ 告警分级(CRITICAL/HIGH/MEDIUM/LOW)

### 2. 精准检测

- ✅ procfs挂载逃逸检测
- ✅ ptrace宿主机进程检测(基于target_pid=1)
- ⚠️ 敏感文件访问检测(已配置规则，但代码中暂时注释openat事件输出以避免噪音)
- ✅ 智能排除正常进程(dockerd, runc等)

### 3. 云原生安全哲学

> **从"怎么逃"到"逃向谁"**
> 
> 不关注攻击者使用了什么具体参数,而是判断行为的越权方向。

## 🔧 扩展规则

在 `rules.yaml` 中添加新规则:

```yaml
- name: "my_custom_rule"
  description: "自定义检测规则"
  severity: "HIGH"
  condition:
    event_type: "openat"
    path: "/etc/shadow"
  action: "alert_and_log"
```

## 📝 调试技巧

### 临时放宽规则

如果规则太严格导致无法触发,可以先只匹配event_type:

```yaml
condition:
  event_type: "ptrace"  # 只检查类型,忽略其他字段
```

### 查看原始值

在 `escape-detect.py` 中添加调试输出:

```python
print(f"[DEBUG] event.request_raw={event.request_raw}")
```

### 单元测试

使用 `test-rule-match.py` 验证规则引擎:

```python
from detector import EscapeDetector

detector = EscapeDetector('rules.yaml')

test_event = {
    'event_type': 'ptrace',
    'target_pid': 1
}

matched = detector.check_event(test_event)
print(f"匹配规则数: {len(matched)}")
```

## 🔗 相关链接

- **笔记文档**: [Eight、从监控到检测——构建容器逃逸规则引擎](../docs/Eight、从监控到检测——构建容器逃逸规则引擎.md)
- **上一篇**: [Seven、终极合体：打造容器运行时安全监控面板](../docs/Seven、终极合体：打造容器运行时安全监控面板.md)
- **下一篇**: [Nine、主动防御：从检测到自动响应(待规划)](../docs/Nine、主动防御：从检测到自动响应.md)

---

_最后更新: 2026-05-29_
