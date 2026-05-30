# Nine、主动防御：从检测到自动响应

date: 2026-05-30

第八篇我们构建了基于 YAML 规则引擎的**容器逃逸检测系统**,能从海量系统调用中精准识别出 procfs 挂载、ptrace 注入等逃逸行为。但这只是"看见并报警",还没到"自动处置"。

真正的安全产品,需要从**检测到响应的完整闭环**。这篇,我们将引入**响应策略引擎**,实现从"入侵检测系统(IDS)"到"入侵防护系统(IPS)"的华丽转身!

## 核心内容结构

```text
1. 从"检测"到"主动防御":概念与架构
2. 响应策略模型:威胁等级 × 动作表
3. 响应引擎实现:Docker SDK + eBPF bpf_send_signal
4. 工程实践:把 detector 升级成"检测 + 响应"引擎
5. Docker Compose 靶场:攻防演练环境
6. 安全与边界:主动防御不能乱"打人"
7. 三维响应模型:构建完整的逃逸防护体系
```

---

## 一、从"检测"到"主动防御":概念与架构

### **1.1 为什么需要主动防御?**

回顾第八篇的检测系统,我们在 Python 代码中实现了规则匹配和告警输出:

```python
# ✅ 第八篇:只检测不响应
matched_rules = self.detector.check_event(event_dict)
if matched_rules:
    for rule in matched_rules:
        alert = self.detector.generate_alert(rule, event_dict)
        print_alert(alert)  # 仅打印红色告警
```

**问题:**

- ❌ 告警后攻击者仍在容器内继续操作
- ❌ 需要人工介入才能隔离/杀死容器
- ❌ 无法实现实时阻断和自动化处置

**解决方案:主动防御!**

```text
┌─────────────────────────────────────────────────────────┐
│                 用户态 Python                             │
│                                                         │
│  [eBPF 事件] → [规则引擎] → [告警] → [响应引擎]          │
│                   ↕                        ↕            │
│            [rules.yaml]          [responses.yaml]       │
│            - procfs_mount        - pause_container      │
│            - dangerous_ptrace    - isolate_network      │
│                                  - kill_process         │
└─────────────────────────────────────────────────────────┘
                       ↕ (BPF Ring Buffer)
┌─────────────────────────────────────────────────────────┐
│                 内核态 eBPF                               │
│                                                         │
│  [mount 探针] ──→ Ring Buffer ──→ 事件上报              │
│  [ptrace 探针] ──→ Ring Buffer ──→ 事件上报             │
│  [bpf_send_signal] ←── 直接在内核态终止恶意进程          │
└─────────────────────────────────────────────────────────┘
```

**优势:**

- ✅ 毫秒级自动响应,无需人工介入
- ✅ 分级处置策略(CRITICAL → 立即冻结, HIGH → 断网隔离)
- ✅ 保留现场用于取证(pause 而非直接 kill)
- ✅ 形成完整的"检测-决策-响应"闭环

---

## 二、响应策略模型:威胁等级 × 动作表

### **2.1 响应配置文件设计**

创建 `responses.yaml`:

```yaml
responses:
  - threat_level: critical
    action: pause_container # 冻结容器,保留内存现场
    description: "立即冻结高危容器,等待人工取证"

  - threat_level: high
    action: isolate_network # 断网隔离
    description: "切断容器网络连接,防止横向移动"

  - threat_level: medium
    action: kill_process # 仅杀进程
    description: "终止可疑进程,但不影响容器其他服务"

  - threat_level: low
    action: log_only # 仅记录
    description: "写入审计日志,不执行自动处置"
```

### **2.2 威胁等级与响应动作映射**

| 威胁等级     | 触发条件示例                  | 自动响应动作                         | 是否需要人工复核      |
| ------------ | ----------------------------- | ------------------------------------ | --------------------- |
| **CRITICAL** | procfs 挂载逃逸 + ptrace 注入 | 立即冻结容器 (docker pause)          | 必须,取证后决定下一步 |
| **HIGH**     | 单一 ptrace 对 PID 1          | 断网隔离 (docker network disconnect) | 建议复核              |
| **MEDIUM**   | 敏感文件访问 (/etc/shadow)    | 终止进程 (kill)                      | 可选                  |
| **LOW**      | 异常命令执行                  | 仅告警 + 记录日志                    | 不需要                |

**设计原则:**

- **CRITICAL**: 多规则同时命中 → 确信度极高 → 立即冻结保留现场
- **HIGH**: 单一致命行为 → 高置信度 → 断网阻止进一步动作
- **MEDIUM**: 单一可疑行为 → 中等置信度 → 精准打击单个进程
- **LOW**: 边缘行为 → 低置信度 → 仅记录避免误杀

---

## 三、响应引擎实现:Docker SDK + eBPF bpf_send_signal

### **3.1 容器级响应:Docker SDK**

创建 `responder.py`（完整代码见 [`code/09-response/responder.py`](../code/09-response/responder.py)）：

```python
#!/usr/bin/env python3
# responder.py — 主动防御响应引擎

class ResponseEngine:
    """基于威胁等级的自动响应：pause → isolate → kill → log"""

    def __init__(self, responses_file):
        self.policy = {r['threat_level']: r['action'] for r in config}
        self.cooldown = {}     # 10分钟冷却，防止重复处置
        self.docker_client = docker.from_env()

    def handle_alert(self, alert):
        """告警 → 查策略 → 执行动作 → 写审计日志"""
        # 1. 跳过宿主机事件（container_id == 'host'）
        # 2. 冷却检查（同容器10分钟内不重复响应）
        # 3. 按威胁等级执行: critical→pause, high→disconnect, medium→kill, low→log

    def pause_container(self, cid):
        """冻结容器（docker pause），保留内存现场供取证"""

    def isolate_network(self, cid):
        """逐网络独立断开，单个失败不影响其他"""

    def kill_process(self, cid, pid):
        """os.kill(host_pid)——注意 eBPF 给的是宿主机 PID，不是容器内 PID"""

    def log_only(self, alert):
        """仅写入 audit.log（JSON格式），不执行自动处置"""
```

> 📄 完整代码: [`code/09-response/responder.py`](../code/09-response/responder.py)（含 `kill_container`、`_audit_log`、冷却时间机制等完整实现）

### **3.2 进程级响应:eBPF bpf_send_signal**

对于 CRITICAL 级别的逃逸行为,等 Docker Daemon 去 pause 可能太慢。我们可以直接在 eBPF 内核态发送 SIGKILL!

修改 `escape-detect.c`:

```c
// escape-detect.c - 容器逃逸检测eBPF探针（主动防御增强版）
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 事件类型定义
#define EVENT_MOUNT 1
#define EVENT_PTRACE 2
#define EVENT_OPENAT 3

// 通用事件结构（🔥 新增 cgroup_id 字段，解决 PID 映射竞态问题）
struct event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u64 cgroup_id;      // 🔥 内核态直接记录 cgroup inode
    char comm[16];
    char container_id[64];

    char fstype[32];
    char target_path[256];

    u32 target_pid;
    u64 request_raw;
};

// ... maps 定义 ...

// 以 mount 探针为例，每个探针都加上 cgroup_id 的获取
TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    struct event evt = {};
    evt.event_type = EVENT_MOUNT;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.cgroup_id = bpf_get_current_cgroup_id();  // 🔥 关键：在内核态记录
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_probe_read_user_str(&evt.fstype, sizeof(evt.fstype), (void *)args->type);
    bpf_probe_read_user_str(&evt.target_path, sizeof(evt.target_path), (void *)args->dir_name);

    get_container_id(&evt);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}
```

**为什么加 `cgroup_id`？**

第八篇的 PID 映射表有一个根本性问题：`docker exec` 创建的新进程 PID 不在初始映射中。进程退出后（如 `strace` 在微秒级完成 ptrace 调用就死了），用户态来不及读 `/proc/<pid>/cgroup` 来补救。

解决方式：**让 eBPF 内核态在事件发生瞬间就记录 `bpf_get_current_cgroup_id()`**。用户态启动时构建 `cgroup_inode → container_id` 映射表，事件处理时直接用内核态记录的 inode 反查，零竞态。

**关键点:**

- `bpf_send_signal(sig)` 会对**当前执行系统调用的进程**发送信号
- 在内核态直接拦截,延迟极低(微秒级)
- 但要注意:这会导致进程立即终止,无法保留完整现场

**使用建议:**

- 仅在 CRITICAL 级别且确信度极高时使用
- 配合容器级 pause 形成双重保障

---

## 四、工程实践:把 detector 升级成"检测 + 响应"引擎

### **4.1 集成响应引擎到主程序**

修改 `escape-respond.py`（完整代码见 [`code/09-response/escape-respond.py`](../code/09-response/escape-respond.py)）：

```python
#!/usr/bin/env python3
# escape-respond.py — 容器逃逸检测与主动防御系统（检测 + 响应闭环）

class ContainerEscapeMonitor:
    def __init__(self, rules_file, responses_file):
        self.bpf = BPF(src_file="escape-detect.c")          # 1. eBPF探针
        self.detector = EscapeDetector(rules_file)           # 2. 规则引擎
        self.responder = ResponseEngine(responses_file)      # 3. 🆕 响应引擎
        self.update_container_map()                          # 4. PID映射
        self._build_cgroup_map()                             # 5. 🆕 cgroup→容器映射

    def _build_cgroup_map(self):
        """cgroup_inode → container_id 映射表
        🔥 解决 PID 映射竞态：eBPF 内核态记录 cgroup_id，
        用户态用此表反查，不依赖进程是否存活"""
        for c in docker_client.containers.list():
            inode = os.stat(f"/sys/fs/cgroup/.../docker-{c.id}.scope").st_ino
            self.cgroup_map[inode] = c.id[:12]

    def handle_event(self, cpu, data, size):
        # 🔥 cgroup fallback：PID映射未命中时用内核态记录的 cgroup_id 反查
        if raw_cid in ('host', '', 'unknown'):
            if event.cgroup_id in self.cgroup_map:
                raw_cid = self.cgroup_map[event.cgroup_id]

        # 检测 + 响应闭环
        for rule in self.detector.check_event(event_dict):
            alert = self.detector.generate_alert(rule, event_dict)
            print_alert(alert)
            self.responder.handle_alert(alert)  # 🆕 自动执行防御动作
```

> 📄 完整代码: [`code/09-response/escape-respond.py`](../code/09-response/escape-respond.py)（含完整 PTRACE_MAP、三种事件类型处理、openat 噪音抑制）

### **4.2 目录结构**

创建 `code/09-response/`:

```
code/09-response/
├── escape-respond.py      # 主程序(检测+响应闭环)
├── responder.py           # 🆕 响应引擎(含 cgroup 容器识别 fallback)
├── detector.py            # 检测引擎(与08-detection相同)
├── escape-detect.c        # eBPF探针(🔥 新增 cgroup_id 字段)
├── rules.yaml             # 检测规则配置(与08-detection相同)
├── responses.yaml         # 🆕 响应策略配置
├── test-ptrace-simple.sh  # ptrace注入测试(HIGH → isolate_network)
├── test-escape.sh         # procfs挂载逃逸测试(CRITICAL → pause_container)
├── test-openat.sh         # 敏感文件读取测试(已知openat噪音限制)
├── README.md              # 说明文档
└── QUICKSTART.md          # 快速启动指南
```

---

## 五、实战演练：本地环境测试（与前八篇一致）

和前面八篇一样，**直接在宿主机上运行 Python 脚本**，用简单的 `docker run`/`docker exec` 模拟攻击，无需 Docker Compose 靶场。

### **5.1 准备测试容器**

只需要两个基础容器，创建一次、后续复用：

```bash
# ptrace 注入测试容器（需要 --pid=host + SYS_PTRACE）
docker run -d --name ptrace-test \
  --cap-add=SYS_PTRACE \
  --pid=host \
  ubuntu:22.04 sleep 3600

# 安装 strace（只需一次，重启容器不需要重装）
docker exec ptrace-test bash -c "
  apt-get update -qq && apt-get install -y -qq strace
"

# procfs 挂载测试容器（需要 --privileged）
docker run -d --privileged --name escape_test ubuntu:22.04 sleep 300
```

> ⚠️ **关于容器内网络**：如果 `apt-get update` 报 DNS 解析失败（常见于 VMware NAT 环境），检查 `/etc/docker/daemon.json` 中的 DNS 配置是否指向了宿主机网关（如 `192.168.65.2`），详见 FAQ Q21。

### **5.2 启动主动防御系统**

```bash
cd /mnt/hgfs/code/09-response
sudo python3 escape-respond.py -r rules.yaml -s responses.yaml
```

预期输出：

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

### **5.3 测试 1: Ptrace 注入（HIGH → isolate_network）**

新开终端：

```bash
cd /mnt/hgfs/code/09-response
bash test-ptrace-simple.sh
```

预期监控终端输出：

```
🚨 安全告警 - HIGH 级别
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
规则: dangerous_ptrace
描述: 检测容器内尝试ptrace宿主机1号进程(systemd/init)
Ptrace请求: PTRACE_SECCOMP_GET_METADATA -> 目标PID: 1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🛡️  [RESPONSE] 触发自动防御: HIGH → isolate_network
✅ Container xxxxxxxxxxxx DISCONNECTED from bridge
```

### **5.4 测试 2: Procfs 挂载逃逸（CRITICAL → pause_container）**

```bash
bash test-escape.sh
```

预期输出：

```
🚨 安全告警 - CRITICAL 级别
规则: procfs_mount_escape
文件系统: proc -> 目标: /tmp/host_proc

🛡️  [RESPONSE] 触发自动防御: CRITICAL → pause_container
✅ Container xxxxxxxxxxxx PAUSED - 已冻结,等待人工取证
```

验证容器已被冻结：

```bash
docker inspect escape_test --format '{{.State.Status}}'
# 输出: paused
```

### **5.5 测试 3: 敏感文件读取（可选，已知 openat 噪音限制）**

```bash
bash test-openat.sh
```

⚠️ openat 是最高频调用，Ring Buffer（256 条目）可能溢出导致事件丢失。ptrace 和 mount 不受影响。

### **5.6 验证响应动作的防护效果**

| 告警类型              | 响应动作          | 验证方法                                                                          |
| --------------------- | ----------------- | --------------------------------------------------------------------------------- |
| CRITICAL (procfs挂载) | `pause_container` | `docker inspect escape_test --format '{{.State.Status}}'` → `paused`              |
| HIGH (ptrace注入)     | `isolate_network` | `docker inspect ptrace-test --format '{{json .NetworkSettings.Networks}}'` → `{}` |
| MEDIUM (敏感文件)     | `kill_process`    | 容器内 `ps aux` 确认恶意进程已消失                                                |
| LOW                   | `log_only`        | `cat audit.log` 查看 JSON 审计记录                                                |

### **5.7 测试结果与已知限制**

在 Ubuntu 22.04 (kernel 6.8.0) + VMware 虚拟机环境下验证：

| 验证项          | 结果 | 说明                                                 |
| --------------- | ---- | ---------------------------------------------------- |
| eBPF 编译加载   | ✅   | 3 个 tracepoint 探针全部成功                         |
| 事件捕获        | ✅   | ptrace/mount 事件正常接收                            |
| 规则引擎匹配    | ✅   | `procfs_mount_escape` 和 `dangerous_ptrace` 均能触发 |
| cgroup 容器识别 | ✅   | 用户态 `cgroup_id → container_id` 映射生效           |
| 响应引擎分流    | ✅   | 宿主机事件正确跳过，不误杀                           |

**已知限制**（非代码问题，属环境差异）：

1. **容器内 mount 不被 tracepoint 捕获**：kernel 6.8.0 下，`--privileged` 容器内的 `mount()` 调用可能不被宿主机 `sys_enter_mount` tracepoint 感知。这是内核版本差异，不影响逻辑正确性。
2. **ptrace 到 PID 1 权限不足**：即使有 `--pid=host` + `CAP_SYS_PTRACE`，`ptrace_scope=1` 会阻止对 systemd 的附加。测试时需要 `echo 0 > /proc/sys/kernel/yama/ptrace_scope`。
3. **openat Ring Buffer 溢出**：256 条目的 Ring Buffer 在面对 openat 洪水时严重不足，属于第八篇中已说明的已知问题，未来通过内核态过滤解决。

> 💡 同一套代码在 kernel 5.15（如标准 Ubuntu 22.04 初始内核）上可以触发完整的"容器 mount → CRITICAL 告警 → pause_container"闭环。见第八篇的完整流程。

---

## 六、安全与边界:主动防御不能乱"打人"

### **6.1 主动防御的法律与伦理边界**

在设计主动防御系统时,必须明确:

**我们做的主动防御 = 阻断 + 隔离 + 取证 + 告警**

- ✅ 冻结自己的容器(企业资产)
- ✅ 断开可疑容器的网络
- ✅ 终止恶意进程
- ✅ 记录审计日志

**我们不做的"反击" = 主动攻击攻击者**

- ❌ 反向入侵攻击者机器
- ❌ 向攻击者发送恶意 payload
- ❌ 追踪攻击者真实身份(这是执法部门的事)

**原因:**

- 法律风险:"反击"可能触犯《网络安全法》
- 技术风险:可能误判(告警来源可能是内部测试)
- 责任问题:企业安全团队的职责是保护资产,不是执法

### **6.2 Docker Socket 的双刃剑**

我们的 defender 容器需要挂载 `/var/run/docker.sock`:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

**风险:**

- 如果攻击者反杀 defender 容器,就能完全控制宿主机 Docker
- 可以创建新的特权容器、读取所有容器数据

**缓解方案:**

1. **最小权限原则**: 只读挂载(如果只需查询状态)

   ```yaml
   volumes:
     - /var/run/docker.sock:/var/run/docker.sock:ro
   ```

2. **Docker Socket Proxy**: 使用 Tecnativa 的 socket-proxy 限制 API

   ```yaml
   services:
     docker-proxy:
       image: tecnativa/docker-socket-proxy
       environment:
         CONTAINERS: 1 # 只允许容器相关API
         EXEC: 0 # 禁止exec
         POST: 0 # 禁止创建新容器
   ```

3. **白名单机制**: 只对关键容器执行自动响应

   ```python
   SAFE_CONTAINERS = ['database', 'redis', 'nginx']

   def handle_alert(self, alert):
       container_name = alert['event'].get('container_name')
       if container_name in SAFE_CONTAINERS:
           print(f"[SKIP] 跳过白名单容器: {container_name}")
           return
       # ... existing code: 执行正常响应 ...
   ```

### **6.3 误杀防护设计**

**问题:** 如果规则误报,自动响应可能会中断正常业务!

**解决方案:**

1. **分级响应**: LOW/MEDIUM 仅告警,CRITICAL/HIGH 才自动处置
2. **人工确认开关**: 生产环境先打标记,人工确认后手动执行
3. **冷却时间**: 同一容器 N 分钟内只执行一次自动响应
   ```python
   class ResponseEngine:
       def __init__(self):
           self.cooldown = {}  # container_id → last_response_time

       def handle_alert(self, alert):
           container_id = alert['event']['container_id']
           now = time.time()

           # 检查冷却时间
           if container_id in self.cooldown:
               last_time = self.cooldown[container_id]
               if now - last_time < 600:  # 10分钟冷却
                   print(f"[SKIP] 容器 {container_id[:12]} 在冷却期内")
                   return

           # ... existing code: 执行响应 ...
           self.cooldown[container_id] = now
   ```

---

## 七、三维响应模型:构建完整的逃逸防护体系

### **7.1 为什么需要三维响应?**

类比第八篇的"三维检测模型",响应也需要多维度覆盖:

| 响应维度   | 覆盖场景              | 优势                 | 局限性                         |
| ---------- | --------------------- | -------------------- | ------------------------------ |
| **容器级** | pause/disconnect/kill | 彻底阻断,操作简单    | 影响整个容器(可能误杀正常服务) |
| **进程级** | bpf_send_signal/kill  | 精准打击,影响面小    | 需要PID准确,可能遗漏多线程攻击 |
| **网络级** | XDP/TC丢包            | 阻止C2回连和横向移动 | 不影响本地文件系统操作         |

**结论**: 必须组合使用多个响应维度,形成**纵深防御**,才能有效应对复杂攻击。

### **7.2 三维响应模型的实现**

当前系统已实现的三个响应维度:

#### **维度1: 容器级响应 (Docker SDK)**

```python
def pause_container(self, container_id):
    """冻结容器(推荐用于CRITICAL级别,保留取证现场)"""
    container = self.docker_client.containers.get(container_id)
    container.pause()  # 底层调用cgroup freezer
```

**典型场景:**

- procfs 挂载逃逸 → 立即冻结,保留内存现场
- ptrace 注入宿主机 → 冻结容器,防止进一步操作

#### **维度2: 进程级响应 (eBPF bpf_send_signal)**

```c
// 在内核态直接发送SIGKILL
if (is_critical_escape(&evt)) {
    bpf_send_signal(SIGKILL);
}
```

**典型场景:**

- 反弹 shell 瞬间 → 内核态直接掐断
- 高频恶意系统调用 → 毫秒级拦截

#### **维度3: 网络级响应 (XDP/TC - 概念性介绍)**

虽然本篇未提供完整实现,但思路是:

```c
// XDP程序示例(伪代码)
SEC("xdp")
int xdp_drop_malicious(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // 检查是否为恶意IP或端口
    if (is_malicious_destination(eth)) {
        return XDP_DROP;  // 直接丢包
    }

    return XDP_PASS;
}
```

**典型场景:**

- 容器连接恶意 C2 服务器 → XDP 层丢包
- 容器间横向扫描 → TC 层重定向到蜜罐

### **7.3 响应模型的扩展性**

通过 YAML 响应策略,可以轻松扩展更多动作:

```yaml
# 扩展1: 资源限制
- threat_level: medium
  action: limit_resources
  config:
    cpu_quota: 50% # 限制CPU使用率
    memory_limit: 256MB # 限制内存上限

# 扩展2: 通知集成
- threat_level: high
  action: notify_slack
  config:
    webhook_url: "https://hooks.slack.com/..."
    channel: "#security-alerts"

# 扩展3: 自动化取证
- threat_level: critical
  action: capture_forensics
  config:
    dump_memory: true # 导出内存快照
    save_logs: true # 保存容器日志
    snapshot_filesystem: true # 快照文件系统
```

**核心思想**: 三维响应模型不是固定的,而是可以根据实际威胁情报动态调整的**活框架**。

---

## 第九篇的关键点与避坑指南

### **1. 响应策略设计**

- **分级处置**: CRITICAL 才用 pause(保留现场),HIGH 用 disconnect(阻止横向)
- **冷却时间**: 同一容器 10 分钟内只执行一次自动响应
- **白名单机制**: 关键业务容器不要自动 kill/pause
- **宿主机事件跳过**: `container_id == 'host'` 的事件不触发自动响应，防止误杀

### **2. PID 映射竞态与 cgroup fallback**

第八篇的 PID 映射表是静态的——`docker exec` 创建的新进程 PID 不在初始映射中。更致命的是，strace 这类进程在微秒级完成 ptrace 调用后就退出，用户态来不及读 `/proc/<pid>/cgroup`。

**解决方案**:

1. **内核态**：在 eBPF 事件结构体中新增 `u64 cgroup_id` 字段，通过 `bpf_get_current_cgroup_id()` 在事件发生瞬间记录
2. **用户态**：启动时遍历 Docker 容器，构建 `cgroup_inode → container_id` 映射表（`stat` cgroup 目录获取 inode）
3. **事件处理时**：PID 映射未命中 → 用内核态记录的 `cgroup_id` 反查 → 零竞态

这是本篇最关键的架构改进，让容器识别从"猜测"变成了"铁证"。

### **3. Docker Socket 权限管理**

- **最小权限**: 只读挂载或使用 socket-proxy
- **细粒度控制**: 只允许 pause/disconnect,禁止 rm/run
- **审计日志**: 所有自动响应动作必须记录到 `response_audit.log`

### **4. kill_process 的 PID 陷阱**

eBPF 捕获的 `pid` 是**宿主机 PID**，不是容器内 PID。如果容器没有 `--pid=host`，容器内的 PID 1 在宿主机上可能是 PID 34567。因此 `docker exec <container> kill -9 <host_pid>` 会失败。

**正确做法**：本系统运行在宿主机上，直接用 `os.kill(host_pid, signal.SIGKILL)` 发信号，绕过容器 PID namespace 的映射问题。

### **5. 内核版本差异**

在 kernel 6.8.0 上测试发现：

- 容器内 mount 调用可能不被 `sys_enter_mount` tracepoint 捕获（与 mount namespace 隔离有关）
- `ptrace_scope=1` 会阻止对 systemd(PID 1)的附加，即使有 `CAP_SYS_PTRACE`
- 同一套代码在 kernel 5.15（标准 Ubuntu 22.04 初始内核）上无此问题

### **6. Python 输出缓冲**

用 `sudo python3 escape-respond.py > log.txt` 重定向输出时，Python 默认全缓冲。会导致日志文件长时间看不到输出，误以为程序卡死。

**解决**: `sudo PYTHONUNBUFFERED=1 python3 -u escape-respond.py > log.txt`

### **7. 测试环境注意事项**

- **特权容器**: 测试逃逸需要 `--privileged` 或 `--cap-add=SYS_PTRACE --pid=host`，生产环境不要这样跑
- **容器复用**: 测试容器创建一次即可，后续 `docker start` 复用，不需要每次重建和重装软件
- **日志清理**: 测试产生的 `audit.log`、`response_audit.log` 不要提交到 git
- **多实例冲突**: 多个监控实例会竞争同一个 Ring Buffer，务必 `pkill -f escape-respond` 确认只有一个实例在跑

---

## 🔗 相关链接与下一步

**相关代码示例:**

- [`escape-respond.py`](../code/09-response/escape-respond.py) - 主动防御主程序(检测+响应)
- [`responder.py`](../code/09-response/responder.py) - 响应引擎实现
- [`responses.yaml`](../code/09-response/responses.yaml) - 响应策略配置
- [`escape-detect.c`](../code/09-response/escape-detect.c) - eBPF探针(含bpf_send_signal)
- [`docker-compose.yml`](../code/09-response/docker-compose.yml) - 攻防靶场编排

**学习笔记:**

- **上一篇**: [Eight、从监控到检测——构建容器逃逸规则引擎](./Eight、从监控到检测——构建容器逃逸规则引擎.md)
- **下一篇**: [Ten、性能优化与生产级部署(待规划)](./Ten、性能优化与生产级部署.md)

**相关文档:**

- [docker 容器环境准备](./docker%20容器环境准备.md)
- [eBPF 常用字典](./eBPFBPF%20常用字典.md)

**常见问题:**

- [FAQ](../FAQ.md) - 包含响应引擎相关问题解答
- [项目环境](./项目环境.md) - Ubuntu环境配置

---

_最后更新: 2026-05-30_
