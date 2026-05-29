# Eight、从监控到检测——构建容器逃逸规则引擎

date: 2026-05-29

前七篇我们打造了一个功能完整的**容器运行时监控系统**,能实时捕获 `execve`、`openat`、`connect` 等系统调用,还能识别容器身份。但这只是"看见",还没到"理解"。

真正的安全产品,需要从**海量正常行为中精准识别出攻击模式**。这篇,我们将引入 **YAML 规则引擎**,实现从"监控面板"到"入侵检测系统(IDS)"的华丽转身!

## 核心内容结构

```text
1. 架构升级：从"硬编码"到"规则驱动"
2. YAML 规则设计：声明式安全策略
3. 检测引擎实现：模式匹配与告警分级
4. 实战演练：procfs 挂载逃逸检测
5. 深度对抗：ptrace 注入检测的思维升级
6. 云原生安全哲学：从"怎么逃"到"逃向谁"
7. 三维检测模型：构建完整的逃逸防护体系
```

---

## 一、架构升级：从"硬编码"到"规则驱动"

### **1.1 为什么需要规则引擎?**

回顾第七篇的监控面板,我们在 Python 代码中硬编码了检测逻辑:

```python
# ❌ 硬编码检测(第七篇)
if event['comm'] == 'nmap' or 'sensitive-file' in event['path']:
    print("🚨 告警!")
```

**问题:**
- ❌ 每次新增规则都要修改代码
- ❌ 无法动态调整检测策略
- ❌ 难以管理成百上千条规则
- ❌ 运维人员看不懂 Python 代码

**解决方案:YAML 规则引擎!**

```text
┌───────────────────────────────────────────────────┐
│                 用户态 Python                       │
│                                                   │
│  [eBPF 事件] → [规则引擎] → [匹配成功] → [告警]    │
│                   ↕                               │
│            [rules.yaml 配置文件]                   │
│            - procfs_mount_escape                  │
│            - dangerous_ptrace                     │
│            - sensitive_file_read                  │
└───────────────────────────────────────────────────┘
                       ↕ (BPF Ring Buffer)
┌───────────────────────────────────────────────────┐
│                 内核态 eBPF                         │
│                                                   │
│  [mount 探针] ──→ Ring Buffer ──→ 事件上报        │
│  [ptrace 探针] ──→ Ring Buffer ──→ 事件上报       │
│  [openat 探针] ──→ Ring Buffer ──→ 事件上报       │
└───────────────────────────────────────────────────┘
```

**优势:**
- ✅ 规则与代码分离,运维友好
- ✅ 支持热加载,无需重启服务
- ✅ 声明式语法,安全专家可独立编写
- ✅ 易于版本管理和审计

---

## 二、YAML 规则设计：声明式安全策略

### **2.1 规则文件格式设计**

创建 `rules.yaml`:

```yaml
rules:
  - name: "procfs_mount_escape"
    description: "检测容器内挂载宿主机procfs文件系统"
    severity: "CRITICAL"
    condition:
      event_type: "mount"
      fstype: "proc"
    exclude:
      comm:
        - "dockerd"
        - "containerd"
        - "runc:[2:INIT]"
        - "runc"
        - "docker-proxy"
      target_path:
        - "/proc/thread-self/fd/*"
    action: "alert_and_log"

  - name: "dangerous_ptrace"
    description: "检测容器内尝试ptrace宿主机1号进程(systemd/init)"
    severity: "HIGH"
    condition:
      event_type: "ptrace"
      target_pid: 1 # 核心修改:只要对 PID 1 发起 ptrace,一律视为逃逸告警!
    action: "alert_and_log"

  - name: "sensitive_file_read"
    description: "检测容器内读取宿主机敏感文件(如shadow)"
    severity: "HIGH"
    condition:
      event_type: "openat"
      target_path:
        - "/host_etc/shadow" # 匹配测试脚本挂载的路径
        # 也可以匹配更通用的，比如包含 /etc/shadow 的路径
    action: "alert_and_log"
```

### **2.2 规则字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | 规则唯一标识符(英文+下划线) |
| `description` | string | 人类可读的描述 |
| `severity` | enum | 严重级别: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `condition` | map | 匹配条件(所有条件必须满足 = AND) |
| `exclude` | map | 排除条件(任一条件满足 = 跳过) |
| `action` | enum | 触发动作: `alert_and_log`, `terminate_process` |

### **2.3 条件匹配语义**

**精确匹配:**
```yaml
condition:
  event_type: "mount"  # event['event_type'] == "mount"
  fstype: "proc"       # AND event['fstype'] == "proc"
```

**列表 OR 匹配:**
```yaml
condition:
  request: 
    - "PTRACE_ATTACH"   # event['request'] in ["PTRACE_ATTACH", ...]
    - "PTRACE_SEIZE"
```

**通配符排除:**
```yaml
exclude:
  comm:
    - "dockerd"         # event['comm'] != "dockerd"
    - "runc:*"          # AND not fnmatch(event['comm'], "runc:*")
```

---

## 三、检测引擎实现：模式匹配与告警分级

### **3.1 Detector 类设计**

创建 `detector.py`:

```python
#!/usr/bin/env python3
import yaml
from datetime import datetime
import fnmatch


class EscapeDetector:
    def __init__(self, rules_file):
        with open(rules_file, 'r') as f:
            self.rules = yaml.safe_load(f).get('rules', [])
        self.rule_index = self._build_rule_index()
        print(f"[Detector] 已加载 {len(self.rules)} 条规则")

    def _build_rule_index(self):
        index = {}
        for rule in self.rules:
            event_type = rule.get('condition', {}).get('event_type')
            if event_type not in index:
                index[event_type] = []
            index[event_type].append(rule)
        return index

    def check_event(self, event_dict):
        event_type = event_dict.get('event_type')
        if not event_type or event_type not in self.rule_index:
            return []
        matched = []
        for rule in self.rule_index[event_type]:
            if self._match(event_dict, rule['condition']):
                if not self._is_excluded(event_dict, rule.get('exclude', {})):
                    matched.append(rule)
        return matched

    def _match(self, event, condition):
        """精确匹配 + 列表OR匹配"""
        for key, expected in condition.items():
            if key not in event:
                return False
            actual = event[key]
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    def _is_excluded(self, event, exclude):
        """检查事件是否匹配排除条件（支持通配符）"""
        for key, patterns in exclude.items():
            if key not in event:
                continue
            actual = event[key]
            if isinstance(patterns, str):
                patterns = [patterns]
            for pattern in patterns:
                if fnmatch.fnmatch(str(actual), pattern):
                    return True  # 命中排除规则，跳过
        return False

    def generate_alert(self, rule, event):
        return {
            'timestamp': datetime.now().isoformat(),
            'rule_name': rule['name'],
            'severity': rule['severity'],
            'description': rule['description'],
            'event': event
        }


def print_alert(alert):
    RED = '\033[91m'
    RESET = '\033[0m'
    BG_RED = '\033[101m'
    sev = alert['severity']
    color = BG_RED if sev == 'CRITICAL' else RED
    print(f"\n{color}🚨 安全告警 - {sev} 级别 {RESET}")
    print(f"{RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
    print(f"{RED}规则: {alert['rule_name']}{RESET}")
    print(f"{RED}描述: {alert['description']}{RESET}")
    evt = alert['event']
    print(f"{RED}容器: {evt.get('container_id', 'unknown')}{RESET}")
    print(f"{RED}进程: {evt.get('pid')} ({evt.get('comm')}){RESET}")
    if 'fstype' in evt:
        print(f"{RED}文件系统: {evt['fstype']} -> 目标: {evt.get('target_path')}{RESET}")
    if 'request' in evt:
        print(f"{RED}Ptrace请求: {evt['request']} -> 目标PID: {evt.get('target_pid')}{RESET}")
    # 🚀 留给读者的作业扩展：在告警中显示 openat 的路径
    if evt.get('event_type') == 'openat' and 'target_path' in evt:
        print(f"{RED}访问路径: {evt['target_path']}{RESET}")
        
    print(f"{color}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}\n")



def log_alert(alert, log_file="detection.log"):
    evt = alert['event']
    with open(log_file, 'a') as f:
        f.write(f"[{alert['timestamp']}] {alert['severity']} | "
                f"{alert['rule_name']} | "
                f"容器={evt.get('container_id','?')} "
                f"PID={evt.get('pid','?')} "
                f"Comm={evt.get('comm','?')}\n")
```

### **3.2 集成到主程序**

修改 `escape-detect.py`:

```python
#!/usr/bin/env python3
""" 
容器逃逸检测系统 - 基于eBPF 
对应笔记: Eight、从监控到检测——构建容器逃逸规则引擎 
"""
from bcc import BPF
import ctypes as ct
import docker
import time
import sys
from detector import EscapeDetector, print_alert

# ptrace 请求常量完整映射表
PTRACE_MAP = {
    0: "PTRACE_TRACEME",
    1: "PTRACE_PEEKTEXT",
    2: "PTRACE_PEEKDATA",
    3: "PTRACE_PEEKUSER",
    4: "PTRACE_POKETEXT",
    5: "PTRACE_POKEDATA",
    6: "PTRACE_POKEUSER",
    7: "PTRACE_CONT",
    8: "PTRACE_KILL",
    9: "PTRACE_SINGLESTEP",
    12: "PTRACE_GETREGS",
    13: "PTRACE_SETREGS",
    14: "PTRACE_GETFPREGS",
    15: "PTRACE_SETFPREGS",
    16: "PTRACE_ATTACH",
    17: "PTRACE_DETACH",
    24: "PTRACE_SYSCALL",
    0x4200: "PTRACE_SECCOMP_GET_FILTER",
    0x4201: "PTRACE_SECCOMP_GET_METADATA",
    0x4206: "PTRACE_SECCOMP_GET_METADATA", # 部分内核版本的兼容
    0x420e: "PTRACE_GET_SYSCALL_INFO",
    0x1000: "PTRACE_SEIZE",
    0x1001: "PTRACE_INTERRUPT",
    0x1002: "PTRACE_LISTEN",
}

class ContainerEscapeMonitor:
    """容器逃逸监控系统"""
    
    def __init__(self, rules_file='rules.yaml'):
        # 初始化eBPF程序
        print("[1] 编译并加载eBPF程序...")
        self.bpf = BPF(src_file="escape-detect.c")
        
        # 初始化检测引擎
        print("[2] 加载检测规则...")
        self.detector = EscapeDetector(rules_file)
        
        # 初始化Docker客户端
        print("[3] 连接Docker守护进程...")
        try:
            self.docker_client = docker.from_env()
        except docker.errors.DockerException as e:
            print(f"[!] Docker连接失败: {e}", file=sys.stderr)
            print("[!] 提示: 请确保Docker正在运行", file=sys.stderr)
            sys.exit(1)
        
        # 初始化容器映射
        print("[4] 初始化容器ID映射...")
        self.update_container_map()
        print("\n[✓] 容器逃逸检测系统启动成功!")
        print("[i] 按Ctrl+C停止监控\n")
    
    def update_container_map(self):
        """更新容器ID映射表"""
        try:
            containers = self.docker_client.containers.list()
            for container in containers:
                top_result = container.top()
                for process in top_result['Processes']:
                    pid_str = process[1].strip()
                    if not pid_str.isdigit():
                        continue
                    pid = int(pid_str)
                    cid = container.id[:12]
                    
                    ContainerId = self.bpf['container_map'].Leaf
                    c_id = ContainerId()
                    c_id.id = cid.encode('utf-8')
                    self.bpf['container_map'][ct.c_uint32(pid)] = c_id
            print(f"[✓] 已映射 {len(containers)} 个容器的进程ID")
        except Exception as e:
            print(f"[!] 更新容器映射失败: {e}", file=sys.stderr)
    
    def handle_event(self, cpu, data, size):
        """处理从eBPF捕获的事件"""
        try:
            event = self.bpf['events'].event(data)
            
            # 修正：支持 3 种事件类型的映射，不再用 if-else 硬编码
            event_type_map = {1: 'mount', 2: 'ptrace', 3: 'openat'}
            
            # 转换为字典格式
            event_dict = {
                'event_type': event_type_map.get(event.event_type, 'unknown'),
                'pid': event.pid,
                'uid': event.uid,
                'comm': event.comm.decode('utf-8', errors='replace'),
                'container_id': event.container_id.decode('utf-8', errors='replace').rstrip('\x00'),
                'timestamp': time.time()
            }

            # 根据事件类型添加特定字段
            if event.event_type == 1: # MOUNT
                event_dict['fstype'] = event.fstype.decode('utf-8', errors='replace').rstrip('\x00')
                event_dict['target_path'] = event.target_path.decode('utf-8', errors='replace').rstrip('\x00')
            elif event.event_type == 2: # PTRACE
                event_dict['target_pid'] = event.target_pid
                # 完善的 request 映射逻辑
                request_val = event.request_raw
                mapped_req = PTRACE_MAP.get(request_val)
                if not mapped_req:
                    mapped_req = PTRACE_MAP.get(request_val & 0xFFFFFFFF)
                if mapped_req:
                    event_dict['request'] = mapped_req
                else:
                    event_dict['request'] = f"UNKNOWN(0x{request_val:x}/{request_val})"
                    
            #  留的扩展：处理 openat 事件
            # ⚠️ 注意：目前尚未实现宿主机噪音筛选功能，openat 会产生大量正常事件
            # 因此暂时注释掉 openat 事件的日志输出，避免信息过载
            # elif event.event_type == 3: # OPENAT
            #     event_dict['target_path'] = event.target_path.decode('utf-8', errors='replace').rstrip('\x00')

            # 交给检测引擎检查
            matched_rules = self.detector.check_event(event_dict)
            if matched_rules:
                # 匹配到规则,生成告警
                for rule in matched_rules:
                    alert = self.detector.generate_alert(rule, event_dict)
                    print_alert(alert)
            else:
                # 正常事件,绿色输出，完善显示信息
                if event_dict['event_type'] == 'ptrace':
                    print(f"\033[92m[INFO] {event_dict['event_type']} - PID:{event_dict['pid']} Comm:{event_dict['comm']} CID:{event_dict['container_id']} Req:{event_dict['request']} Target:{event_dict['target_pid']}\033[0m")
                # ⚠️ 已注释：暂时不输出 openat 正常事件（未实现宿主机噪音过滤）
                # elif event_dict['event_type'] == 'openat':
                #     print(f"\033[92m[INFO] {event_dict['event_type']} - PID:{event_dict['pid']} Comm:{event_dict['comm']} CID:{event_dict['container_id']} Path:{event_dict['target_path']}\033[0m")
                else:
                    print(f"\033[92m[INFO] {event_dict['event_type']} - PID:{event_dict['pid']} Comm:{event_dict['comm']} CID:{event_dict['container_id']}\033[0m")
                    
        except Exception as e:
            print(f"[ERROR] 处理事件异常: {e}", file=sys.stderr)

    
    def run(self):
        """运行监控系统"""
        # 打开Ring Buffer
        self.bpf['events'].open_ring_buffer(self.handle_event)
        
        # 主循环
        try:
            while True:
                self.bpf.ring_buffer_poll()
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[i] 停止监控")


def main():
    """主函数"""
    import argparse
    parser = argparse.ArgumentParser(description='容器逃逸检测系统')
    parser.add_argument('-r', '--rules', default='rules.yaml', help='规则文件路径')
    args = parser.parse_args()
    
    # 创建监控器实例
    monitor = ContainerEscapeMonitor(args.rules)
    
    # 运行监控
    monitor.run()


if __name__ == "__main__":
    main()
```

---

## 四、实战演练：procfs 挂载逃逸检测

### **4.1 攻击场景**

攻击者在特权容器内执行:

```bash
# 挂载宿主机 procfs,读取宿主机进程信息
mkdir /tmp/host_proc
mount -t proc proc /tmp/host_proc
cat /tmp/host_proc/1/cmdline  # 读取宿主机 init 进程
```

### **4.2 eBPF 探针代码**

创建 `escape-detect.c`:

```c
// escape-detect.c - 容器逃逸检测eBPF探针（修正版）
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 事件类型定义
#define EVENT_MOUNT 1
#define EVENT_PTRACE 2
// #define EVENT_OPENAT 3

// 通用事件结构
struct event {
    u32 event_type;
    u32 pid;
    u32 uid;
    char comm[16];
    char container_id[64];

    // mount相关字段
    char fstype[32];
    char target_path[256];

    // ptrace相关字段
    u32 target_pid;
    u64 request_raw; // 使用 u64 保留完整的原始值
};

// 容器ID结构体
struct container_id_t {
    char id[64];
};

// Ring Buffer声明
BPF_RINGBUF_OUTPUT(events, 1 << 8);

// Hash Map声明
BPF_HASH(container_map, u32, struct container_id_t);

// 获取容器ID辅助函数
static inline void get_container_id(struct event *evt) {
    u32 pid = evt->pid;
    struct container_id_t *cid = container_map.lookup(&pid);
    if (cid) {
        bpf_probe_read_str(evt->container_id, sizeof(evt->container_id), cid->id);
    } else {
        // 默认标记为宿主机
        evt->container_id[0] = 'h';
        evt->container_id[1] = 'o';
        evt->container_id[2] = 's';
        evt->container_id[3] = 't';
        evt->container_id[4] = '\0';
    }
}

// ==========================================
// 监控 mount 系统调用 (使用 tracepoint)
// ==========================================
TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    struct event evt = {};
    evt.event_type = EVENT_MOUNT;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // 从用户态指针读取字符串
    bpf_probe_read_user_str(&evt.fstype, sizeof(evt.fstype), (void *)args->type);
    bpf_probe_read_user_str(&evt.target_path, sizeof(evt.target_path), (void *)args->dir_name);

    get_container_id(&evt);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

// ==========================================
// 监控 ptrace 系统调用（改用 tracepoint）
// ==========================================
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct event evt = {};
    evt.event_type = EVENT_PTRACE;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // 🔥 关键修正：直接将完整的 64 位 request 值传回用户态，不做任何掩码处理，方便调试
    evt.request_raw = (u64)args->request;
    evt.target_pid = (u32)args->pid;

    get_container_id(&evt);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

// ==========================================
// 监控 openat 系统调用（改用 tracepoint）
// ==========================================
// TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
//     struct event evt = {};
//     evt.event_type = EVENT_OPENAT;
//     evt.pid = bpf_get_current_pid_tgid() >> 32;
//     evt.uid = bpf_get_current_uid_gid();
//     bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    
//     // 读取文件路径
//     bpf_probe_read_user_str(&evt.target_path, sizeof(evt.target_path), (void *)args->filename);
    
//     get_container_id(&evt);
//     events.ringbuf_output(&evt, sizeof(evt), 0);
//     return 0;
// }
```

### **4.3 测试脚本**

创建 `test-escape.sh`:

```bash
#!/bin/bash
echo "===== Procfs 挂载逃逸测试 ====="

# 启动特权容器
echo "[1] 启动特权容器..."
docker run -d --privileged --name escape_test ubuntu:22.04 sleep 300

# 等待容器启动
sleep 2

# 在容器内执行挂载命令
echo "[2] 执行procfs挂载..."
docker exec escape_test bash -c "
mkdir -p /tmp/host_proc && \
mount -t proc proc /tmp/host_proc && \
ls /tmp/host_proc/1/cmdline
"

# 清理
echo "[3] 清理测试容器..."
docker rm -f escape_test

echo "===== 测试完成 ====="
echo "请查看监控终端是否有红色CRITICAL告警!"
```

### **4.4 预期结果**

**监控终端应该显示:**

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

![image-20260529134103005](https://raw.githubusercontent.com/Chenjx12/PicGO/main/img/20260529134104437.png)

---

## 五、深度对抗：ptrace 注入检测的思维升级

### **5.1 第一次尝试：匹配具体参数(失败)**

最初,我天真地认为只需要匹配 `PTRACE_ATTACH`:

```yaml
condition:
  event_type: "ptrace"
  request: 
    - "PTRACE_ATTACH"
    - "PTRACE_SEIZE"
```

**结果:** 根本没触发告警!调试输出显示:

```bash
[DEBUG] event.request=285392728, type=<class 'int'>
[DEBUG] mapped request=UNKNOWN(285392728)
```

**原因分析:** 

现代 `strace` 为了获取更多控制权和上下文信息,默认使用的是高级请求:
- `0x4200` = `PTRACE_SECCOMP_GET_FILTER`
- `0x420e` = `PTRACE_GET_SYSCALL_INFO` (Linux 5.9+ 引入)
- `0x4206`, `0x4207` 等也是现代内核扩展操作

**我们死磕 `PTRACE_ATTACH` 是永远匹配不到的!**

### **5.2 思维升级：从"怎么逃"到"逃向谁"**

智谱AI的分析给了我启发:

> 在云原生安全中,不应该过度关注攻击者使用了哪种具体的系统调用参数,而应该关注行为的"越权方向"。

对于 `ptrace` 逃逸:
- 在普通容器中,PID 1 是容器自身的 init 进程,对它 `ptrace` 不是逃逸。
- 在 `--pid=host` 的容器中,**PID 1 是宿主机的 systemd!** 对宿主机的 PID 1 发起**任何** `ptrace` 操作,无论是什么参数,都是极度危险的逃逸行为!

### **5.3 最终方案：匹配 target_pid = 1**

修改 `rules.yaml`:

```yaml
- name: "dangerous_ptrace"
  description: "检测容器内尝试ptrace宿主机1号进程(systemd/init)"
  severity: "HIGH"
  condition:
    event_type: "ptrace"
    target_pid: 1  #  核心修改:只要对 PID 1 发起 ptrace,一律视为逃逸告警!
  action: "alert_and_log"
```

**测试脚本** `test-ptrace.sh`:

```bash
#!/bin/bash
# test-ptrace.sh - 使用已有ptrace-test容器测试ptrace监控

echo "===== Ptrace 逃逸检测测试 ====="
echo ""

# 检查ptrace容器是否存在
if ! docker ps -a --format '{{.Names}}' | grep -q "^ptrace-test$"; then
    echo "❌ ptrace容器不存在!"
    echo "请先创建容器: docker run -d --name ptrace-test --cap-add=SYS_PTRACE --pid=host ubuntu:22.04 sleep 3600"
    exit 1
fi

# 启动容器(如果已停止)
if ! docker ps --format '{{.Names}}' | grep -q "^ptrace-test$"; then
    echo "[1] 启动ptrace容器..."
    docker start ptrace-test > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✅ ptrace容器已启动"
    fi
    sleep 2
else
    echo "[1] ptrace容器正在运行 ✓"
fi

echo ""
echo "[2] 检查strace是否已安装..."
docker exec ptrace-test which strace > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ strace已安装"
else
    echo "⚠️ strace未安装,正在安装..."
    docker exec ptrace-test bash -c "apt-get update > /dev/null 2>&1 && apt-get install -y strace > /dev/null 2>&1"
    if [ $? -eq 0 ]; then
        echo "✅ strace安装成功"
    else
        echo "❌ strace安装失败"
        exit 1
    fi
fi

echo ""
echo "[3] 执行ptrace测试(应该触发HIGH告警)..."
docker exec ptrace-test bash -c "
    echo '尝试追踪PID 1 (宿主机init进程)...'
    timeout 10 strace -p 1 -e trace=read 2>&1 | head -n 10
"

echo ""
echo "===== 测试完成 ====="
echo "请查看监控终端是否有红色ptrace告警!"
echo ""
echo "预期输出:"
echo "🚨 安全告警 - HIGH 级别"
echo "规则: dangerous_ptrace"
echo "Ptrace请求: PTRACE_ATTACH -> 目标PID: 1"
```

### **5.4 测试结果**

**完美触发红色告警!** 🔥🔥🔥

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

**绿色INFO日志也会显示完整信息:**
```bash
[INFO] ptrace - PID:17726 Comm:strace CID:host Req:PTRACE_GET_SYSCALL_INFO Target:1
```

![image-20260529133512061](https://raw.githubusercontent.com/Chenjx12/PicGO/main/img/20260529133515232.png)

---

## 六、云原生安全哲学：从"怎么逃"到"逃向谁"

这次 ptrace 检测的调试过程,揭示了一个深刻的云原生安全哲学:

### **6.1 传统安全思维 vs 云原生安全思维**

| 维度 | 传统安全 | 云原生安全 |
|------|---------|-----------|
| **关注点** | 攻击手法(signature) | 行为方向(intent) |
| **规则** | 匹配具体参数 | 判断越权边界 |
| **绕过** | 换参数即可绕过 | 难以绕过(本质检测) |
| **示例** | 匹配 `PTRACE_ATTACH` | 检测 `target_pid=1` |

### **6.2 为什么"逃向谁"更重要?**

在容器环境中:
- **容器内 PID 1**: 容器自身的 init 进程,正常访问
- **宿主机 PID 1**: systemd/init,绝对不应该被容器访问!

**这就是本质的区别!**

无论攻击者使用什么 ptrace 参数(`ATTACH`, `SEIZE`, `GET_SYSCALL_INFO`),只要目标是宿主机 PID 1,就是逃逸!

### **6.3 延伸思考：其他逃逸检测规则**

基于这个思路,我们可以设计更多精准的规则:

```yaml
# 规则1: 检测容器内访问宿主机敏感文件
- name: "host_file_access"
  condition:
    event_type: "openat"
    path: 
      - "/host_etc/shadow"
      - "/host_proc/kcore"

# 规则2: 检测容器内修改宿主机网络配置
- name: "host_network_modify"
  condition:
    event_type: "connect"
    dst_port: 22  # SSH端口

# 规则3: 检测特权容器内的危险命令
- name: "privileged_dangerous_cmd"
  condition:
    container_privileged: true
    comm: 
      - "nsenter"
      - "chroot"
      - "mount"
```

---

## 七、三维检测模型：构建完整的逃逸防护体系

### **7.1 为什么需要三维检测?**

容器逃逸是一个多维度的攻击过程,单一检测机制存在固有盲区:

| 检测维度 | 覆盖场景 | 优势 | 局限性 |
|---------|---------|------|--------|
| **挂载逃逸** | procfs/sysfs挂载、设备文件访问 | 捕获文件系统层面的越权 | 无法检测纯内存操作 |
| **进程注入** | ptrace系统调用、信号注入 | 捕获进程间控制行为 | 需要PID命名空间共享 |
| **敏感文件访问** | /etc/shadow、内核符号表 | 捕获数据窃取意图 | 产生大量正常事件噪音 |

**结论**: 必须组合使用多个探针,形成**三维检测模型**,才能有效覆盖主流逃逸路径。

### **7.2 三维检测模型的实现**

当前系统已实现的三个核心维度:

#### **维度1: 挂载逃逸检测 (mount)**

```yaml
- name: "procfs_mount_escape"
  description: "检测容器内挂载宿主机procfs文件系统"
  severity: "CRITICAL"
  condition:
    event_type: "mount"
    fstype: "proc"
```

**典型场景**:
- 挂载宿主机 procfs (`mount -t proc proc /tmp/host_proc`)
- 读取宿主机进程信息 (`cat /tmp/host_proc/1/cmdline`)

#### **维度2: 进程注入检测 (ptrace)**

```yaml
- name: "dangerous_ptrace"
  description: "检测容器内尝试ptrace宿主机1号进程(systemd/init)"
  severity: "HIGH"
  condition:
    event_type: "ptrace"
    target_pid: 1  # 核心:只要对 PID 1 发起 ptrace,一律视为逃逸!
```

**典型场景**:
- 追踪宿主机 init 进程 (`strace -p 1`)
- 注入宿主机关键进程 (CVE-2019-5736 runc漏洞)

#### **维度3: 敏感文件访问检测 (openat)**

```yaml
- name: "sensitive_file_read"
  description: "检测容器内读取宿主机敏感文件(如shadow)"
  severity: "HIGH"
  condition:
    event_type: "openat"
    target_path:
      - "/host_etc/shadow"
      - "/host_proc/kcore"
```

**典型场景**:
- 读取宿主机密码文件 (`cat /host_etc/shadow`)
- 访问内核符号表 (`cat /host_proc/kcore`)

### **7.3 关于 openat 检测的重要说明**

#### **当前状态**

⚠️ **由于尚未实现宿主机噪音筛选功能,openat 事件的正常日志输出已在代码中暂时注释掉。**

**原因**: openat 是高频系统调用,会产生海量正常事件,若全部输出将淹没真实攻击信号。

**处理方式**:
- ✅ **规则引擎仍保留** [`sensitive_file_read`](../code/08-detection/rules.yaml#L25-L34) 规则
- ✅ **告警仍会触发**: 当匹配到敏感路径时,仍会生成红色告警
- ⚠️ **正常事件不输出**: 不再打印绿色的 `[INFO] openat` 日志

**未来优化方向**:
1. **用户态开关**: 添加 `--verbose` 参数控制调试模式
2. **内核态过滤**: 在 eBPF 程序中提前过滤非目标事件
3. **智能降噪**: 基于行为分析自动识别异常模式

#### **测试脚本**

虽然正常事件已注释,但测试脚本仍保留供参考:

```
# 敏感文件访问测试(可选)
bash test-openat.sh
```

### **7.4 三维模型的扩展性**

通过 YAML 规则引擎,可以轻松扩展更多检测维度:

```yaml
# 扩展1: 网络连接检测
- name: "suspicious_connection"
  condition:
    event_type: "connect"
    dst_port: 
      - 22   # SSH
      - 2375 # Docker API

# 扩展2: 特权命令检测
- name: "privileged_command"
  condition:
    container_privileged: true
    comm: 
      - "nsenter"
      - "chroot"

# 扩展3: 设备文件访问
- name: "device_access"
  condition:
    event_type: "openat"
    target_path:
      - "/dev/sda*"
      - "/dev/mem"
```

**核心思想**: 三维检测模型不是固定的,而是可以根据实际威胁情报动态调整的**活框架**。

---

## 第八篇的关键点与避坑指南

### **1. YAML 规则引擎设计**

- **字段一致性**: 规则中的字段名必须与事件数据结构完全一致
- **索引优化**: 按 `event_type` 建立索引,避免全量遍历
- **排除规则**: 善用 `exclude` 减少误报(dockerd, runc 等正常进程)

### **2. ptrace 参数映射陷阱**

- **现代 strace 行为**: 不再使用简单的 `PTRACE_ATTACH`,而是 `0x420e` 等高级请求
- **位掩码修正**: C代码中需要用 `(request_long & 0xFFFFFFFF)` 确保只取低32位
- **检测思维升级**: 从"匹配参数"转向"判断行为方向"

### **3. 容器ID映射**

- **Map Key**: 使用 PID(u32),Value 用 struct 包装 char[64]
- **BCC限制**: BCC不支持直接返回 char[64],必须用 struct
- **动态更新**: 容器启停时需要更新映射表(第九篇预告!)

### **4. 调试技巧**

- **临时放宽规则**: 先只匹配 `event_type`,确认事件能到达
- **逐步收紧**: 再添加具体字段匹配
- **十六进制显示**: 未知常量用 `0x%x` 显示,方便补充映射表

---

## 🔗 相关链接与下一步

**相关代码示例:**

- [`escape-detect.c`](../code/08-detection/escape-detect.c) - 容器逃逸检测C代码（三维探针：mount + ptrace + openat）
- [`escape-detect.py`](../code/08-detection/escape-detect.py) - Python加载器和事件处理
- [`detector.py`](../code/08-detection/detector.py) - YAML规则引擎
- [`rules.yaml`](../code/08-detection/rules.yaml) - 检测规则配置（包含sensitive_file_read规则）
- [`test-escape.sh`](../code/08-detection/test-escape.sh) - procfs挂载测试
- [`test-ptrace.sh`](../code/08-detection/test-ptrace.sh) - ptrace注入测试
- [`test-openat.sh`](../code/08-detection/test-openat.sh) - 敏感文件访问测试（已注释openat输出）

**学习笔记:**

- **上一篇**: [Seven、终极合体：打造容器运行时安全监控面板](./Seven、终极合体：打造容器运行时安全监控面板.md)
- **下一篇**: [Nine、主动防御：从检测到自动响应(待规划)](./Nine、主动防御：从检测到自动响应.md)

**相关文档:**

- [docker 容器环境准备](./docker%20容器环境准备.md)
- [eBPF 常用字典](./eBPFBPF%20常用字典.md)

**常见问题:**

- [FAQ](../FAQ.md) - 包含规则引擎相关问题解答
- [项目环境](./项目环境.md) - Ubuntu环境配置

---

_最后更新: 2026-05-29_
