#!/usr/bin/env python3
""" 
容器逃逸检测与主动防御系统 - 基于eBPF 
对应笔记: Nine、主动防御:从检测到自动响应 
"""
from bcc import BPF
import ctypes as ct
import docker
import os
import time
import sys

from detector import EscapeDetector, print_alert
from responder import ResponseEngine

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
    0x4206: "PTRACE_SECCOMP_GET_METADATA",
    0x420e: "PTRACE_GET_SYSCALL_INFO",
    0x1000: "PTRACE_SEIZE",
    0x1001: "PTRACE_INTERRUPT",
    0x1002: "PTRACE_LISTEN",
}


class ContainerEscapeMonitor:
    """容器逃逸监控与主动防御系统"""
    
    def __init__(self, rules_file='rules.yaml', responses_file='responses.yaml'):
        # 初始化eBPF程序
        print("[1] 编译并加载eBPF程序...")
        self.bpf = BPF(src_file="escape-detect.c")
        
        # 初始化检测引擎
        print("[2] 加载检测规则...")
        self.detector = EscapeDetector(rules_file)
        
        # 🆕 初始化响应引擎
        print("[3] 加载响应策略...")
        self.responder = ResponseEngine(responses_file)
        
        # 初始化Docker客户端
        print("[4] 连接Docker守护进程...")
        try:
            self.docker_client = docker.from_env()
        except docker.errors.DockerException as e:
            print(f"[!] Docker连接失败: {e}", file=sys.stderr)
            sys.exit(1)
        
        # 初始化容器映射
        print("[5] 初始化容器ID映射...")
        self.update_container_map()
        self._build_cgroup_map()
        print("\n[✓] 容器逃逸检测与主动防御系统启动成功!")
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
    
    def _resolve_by_cgroup(self, pid):
        """通过 /proc/<pid>/cgroup 反查 Docker 容器短 ID（进程存活时可用）"""
        try:
            with open(f"/proc/{pid}/cgroup", 'r') as f:
                for line in f:
                    if 'docker-' in line and '.scope' in line:
                        start = line.index('docker-') + 7
                        end = line.index('.scope', start)
                        return line[start:end][:12]
        except (FileNotFoundError, PermissionError, ValueError):
            pass
        return 'host'

    def _build_cgroup_map(self):
        """构建 cgroup_inode → container_short_id 映射（内核态记录的 cgroup_id 用）"""
        self.cgroup_map = {}
        try:
            for c in self.docker_client.containers.list():
                cgroup_path = f"/sys/fs/cgroup/system.slice/docker-{c.id}.scope"
                if os.path.exists(cgroup_path):
                    inode = os.stat(cgroup_path).st_ino
                    self.cgroup_map[inode] = c.id[:12]
        except Exception as e:
            print(f"[!] cgroup 映射构建失败: {e}", file=sys.stderr)

    def handle_event(self, cpu, data, size):
        """处理从eBPF捕获的事件"""
        try:
            event = self.bpf['events'].event(data)
            
            # 转换为字典格式
            event_type_map = {1: 'mount', 2: 'ptrace', 3: 'openat'}
            raw_cid = event.container_id.decode('utf-8', errors='replace').rstrip('\x00')
            event_pid = event.pid
            event_cgid = event.cgroup_id  # eBPF 内核态记录的 cgroup inode

            # 当 PID 映射表未命中时，用 eBPF 记录的 cgroup_id 反查容器 ID
            # cgroup_id 在内核态采集，不存在 /proc 竞态问题
            if raw_cid in ('host', '', 'unknown'):
                if event_cgid in getattr(self, 'cgroup_map', {}):
                    raw_cid = self.cgroup_map[event_cgid]
                elif event_pid > 0:
                    # 最后兜底：尝试 /proc（仅进程仍存活时有效）
                    raw_cid = self._resolve_by_cgroup(event_pid)

            event_dict = {
                'event_type': event_type_map.get(event.event_type, 'unknown'),
                'pid': event_pid,
                'uid': event.uid,
                'comm': event.comm.decode('utf-8', errors='replace'),
                'container_id': raw_cid,
                'timestamp': time.time()
            }
            
            # 根据事件类型添加特定字段
            if event.event_type == 1:  # MOUNT
                event_dict['fstype'] = event.fstype.decode('utf-8', errors='replace').rstrip('\x00')
                event_dict['target_path'] = event.target_path.decode('utf-8', errors='replace').rstrip('\x00')
            elif event.event_type == 2:  # PTRACE
                event_dict['target_pid'] = event.target_pid
                request_val = event.request_raw
                mapped_req = PTRACE_MAP.get(request_val, PTRACE_MAP.get(request_val & 0xFFFFFFFF))
                event_dict['request'] = mapped_req if mapped_req else f"UNKNOWN(0x{request_val:x})"
            elif event.event_type == 3:  # OPENAT
                event_dict['target_path'] = event.target_path.decode('utf-8', errors='replace').rstrip('\x00')
            
            # 🆕 检测 + 响应闭环
            matched_rules = self.detector.check_event(event_dict)
            if matched_rules:
                for rule in matched_rules:
                    alert = self.detector.generate_alert(rule, event_dict)
                    print_alert(alert)
                    
                    # 🔥 关键新增:自动执行响应动作
                    self.responder.handle_alert(alert)
            else:
                # 正常事件,绿色输出
                if event_dict['event_type'] == 'ptrace':
                    print(f"\033[92m[INFO] {event_dict['event_type']} - PID:{event_dict['pid']} Comm:{event_dict['comm']} CID:{event_dict['container_id']} Req:{event_dict['request']} Target:{event_dict['target_pid']}\033[0m")
                elif event_dict['event_type'] == 'mount':
                    print(f"\033[92m[INFO] {event_dict['event_type']} - PID:{event_dict['pid']} Comm:{event_dict['comm']} CID:{event_dict['container_id']} FS:{event_dict['fstype']} Path:{event_dict['target_path']}\033[0m")
                elif event_dict['event_type'] == 'openat':
                    # ⚠️ openat 是高频调用，正常事件不打印，避免淹没终端
                    # 只有命中规则时才会通过 print_alert 输出红色告警
                    pass
                    
        except Exception as e:
            print(f"[ERROR] 处理事件异常: {e}", file=sys.stderr)
    
    def run(self):
        """运行监控系统"""
        self.bpf['events'].open_ring_buffer(self.handle_event)
        
        try:
            while True:
                self.bpf.ring_buffer_poll()
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[i] 停止监控")


def main():
    """主函数"""
    import argparse
    parser = argparse.ArgumentParser(description='容器逃逸检测与主动防御系统')
    parser.add_argument('-r', '--rules', default='rules.yaml', help='规则文件路径')
    parser.add_argument('-s', '--responses', default='responses.yaml', help='响应策略文件路径')
    args = parser.parse_args()
    
    # 创建监控器实例
    monitor = ContainerEscapeMonitor(args.rules, args.responses)
    
    # 运行监控
    monitor.run()


if __name__ == "__main__":
    main()
