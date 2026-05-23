#!/usr/bin/python3
"""
eBPF Tracepoint 示例 - 获取被执行的完整命令路径

功能: 使用 tracepoint 而非 kprobe,可以直接访问系统调用参数,获取 execve 的 filename

关键改进:
- 使用 TRACEPOINT_PROBE 宏(BCC自动挂钩)
- 从 args->filename 读取被执行的程序路径
- 区分"谁发起的"(comm)和"执行了什么"(filename)

使用方法:
    sudo python3 hello-perf-plus.py
    
预期输出:
    PID=  4762 UID= 1000 CALLER=bash             → CMD=/usr/bin/ls
    PID=  4766 UID= 1000 CALLER=bash             → CMD=/usr/bin/sudo
"""

from bcc import BPF

# eBPF C 程序代码
program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 定义事件结构体
struct data_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[16];          // 调用者进程名
    char filename[128];     // 被执行的程序路径
};

// 声明 perf buffer
BPF_PERF_OUTPUT(events);

// 改用 tracepoint,可以直接访问系统调用参数
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    // 填充基本信息
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.ts  = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 关键!从 tracepoint 参数中读取 filename
    // args 是 tracepoint 给的参数结构体,包含 execve 的所有入参
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), 
                            (void *)args->filename);

    // 推送事件
    events.perf_submit(args, &data, sizeof(data));
    
    return 0;
}
"""

# 编译并加载 eBPF 程序
# 注意: tracepoint 不需要手动 attach!
# BCC 看到 TRACEPOINT_PROBE 宏会自动帮你挂好
b = BPF(text=program)

# 用户态回调函数
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID={event.pid:6d} UID={event.uid:5d} "
          f"CALLER={event.comm.decode():16s} → "
          f"CMD={event.filename.decode()}")

# 打开 perf buffer
b["events"].open_perf_buffer(print_event)

print("通过 Tracepoint 监控 execve,显示完整命令路径,按 Ctrl-C 退出...")
print("\n示例:")
print("  ls        → CALLER=bash   → CMD=/usr/bin/ls")
print("  sudo su   → CALLER=bash   → CMD=/usr/bin/sudo")
print("            → CALLER=sudo   → CMD=/usr/bin/su\n")

# 持续轮询
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
