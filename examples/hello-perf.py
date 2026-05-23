#!/usr/bin/python3
"""
eBPF Perf Buffer 示例 - 实时推送 execve 事件详情

功能: 每次 execve 触发时,将完整的事件信息(PID, UID, 进程名, 时间戳)推送到用户空间

使用方法:
    sudo python3 hello-perf.py
    
预期输出:
    PID=  4571 UID= 1000 COMM=bash             TS=8483481047509
    PID=  4572 UID= 1000 COMM=bash             TS=8492034938577
"""

from bcc import BPF

# eBPF C 程序代码
program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 定义传给用户态的结构体
struct data_t {
    u32 pid;                    // 进程 ID
    u32 uid;                    // 用户 ID
    u64 ts;                     // 时间戳(纳秒,自系统启动)
    char comm[TASK_COMM_LEN];   // 进程名(16字节)
};

// 声明 perf buffer
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    // 填充字段
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.ts  = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 推送事件到 perf buffer
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}
"""

# 编译并加载 eBPF 程序
b = BPF(text=program)

# 挂钩到 execve 系统调用
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

# 用户态回调函数:逐条处理事件
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID={event.pid:6d} UID={event.uid:5d} COMM={event.comm.decode():16s} TS={event.ts}")

# 打开 perf buffer,注册回调
b["events"].open_perf_buffer(print_event)

print("通过 Perf Buffer 实时监控 execve 事件,按 Ctrl-C 退出...")

# 持续轮询 perf buffer
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
