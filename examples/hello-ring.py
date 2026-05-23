#!/usr/bin/python3
"""
eBPF Ring Buffer 示例 - 全局有序的实时事件流 (推荐)

功能: 与 Perf Buffer 类似,但所有 CPU 共享一个缓冲区,保证全局有序

优势:
- 全局事件顺序保证
- 内存使用更高效
- 支持检测数据丢失

使用方法:
    sudo python3 hello-ring.py
    
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

// 声明 ring buffer (1 << 8 = 256 页 ≈ 1MB)
BPF_RINGBUF_OUTPUT(events, 8);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};
    
    // 填充字段
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.ts  = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 推送事件到 ring buffer
    // 第三个参数 flags: 0=正常提交, BPF_RB_FORCE_WAKEUP=立即唤醒
    events.ringbuf_output(&data, sizeof(data), 0);
    
    return 0;
}
"""

# 编译并加载 eBPF 程序
b = BPF(text=program)

# 挂钩到 execve 系统调用
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

# 用户态回调函数
def print_event(ctx, data, size):
    event = b["events"].event(data)
    print(f"PID={event.pid:6d} UID={event.uid:5d} COMM={event.comm.decode():16s} TS={event.ts}")

# 打开 ring buffer,注册回调
b["events"].open_ring_buffer(print_event)

print("通过 Ring Buffer 实时监控 execve 事件(全局有序),按 Ctrl-C 退出...")

# 持续轮询 ring buffer
while True:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
