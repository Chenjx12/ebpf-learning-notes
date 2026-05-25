// hello-perf-plus.c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 定义事件结构体
struct data_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[16];       // 调用者进程名
    char filename[128];  // 被执行的程序路径
};

// 声明 perf buffer
BPF_PERF_OUTPUT(events);

// 改用 tracepoint，可以直接访问系统调用参数
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    // 填充基本信息
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 关键！从 tracepoint 参数中读取 filename
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);

    // 推送事件
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
