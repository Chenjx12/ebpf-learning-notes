// simple-func.c — eBPF 中的函数调用实验
// 功能：把"获取进程信息"提取为辅助函数，演示 BPF-to-BPF 调用
// 用法：sudo python3 simple-func.py

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

// 🔥 辅助函数：填充进程信息
// __always_inline 强制内联展开，避免函数调用栈开销
static __always_inline void fill_proc_info(struct data_t *data) {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    // 调用辅助函数
    fill_proc_info(&data);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
