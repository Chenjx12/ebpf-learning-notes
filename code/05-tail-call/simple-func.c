// simple-func.c — eBPF 中的函数调用实验
// 编译: clang -O2 -target bpf -c simple-func.c -o simple-func.o
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

// 辅助函数：填充进程信息
// __always_inline 强制内联，避免函数调用栈开销
static __always_inline void fill_proc_info(struct data_t *data) {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

// 辅助函数：从 args 中提取文件名
static __always_inline int extract_filename(struct pt_regs *ctx,
                                            struct data_t *data) {
    // tracepoint 的 args 是固定格式，用 bpf_probe_read 读
    // 这里简化处理，用 tracepoint 的 __data_loc 方式
    // 实际项目中需要完整解析
    return 0;  // 0 表示成功
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    // 调用辅助函数（BPF-to-BPF call）
    // 即使 __always_inline，这里也是源码级函数调用
    fill_proc_info(&data);

    // 提取可执行文件路径
    // args->filename 是 __data_loc 类型，需要特殊处理
    // 这里用简化方式：直接读用户态字符串
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename),
                            (void *)args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}