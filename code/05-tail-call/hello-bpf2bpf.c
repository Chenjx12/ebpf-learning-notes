// hello-bpf2bpf.c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(events);

// ✅ 用 __always_inline 替代 noinline
// BCC 会内联它，但代码组织上仍然是"函数"
static __always_inline void get_common_info(struct data_t *data) {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() >> 32;
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    
    get_common_info(&data);
    
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

