#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>

char LICENSE[] SEC("license") = "GPL";

struct data_t {
    __u32 pid;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

static __always_inline void fill_proc_info(struct data_t *data) {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    fill_proc_info(&data);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
