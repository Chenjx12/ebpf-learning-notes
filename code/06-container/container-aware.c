#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 1. 事件结构体：新增 cgroup_id
struct data_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;  //  容器的“身份证号”
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};
    
    // 2. 获取公共信息
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    
    // 3. 获取当前进程的 Cgroup ID
    data.cgroup_id = bpf_get_current_cgroup_id();
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
