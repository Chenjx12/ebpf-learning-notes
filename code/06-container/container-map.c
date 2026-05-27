#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 容器身份信息
struct container_info {
    char name[64]; // 容器名，如 "happy_nginx"
};

// 键是 cgroup_id (u64)，值是 container_info
BPF_HASH(container_map, u64, struct container_info);

// 修改 data_t，用人类可读的名字代替长字符串
struct data_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    char container_name[64]; // 替换原来的 cgroup_id 展示
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};

    // 1. 获取公共信息
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.cgroup_id = bpf_get_current_cgroup_id();

    // 2. 查询容器身份映射表
    struct container_info *info = container_map.lookup(&data.cgroup_id);
    if (info) {
        // 查到了：打上容器名标签
        bpf_probe_read_kernel_str(&data.container_name, sizeof(data.container_name), info->name);
    } else {
        // 查不到的，就是宿主机进程
        char host[] = "[HOST]";
        bpf_probe_read_kernel_str(&data.container_name, sizeof(host), host);
    }

    // 3. 获取进程名和执行的命令
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);

    // 4. 提交事件到用户态
    events.perf_submit(args, &data, sizeof(data));

    return 0;
}
