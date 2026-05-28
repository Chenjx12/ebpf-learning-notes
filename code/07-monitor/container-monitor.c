#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

// 1. 容器身份映射表 (与第六篇一致)
struct container_info {
    char name[64];
};
BPF_HASH(container_map, u64, struct container_info);

// 2. 统一事件结构体 (用枚举区分类型)
enum event_type {
    EVENT_EXECVE = 1,
    EVENT_OPENAT = 2,
    EVENT_CONNECT = 3
};

struct data_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    char container_name[64];
    enum event_type type;
    char comm[16];
    // 联合体节省内存，每次只传一种数据
    union {
        char filename[128]; // for execve & openat
        u32 daddr;          // for connect
        u16 dport;          // for connect
    } data;
};

BPF_PERF_OUTPUT(events);

// 3. 公共函数：打容器标签
static inline void fill_container_info(struct data_t *data)
{
    data->cgroup_id = bpf_get_current_cgroup_id();
    struct container_info *info = container_map.lookup(&data->cgroup_id);
    if (info) {
        bpf_probe_read_kernel_str(&data->container_name, sizeof(data->container_name), info->name);
    } else {
        char host[] = "[HOST]";
        bpf_probe_read_kernel_str(&data->container_name, sizeof(host), host);
    }
}

// ========================================================
// 4. 平铺版：直接在探针里处理逻辑，不用尾调用！
// ========================================================

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_EXECVE;
    fill_container_info(&data);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // HOST execve 保留（低频，安全相关）
    // 容器 execve 也保留

    bpf_probe_read_user_str(&data.data.filename, sizeof(data.data.filename), (void *)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_OPENAT;
    fill_container_info(&data);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 内核态过滤：HOST 的 openat 直接丢弃！
    // HOST openat 每秒数万次，是 Perf Buffer 溢出的元凶
    // container_name[0]=='[' 说明是 "[HOST]"，不是容器名
    if (data.container_name[0] == '[') {
        return 0;
    }

    bpf_probe_read_user_str(&data.data.filename, sizeof(data.data.filename), (void *)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_CONNECT;
    fill_container_info(&data);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 内核态过滤：HOST 的 connect 也直接丢弃！
    if (data.container_name[0] == '[') {
        return 0;
    }

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), (void *)args->uservaddr);
    data.data.daddr = sin.sin_addr.s_addr;
    data.data.dport = sin.sin_port;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

