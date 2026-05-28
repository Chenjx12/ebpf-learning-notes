#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

// 1. 容器身份映射表 (与第六篇一致)
struct container_info {
    char name[64];
};
BPF_HASH(container_map, u64, struct container_info);

// 2. 尾调用映射表
BPF_PROG_ARRAY(prog_array, 10);

// 3. 统一事件结构体 (用枚举区分类型)
enum event_type { EVENT_EXECVE = 1, EVENT_OPENAT = 2, EVENT_CONNECT = 3 };

struct data_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    char container_name[64];
    enum event_type type;
    
    // 联合体节省内存，每次只传一种数据
    union {
        char filename[128];     // for execve & openat
        u32 daddr;              // for connect
        u16 dport;              // for connect
    } data;
};

BPF_PERF_OUTPUT(events);

// 4. 公共函数：打容器标签
static inline void fill_container_info(struct data_t *data) {
    data->cgroup_id = bpf_get_current_cgroup_id();
    struct container_info *info = container_map.lookup(&data->cgroup_id);
    if (info) {
        bpf_probe_read_kernel_str(&data->container_name, sizeof(data->container_name), info->name);
    } else {
        char host[] = "[HOST]";
        bpf_probe_read_kernel_str(&data->container_name, sizeof(host), host);
    }
}

// 5. Entry 探针：只做分发
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.type = EVENT_EXECVE;
    // 尾调用跳转到具体处理器，索引为 1
    prog_array.call(data, 1);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.type = EVENT_OPENAT;
    prog_array.call(data, 2);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct data_t data = {};
    data.type = EVENT_CONNECT;
    prog_array.call(data, 3);
    return 0;
}

// 6. 具体处理器 (注意 BCC 的尾调用处理方式)
PROBE_INDEX(1) // 对应 execve
int handle_execve(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_EXECVE;
    fill_container_info(&data);
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.data.filename, sizeof(data.data.filename), (void *)ctx->si);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

PROBE_INDEX(2) // 对应 openat
int handle_openat(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_OPENAT;
    fill_container_info(&data);

    bpf_probe_read_user_str(&data.data.filename, sizeof(data.data.filename), (void *)ctx->si);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

PROBE_INDEX(3) // 对应 connect
int handle_connect(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.type = EVENT_CONNECT;
    fill_container_info(&data);

    struct sock *sk = (struct sock *)ctx->di;
    struct sockaddr_in *sin = (struct sockaddr_in *)ctx->si;
    
    bpf_probe_read_kernel(&data.data.daddr, sizeof(data.data.daddr), &sin->sin_addr.s_addr);
    bpf_probe_read_kernel(&data.data.dport, sizeof(data.data.dport), &sin->sin_port);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
