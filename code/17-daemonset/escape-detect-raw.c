// escape-detect-raw.c — 容器逃逸检测 (Raw Tracepoint 版)
// 兼容 BCC 0.18.0 + kernel 6.8
//
// 不用 TRACEPOINT_PROBE (kernel 6.8 不兼容)
// 改用 raw_syscalls/sys_enter + syscall nr 过滤

#include <uapi/linux/ptrace.h>

#define EVENT_MOUNT  1
#define EVENT_PTRACE 2
#define EVENT_OPENAT 3

#define __NR_mount  165
#define __NR_ptrace 101
#define __NR_openat 257

struct event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    char comm[16];
    char container_id[64];
    char fstype[32];
    char target_path[256];
    u32 target_pid;
    u64 request_raw;
};

struct container_id_t { char id[64]; };

BPF_RINGBUF_OUTPUT(events, 1 << 8);
BPF_HASH(container_map, u32, struct container_id_t);

static inline void get_container_id(struct event *evt) {
    u32 pid = evt->pid;
    struct container_id_t *cid = container_map.lookup(&pid);
    if (cid) {
        bpf_probe_read_kernel_str(evt->container_id, sizeof(evt->container_id), cid->id);
    } else {
        evt->container_id[0] = 'h'; evt->container_id[1] = 'o';
        evt->container_id[2] = 's'; evt->container_id[3] = 't'; evt->container_id[4] = '\0';
    }
}

// 主函数: raw_syscalls/sys_enter 覆盖所有 syscall
int sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    // ctx->args[1] 是 syscall number (long id)
    long id = ctx->args[1];
    struct event evt = {};

    if (id == __NR_mount) {
        evt.event_type = EVENT_MOUNT;
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        evt.uid = bpf_get_current_uid_gid();
        evt.cgroup_id = bpf_get_current_cgroup_id();
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        bpf_probe_read_user_str(evt.fstype, sizeof(evt.fstype), (void *)ctx->args[2]);
        bpf_probe_read_user_str(evt.target_path, sizeof(evt.target_path), (void *)ctx->args[3]);
        get_container_id(&evt);
        events.ringbuf_output(&evt, sizeof(evt), 0);

    } else if (id == __NR_ptrace) {
        evt.event_type = EVENT_PTRACE;
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        evt.uid = bpf_get_current_uid_gid();
        evt.cgroup_id = bpf_get_current_cgroup_id();
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        evt.request_raw = ctx->args[2];
        evt.target_pid = (u32)ctx->args[3];
        get_container_id(&evt);
        events.ringbuf_output(&evt, sizeof(evt), 0);

    } else if (id == __NR_openat) {
        evt.event_type = EVENT_OPENAT;
        evt.pid = bpf_get_current_pid_tgid() >> 32;
        evt.uid = bpf_get_current_uid_gid();
        evt.cgroup_id = bpf_get_current_cgroup_id();
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        bpf_probe_read_user_str(evt.target_path, sizeof(evt.target_path), (void *)ctx->args[3]);
        get_container_id(&evt);
        events.ringbuf_output(&evt, sizeof(evt), 0);
    }

    return 0;
}
