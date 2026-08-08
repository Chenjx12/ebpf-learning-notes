// escape-detect.bpf.c — 容器逃逸检测 (libbpf 风格, clang 预编译)
// 对应蓝图选项 B: clang 预编译 .bpf.o → BCC BPF(src_file=".bpf.o") 加载
//
// 编译: clang -target bpf -O2 -g -c $< -o $@
// 加载: bpf = BPF(src_file="escape-detect.bpf.o")  # BCC 直接加载预编译 .o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EVENT_MOUNT  1
#define EVENT_PTRACE 2
#define EVENT_OPENAT 3

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

// ===== Ring Buffer =====
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// ===== PID → 容器名 映射 =====
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct container_id_t);
} container_map SEC(".maps");

// ===== 辅助函数 =====
static __always_inline void get_container_id(struct event *evt) {
    u32 pid = evt->pid;
    struct container_id_t *cid = bpf_map_lookup_elem(&container_map, &pid);
    if (cid) {
        bpf_probe_read_kernel_str(evt->container_id, sizeof(evt->container_id), cid->id);
    } else {
        evt->container_id[0] = 'h'; evt->container_id[1] = 'o';
        evt->container_id[2] = 's'; evt->container_id[3] = 't'; evt->container_id[4] = '\0';
    }
}

// ===== 探针: __x64_sys_mount =====
SEC("kprobe/__x64_sys_mount")
int BPF_KPROBE(kprobe_mount)
{
    struct event evt = {};
    evt.event_type = EVENT_MOUNT;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // mount(char *source, char *target, char *fstype, ...)
    char *fstype = (char *)PT_REGS_PARM3_CORE(ctx);
    char *target = (char *)PT_REGS_PARM2_CORE(ctx);
    bpf_probe_read_user_str(evt.fstype, sizeof(evt.fstype), fstype);
    bpf_probe_read_user_str(evt.target_path, sizeof(evt.target_path), target);

    get_container_id(&evt);
    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
    return 0;
}

// ===== 探针: __x64_sys_ptrace =====
SEC("kprobe/__x64_sys_ptrace")
int BPF_KPROBE(kprobe_ptrace)
{
    struct event evt = {};
    evt.event_type = EVENT_PTRACE;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    evt.request_raw = PT_REGS_PARM1_CORE(ctx);
    evt.target_pid = (u32)PT_REGS_PARM2_CORE(ctx);

    get_container_id(&evt);
    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
    return 0;
}

// ===== 探针: __x64_sys_openat =====
SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(kprobe_openat)
{
    struct event evt = {};
    evt.event_type = EVENT_OPENAT;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    char *filename = (char *)PT_REGS_PARM2_CORE(ctx);
    bpf_probe_read_user_str(evt.target_path, sizeof(evt.target_path), filename);

    get_container_id(&evt);
    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
