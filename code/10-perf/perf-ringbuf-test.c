// perf-ringbuf-test.c — 第十篇实验1：Ring Buffer 容量测试
// 只挂 openat 探针，将所有事件发送到 Ring Buffer
#include <uapi/linux/ptrace.h>

struct event {
    u32 pid;
    char comm[16];
    char filename[128];
};

// ⚠️ RINGBUF_SIZE 通过 Python 端替换，只需改这一个数字
BPF_RINGBUF_OUTPUT(events, 1 << 8);  // 默认 256，测试时替换

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename),
                            (void *)args->filename);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}
