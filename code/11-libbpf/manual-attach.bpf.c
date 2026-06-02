// manual-attach.bpf.c — 练习6: 演示自定义 SEC() + 手动附加
// 与 hello-buffer-config.bpf.c 功能相同, 但 SEC() 改为自定义名称
// 用户态需要通过 bpf_program__attach_kprobe() 显式附加

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hello-buffer-config.h"

// ===== Map 定义 (同 hello-buffer-config.bpf.c) =====

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} output SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct user_msg_t);
} my_config SEC(".maps");

char message[12] = "Hello World";

// ===== ⚠️ 关键改动: 自定义 SEC() 名称 =====
// 正常写法: SEC("ksyscall/execve") — Libbpf 自动识别并附加
// 练习写法: SEC("custom_ksyscall")  — Libbpf 无法识别, 需手动附加
SEC("custom_ksyscall")
int BPF_KPROBE_SYSCALL(hello, const char *pathname)
{
    struct data_t data = {};
    struct user_msg_t *p;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);

    p = bpf_map_lookup_elem(&my_config, &data.uid);
    if (p) {
        bpf_probe_read_kernel_str(&data.message, sizeof(data.message),
                                  p->message);
    } else {
        bpf_probe_read_kernel_str(&data.message, sizeof(data.message),
                                  message);
    }

    bpf_ringbuf_output(&output, &data, sizeof(data), 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
