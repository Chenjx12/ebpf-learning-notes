// hello-buffer-config.bpf.c — eBPF 内核程序 (CO-RE / Libbpf 风格)
// 对应《Learning eBPF》第5章
//
// 用法:
//   1. 生成 vmlinux.h: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//   2. 编译: make
//   3. 运行: sudo ./hello-buffer-config

#include "vmlinux.h"               // ⚠️ 需要先运行 bpftool 生成
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>       // BPF_KPROBE_SYSCALL 宏
#include <bpf/bpf_core_read.h>     // BPF_CORE_READ / bpf_core_read
#include "hello-buffer-config.h"

// ===== Map 定义 =====

// Ring Buffer 输出 (取代 Perf Buffer, 5.8+)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} output SEC(".maps");

// 可配置消息: UID → 自定义问候语
// 用户态在加载前写入, 加载后内核态只读
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);               // UID
    __type(value, struct user_msg_t);
} my_config SEC(".maps");

// ===== 全局变量 =====

// 默认问候语 (用户态可在 open() 和 load() 之间修改)
char message[12] = "Hello World";

// ===== eBPF 程序 =====

// SEC("ksyscall/execve") — Libbpf 自动附加到 execve 系统调用
// BPF_KPROBE_SYSCALL — 架构无关的 syscall kprobe 宏
SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(hello, const char *pathname)
{
    struct data_t data = {};
    struct user_msg_t *p;

    // 获取 PID 和 UID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 获取进程名
    bpf_get_current_comm(&data.command, sizeof(data.command));

    // 安全读取用户态字符串 (execve 的路径参数)
    bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);

    // 查找该 UID 是否有自定义消息
    p = bpf_map_lookup_elem(&my_config, &data.uid);
    if (p) {
        bpf_probe_read_kernel_str(&data.message, sizeof(data.message),
                                  p->message);
    } else {
        bpf_probe_read_kernel_str(&data.message, sizeof(data.message),
                                  message);
    }

    // 通过 Ring Buffer 发送到用户态
    bpf_ringbuf_output(&output, &data, sizeof(data), 0);

    return 0;
}

// ===== 许可证 (必须) =====
char LICENSE[] SEC("license") = "Dual BSD/GPL";
