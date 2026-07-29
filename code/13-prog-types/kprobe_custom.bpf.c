// kprobe_custom.bpf.c — 通用 kprobe 程序 (供练习3: 手动附加)
// 对应《Learning eBPF》第7章
//
// 注意: SEC("kprobe") 没有指定具体函数 → libbpf 不会自动附加
//       需要用 bpf_program__attach_kprobe() 手动指定目标函数
//
// 用法:
//   sudo ./ex3_kprobe kprobe_custom.bpf.o <内核函数名>
//   例如: sudo ./ex3_kprobe kprobe_custom.bpf.o do_sys_openat2

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe")
int BPF_KPROBE(custom_kprobe)
{
    bpf_printk("[custom_kprobe] hit!\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
