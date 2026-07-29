// tp_custom.bpf.c — 通用 tracepoint 程序 (供练习4: 自定义 tracepoint)
// 对应《Learning eBPF》第7章
//
// 注意: SEC("tp") 没有指定具体的 category/name → 需要手动附加
//
// 用法:
//   sudo ./ex4_tracepoint tp_custom.bpf.o <category> <name>
//   例如: sudo ./ex4_tracepoint tp_custom.bpf.o sched sched_process_exec

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tp")
int custom_tp(void *ctx)
{
    bpf_printk("[custom_tp] tracepoint hit!\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
