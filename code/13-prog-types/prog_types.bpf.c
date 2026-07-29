// prog_types.bpf.c — 多程序类型演示
// 对应《Learning eBPF》第7章: eBPF 程序类型与附加点
//
// 包含 3 种不同类型的 eBPF 程序:
//   1. kprobe    — 内核函数入口探测
//   2. tracepoint — 经典 tracepoint (自动附加)
//   3. tp (raw tracepoint) — 原始 tracepoint (更高性能)
//
// 用途: 用 ex1_list 查看每个程序的类型; 用 ex2_selective 只加载其中一个

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ===== 程序 1: Kprobe =====
// SEC("kprobe/<func>") → BPF_PROG_TYPE_KPROBE, 自动附加
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(kprobe_openat)
{
    bpf_printk("[kprobe] do_sys_openat2 called\n");
    return 0;
}

// ===== 程序 2: Classic Tracepoint =====
// SEC("tracepoint/<category>/<name>") → BPF_PROG_TYPE_TRACEPOINT, 自动附加
// tracepoint 上下文必须声明 struct trace_event_raw_<name> * 类型参数
SEC("tracepoint/sched/sched_process_exec")
int tracepoint_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    bpf_printk("[tracepoint] sched_process_exec fired\n");
    return 0;
}

// ===== 程序 3: Raw Tracepoint =====
// SEC("tp/<category>/<name>") → BPF_PROG_TYPE_RAW_TRACEPOINT
// 比 classic tracepoint 更快 (跳过公共字段), 但需要手动处理上下文
SEC("tp/syscalls/sys_enter_openat")
int raw_tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    // ctx->args[0] = dfd, ctx->args[1] = filename pointer
    bpf_printk("[raw_tp] sys_enter_openat called, dfd=%ld\n", ctx->args[0]);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
