// hello-tail.c — eBPF 尾调用实验
// 功能：用 prog_array Map 构建 3 级程序链：entry → handler1 → handler2
// 用法：sudo python3 hello-tail.py

#include <uapi/linux/ptrace.h>

// ============================================================
// 1. 定义 prog_array map（尾调用的核心基础设施）
//    key: u32 索引
//    value: u32 程序的文件描述符
//    max_entries: 链中最多几个程序
// ============================================================
BPF_PROG_ARRAY(jmp_table, 4);

// ============================================================
// 程序 1: 入口（挂载到 kprobe/sys_execve）
// 功能：打印入口日志，尾调用到 handler1
// ============================================================
int hello_entry(struct pt_regs *ctx) {
    char fmt[] = "[ENTRY] pid=%d, entering tail call chain\n";
    bpf_trace_printk(fmt, sizeof(fmt), bpf_get_current_pid_tgid() >> 32);

    // 尾调用到索引 1（hello_handler1）
    // 成功则不返回！失败则继续执行下面的 fallback
    bpf_tail_call(ctx, &jmp_table, 1);

    char fmt_fb[] = "[FALLBACK] tail call to handler1 failed\n";
    bpf_trace_printk(fmt_fb, sizeof(fmt_fb));
    return 0;
}

// ============================================================
// 程序 2: 处理器 1
// 功能：打印处理日志，尾调用到 handler2
// ============================================================
int hello_handler1(struct pt_regs *ctx) {
    char fmt[] = "[HANDLER1] processing...\n";
    bpf_trace_printk(fmt, sizeof(fmt));

    // 继续尾调用到索引 2（hello_handler2）
    bpf_tail_call(ctx, &jmp_table, 2);

    char fmt_fb[] = "[FALLBACK] tail call to handler2 failed\n";
    bpf_trace_printk(fmt_fb, sizeof(fmt_fb));
    return 0;
}

// ============================================================
// 程序 3: 处理器 2（链的终点）
// 功能：打印结束日志，链结束
// ============================================================
int hello_handler2(struct pt_regs *ctx) {
    char fmt[] = "[HANDLER2] end of chain\n";
    bpf_trace_printk(fmt, sizeof(fmt));
    return 0;
}
