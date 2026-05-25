// hello-tail.c — eBPF 尾调用实验
//
// 本程序演示:
//   1. 用 BPF_MAP_TYPE_PROG_ARRAY 实现尾调用
//   2. 程序链：entry -> handler1 -> handler2
//   3. fallback 降级机制
//
// 编译: clang -O2 -target bpf -c hello-tail.c -o hello-tail.o

#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ============================================================
// 1. 定义 prog_array map（尾调用的核心）
//    key: u32 索引
//    value: u32 fd（程序文件描述符）
//    max_entries: 链中最多几个程序
// ============================================================
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

// ============================================================
// 2. 共享数据 map（tail call 之间传递数据）
// ============================================================
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} shared_data SEC(".maps");

// ============================================================
// 3. 许可证
// ============================================================
char LICENSE[] SEC("license") = "GPL";

// ============================================================
// 程序 1: 入口 (entry)
// 挂载点: kprobe/sys_execve
// 功能: 收集基本信息，分派到处理程序
// ============================================================
SEC("kprobe/sys_execve")
int hello_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u32 key = 0;

    bpf_trace_printk("[ENTRY] pid=%u, entering tail call chain\\n",
                     pid >> 32);

    // 保存 pid 到共享 map，给后续程序用
    bpf_map_update_elem(&shared_data, &key, &pid, BPF_ANY);

    // 尾调用到索引 1（hello_handler1）
    // 关键: bpf_tail_call 成功则不返回！
    bpf_tail_call(ctx, &jmp_table, 1);

    // 如果执行到这里，说明尾调用失败（handler1 未加载）
    bpf_trace_printk("[FALLBACK] tail call to handler1 failed\\n");

    return 0;
}

// ============================================================
// 程序 2: 处理器 1 (handler1)
// 功能: 进程信息处理，继续尾调用
// ============================================================
SEC("kprobe/sys_execve")
int hello_handler1(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    char comm[16] = {};
    u32 key = 0;

    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_trace_printk("[HANDLER1] pid=%u comm=%s processing...\\n",
                     pid >> 32, comm);

    // 继续尾调用到索引 2（hello_handler2）
    bpf_tail_call(ctx, &jmp_table, 2);

    // 如果 handler2 未加载，走降级
    bpf_trace_printk("[HANDLER1] no handler2, completing\\n");
    return 0;
}

// ============================================================
// 程序 3: 处理器 2 (handler2)
// 功能: 最终处理，链结束
// ============================================================
SEC("kprobe/sys_execve")
int hello_handler2(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    char comm[16] = {};
    u32 key = 0;

    bpf_get_current_comm(&comm, sizeof(comm));
    u64 *shared_pid = bpf_map_lookup_elem(&shared_data, &key);

    bpf_trace_printk("[HANDLER2] pid=%u comm=%s end of chain\\n",
                     pid >> 32, comm);

    if (shared_pid) {
        bpf_trace_printk("[HANDLER2] entry saved pid=%u\\n",
                         (u32)(*shared_pid >> 32));
    }

    return 0;
}

// ============================================================
// 程序 4: 降级处理器 (fallback)
// 当主链出问题时使用
// ============================================================
SEC("kprobe/sys_execve")
int hello_fallback(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();

    bpf_trace_printk("[FALLBACK] pid=%u basic monitoring only\\n",
                     pid >> 32);
    return 0;
}