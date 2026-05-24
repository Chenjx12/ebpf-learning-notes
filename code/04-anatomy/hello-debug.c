// hello-debug.c - 用于测试手动编译的eBPF程序
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

// 定义许可证(必须的)
char LICENSE[] SEC("license") = "GPL";

// eBPF程序入口点
SEC("kprobe/sys_execve")
int hello(struct pt_regs *ctx) {
    // bpf_trace_printk 需要 fmt 和 fmt_size 两个参数
    char fmt[] = "Hello from manual clang compile!";
    bpf_trace_printk(fmt, sizeof(fmt));
    return 0;
}
