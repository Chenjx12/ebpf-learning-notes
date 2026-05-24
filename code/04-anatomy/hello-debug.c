// hello-debug.c - 用于测试手动编译的eBPF程序
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// 定义许可证(必须的)
char LICENSE[] SEC("license") = "GPL";

// eBPF程序入口点
SEC("kprobe/sys_execve")
int hello(struct pt_regs *ctx) {
    bpf_trace_printk("Hello from manual clang compile!");
    return 0;
}
