#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/sys_execve")
int hello(struct pt_regs *ctx) {
    char fmt[] = "Hello!";
    bpf_trace_printk(fmt, sizeof(fmt));
    return 0;
}
