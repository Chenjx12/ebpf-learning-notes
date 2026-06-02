// hello-ebpf.c — Go 配套的 eBPF C 程序 (Ch10 练习1)
// 编译: clang -target bpf -O2 -g -c hello-ebpf.c -o hello-ebpf.o
//
// 然后用 Go 加载: sudo ./hello-ebpf

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/__x64_sys_execve")
int on_execve(struct pt_regs *ctx)
{
    const char msg[] = "Hello from eBPF (loaded by Go with cilium/ebpf)!";
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
