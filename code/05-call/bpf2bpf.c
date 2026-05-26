// bpf2bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// 🔥 关键：noinline 让 clang 生成真正的函数调用
static __attribute__((noinline)) int get_pid(void) {
    return bpf_get_current_pid_tgid() >> 32;
}

SEC("kprobe/sys_execve")
int hello(struct pt_regs *ctx) {
    int pid = get_pid();  // 这里会生成 call 指令
    char fmt[] = "hello pid=%d";
    bpf_trace_printk(fmt, sizeof(fmt), pid);
    return 0;
}
