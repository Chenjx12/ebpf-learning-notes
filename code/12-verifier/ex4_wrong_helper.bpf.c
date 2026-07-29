// ex4_wrong_helper.bpf.c — 练习4: 跨程序类型调用 helper (验证器拒绝)
// 对应《Learning eBPF》第6章: eBPF 验证器
//
// 预期: 验证器拒绝 ❌
// 错误: unknown func bpf_xdp_adjust_head#XX
//
// 原因: 每个 BPF 程序类型有允许使用的 helper 函数白名单
//       bpf_xdp_adjust_head 只允许 XDP 程序使用
//       kprobe 程序不在白名单中 → 验证器拒绝
//
// 扩展: 可以通过 /sys/kernel/debug/bpf/bpf_prog_type_helper_whitelist
//       查看各程序类型允许的 helper 列表 (需挂载 debugfs)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(ex4_wrong_helper)
{
    // ❌ bpf_xdp_adjust_head 是 XDP 程序的专属 helper
    // kprobe 程序调用它 → 验证器: "unknown func bpf_xdp_adjust_head#XX"
    //
    // 类似的常见错误:
    //   - XDP 程序调用 bpf_get_current_pid_tgid() (tracing only)
    //   - socket 程序调用 bpf_probe_read_kernel() (tracing only)
    //   - tracing 程序调用 bpf_skb_load_bytes() (socket only)
    bpf_xdp_adjust_head((struct xdp_md *)ctx, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
