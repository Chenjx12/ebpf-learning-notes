// ex3_unbounded_loop.bpf.c — 练习3: 无界循环 (验证器拒绝)
// 对应《Learning eBPF》第6章: eBPF 验证器
//
// 预期: 验证器拒绝 ❌
// 错误: back-edge from insn X to Y (向后跳转) 或
//       BPF program is too large. Processed 1000001 insn
//
// 原因: 循环上限来自全局变量 (运行时可变)，
//       验证器无法静态确定迭代次数，拒绝加载

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 全局变量 — 用户态可以在加载前修改，验证时视为未知值
volatile int loop_limit = 100;

// 一个简单的 Hash Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} counters SEC(".maps");

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(ex3_unbounded_loop)
{
    u64 *val;

    // ❌ 无界循环 — loop_limit 是变量，验证器无法静态确定上限
    // 验证器尝试逐次展开 → 超过 1M 指令限制 → 拒绝
    for (int i = 0; i < loop_limit; i++) {
        u32 key = i;
        val = bpf_map_lookup_elem(&counters, &key);
        if (val) {
            *val += 1;  // 简单操作, 仅用于展示循环
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
