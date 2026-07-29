// ex2_bounded_loop.bpf.c — 练习2: 有界循环 (验证器通过)
// 对应《Learning eBPF》第6章: eBPF 验证器
//
// 预期: 验证器接受 ✅
// 关键: 循环次数是编译时常量 (10)，验证器可以静态展开分析
//
// 在验证器日志中可以观察到:
//   - 每次迭代都进入新状态 (last_idx/first_idx 模式)
//   - 循环变量 i 的值范围被精确追踪 [0, 9]
//   - 10 次迭代后验证器剪枝，确认所有路径都到达 return

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 一个简单的 Hash Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} counters SEC(".maps");

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(ex2_bounded_loop)
{
    u64 *val, *prev = NULL;
    u32 total = 0;

    // ✅ 有界循环 — 验证器可以静态确定迭代次数
    // i < 10 是编译时常量, 验证器逐次展开分析
    for (int i = 0; i < 10; i++) {
        u32 key = i;
        val = bpf_map_lookup_elem(&counters, &key);
        if (val) {
            total += *val;
            prev = val;
        }
    }

    // 使用 total 避免编译器优化掉整个循环
    if (prev)
        *prev = total;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
