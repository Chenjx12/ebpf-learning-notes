// ex1_boundary.bpf.c — 练习1: 再现 NULL 指针解引用错误
// 对应《Learning eBPF》第6章: eBPF 验证器
//
// 预期: 验证器拒绝加载
// 错误: R1 type=map_value_or_null expected=map_value
//
// 修复: 添加 if (!val) return 0; 空指针检查

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
int BPF_KPROBE(ex1_boundary)
{
    u32 key = 0;

    // bpf_map_lookup_elem() 可能返回 NULL
    u64 *val = bpf_map_lookup_elem(&counters, &key);

    // ❌ 没有检查 val 是否为 NULL!
    // 验证器报错: R1 type=map_value_or_null expected=map_value
    *val = *val + 1;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
