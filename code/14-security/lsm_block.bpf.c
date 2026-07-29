// lsm_block.bpf.c — BPF LSM 阻断实验
// 对应《Learning eBPF》第9章: 用于安全的 eBPF
//
// 核心原理:
//   LSM hook 在参数已复制到内核内存后、操作执行前触发
//   与 tracepoint 的本质区别: LSM 无 TOCTOU 风险 + 可以阻断
//
//   Tracepoint: 参数在用户态 → TOCTOU → 只能检测
//   LSM hook:   参数已在内核态 → 无 TOCTOU → 可以阻断
//
// 用法:
//   sudo ./ex1_lsm lsm_block.bpf.o
//   然后新终端测试: chmod 777 /tmp/test → Permission denied
//
// 要求: 内核 ≥ 5.7, CONFIG_BPF_LSM=y

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// ===== 任务1: LSM 阻断 path_chmod =====
// 返回 -EPERM = 拒绝所有 chmod 操作
// 注意: 加载后连 sudo chmod 都会被拒绝, 卸载前无法修改文件权限

SEC("lsm/path_chmod")
int BPF_PROG(block_chmod, struct path *path, umode_t mode)
{
    // 返回非零值 = 拒绝该操作
    // -EPERM (-1): Operation not permitted
    // 内核会将此返回值视为"拒绝", 但不会返回给用户态
    return -1;  // -EPERM
}

// ===== 可选扩展: 更精细的策略 =====
// 下面是条件阻断的参考写法 (取消注释并注释掉上面的无条件阻断即可):
//
// SEC("lsm/path_chmod")
// int BPF_PROG(block_chmod_conditional, struct path *path, umode_t mode)
// {
//     // 只拒绝 SUID 位设置 (mode 的 04000/02000 位)
//     if (mode & 06000)
//         return -1;  // -EPERM
//
//     // 只拒绝特定 UID 的操作
//     u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//     if (uid == 1000)
//         return -1;  // -EPERM
//
//     return 0; // 允许
// }
