#ifndef __COMMON_H
#define __COMMON_H

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 通用事件结构体
struct common_event {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[16];
};

// 提取公共信息的宏
#define EXTRACT_COMMON_INFO(event) do { \
    (event).pid = bpf_get_current_pid_tgid() >> 32; \
    (event).uid = bpf_get_current_uid_gid() >> 32; \
    (event).ts = bpf_ktime_get_ns(); \
    bpf_get_current_comm(&(event).comm, sizeof((event).comm)); \
} while(0)

#endif
