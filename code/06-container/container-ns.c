#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>        // 补全 nsproxy 结构体定义
#include <linux/pid_namespace.h>  // 补全 pid_namespace 结构体定义

// 1. 事件结构体：新增 pid_ns_inum
struct data_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    u32 pid_ns_inum;  // PID Namespace 的 Inode 号
    char comm[16];
    char filename[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct data_t data = {};

    // 获取公共信息
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() >> 32;
    data.cgroup_id = bpf_get_current_cgroup_id();

    // 通过 task_struct 深入内核获取 PID Namespace Inode
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // 第1步：读取 nsproxy 指针
    struct nsproxy *nsproxy = NULL;
    bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    if (!nsproxy) goto out;

    // 第2步：读取 pid_namespace 指针
    struct pid_namespace *pid_ns = NULL;
    bpf_probe_read_kernel(&pid_ns, sizeof(pid_ns), &nsproxy->pid_ns_for_children);
    if (!pid_ns) goto out;

    // 第3步：读取 ns.inum (Namespace 的 Inode 号)
    unsigned int inum = 0;
    bpf_probe_read_kernel(&inum, sizeof(inum), &pid_ns->ns.inum);
    data.pid_ns_inum = inum;

out:
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
