#!/usr/bin/python3
# simple-func.py — 观察 eBPF 函数调用的加载器
#
# 本程序演示:
#   1. 加载包含函数调用的 eBPF 程序
#   2. 用 bpftool 观察函数调用栈
#   3. 对比 inline 和非 inline 的字节码差异
#
# 用法:
#   sudo python3 simple-func.py          # 运行监控
#   sudo python3 simple-func.py --dump   # 查看字节码后退出

from bcc import BPF
import ctypes as ct
import sys
import subprocess
import os

# BCC 会自行编译 C 代码，不需要预编译 .o 文件
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

// 实验 A：__always_inline 函数（内联展开，无调用帧）
static __always_inline void fill_proc_info(struct data_t *data) {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

// 实验 B：普通 static 函数（产生 BPF-to-BPF call）
// 取消下面的注释来对比实验
#if 0
static void fill_proc_info_noinline(struct data_t *data) {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}
#endif

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    fill_proc_info(&data);

    bpf_probe_read_user_str(&data.filename, sizeof(data.filename),
                            (void *)args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

def dump_bpf_prog(prog_id):
    """用 bpftool 查看 BPF 程序字节码"""
    try:
        result = subprocess.run(
            ["sudo", "bpftool", "prog", "dump", "xlated", "id", str(prog_id)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            print(result.stdout)
        else:
            print(f"bpftool error: {result.stderr}")
    except Exception as e:
        print(f"Failed to dump prog: {e}")

def main():
    dump_only = "--dump" in sys.argv

    print("=" * 60)
    print("实验 1: eBPF 函数调用实验")
    print("=" * 60)

    # 加载 BPF 程序
    b = BPF(text=bpf_text)

    if dump_only:
        # 只打印字节码，不运行
        progs = subprocess.run(
            ["sudo", "bpftool", "prog", "list"],
            capture_output=True, text=True, timeout=5
        )
        print("当前 BPF 程序列表:")
        print(progs.stdout)
        return

    # 获取程序 ID（用 bpftool）
    progs = subprocess.run(
        ["sudo", "bpftool", "prog", "list", "--json"],
        capture_output=True, text=True, timeout=5
    )

    # 回调函数
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        print(f"[EXEC] PID={event.pid} UID={event.uid} "
              f"COMM={event.comm.decode('utf-8', 'replace')} "
              f"FILE={event.filename.decode('utf-8', 'replace')}")

    b["events"].open_perf_buffer(print_event)

    print("监控中... 在另一个终端执行命令观察输出")
    print("按 Ctrl+C 退出\n")

    try:
        while True:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n退出.")

    # 退出前打印程序 ID，方便用户用 bpftool 观察
    print("\n💡 实验结束后，可以用以下命令查看函数调用:")
    print("   sudo bpftool prog list | grep execve")
    print("   sudo bpftool prog dump xlated id <ID>")

if __name__ == "__main__":
    main()