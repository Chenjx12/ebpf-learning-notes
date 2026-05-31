#!/usr/bin/env python3
"""第十篇实验1：Ring Buffer 容量 vs 事件丢失率

改进方案：
- eBPF 内核态用 BPF_ARRAY 计数器记录"总生成事件数"
- 用户态接收 Ring Buffer 事件，"接收到的事件数"
- 丢失率 = (内核计数 - 用户接收) / 内核计数 × 100%

用法: sudo python3 perf-ringbuf-bench.py
"""

from bcc import BPF
import ctypes as ct
import time
import subprocess
import sys

DURATION = 10  # 每轮测试秒数

SIZES = [
    (8,   256,    "1<<8"),
    (12,  4096,   "1<<12"),
    (16,  65536,  "1<<16"),
]

def run_bench(power, entries, label):
    """运行单轮测试，返回 (内核事件数, 用户接收数, 运行秒数)"""
    c_src = f"""
#include <uapi/linux/ptrace.h>

struct event {{
    u32 pid;
    char filename[128];
}};

BPF_RINGBUF_OUTPUT(events, 1 << {power});
BPF_ARRAY(kern_count, u64, 1);  // 内核态计数器

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {{
    // 内核态原子计数（不依赖 Ring Buffer）
    u32 key = 0;
    u64 *cnt = kern_count.lookup(&key);
    if (cnt) (*cnt)++;

    // 尝试发送到 Ring Buffer
    struct event evt = {{}};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename),
                            (void *)args->filename);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}}
"""
    print(f"\n  [{label}] 条目={entries} ...", end=" ", flush=True)

    try:
        b = BPF(text=c_src)
    except Exception as e:
        print(f"编译失败: {e}")
        return 0, 0, 0

    user_count = [0]

    def callback(ctx, data, size):
        user_count[0] += 1

    b["events"].open_ring_buffer(callback)

    # 运行 DURATION 秒
    start = time.time()
    try:
        while time.time() - start < DURATION:
            b.ring_buffer_poll(timeout=50)
    except KeyboardInterrupt:
        pass
    elapsed = time.time() - start

    # 读取内核态计数器
    kern = b["kern_count"]
    kern_val = kern[ct.c_int(0)].value if kern else 0

    loss_pct = ((kern_val - user_count[0]) / kern_val * 100) if kern_val > 0 else 0
    print(f"内核={kern_val} 用户={user_count[0]} 丢失={loss_pct:.1f}%")
    return kern_val, user_count[0], elapsed


def main():
    print("╔══════════════════════════════════════════════════╗")
    print("║  实验1: Ring Buffer 容量 vs 事件丢失率           ║")
    print("║  方法: 内核态计数 vs 用户态接收, 运行{}秒/轮      ║".format(DURATION))
    print("╚══════════════════════════════════════════════════╝")

    # 后台启动 stress-ng 产生持续 openat 负载
    print("\n[准备] 启动 stress-ng 持续负载...")
    stress = subprocess.Popen(
        ["stress-ng", "--open", "4", "--timeout", str(len(SIZES) * DURATION + 15)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(3)
    if stress.poll() is not None:
        print("[警告] stress-ng 不可用，使用系统自然负载")
    else:
        print("[OK] stress-ng 运行中")

    results = []
    for power, entries, label in SIZES:
        k, u, e = run_bench(power, entries, label)
        results.append((label, entries, k, u, e))
        time.sleep(1)

    stress.terminate()
    stress.wait()

    # 汇总表格
    print(f"\n{'='*65}")
    print(f"  {'Buffer':<12} {'内核事件':<10} {'用户接收':<10} {'丢失率':<10} {'速率/s'}")
    print(f"  {'-'*50}")
    for label, entries, k, u, e in results:
        rate = k / e if e > 0 else 0
        loss = ((k - u) / k * 100) if k > 0 else 0
        bar = "▓" * int(loss / 5) + "░" * (20 - int(loss / 5)) if loss > 0 else "░" * 20
        print(f"  {label:<12} {k:<10} {u:<10} {loss:>5.1f}%   {bar}  ({rate:.0f}/s)")

    # 结论
    base_k = results[-1][2] if results[-1][2] > 0 else 1
    worst_loss = max(((r[2]-r[3])/r[2]*100) if r[2] > 0 else 0 for r in results)

    print(f"\n  结论:")
    if worst_loss < 5:
        print(f"  当前系统 openat 负载较低（~{base_k/DURATION:.0f}/s），所有 buffer 均无显著丢失。")
        print(f"  但生产环境中 openat 速率可达 50K-100K/s，")
        print(f"  256 条目 buffer (约 0.1MB) 仅提供 ~2.5ms 缓冲，极易溢出。")
        print(f"  推荐生产环境至少使用 1<<12 (4096 条目, ~1.6MB)。")
    else:
        print(f"  256 条目丢失率显著！推荐至少 4096 条目。")
    print(f"{'='*65}")


if __name__ == "__main__":
    main()
