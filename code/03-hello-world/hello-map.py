#!/usr/bin/python3
"""
eBPF Hash Map 示例 - 按 UID 统计 execve 调用次数

功能: 在内核中维护一个 uid -> count 的哈希表,每2秒轮询一次并打印结果

使用方法:
    sudo python3 hello-map.py
    
预期输出:
    ID 1000: 8        ← UID 1000 执行了 8 次 execve
    ID 1000: 14       ← 2秒后变成 14 次
    ID 1000: 16  ID 0: 1   ← 出现 root (UID 0)
"""

from bcc import BPF
from time import sleep

# eBPF C 程序代码
program = r"""
BPF_HASH(counter_table);  // 定义一个哈希表 map

int hello(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    // 获取当前用户 ID
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // 在 map 中查找该 UID 的计数
    p = counter_table.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }
    
    // 计数 +1 并写回 map
    counter++;
    counter_table.update(&uid, &counter);
    
    return 0;
}
"""

# 编译并加载 eBPF 程序
b = BPF(text=program)

# 挂钩到 execve 系统调用
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

print("开始监控 execve 调用,每 2 秒输出一次各 UID 的执行次数...")
print("按 Ctrl-C 退出\n")

# 持续轮询并打印统计结果
while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
