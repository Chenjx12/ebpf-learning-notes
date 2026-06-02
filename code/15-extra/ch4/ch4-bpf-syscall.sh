#!/bin/bash
# ch4-bpf-syscall.sh — Ch4 练习: bpf() 系统调用 + bpftool pin/link
# 运行方式: bash ch4-bpf-syscall.sh

set -e
echo "===== Ch4 练习: bpf() 系统调用 ====="
echo ""

echo "--- 练习1: insn_cnt 验证 ---"
echo "# 1. 加载一个 eBPF 程序"
echo "# 2. bpftool prog dump xlated id <ID> | wc -l  (数指令数)"
echo "# 3. strace -e bpf 运行程序, 找 BPF_PROG_LOAD 的 insn_cnt"
echo "# 4. 两者应该匹配"
echo ""

echo "--- 练习2: 同名 map 两个实例 ---"
echo "# 运行两个 hello-buffer-config 实例"
echo "# bpftool map dump name config  → 看到两个不同的 map"
echo "# strace -e bpf ./hello-buffer-config 2>&1 | grep BPF_MAP_CREATE"
echo ""

echo "--- 练习3: bpftool map update 热修改 ---"
echo "# 运行时修改 config map"
echo "  sudo bpftool map update name my_config key 0 0 0 0 value 'Hi root'"
echo "# 用不同用户验证"
echo "  sudo -u nobody ls  # 观察消息变化"
echo ""

echo "--- 练习4: bpftool pin ---"
echo "# 固定程序到 BPF 文件系统"
echo "  sudo bpftool prog pin name hello /sys/fs/bpf/hi"
echo "# 退出程序后验证"
echo "  sudo bpftool prog list | grep hello  # 仍在!"
echo "# 清理"
echo "  sudo rm /sys/fs/bpf/hi"
echo ""

echo "--- 练习5: RAW_TRACEPOINT + strace ---"
echo "# 用 RAW_TRACEPOINT_PROBE(sys_enter) 转换 hello-buffer-config.py"
echo "# strace 观察:"
echo "  sudo strace -e bpf python3 hello-buffer-config.py 2>&1 | grep RAW_TRACEPOINT"
echo ""

echo "--- 练习6: opensnoop + bpftool link ---"
echo "# 启动 opensnoop"
echo "  cd /usr/share/bcc/tools && sudo ./opensnoop-bpfcc"
echo "# 另一终端:"
echo "  sudo bpftool link list"
echo "  sudo bpftool prog list | grep opensnoop"
echo ""

echo "--- 练习7: bpftool link pin ---"
echo "# 固定 link"
echo "  sudo bpftool link pin id <ID> /sys/fs/bpf/mylink"
echo "# 终止 opensnoop, link 和程序仍在内核中"
echo "# 清理"
echo "  sudo rm /sys/fs/bpf/mylink"
echo ""

echo "--- 练习8: Libbpf BPF_LINK_CREATE ---"
echo "# 用 Ch5 的 libbpf 版程序"
echo "  cd ../../11-libbpf && make && sudo strace -e bpf ./hello-buffer-config 2>&1 | grep LINK_CREATE"
echo ""

echo "===== 完成 ====="
