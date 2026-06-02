#!/bin/bash
# ch3-bpftool.sh — Ch3 练习: eBPF 程序剖析 (bpftool 实操)
# 运行方式: bash ch3-bpftool.sh

set -e
echo "===== Ch3 练习: bpftool 实操 ====="
echo ""

# 练习1: ip link 附加/卸载 XDP
echo "--- 练习1: ip link 附加 XDP ---"
echo "# 附加 (需 XDP 目标文件)"
echo "  sudo ip link set dev eth0 xdp obj hello.bpf.o sec xdp"
echo "# 查看附加状态"
echo "  ip link show eth0"
echo "# 卸载"
echo "  sudo ip link set dev eth0 xdp off"
echo ""

# 练习2: bpftool 检查运行中程序
echo "--- 练习2: bpftool 检查运行中程序 ---"
echo "# 列出所有加载的 eBPF 程序"
echo "  sudo bpftool prog list"
echo ""
echo "# 转储翻译后的字节码 (xlated)"
echo "  sudo bpftool prog dump xlated name hello"
echo ""
echo "# 转储 JIT 编译后的机器码 (jited)"
echo "  sudo bpftool prog dump jited name hello"
echo ""

# 练习3: 检查 tail call 程序
echo "--- 练习3: bpftool 检查 tail call ---"
echo "# 查看每个 tail call 程序"
echo "  sudo bpftool prog list | grep -A2 hello"
echo ""
echo "# 比较 xlated 字节码与 BPF-to-BPF 调用的差异"
echo "  sudo bpftool prog dump xlated id <prog_id>"
echo ""

# 练习4: XDP_ABORTED
echo "--- 练习4: XDP_ABORTED 的危险 ---"
echo "⚠️  XDP 返回 0 = XDP_ABORTED = 丢弃所有包"
echo "⚠️  不要附加到 eth0! 建议在容器中测试"
echo "  参考: https://github.com/lizrice/learning-ebpf"
echo ""

echo "===== 完成 ====="
