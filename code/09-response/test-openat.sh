#!/bin/bash
# test-openat.sh - 敏感文件读取检测与主动防御测试
# 对应笔记: Nine、主动防御：从检测到自动响应
#
# 预期行为:
#   1. eBPF 捕获 openat 系统调用(访问 /host_etc/shadow)
#   2. 规则引擎匹配 sensitive_file_read 规则(HIGH)
#   3. 响应引擎执行 kill_process 动作(终止 cat 进程)
#
# ⚠️ 注意:
#   - openat 是超高频调用，eBPF Ring Buffer 可能溢出导致事件丢失
#   - 如果未看到告警，属正常现象（已在第八篇文档中说明此限制）
#   - 本测试主要验证"检测到敏感路径时能否触发告警+响应"

echo "===== 敏感文件读取检测与主动防御测试 ====="
echo ""

echo "[1] 挂载宿主机 /etc 目录到容器并读取 /host_etc/shadow..."
echo "   (使用 --rm 参数，容器执行完后自动删除)"

docker run --rm --name openat_test \
    -v /etc:/host_etc:ro \
    ubuntu:22.04 bash -c "
    echo '尝试读取宿主机 /etc/shadow ...'
    cat /host_etc/shadow 2>/dev/null && echo '(读取成功 - 容器逃逸)' || echo '(读取被拒绝)'
    sleep 2
" 2>&1

sleep 2

echo ""
echo "===== 测试完成 ====="
echo ""
echo "预期监控终端输出(如果事件未被 Ring Buffer 溢出丢弃):"
echo "  🚨 安全告警 - HIGH 级别"
echo "  规则: sensitive_file_read"
echo "  访问路径: /host_etc/shadow"
echo "  🛡️  [RESPONSE] 触发自动防御: HIGH → isolate_network"
echo ""
echo "💡 提示: 如果未看到告警，说明 openat 事件被 Ring Buffer 溢出丢弃。"
echo "   这是第八篇文档中已说明的已知限制，属于正常现象。"
echo "   ptrace 和 mount 测试不受影响，因为它们频率低不会溢出。"
