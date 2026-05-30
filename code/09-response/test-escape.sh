#!/bin/bash
# test-escape.sh - Procfs 挂载逃逸检测与主动防御测试
# 对应笔记: Nine、主动防御：从检测到自动响应
#
# 预期行为:
#   1. eBPF 捕获 mount 系统调用(fstype=proc)
#   2. 规则引擎匹配 procfs_mount_escape 规则(CRITICAL)
#   3. 响应引擎执行 pause_container 动作
#   4. escape_test 容器被冻结

echo "===== Procfs 挂载逃逸检测与主动防御测试 ====="
echo ""

# 清理残留(如果上次测试没清理干净)
docker rm -f escape_test 2>/dev/null || true

echo "[1] 启动特权容器..."
docker run -d --privileged --name escape_test ubuntu:22.04 sleep 300
sleep 3

echo "[2] 检查容器状态..."
if docker ps --format '{{.Names}}' | grep -q "^escape_test$"; then
    echo "✅ escape_test 容器正在运行"
else
    echo "❌ escape_test 容器启动失败"
    exit 1
fi

echo ""
echo "[3] 执行 procfs 挂载逃逸(应触发 CRITICAL 告警并自动冻结容器)..."
docker exec escape_test bash -c "
mkdir -p /tmp/host_proc && \
mount -t proc proc /tmp/host_proc && \
echo '宿主机 PID 1 命令行:' && \
cat /tmp/host_proc/1/cmdline
" 2>&1

sleep 3

echo ""
echo "[4] 验证容器是否被自动冻结..."
CONTAINER_STATUS=$(docker inspect escape_test --format '{{.State.Status}}' 2>/dev/null)
echo "   容器状态: $CONTAINER_STATUS"

if [ "$CONTAINER_STATUS" = "paused" ]; then
    echo "✅ 容器已被自动冻结(paused) — 主动防御生效!"
elif [ "$CONTAINER_STATUS" = "running" ]; then
    echo "⚠️  容器仍在运行 — 请检查监控终端是否有 CRITICAL 告警和响应动作"
else
    echo "⚠️  容器状态异常: $CONTAINER_STATUS"
fi

echo ""
echo "[5] 清理测试容器..."
docker rm -f escape_test 2>/dev/null || true

echo ""
echo "===== 测试完成 ====="
echo ""
echo "预期监控终端输出:"
echo "  🚨 安全告警 - CRITICAL 级别"
echo "  规则: procfs_mount_escape"
echo "  文件系统: proc -> 目标: /tmp/host_proc"
echo "  🛡️  [RESPONSE] 触发自动防御: CRITICAL → pause_container"
echo "  ✅ Container xxxxxxxxxxxx PAUSED - 已冻结,等待人工取证"
