#!/bin/bash
# test-ptrace.sh - 使用已有ptrace-test容器测试ptrace监控

echo "===== Ptrace 逃逸检测测试 ====="
echo ""

# 检查ptrace容器是否存在
if ! docker ps -a --format '{{.Names}}' | grep -q "^ptrace-test$"; then
    echo "❌ ptrace容器不存在!"
    echo "请先创建容器: docker run -d --name ptrace-test --cap-add=SYS_PTRACE --pid=host ubuntu:22.04 sleep 3600"
    exit 1
fi

# 启动容器(如果已停止)
if ! docker ps --format '{{.Names}}' | grep -q "^ptrace-test$"; then
    echo "[1] 启动ptrace容器..."
    docker start ptrace-test > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✅ ptrace容器已启动"
    fi
    sleep 2
else
    echo "[1] ptrace容器正在运行 ✓"
fi

echo ""
echo "[2] 检查strace是否已安装..."
docker exec ptrace-test which strace > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ strace已安装"
else
    echo "⚠️ strace未安装,正在安装..."
    docker exec ptrace-test bash -c "apt-get update > /dev/null 2>&1 && apt-get install -y strace > /dev/null 2>&1"
    if [ $? -eq 0 ]; then
        echo "✅ strace安装成功"
    else
        echo "❌ strace安装失败"
        exit 1
    fi
fi

echo ""
echo "[3] 执行ptrace测试(应该触发HIGH告警)..."
docker exec ptrace-test bash -c "
    echo '尝试追踪PID 1 (宿主机init进程)...'
    timeout 10 strace -p 1 -e trace=read 2>&1 | head -n 10
"

echo ""
echo "===== 测试完成 ====="
echo "请查看监控终端是否有红色ptrace告警!"
echo ""
echo "预期输出:"
echo "🚨 安全告警 - HIGH 级别"
echo "规则: dangerous_ptrace"
echo "Ptrace请求: PTRACE_ATTACH -> 目标PID: 1"
