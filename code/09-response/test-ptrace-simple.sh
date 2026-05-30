#!/bin/bash
# test-ptrace-simple.sh - 使用现有 ptrace-test 容器测试主动防御

echo "===== Ptrace 逃逸检测与主动防御测试 ====="
echo ""

# 检查 ptrace-test 容器是否存在
if ! docker ps -a --format '{{.Names}}' | grep -q "^ptrace-test$"; then
    echo "❌ ptrace-test 容器不存在!"
    echo "请先创建容器:"
    echo "docker run -d --name ptrace-test --cap-add=SYS_PTRACE --pid=host ubuntu:22.04 sleep 3600"
    exit 1
fi

# 启动容器（如果已停止）
if ! docker ps --format '{{.Names}}' | grep -q "^ptrace-test$"; then
    echo "[1] 启动 ptrace-test 容器..."
    docker start ptrace-test > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✅ ptrace-test 容器已启动"
    fi
    sleep 2
else
    echo "[1] ptrace-test 容器正在运行 ✓"
fi

echo ""
echo "[2] 检查 strace 是否已安装..."
docker exec ptrace-test which strace > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ strace 已安装"
else
    echo "⚠️ strace 未安装，正在安装..."
    docker exec ptrace-test bash -c "apt-get update > /dev/null 2>&1 && apt-get install -y strace > /dev/null 2>&1"
    if [ $? -eq 0 ]; then
        echo "✅ strace 安装成功"
    else
        echo "❌ strace 安装失败"
        exit 1
    fi
fi

echo ""
echo "[3] 执行 ptrace 测试（应该触发 HIGH 告警并自动断网隔离）..."
echo "预期行为:"
echo "  1. eBPF 捕获 ptrace 系统调用"
echo "  2. 规则引擎匹配 dangerous_ptrace 规则"
echo "  3. 响应引擎执行 isolate_network 动作"
echo "  4. ptrace-test 容器网络被断开"
echo ""

docker exec ptrace-test bash -c "
    echo '尝试追踪 PID 1 (宿主机 init 进程)...'
    timeout 10 strace -p 1 -e trace=read 2>&1 | head -n 10
"

echo ""
echo "===== 测试完成 ====="
echo ""
echo "请检查以下内容:"
echo "  1. 监控终端是否有红色 HIGH 级别告警"
echo "  2. 是否显示 '🛡️  [RESPONSE] 触发自动防御: HIGH → isolate_network'"
echo "  3. ptrace-test 容器网络是否被断开:"
echo "     docker inspect ptrace-test | grep Networks"
echo ""
