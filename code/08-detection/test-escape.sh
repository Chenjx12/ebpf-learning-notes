#!/bin/bash
echo "===== Procfs 挂载逃逸测试 ====="

# 启动特权容器
echo "[1] 启动特权容器..."
docker run -d --privileged --name escape_test ubuntu:22.04 sleep 300

# 等待容器启动
sleep 2

# 在容器内执行挂载命令
echo "[2] 执行procfs挂载..."
docker exec escape_test bash -c "
mkdir -p /tmp/host_proc && \
mount -t proc proc /tmp/host_proc && \
ls /tmp/host_proc/1/cmdline
"

# 清理
echo "[3] 清理测试容器..."
docker rm -f escape_test

echo "===== 测试完成 ====="
echo "请查看监控终端是否有红色CRITICAL告警!"
