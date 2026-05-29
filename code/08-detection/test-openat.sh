#!/bin/bash
# test-openat.sh - 敏感文件读取逃逸测试
# 
# 这是一个留给读者自己解读：
# 1. 在 escape-detect.c 中添加的 sys_enter_openat 探针
# 2. 在 rules.yaml 中添加的对 /host_etc/shadow 等敏感路径的检测规则
# 3. 在 escape-detect.py 中处理 openat 事件

echo "===== 敏感文件读取逃逸测试 ====="
echo ""

echo "[1] 挂载宿主机 /etc 目录到容器..."
docker run --rm --name openat_test -v /etc:/host_etc:ro ubuntu:22.04 bash -c "
  echo '[2] 尝试读取宿主机 /etc/shadow ...'
  cat /host_etc/shadow 2>/dev/null && echo '⚠️ 读取成功！容器发生逃逸！' || echo '✅ 访问被拒绝(预期行为)'
  sleep 1
"

echo ""
echo "===== 测试完成 ====="
