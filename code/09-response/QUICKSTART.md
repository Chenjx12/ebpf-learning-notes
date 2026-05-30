# 主动防御系统快速启动指南

> 与前面八篇一致：**直接在宿主机上运行 Python 脚本**，无需 Docker Compose 靶场。

## 前置准备

```bash
cd /mnt/hgfs/code/09-response

# 安装 Python 依赖（只需一次）
pip3 install docker pyyaml
```

## 准备测试容器

### ptrace-test（ptrace 注入测试用）

```bash
# 创建容器（只需一次）
docker run -d --name ptrace-test \
  --cap-add=SYS_PTRACE \
  --pid=host \
  ubuntu:22.04 sleep 3600

# 安装 strace（只需一次，安装后重启容器不需要重装）
docker exec ptrace-test bash -c "
  apt-get update -qq && apt-get install -y -qq strace
"
```

如果容器已存在但已停止：
```bash
docker start ptrace-test
```

## 启动主动防御系统

```bash
sudo python3 escape-respond.py -r rules.yaml -s responses.yaml
```

看到 `[✓] 容器逃逸检测与主动防御系统启动成功!` 即可。

## 执行测试

**新开一个终端**，依次运行：

### 测试 1：Ptrace 注入检测 + 自动断网

```bash
cd /mnt/hgfs/code/09-response
bash test-ptrace-simple.sh
```

预期：监控终端看到 🚨 HIGH 告警 → 🛡️ `isolate_network` → 容器断网。

### 测试 2：Procfs 挂载逃逸检测 + 自动冻结

```bash
bash test-escape.sh
```

预期：监控终端看到 🚨 CRITICAL 告警 → 🛡️ `pause_container` → 容器冻结。

验证容器已冻结：
```bash
docker inspect escape_test --format '{{.State.Status}}'
# 应输出: paused
```

### 测试 3：敏感文件读取（可选）

```bash
bash test-openat.sh
```

⚠️ openat 是高频调用，Ring Buffer 可能溢出导致事件丢失。如果未看到告警，属于已知限制，不影响 ptrace 和 mount 测试。

## 审计日志

```bash
# 查看检测日志
cat detection.log

# 查看响应动作日志
cat response_audit.log

# 查看结构化告警日志（JSON）
cat audit.log | python3 -m json.tool
```

## 清理

```bash
docker rm -f ptrace-test 2>/dev/null
docker rm -f escape_test 2>/dev/null
rm -f audit.log response_audit.log detection.log
```
