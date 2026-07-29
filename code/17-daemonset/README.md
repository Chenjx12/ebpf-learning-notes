# Pod 与 DaemonSet — eBPF 检测器容器化 (Week 2)

> 对应笔记: [WEEK 2 — Pod 与 DaemonSet](../../docs/Three-扩展/WEEK%202.md)

## 📂 文件

| 文件 | 说明 |
|------|------|
| `escape-detect.c` | eBPF 探针 C 代码 (从 `09-response` 复制) |
| `escape-respond.py` | 主程序入口 |
| `detector.py` | 检测引擎 (事件解析 + 规则匹配) |
| `responder.py` | Docker 响应引擎 (Week 4 将替换为 K8s 版) |
| `rules.yaml` | 检测规则 (通过 ConfigMap 挂载) |
| `responses.yaml` | 响应策略 (通过 ConfigMap 挂载) |
| `Dockerfile` | 容器镜像构建文件 |
| `configmap.yaml` | K8s ConfigMap (规则热更新) |
| `rbac.yaml` | ServiceAccount + ClusterRole |
| `daemonset.yaml` | DaemonSet 部署清单 |
| `Makefile` | 构建/部署/日志 一键命令 |

## 🚀 快速开始

```bash
# 1. 构建镜像
make build

# 2. 部署到 K8s
make deploy

# 3. 查看状态
make status

# 4. 查看日志
make logs

# 5. 清理
make clean
```

## ⚠️ 前置条件

- k3s/minikube 已安装 (Week 1)
- Docker socket 可用 (`/var/run/docker.sock`)

## 📖 相关文档

- **上一篇**: [K8s 环境搭建](../16-k8s-setup/)
- **下一篇**: [K8s 网络与逃逸面](../18-k8s-network/)
