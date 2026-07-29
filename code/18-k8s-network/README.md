# K8s 网络与逃逸面 (Week 3)

> 对应笔记: [WEEK 3 — K8s 网络与逃逸面](../../docs/Three-扩展/WEEK%203.md)

## 📂 文件

| 文件 | 说明 |
|------|------|
| `deny-all.yaml` | 默认拒绝所有 Pod 间通信 |
| `allow-dns.yaml` | 允许 DNS 出站（配合 deny-all） |
| `isolate-pod.yaml` | 单 Pod 网络隔离模板 |

## 🚀 快速开始

```bash
# 应用 default-deny
kubectl apply -f deny-all.yaml

# 允许 DNS
kubectl apply -f allow-dns.yaml

# 隔离特定 Pod（替换 <pod-name>）
sed 's/<pod-name>/malicious-pod/g' isolate-pod.yaml | kubectl apply -f -

# 查看生效的 NetworkPolicy
kubectl get networkpolicy -A
```

## 📖 相关文档

- **上一篇**: [Pod 与 DaemonSet](../17-daemonset/)
- **下一篇**: [K8s API 编程](../19-k8s-api/)
