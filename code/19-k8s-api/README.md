# K8s API 编程 — 响应引擎改造 (Week 4)

> 对应笔记: [WEEK 4 — K8s API 编程](../../docs/Three-扩展/WEEK%204.md)

## 📂 文件

| 文件 | 说明 |
|------|------|
| `k8s_responder.py` | K8s 响应引擎 (替代 `responder.py` 的 Docker SDK) |
| `requirements.txt` | Python 依赖 |

## 🔄 Docker SDK → K8s API 映射

| 响应操作 | Docker SDK | K8s API |
|---------|-----------|---------|
| 暂停容器 | `container.pause()` | 删除 Pod (`V1DeleteOptions`) |
| 隔离网络 | `container.disconnect()` | `NetworkPolicy` with podSelector |
| 杀死进程 | `docker exec kill -9` | 删除 Pod (进程一并终止) |
| 停止容器 | `container.stop()` | 删除 Pod |
| 容器发现 | `docker.from_env()` | `config.load_incluster_config()` |

## 🚀 快速开始

```bash
pip install -r requirements.txt

# 本地开发 (用 kubeconfig)
python3 -c "
from k8s_responder import K8sResponseEngine
engine = K8sResponseEngine('responses.yaml')
# engine.handle_alert(alert_dict)
"
```

## 🔗 集成到 DaemonSet

将 `k8s_responder.py` 替换 `responder.py`:

```bash
cd ../17-daemonset
cp ../19-k8s-api/k8s_responder.py ./responder.py
# 修改 escape-respond.py: from k8s_responder import K8sResponseEngine as ResponseEngine
docker build -t ebpf-detector:k8s .
```

## 📖 相关文档

- **上一篇**: [K8s 网络与逃逸面](../18-k8s-network/)
- **第二小节起点**: [CO-RE、BTF 与 Libbpf](../../docs/Two-回顾/一、CO-RE、BTF%20与%20Libbpf.md)
