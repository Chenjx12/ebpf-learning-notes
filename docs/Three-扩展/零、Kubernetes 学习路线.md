# 零、Kubernetes 学习路线

> 目标：把你现有的 eBPF 逃逸检测系统部署到 K8s 集群上。不是要成为 K8s 专家——只需学会"把程序跑起来 + 用 K8s API 替代 Docker SDK"。

---

## 学习路线图

```txt
Week 1（2晚+周末）   Week 2（2晚+周末）    Week 3（2晚+周末）    Week 4（2晚+周末）
┌─────────────┐    ┌─────────────┐     ┌─────────────┐    ┌─────────────┐
│ 搭集群       │ →  │ Pod / DS    │ →   │ K8s 网络    │ →  │ K8s API     │
│ minikube/k3s │    │ 把 eBPF     │     │ 逃逸路径    │    │ 替代 Docker │
│ kubectl 基础 │    │ 跑成DS      │     │ NetworkPol. │    │ Python SDK  │
└─────────────┘    └─────────────┘     └─────────────┘    └─────────────┘

每阶段: 2~3 个晚上（每晚 1~2h）+ 周末集中动手（2~3h），一周一个主题，不赶进度。

```

---

## 一、核心主题（需要学）

### 1. 搭一个开发集群（2~3 晚）

**目标**：在自己机器上跑起来一个单节点 K8s。

```bash
# 推荐 minikube（简单）或 k3s（轻量）
# minikube:
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
minikube start --driver=docker

# k3s:
curl -sfL https://get.k3s.io | sh -

# 验证
kubectl get nodes
```

**学习资源**：

- [minikube 官方文档](https://minikube.sigs.k8s.io/docs/start/)
- [k3s 快速开始](https://docs.k3s.io/quick-start)

**关联项目**：你的 eBPF detector 最终要作为一个 K8s 工作负载跑在这个集群上。

---

### 2. Pod + DaemonSet（1 周）

**目标**：把你的 eBPF 程序以 DaemonSet 方式跑在每个节点上。

**必须理解的概念**：

| 概念 | 一句话 | 类比你的现有知识 |
|------|--------|----------------|
| Pod | 最小调度单位，含 1+ 个容器共享 namespace | 相当于 `docker run` 的一个容器（或几个紧密耦合的容器） |
| DaemonSet | 保证每个节点运行一个 Pod 副本 | 相当于在每个节点上执行 `sudo python3 detector.py` |
| privileged container | 允许容器访问宿主机内核 | 你的 eBPF 程序需要 `sudo` 权限 |
| hostPID / hostNetwork | Pod 共享宿主机 PID/网络 namespace | 替代你现在的 `--pid=host --net=host` |

**动手验证**：

```yaml
# daemonset-ebpf.yaml — 把你的 eBPF 程序跑成 DaemonSet 的骨架
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebpf-detector
spec:
  selector:
    matchLabels:
      app: ebpf-detector
  template:
    spec:
      hostPID: true        # 共享宿主机 PID namespace
      hostNetwork: true    # 共享宿主机网络
      containers:
      - name: detector
        image: your-detector-image
        securityContext:
          privileged: true  # eBPF 需要特权
```

**学习资源**：
- [Kubernetes: Pods](https://kubernetes.io/docs/concepts/workloads/pods/)
- [Kubernetes: DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/)
- [Kubernetes: Pod Security](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

**关联项目**：这是第三小节的核心代码——把你现有的 `escape-respond.py` 容器化并部署为 DaemonSet。

---

### 3. K8s 网络模型（1 周）

**目标**：理解 Pod 间通信，以及逃逸检测在网络层的意义。

**必须理解的概念**：

| 概念 | 说明 |
|------|------|
| Pod IP | 每个 Pod 有独立 IP，跨节点通信走 CNI |
| CNI 插件 | Calico / Flannel / Cilium。**Cilium 本身就是基于 eBPF 的！** |
| NetworkPolicy | 防火墙规则，控制 Pod 间流量 |
| Service | 稳定入口，背后是 kube-proxy（或 Cilium 替代） |

**动手验证**：

```bash
# 创建两个 Pod，互相 ping
kubectl run nginx --image=nginx
kubectl run client --image=busybox --command -- sleep 3600
kubectl exec client -- ping <nginx-pod-ip>

# 查看网络策略
kubectl get networkpolicy -A
```

**学习资源**：
- [Kubernetes: Cluster Networking](https://kubernetes.io/docs/concepts/cluster-administration/networking/)
- [Cilium eBPF-based Networking](https://docs.cilium.io/en/stable/network/) — 了解 eBPF 在 K8s 网络中的实际应用

**关联项目**：你的容器逃逸检测需要识别"异常的网络连接"（如容器 A 访问容器 B 的 private port），理解 Pod 网络模型是基础。

---

### 4. K8s API 编程（1 周）

**目标**：用 K8s API 替代 Docker SDK 做响应。

**对比**：

| 操作 | Docker SDK | K8s API |
|------|-----------|---------|
| 列出容器/工作负载 | `docker.containers.list()` | `k8s.list_namespaced_pod()` |
| 停止容器 | `container.stop()` | 删除 Pod 或 scale → 0 |
| 隔离网络 | `container.disconnect()` | 应用 NetworkPolicy deny-all |
| 获取容器信息 | `container.attrs` | `k8s.read_namespaced_pod()` |

**推荐使用 Python client**（你现在用 Python + Docker SDK）：

```bash
pip install kubernetes
```

```python
from kubernetes import client, config

config.load_incluster_config()  # Pod 内自动认证
# 或 config.load_kube_config()  # 本地开发

v1 = client.CoreV1Api()
pods = v1.list_namespaced_pod(namespace="default")
for pod in pods.items:
    print(f"{pod.metadata.name} — {pod.status.phase}")
```

**学习资源**：
- [Kubernetes Python Client](https://github.com/kubernetes-client/python)
- [Kubernetes API Overview](https://kubernetes.io/docs/reference/using-api/)

**关联项目**：这是第三小节最关键的代码改动——把 `responder.py` 从 Docker SDK 迁移到 K8s API。

---

## 二、不需要现在学的（跳过）

| 主题 | 原因 |
|------|------|
| Helm Chart / Kustomize | DaemonSet 一个 YAML 就够，不需要模板引擎 |
| Service Mesh (Istio/Linkerd) | 跟你项目无关 |
| Operator 开发 | 太重，毕设不需要自定义 Controller |
| StatefulSet / PV/PVC | 你不需要持久存储 |
| Ingress / Gateway API | 不需要对外暴露 HTTP 服务 |
| HPA / VPA 自动扩缩容 | DaemonSet 固定每节点一个 |
| 多集群 / Federation | 远超范围 |
| K8s 调度 / Affinity | DaemonSet 默认每节点一个，不需要调度规则 |

---

## 三、动手路线（跟笔记配套）

每个主题写一篇笔记 + 一段代码：

| 序号 | 笔记 | 代码 | 核心内容 |
|:--:|------|------|------|
| 零 | 本文档 | — | 学习路线规划 |
| 一 | K8s 环境搭建 | `code/16-k8s-setup/` | minikube/k3s 安装 + kubectl 基础命令 |
| 二 | Pod 与 DaemonSet | `code/17-daemonset/` | 把你的 eBPF 程序跑成 DaemonSet |
| 三 | K8s 网络与逃逸面 | `code/18-k8s-network/` | Pod 网络模型 + NetworkPolicy + 逃逸路径分析 |
| 四 | K8s API 编程 | `code/19-k8s-api/` | Python client 替代 Docker SDK 做响应 |

---

## 四、推荐学习资源

**按需看，不要从头读**：

- [Kubernetes 官方教程 — 基础](https://kubernetes.io/docs/tutorials/kubernetes-basics/) — 2小时过一遍
- [《Kubernetes in Action (2nd)》](https://www.manning.com/books/kubernetes-in-action-second-edition) — Ch1~Ch5, Ch7, Ch10 就够
- [K8s Python Client Examples](https://github.com/kubernetes-client/python/tree/master/examples) — 直接看代码改
- [Cilium — eBPF in K8s](https://docs.cilium.io/) — 看看 eBPF 在 K8s 里真正怎么用的

---

*最后更新: 2026-07-29*
