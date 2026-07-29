# WEEK 4

## 一、K8s API 编程

> 目标：用 K8s Python Client 替代 Docker SDK，实现响应引擎的 K8s 化改造。
> 时间：1 周（2~3 晚 + 周末）
> 前置：已完成 Week 3（理解 Pod 网络和 NetworkPolicy）

---

### 1.1 核心概念

#### 为什么需要替换 Docker SDK？

**现状**： `responder.py` 使用 `docker` 库做响应：

- `docker.containers.list()` -> 列出容器
- `container.stop()` -> 停止容器
- `container.disconnect()` -> 断开网络

**问题**：

- k3s 使用 containerd 作为运行时，没有 Docker daemon
- Docker SDK 调用会报 `DockerException`
- 即使装了 Docker，K8s 创建的容器 Docker 也看不到

**解决方案**：用 K8s API 替代

| Docker SDK 操作            | K8s API 替代                                              | 说明                                  |
| -------------------------- | --------------------------------------------------------- | ------------------------------------- |
| `docker.containers.list()` | `list_namespaced_pod()` / `list_pod_for_all_namespaces()` | 列出 Pod                              |
| `container.stop()`         | `delete_namespaced_pod()`                                 | 删除 Pod（K8s 中停止容器 = 删除 Pod） |
| `container.disconnect()`   | 创建 NetworkPolicy deny-all                               | 网络隔离                              |
| `container.attrs`          | `read_namespaced_pod()`                                   | 获取 Pod 详细信息                     |
| 获取容器日志               | `read_namespaced_pod_log()`                               | 读取 Pod 日志                         |

---

#### ServiceAccount -- Pod 的"身份证"

**一句话**：ServiceAccount 是 Pod 访问 K8s API 时的身份标识。

**为什么需要**：
- eBPF 响应脚本跑在 Pod 里，需要调用 K8s API
- API Server 不认识"匿名请求"，必须凭 ServiceAccount 的 token 认证
- 每个 namespace 有一个默认 ServiceAccount（`default`），但**默认没有任何权限**

**类比我们现有的知识**：

- 相当于 SSH 的密钥对 -- ServiceAccount 是"公钥"，token 是"私钥"
- Pod 启动时，K8s 自动把 token 挂载到 `/var/run/secrets/kubernetes.io/serviceaccount/token`

---

#### RBAC -- 权限清单

**一句话**：RBAC（Role-Based Access Control）定义了"谁（ServiceAccount）能对哪些资源做什么操作"。

**三个核心对象**：

| 对象                   | 作用                                      | 范围           |
| ---------------------- | ----------------------------------------- | -------------- |
| **Role**               | 定义权限规则（能对哪些资源做什么）        | 单个 namespace |
| **ClusterRole**        | 定义权限规则                              | 整个集群       |
| **RoleBinding**        | 把 Role/ClusterRole 绑定给 ServiceAccount | 单个 namespace |
| **ClusterRoleBinding** | 把 ClusterRole 绑定给 ServiceAccount      | 整个集群       |

**你的响应引擎需要的权限**：
- `pods`：get、list、delete（删除恶意 Pod）
- `networkpolicies`：create、delete（应用/撤销网络隔离）
- `events`：create（可选，记录安全事件）

---

### 1.2 安装 K8s Python Client

```bash
pip3 install kubernetes
```

---

### 1.3 认证方式

#### 方式 1：Pod 内运行（in-cluster）

```python
from kubernetes import client, config

# 在 Pod 内自动读取 ServiceAccount token
config.load_incluster_config()

v1 = client.CoreV1Api()
pods = v1.list_namespaced_pod(namespace="default")
for pod in pods.items:
    print(f"{pod.metadata.name} -- {pod.status.phase}")
```

**原理**：
- `load_incluster_config()` 自动读取：
  - `/var/run/secrets/kubernetes.io/serviceaccount/token`（认证 token）
  - `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`（CA 证书）
  - `KUBERNETES_SERVICE_HOST` 和 `KUBERNETES_SERVICE_PORT`（API Server 地址）

#### 方式 2：本地开发（kubeconfig）

```python
from kubernetes import client, config

# 读取 ~/.kube/config
config.load_kube_config()

v1 = client.CoreV1Api()
pods = v1.list_namespaced_pod(namespace="default")
for pod in pods.items:
    print(f"{pod.metadata.name} -- {pod.status.phase}")
```

**当下场景**：

- **本地调试**：用 `load_kube_config()`
- **DaemonSet 部署**：用 `load_incluster_config()`
- **推荐写法**（兼容两种场景）：

```python
from kubernetes import client, config

try:
    config.load_incluster_config()   # 优先尝试 Pod 内
except config.ConfigException:
    config.load_kube_config()        # 回退到本地开发

v1 = client.CoreV1Api()
```

---

### 1.4 响应引擎改造（responder.py -> k8s_responder.py）

#### 1.4.1 列出所有 Pod

```python
from kubernetes import client, config

def list_pods(namespace="default"):
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace=namespace)
    return pods.items

# 使用
for pod in list_pods():
    print(f"Pod: {pod.metadata.name}, IP: {pod.status.pod_ip}, Phase: {pod.status.phase}")
```

#### 1.4.2 删除 Pod（替代 container.stop()）

```python
def delete_pod(name, namespace="default"):
    v1 = client.CoreV1Api()
    try:
        v1.delete_namespaced_pod(
            name=name,
            namespace=namespace,
            body=client.V1DeleteOptions()
        )
        print(f"[+] 已删除 Pod: {name}")
        return True
    except client.exceptions.ApiException as e:
        print(f"[-] 删除 Pod 失败: {e}")
        return False
```

#### 1.4.3 创建 NetworkPolicy deny-all（替代 container.disconnect()）

```python
from kubernetes import client

def isolate_pod(name, namespace="default"):
    # 给指定 Pod 应用 deny-all NetworkPolicy，切断所有网络通信
    networking_v1 = client.NetworkingV1Api()

    policy = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(
            name=f"isolate-{name}",
            namespace=namespace
        ),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(
                match_labels={"app": name}  # 需要根据实际标签调整
            ),
            policy_types=["Ingress", "Egress"]
            # ingress 和 egress 为空 = deny all
        )
    )

    try:
        networking_v1.create_namespaced_network_policy(
            namespace=namespace,
            body=policy
        )
        print(f"[+] 已隔离 Pod: {name}（应用 deny-all NetworkPolicy）")
        return True
    except client.exceptions.ApiException as e:
        print(f"[-] 隔离 Pod 失败: {e}")
        return False
```

> 注意：上面的 `match_labels` 需要根据实际 Pod 标签调整。更好的做法是给逃逸的 Pod 动态打标签，然后按标签匹配。

#### 1.4.4 给 Pod 打标签（用于 NetworkPolicy 匹配）

```python
def label_pod(name, namespace="default", labels={"security/isolated": "true"}):
    # 给 Pod 打标签，用于 NetworkPolicy 匹配
    v1 = client.CoreV1Api()

    body = {
        "metadata": {
            "labels": labels
        }
    }

    try:
        v1.patch_namespaced_pod(name=name, namespace=namespace, body=body)
        print(f"[+] 已给 Pod {name} 打标签")
        return True
    except client.exceptions.ApiException as e:
        print(f"[-] 打标签失败: {e}")
        return False
```

#### 1.4.5 完整的隔离流程

```python
def isolate_malicious_pod(pod_name, namespace="default"):
    # 完整的隔离流程：打标签 + 应用 deny-all NetworkPolicy
    # 1. 给 Pod 打标签
    label_pod(pod_name, namespace, {"security/isolated": "true"})

    # 2. 创建 NetworkPolicy，匹配该标签
    networking_v1 = client.NetworkingV1Api()

    policy = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(
            name=f"isolate-{pod_name}",
            namespace=namespace
        ),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(
                match_labels={"security/isolated": "true"}
            ),
            policy_types=["Ingress", "Egress"]
        )
    )

    networking_v1.create_namespaced_network_policy(
        namespace=namespace,
        body=policy
    )
    print(f"[+] Pod {pod_name} 已被网络隔离")
```

---

### 1.5 RBAC 配置

DaemonSet Pod 需要 ServiceAccount + RBAC 才能调用 K8s API。

#### 1.5.1 rbac.yaml

```yaml
# === ServiceAccount ===
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ebpf-detector-sa
  namespace: default
---
# === ClusterRole（集群级权限）===
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ebpf-detector-role
rules:
# Pod 操作权限
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "delete"]
# NetworkPolicy 操作权限
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "create", "delete"]
# 给 Pod 打标签需要 patch
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["patch"]
# 可选：读取节点信息
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list"]
---
# === ClusterRoleBinding ===
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ebpf-detector-binding
subjects:
- kind: ServiceAccount
  name: ebpf-detector-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: ebpf-detector-role
  apiGroup: rbac.authorization.k8s.io
```

#### 1.5.2 修改 DaemonSet 使用 ServiceAccount

```yaml
# 在 daemonset-ebpf.yaml 的 spec.template.spec 下添加：
serviceAccountName: ebpf-detector-sa
```

完整修改后的 Pod spec：

```yaml
spec:
  serviceAccountName: ebpf-detector-sa   # <- 添加这行
  hostPID: true
  hostNetwork: true
  containers:
  - name: detector
    # ... 其他配置不变
```

#### 1.5.3 部署 RBAC

```bash
# 1. 创建 RBAC
kubectl apply -f rbac.yaml

# 2. 重新部署 DaemonSet（带上 ServiceAccount）
kubectl apply -f daemonset-ebpf.yaml

# 3. 验证 ServiceAccount 已挂载到 Pod
kubectl exec -it $(kubectl get pod -l app=ebpf-detector -o jsonpath='{.items[0].metadata.name}') --     cat /var/run/secrets/kubernetes.io/serviceaccount/token
# 应该输出一串 JWT token
```

---

### 1.6 完整的改造后的响应引擎

```python
# k8s_responder.py
from kubernetes import client, config
import os

class K8sResponder:
    def __init__(self):
        # 兼容 Pod 内和本地开发
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        self.v1 = client.CoreV1Api()
        self.networking_v1 = client.NetworkingV1Api()

    def get_pod_by_pid(self, pid):
        # 通过宿主机 PID 查找对应的 Pod（简化版）
        # 实际实现需要：
        # 1. 读取 /proc/<pid>/cgroup 获取 cgroup 路径
        # 2. 从 cgroup 路径提取 container ID
        # 3. 遍历所有 Pod，匹配 container ID
        pass

    def delete_pod(self, name, namespace="default"):
        # 删除恶意 Pod
        try:
            self.v1.delete_namespaced_pod(
                name=name,
                namespace=namespace,
                body=client.V1DeleteOptions()
            )
            print(f"[+] 已删除 Pod: {name}")
            return True
        except client.exceptions.ApiException as e:
            print(f"[-] 删除失败: {e}")
            return False

    def isolate_pod(self, name, namespace="default"):
        # 网络隔离：打标签 + deny-all NetworkPolicy
        # 1. 打标签
        body = {"metadata": {"labels": {"security/isolated": "true"}}}
        self.v1.patch_namespaced_pod(name=name, namespace=namespace, body=body)

        # 2. 创建 deny-all NetworkPolicy
        policy = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(name=f"isolate-{name}"),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(
                    match_labels={"security/isolated": "true"}
                ),
                policy_types=["Ingress", "Egress"]
            )
        )
        self.networking_v1.create_namespaced_network_policy(
            namespace=namespace, body=policy
        )
        print(f"[+] 已隔离 Pod: {name}")
        return True


## 📖 相关文档

- **上一篇**: [WEEK 3 — K8s 网络与逃逸面](./WEEK%203.md)
- **代码目录**: [code/19-k8s-api/](../../code/19-k8s-api/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)
    def respond<response clipped><NOTE>Result is longer than **10000 characters**, will be **truncated**.</NOTE>