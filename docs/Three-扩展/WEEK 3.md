# WEEK 3

## 一、K8s 网络与逃逸面

> 目标：理解 Pod 网络模型，分析容器在 K8s 环境下的逃逸路径，掌握 NetworkPolicy 的基本用法。
> 时间：1 周（2~3 晚 + 周末）
> 前置：已完成 Week 2（eBPF 程序以 DaemonSet 部署）

---

### 1.1 核心概念

#### Pod IP —— 每个 Pod 的独立身份

**一句话**：每个 Pod 在创建时会被 CNI 插件分配一个独立的 IP 地址，跨节点通信走 CNI 网络。

**类比你的现有知识**：
- Docker 默认用 bridge 网络，容器 IP 是 `172.17.0.x`
- K8s 里每个 Pod 也有 IP，但由 CNI 统一管理，且**Pod IP 不是稳定的**（Pod 重建后 IP 会变）

**关键特性**：
- Pod IP 只在集群内部可达
- 同一节点上的 Pod 直接通信；跨节点走 CNI 隧道（如 Flannel 的 VXLAN）
- `hostNetwork: true` 的 Pod 直接使用宿主机 IP，不分配 Pod IP

**在本项目中的意义**：
- 我们的 eBPF 探针通过 `hostNetwork: true` 共享宿主机网络，能直接看到所有 Pod 的网络流量
- 逃逸检测需要识别"异常的网络连接"（如容器 A 访问容器 B 的私有端口）

---

#### CNI 插件 —— K8s 的网络管家

**一句话**：CNI（Container Network Interface）是 K8s 的网络标准，负责给 Pod 分配 IP、设置路由、实现跨节点通信。

**k3s 默认：Flannel**

| 特性          | Flannel          | Calico        | Cilium                 |
| ------------- | ---------------- | ------------- | ---------------------- |
| 网络模式      | Overlay（VXLAN） | BGP / Overlay | eBPF 驱动              |
| 性能          | 中等             | 高            | 最高                   |
| NetworkPolicy | 基础支持         | 完整支持      | 完整支持               |
| eBPF 相关     | 无               | 无            | **本身就是 eBPF 实现** |
| 复杂度        | 低               | 中            | 高                     |

**Flannel 的 VXLAN 模式**：
- 每个节点有一个 `flannel.1` 虚拟网卡
- 跨节点 Pod 通信时，数据包被封装在 VXLAN 报文中，通过宿主机网络传输
- 到达目标节点后解封装，送到目标 Pod

**在本项目中的意义**：
- 理解 CNI 才能分析"容器逃逸后的网络行为"
- Cilium 是 eBPF 驱动的 CNI，毕设后续可以深入了解（但当前不需要替换 k3s 默认的 Flannel）

---

#### NetworkPolicy —— Pod 级防火墙

**一句话**：NetworkPolicy 定义了"哪些 Pod 可以互相通信"，是 namespace 级别的访问控制。

**类比你的现有知识**：
- 相当于 `iptables` 规则，但以声明式 YAML 管理
- 也类似于 Docker 的 `docker network disconnect`，但粒度更细（可以控制 ingress/egress）

**默认行为**：
- **没有 NetworkPolicy 时**：所有 Pod 之间完全互通（零信任的对立面）
- **应用了 deny-all 的 NetworkPolicy**：默认拒绝所有流量，只有白名单允许的才通过

**关键字段**：

| 字段          | 说明                                                        |
| ------------- | ----------------------------------------------------------- |
| `podSelector` | 选择受策略约束的 Pod（空 `{}` 表示该 namespace 下所有 Pod） |
| `policyTypes` | `Ingress`（入站）/ `Egress`（出站）                         |
| `ingress`     | 允许哪些来源访问                                            |
| `egress`      | 允许访问哪些目标                                            |

**在本项目中的意义**：
- Week 4 的响应引擎会用 NetworkPolicy 替代 `docker network disconnect` 做网络隔离
- 检测到逃逸后，给恶意 Pod 应用 deny-all 策略，切断它的所有网络通信

---

#### Service —— 稳定的访问入口

**一句话**：Service 为一组 Pod 提供一个稳定的虚拟 IP（ClusterIP），背后通过 kube-proxy 做负载均衡。

**类比我们现有的知识**：

- 相当于 Nginx 反向代理 + 健康检查
- Pod IP 会变，但 Service IP 是稳定的

**为什么提它**：
- 毕设不需要对外暴露 HTTP 服务，所以不需要 Ingress
- 但如果你的监控面板需要被其他 Pod 访问，可以用 Service 暴露

---

### 1.2 动手验证 Pod 网络

#### 1.2.1 查看 CNI 网络配置

```bash
# 查看节点上的 CNI 网桥和接口
ip addr show
# 应该能看到 flannel.1（VXLAN 接口）和 cni0（网桥）

# 查看路由表
ip route
# 应该能看到指向其他节点 Pod CIDR 的路由

# 查看 k3s 的 Pod CIDR 分配
kubectl get nodes -o wide
# 注意 INTERNAL-IP 和 POD-CIDR 列
```

#### 1.2.2 Pod 间通信实验

```bash
# 1. 启动 nginx Pod
kubectl run nginx --image=nginx

# 2. 等它 Running 后记录 IP
kubectl get pod nginx -o wide
# NAME    READY   STATUS    RESTARTS   AGE   IP           NODE
# nginx   1/1     Running   0          10s   10.42.0.10   learning-ebpf

# 3. 启动 busybox 客户端
kubectl run client --image=busybox --command -- sleep 3600

# 4. 从 client 访问 nginx
kubectl exec client -- wget -qO- http://<nginx-pod-ip>
# 应该返回 nginx 欢迎页 HTML

# 5. 测试跨协议（你的 eBPF 探针可能监控这些）
kubectl exec client -- ping -c 3 <nginx-pod-ip>
kubectl exec client -- nc -zv <nginx-pod-ip> 80
```

#### 1.2.3 观察 eBPF DaemonSet 的网络视角

因为 DaemonSet 设置了 `hostNetwork: true`，它看到的网络就是宿主机网络：

```bash
# 进入 eBPF Pod
kubectl exec -it $(kubectl get pod -l app=ebpf-detector -o jsonpath='{.items[0].metadata.name}') -- /bin/bash

# 在 Pod 里查看网络接口（和宿主机一样）
ip addr show

# 查看所有进程（因为 hostPID: true）
ps aux

# 退出
exit
```

> 💡 **关键理解**：`hostNetwork: true` + `hostPID: true` 让你的 eBPF 探针在容器里拥有和宿主机几乎一样的视角，这是它能监控所有 Pod 的前提。

---

### 1.3 K8s 环境下的容器逃逸路径分析

在 Docker 环境下，我们之前的检测模型覆盖了 procfs 挂载、ptrace 注入、敏感文件访问。

而在 K8s 环境下，逃逸路径有变化：

#### 逃逸路径 1：特权容器逃逸（当下场景）

**攻击方式**：

- 攻击者获得一个 Pod 的 shell（如通过漏洞利用）
- 该 Pod 是 `privileged: true` 或挂载了 `/var/run/docker.sock`
- 攻击者从容器内访问宿主机资源，实现逃逸

**在 K8s 中的检测点**：
- eBPF 探针监控 `mount`、`ptrace`、`openat` 等系统调用
- 通过 `hostPID: true` 可以看到逃逸进程的真实 PID
- 通过 cgroup 信息可以关联到具体的 Pod

#### 逃逸路径 2：ServiceAccount 令牌窃取

**攻击方式**：

- 攻击者进入 Pod 后，读取 `/var/run/secrets/kubernetes.io/serviceaccount/token`
- 用该 token 调用 K8s API，创建新的恶意 Pod 或修改配置

**检测思路**（Week 4 实现）：
- 监控 Pod 内的异常进程（如 `curl` 访问 API Server）
- 通过 eBPF 网络探针监控到 API Server 的异常连接

#### 逃逸路径 3：网络横向移动

**攻击方式**：
- 攻击者从一个被攻破的 Pod 扫描/访问其他 Pod 的敏感端口
- 利用默认的"全互通"网络策略

**防御手段**：
- 应用 NetworkPolicy 限制 Pod 间通信
- 响应引擎可以给恶意 Pod 打上 deny-all 策略

---

### 1.4 NetworkPolicy 实战

#### 1.4.1 默认拒绝所有流量（deny-all）

```yaml
# deny-all.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: default
spec:
  podSelector: {}      # 选择该 namespace 下所有 Pod
  policyTypes:
  - Ingress
  - Egress
  # ingress 和 egress 规则为空 = 拒绝所有流量
```

**注意**：deny-all 后 Pod 无法解析 DNS，如果需要保留 DNS，要额外加 egress 规则：

```yaml
# deny-all-with-dns.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-with-dns
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
```

#### 1.4.2 只允许特定 Pod 通信

```yaml
# allow-nginx-only.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-nginx-only
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: client        # 对 client Pod 应用策略
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          run: nginx     # 只允许访问 nginx Pod
    ports:
    - protocol: TCP
      port: 80
```

#### 1.4.3 测试 NetworkPolicy

```bash
# 1. 先确认 client 能访问 nginx
kubectl exec client -- wget -qO- http://<nginx-pod-ip>
# 成功

# 2. 应用 deny-all
kubectl apply -f deny-all.yaml

# 3. 再次测试
kubectl exec client -- wget -qO- http://<nginx-pod-ip>
# 失败（超时或连接被拒绝）

# 4. 删除策略恢复
kubectl delete -f deny-all.yaml

# 5. 测试带 DNS 的 deny-all
kubectl apply -f deny-all-with-dns.yaml
kubectl exec client -- nslookup kubernetes.default
# 应该能解析（因为允许了 kube-system 的 DNS）
```

---

### 1.5 踩坑记录

| 问题                                               | 现象                                 | 原因                                                         | 解决                                                         |
| -------------------------------------------------- | ------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| NetworkPolicy 不生效                               | 应用了 deny-all 但 Pod 仍能通信      | Flannel 的 NetworkPolicy 支持有限，或 CNI 插件未正确配置     | k3s 默认 Flannel 支持基础 NetworkPolicy，确保 `kube-proxy` 正常运行；如需完整支持可换 Calico |
| Pod 无法解析域名                                   | deny-all 后 `nslookup` 失败          | 没有放行 DNS egress 到 kube-system                           | 添加 egress 规则允许 UDP 53 到 kube-system namespace         |
| `hostNetwork: true` 的 Pod 不受 NetworkPolicy 约束 | 给 DaemonSet 应用 NetworkPolicy 无效 | `hostNetwork` Pod 的网络栈就是宿主机，NetworkPolicy 不适用于它们 | 这是预期行为，hostNetwork Pod 需要用宿主机防火墙（iptables）控制 |

---

### 1.6 与后续章节的衔接

| Week     | 内容                   | 本章铺垫                                                     |
| -------- | ---------------------- | ------------------------------------------------------------ |
| Week 4   | K8s API 编程           | 本章的 NetworkPolicy YAML 就是 Week 4 响应引擎要动态创建的对象 |
| 第四小节 | K8s 下的 eBPF 安全实践 | 结合 eBPF 网络探针 + NetworkPolicy 实现"检测-隔离"闭环       |

---


## 📖 相关文档

- **上一篇**: [WEEK 2 — Pod 与 DaemonSet](./WEEK%202.md)
- **下一篇**: [WEEK 4 — K8s API 编程](./WEEK%204.md)
- **代码目录**: [code/18-k8s-network/](../../code/18-k8s-network/)
*最后更新: 2026-07-29*