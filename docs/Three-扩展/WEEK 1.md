# WEEK 1

## 一、K8s 环境搭建

> 目标：在 VMware Ubuntu 22.04 虚拟机上跑起来一个单节点 K8s 集群，掌握 kubectl 基础操作。
> 时间：2~3 晚

---

### 1.1 为什么选择 k3s？

三种本地 K8s 方案对比

| 方案         | 本质                          | 优点                         | 缺点                           | 是否适合 eBPF |
| ------------ | ----------------------------- | ---------------------------- | ------------------------------ | ------------- |
| **minikube** | 在容器/VM 里再跑一个 K8s 节点 | 文档全、driver 多            | 嵌套一层，eBPF 要额外配 volume | ⚠️ 麻烦        |
| **kind**     | 用 Docker 容器模拟多节点      | 轻量、适合 CI                | 容器套容器，内核隔离           | ❌ 不适合      |
| **k3s**      | 单二进制直接跑在宿主机上      | 最轻量、无嵌套、原生内核访问 | 单节点（对我们够用）           | ✅ 最适合      |

**结论**：我们只需要"把 eBPF 程序以 DaemonSet 跑在每个节点上"，k3s 单节点完全够用，且 eBPF 探针能直接访问 VM 的 `/sys/kernel/debug` 等路径，没有容器嵌套带来的权限问题。

---

### 1.2 安装步骤

```bash
# 1. 一键安装 k3s（约 30 秒）
curl -sfL https://get.k3s.io | sh -

# 2. 验证节点状态
sudo k3s kubectl get nodes
# NAME            STATUS   ROLES           AGE   VERSION
# learning-ebpf   Ready    control-plane   11s   v1.36.2+k3s1

# 3. 配置 kubeconfig（让当前用户免 sudo 使用 kubectl）
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER:$USER ~/.kube/config
chmod 600 ~/.kube/config

# 4. 设置环境变量（永久生效）
export KUBECONFIG=~/.kube/config
echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc

# 5. 验证
kubectl get nodes
```

#### 踩坑记录

| 问题                                                         | 原因                                     | 解决                                                        |
| ------------------------------------------------------------ | ---------------------------------------- | ----------------------------------------------------------- |
| `Unable to read /etc/rancher/k3s/k3s.yaml, permission denied` | kubectl 默认读系统路径，而普通用户无权限 | `export KUBECONFIG=~/.kube/config` 指向复制后的用户目录配置 |

---

### 1.3 kubectl 基础命令速查

```bash
# 查看节点
kubectl get nodes

# 查看所有命名空间的 Pod
kubectl get pods -A

# 查看当前命名空间的 Pod
kubectl get pods

# 查看 Pod 详细信息
kubectl describe pod <pod-name>

# 运行一个临时 Pod
kubectl run nginx --image=nginx
kubectl run client --image=busybox --command -- sleep 3600

# 进入 Pod 容器执行命令
kubectl exec -it <pod-name> -- /bin/sh

# 查看 Pod 日志
kubectl logs <pod-name>

# 删除 Pod
kubectl delete pod <pod-name>

# 查看 Pod IP（用于测试网络连通性）
kubectl get pod <pod-name> -o wide

# 查看所有资源
kubectl get all -A
```

---

### 1.4 验证网络（Week 3 的前置实验）

```bash
# 1. 启动 nginx
kubectl run nginx --image=nginx

# 2. 等它 Running
kubectl get pods -w

# 3. 记录它的 IP
kubectl get pod nginx -o wide
# 例如：10.42.0.5

# 4. 启动 busybox 客户端
kubectl run client --image=busybox --command -- sleep 3600

# 5. 从 client ping nginx
kubectl exec client -- ping -c 3 <nginx-pod-ip>
# 能通说明 CNI 网络正常
```

---

## 二、概念名词详解

### 2.1 什么是"单点 K8s"？

**一句话**：单点 K8s 就是**只有一个节点的 Kubernetes 集群**——这个节点既当"老板"（Control Plane）又当"员工"（Worker）。


想象一家只有一个人的公司：
- 这个人既要**做决策**（Control Plane：调度、管理、API 服务）
- 又要**干活的**（Worker Node：实际运行容器）

和"多节点集群"的区别：

|           | 单点 K8s                | 多节点 K8s                  |
| --------- | ----------------------- | --------------------------- |
| 节点数    | 1                       | 3+（通常）                  |
| 高可用    | ❌ 节点挂了全挂          | ✅ 部分节点故障不影响服务    |
| 适用场景  | 本地开发、学习、毕设    | 生产环境                    |
| 资源占用  | 低（k3s 约 500MB 内存） | 高                          |
| eBPF 监控 | 只需要监控 1 个节点     | 需要 DaemonSet 覆盖所有节点 |

#### 为什么我们够用？

项目核心是"检测容器逃逸"，逃逸检测本身是**节点级**的（每个节点独立运行 eBPF 探针）。单节点上能完整验证：
- eBPF 探针加载 ✅
- 逃逸事件检测 ✅
- K8s API 响应（删除 Pod / 应用 NetworkPolicy）✅

生产环境才需要多节点高可用，毕设不需要。

---

### 2.2 核心概念名词

#### Node（节点）

**一句话**：K8s 集群中的一台机器（物理机或 VM）。

**类比**：一个工厂车间，里面有机器（CPU、内存、磁盘）用来跑容器。

**在本项目中的意义**：你的 eBPF 探针最终以 DaemonSet 形式跑在每个 Node 上。现在只有 1 个 Node（`learning-ebpf`），所以只跑 1 个副本。

---

#### Control Plane（控制平面）

**一句话**：K8s 的"大脑"，负责做决策和管理。

**组成部件**：

| 组件                        | 作用                                 | 类比                         |
| --------------------------- | ------------------------------------ | ---------------------------- |
| **kube-apiserver**          | 暴露 K8s API，所有操作都经过它       | 公司前台，所有请求的统一入口 |
| **etcd**                    | 存储集群所有数据（Pod 信息、配置等） | 公司的档案室                 |
| **kube-scheduler**          | 决定新 Pod 放在哪个 Node 上          | 人力资源部，分配员工到车间   |
| **kube-controller-manager** | 确保实际状态和期望状态一致           | 监工，发现少了 Pod 就补一个  |

**在本项目中的意义**：我们的 Python 响应脚本通过调用 kube-apiserver（`kubernetes` 库）来删除恶意 Pod 或创建 NetworkPolicy。

---

#### Worker Node（工作节点）

**一句话**：实际运行容器（Pod）的机器。

**组成部件**：

| 组件           | 作用                                                 |
| -------------- | ---------------------------------------------------- |
| **kubelet**    | 接收 Control Plane 指令，管理本节点上的 Pod 生命周期 |
| **kube-proxy** | 维护节点上的网络规则（Service 转发）                 |
| **容器运行时** | 实际创建和运行容器（k3s 用的是 containerd）          |

**在本项目中的意义**：eBPF 探针跑在 Worker Node 的内核里，监控这个节点上所有容器的系统调用。

---

#### Pod（豆荚）

**一句话**：K8s 的最小调度单位，里面可以跑 1 个或多个紧密耦合的容器，共享网络和存储。

**类比**：一个豆荚里有几粒豆子——它们共享同一个"壳"（namespace）。

**关键特性**：
- 每个 Pod 有独立的 IP 地址
- Pod 内的容器共享网络栈（localhost 互通）
- Pod 是**临时**的，可以被创建、删除、重建

**在本项目中的意义**：你的 eBPF 程序本身会以 Pod 形式跑在 DaemonSet 里；同时它监控的对象也是其他 Pod 里的容器。

---

#### Namespace（命名空间）

**一句话**：K8s 里的"虚拟集群"，用于隔离不同团队/项目的资源。

**类比**：公司里的不同部门——研发部、财务部各自有独立的办公区域，互不干扰。

**默认命名空间**：

| 命名空间          | 用途                                   |
| ----------------- | -------------------------------------- |
| `default`         | 默认，用户创建的 Pod 默认放这里        |
| `kube-system`     | K8s 系统组件（kube-proxy、coredns 等） |
| `kube-public`     | 公开数据                               |
| `kube-node-lease` | 节点心跳信息                           |

**在本项目中的意义**：我们的 eBPF DaemonSet 可以放在 `default`，也可以新建一个 `security` namespace。NetworkPolicy 是 namespace 级别的，隔离恶意 Pod 时要指定 namespace。

---

#### kubeconfig

**一句话**：kubectl 的配置文件，告诉它"连哪个集群、用哪个账号、上下文是什么"。

**文件位置**：`~/.kube/config`

**三大要素**：

```yaml
clusters:    # 集群列表（API Server 地址）
users:       # 用户列表（认证信息，如证书、token）
contexts:    # 上下文（cluster + user 的组合）
```

**在本项目中的意义**：k3s 安装时把配置写到了 `/etc/rancher/k3s/k3s.yaml`，我们把它复制到 `~/.kube/config` 并设置 `KUBECONFIG` 环境变量，kubectl 就知道连哪个集群了。

---

#### Context（上下文）

**一句话**：kubectl 当前使用的"cluster + user"组合。

**常用命令**：

```bash
kubectl config get-contexts      # 查看所有上下文
kubectl config current-context   # 查看当前上下文
kubectl config use-context xxx   # 切换上下文
```

**在本项目中的意义**：如果你同时有 minikube 和 k3s，`current-context` 决定 kubectl 操作哪个集群。我们现在只有一个 k3s 上下文，所以不需要切换。

---

#### CNI（Container Network Interface）

**一句话**：K8s 的容器网络插件标准，负责给每个 Pod 分配 IP 并让它们互相通信。

**类比**：公司里的内部电话系统——每个员工（Pod）有一个分机号（IP），CNI 负责把电话线（网络）接通。

**常见实现**：Calico、Flannel、Cilium（基于 eBPF！）。

**k3s 默认**：使用 Flannel（Overlay 网络）。

**在本项目中的意义**：
- Pod 间通信走 CNI 网络，理解它才能分析"容器逃逸后的网络行为"
- Cilium 本身就是 eBPF 驱动的，毕设后续可以深入了解
- NetworkPolicy 依赖 CNI 支持，k3s 默认的 Flannel 支持基础 NetworkPolicy

---

#### containerd

**一句话**：容器运行时，负责真正创建和管理容器（Docker 底层也是它）。

**类比**：Docker 是一个带 GUI 的播放器，containerd 是底层的解码引擎。

**为什么 k3s 用它而不是 Docker？**
- 更轻量，去掉 Docker 的 CLI 和构建功能
- K8s 从 1.24 起默认使用 containerd（CRI 标准）

**在本项目中的意义**：我们的 eBPF 探针监控的是**内核层面的系统调用**，和容器运行时无关。但注意：k3s 用 containerd 后，`docker ps` 看不到 K8s 创建的容器，要用 `crictl` 或 `kubectl`。

---

#### ServiceAccount / RBAC（预告）

**一句话**：Pod 访问 K8s API 时的"身份证"和"权限清单"。

**类比**：
- ServiceAccount = 员工工牌
- RBAC（Role-Based Access Control）= 工牌上的权限（能进哪些门、能操作哪些资源）

**为什么需要**： eBPF 响应脚本（跑在 Pod 里）要调用 K8s API 删除恶意 Pod，必须给它配 ServiceAccount + RBAC，否则 API Server 会拒绝。

**Week 4 再详细写**。

---

#### DaemonSet（预告）

**一句话**：确保集群中**每个节点**都运行一个 Pod 副本的控制器。

**类比**：给每个车间门口派一个保安——不管公司有几个车间，每个门口必须有 1 个。

**为什么用它**：eBPF 探针需要监控每个节点的内核事件，DaemonSet 保证"每个节点一个副本"。

**Week 2 核心主题**。

---

### 2.3 单点 K8s 架构图（k3s）

```
┌─────────────────────────────────────────────────────────┐
│                    VMware Ubuntu 22.04                   │
│                    (learning-ebpf Node)                  │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Control Plane（控制平面）            │   │
│  │  ┌─────────────┐  ┌──────────┐  ┌────────────┐  │   │
│  │  │ kube-apiserver│  │ etcd    │  │ scheduler  │  │   │
│  │  └─────────────┘  └──────────┘  └────────────┘  │   │
│  │  ┌─────────────────────────────────────────────┐│   │
│  │  │     kube-controller-manager                  ││   │
│  │  └─────────────────────────────────────────────┘│   │
│  └──────────────────────────────────────────────────┘   │
│                          │                               │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Worker Node（工作节点）               │   │
│  │  ┌─────────┐  ┌──────────┐  ┌────────────────┐  │   │
│  │  │ kubelet │  │kube-proxy│  │ containerd     │  │   │
│  │  └─────────┘  └──────────┘  │ (运行容器)       │  │   │
│  │                             └────────────────┘  │   │
│  │  ┌─────────────────────────────────────────────┐│   │
│  │  │  eBPF DaemonSet Pod（你的探针，待部署）      ││   │
│  │  │  ┌─────────────────────────────────────┐   ││   │
│  │  │  │  escape-respond.py + escape-detect.c │   ││   │
│  │  │  │  (privileged + hostPID + hostNetwork) │   ││   │
│  │  │  └─────────────────────────────────────┘   ││   │
│  │  └─────────────────────────────────────────────┘│   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  Linux Kernel（eBPF 探针加载到这里）                      │
└─────────────────────────────────────────────────────────┘
```

---


## 📖 相关文档

- **上一篇**: [零、Kubernetes 学习路线](./零、Kubernetes%20学习路线.md)
- **下一篇**: [WEEK 2 — Pod 与 DaemonSet](./WEEK%202.md)
- **代码目录**: [code/16-k8s-setup/](../../code/16-k8s-setup/)
*最后更新: 2026-07-29*
