# WEEK 2

## 二、Pod 与 DaemonSet

> 目标：把现有的 eBPF 逃逸检测程序（`code/09-response/`）容器化，并以 DaemonSet 方式部署到 k3s 集群上。
> 时间：1 周（2~3 晚 + 周末）
> 前置：已完成 Week 1（k3s 安装 + kubectl 基础）

---

### 2.1 核心概念

#### Pod —— K8s 的最小调度单位

**一句话**：Pod 是 K8s 里"一组紧密耦合的容器"的封装，是调度的最小单元。

**关键特性**：
- 每个 Pod 有独立的 IP 地址
- Pod 内的容器共享网络栈（localhost 互通）和存储卷
- Pod 是**临时**的，可以被创建、删除、重建

**类比我们现有的知识**：
- `docker run` 启动的一个容器 ≈ K8s 里一个单容器的 Pod
- `docker-compose up` 启动的一组关联容器 ≈ K8s 里一个多容器的 Pod

**在本项目中的意义**： `escape-respond.py` + `escape-detect.c` 会跑在一个 Pod 里。这个 Pod 只有一个容器（eBPF detector），里面同时运行 Python 加载器和 eBPF 探针。

---

#### DaemonSet —— 每个节点一份

**一句话**：DaemonSet 保证集群中**每个节点**都运行一个 Pod 副本。

**类比我们现有的知识**：
- 相当于在每个节点上手动执行 `sudo python3 escape-respond.py`
- 节点增加了，自动补一个；节点减少了，自动删一个

**为什么用它**：
- eBPF 探针需要监控**每个节点**的内核事件
- 如果用 Deployment（另一种控制器），Pod 只会被调度到部分节点
- DaemonSet 确保"一个节点一个探针"

**在本项目中的意义**：这是 eBPF 安全工具的标准部署方式。Tetragon、Falco、Cilium 等安全组件全部以 DaemonSet 部署。

---

#### Privileged Container —— 特权容器

**一句话**：`privileged: true` 让容器拥有几乎和宿主机 root 一样的权限。

**类比我们现有的知识**：
- 相当于 `docker run --privileged`
- eBPF 程序现在需要 `sudo` 才能加载内核探针，privileged 容器就是容器里的 "sudo"

**为什么需要**：
- eBPF 程序调用 `bpf()` 系统调用加载探针，需要 `CAP_SYS_ADMIN`
- 访问 `/sys/kernel/debug` 需要特权
- 读取宿主机 `/proc` 需要 `hostPID`

**⚠️ 安全隐患**：privileged 是"大权限"，生产环境应该用精细 capabilities 替代（见 2.5 节）。

---

#### hostPID / hostNetwork —— 共享宿主机命名空间

| 字段                | 作用                           | 类比 Docker  |
| ------------------- | ------------------------------ | ------------ |
| `hostPID: true`     | Pod 共享宿主机的 PID namespace | `--pid=host` |
| `hostNetwork: true` | Pod 共享宿主机的网络 namespace | `--net=host` |

**为什么需要 hostPID**：
- eBPF 探针通过 PID 识别进程，需要看到宿主机上**所有进程**
- 容器逃逸检测要判断"进程是否脱离了容器 namespace"
- 如果不共享 PID namespace，Pod 里只能看到自己容器内的进程

**为什么需要 hostNetwork**：
- eBPF 网络探针需要绑定宿主机的网络接口
- 后续 Week 3 分析网络逃逸路径时需要
- 响应引擎做网络隔离时，需要操作宿主机的网络栈

---

#### ConfigMap —— 配置文件外挂

**一句话**：ConfigMap 把配置文件从镜像里抽离出来，可以独立修改、无需重新构建镜像。

**类比我们现有的知识**：
- 相当于 `docker run -v $(pwd)/rules.yaml:/app/rules.yaml`
- 但 ConfigMap 是 K8s 原生的配置管理方式，支持热更新

**在本项目中的意义**：
- `rules.yaml` 和 `responses.yaml` 经常需要调整规则
- 用 ConfigMap 挂载后，改规则只需要 `kubectl apply`，不需要重新 `docker build`

---

### 2.2 容器化 eBPF 程序

#### 2.2.1 准备文件

在 `code/17-daemonset/` 目录下准备以下文件（从 `code/09-response/` 复制）：

```
code/17-daemonset/
├── Dockerfile
├── escape-respond.py
├── detector.py
├── responder.py
├── escape-detect.c
├── rules.yaml
└── responses.yaml
```

#### 2.2.2 Dockerfile

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 安装 BCC 工具链 + Python 依赖
RUN apt-get update && apt-get install -y     bpfcc-tools     libbpfcc-dev     python3-bpfcc     python3-pip     python3-yaml     kmod     clang     llvm     && rm -rf /var/lib/apt/lists/*

# 安装 Python 库（docker 库 Week 4 会替换，先保留用于测试）
RUN pip3 install docker pyyaml

WORKDIR /app

# 复制代码
COPY escape-respond.py detector.py responder.py ./
COPY escape-detect.c ./

# 规则文件不 COPY 进镜像，通过 ConfigMap 挂载
# 这样改规则不需要重新 build

CMD ["python3", "escape-respond.py", "-r", "/app/config/rules.yaml", "-s", "/app/config/responses.yaml"]
```

**关键点说明**：

| 依赖            | 作用                                        |
| --------------- | ------------------------------------------- |
| `bpfcc-tools`   | BCC 工具链（bcc-lua、bpfcc 等）             |
| `python3-bpfcc` | BCC 的 Python 绑定（`from bcc import BPF`） |
| `libbpfcc-dev`  | BCC 开发库                                  |
| `clang` `llvm`  | BCC 编译 eBPF C 代码时需要                  |
| `kmod`          | 加载内核模块相关                            |

> ⚠️ **不安装 `linux-headers-$(uname -r)`**：容器里的 `uname -r` 返回宿主机内核版本，但 apt 仓库可能没有这个精确版本。改为在 YAML 里挂载宿主机的 `/lib/modules` 和 `/usr/src`（见 2.3 节）。

#### 2.2.3 构建镜像

```bash
cd code/17-daemonset

# 构建镜像（标签用本地仓库格式）
docker build -t ebpf-detector:latest .

# 验证镜像存在
docker images | grep ebpf-detector
```

> 💡 **单节点 k3s 的镜像问题**：k3s 默认使用 containerd，不会自动看到 Docker 构建的镜像。有两种方案：
> 1. 把镜像导入 containerd：`sudo k3s ctr images import <(docker save ebpf-detector:latest)`
> 2. 或者配置 k3s 使用 Docker 作为运行时（不推荐，k3s 默认 containerd 更轻量）
>
> 我们采用方案 1。

```bash
# 将 Docker 镜像导出并导入到 k3s 的 containerd
sudo k3s ctr images import <(docker save ebpf-detector:latest)

# 验证
sudo k3s ctr images list | grep ebpf-detector
```

---

### 2.3 DaemonSet 部署文件

#### 2.3.1 创建 ConfigMap（从文件）

```bash
# 在 code/17-daemonset/ 目录下执行
kubectl create configmap ebpf-rules --from-file=rules.yaml --dry-run=client -o yaml > configmap-rules.yaml
kubectl create configmap ebpf-responses --from-file=responses.yaml --dry-run=client -o yaml > configmap-responses.yaml
```

#### 2.3.2 daemonset-ebpf.yaml

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebpf-detector
  namespace: default
  labels:
    app: ebpf-detector
spec:
  selector:
    matchLabels:
      app: ebpf-detector
  template:
    metadata:
      labels:
        app: ebpf-detector
    spec:
      # === eBPF 必需：共享宿主机命名空间 ===
      hostPID: true
      hostNetwork: true

      containers:
      - name: detector
        image: ebpf-detector:latest
        imagePullPolicy: IfNotPresent   # 优先用本地镜像，不拉取远程

        securityContext:
          privileged: true

        # 规则文件通过 ConfigMap 挂载
        volumeMounts:
        - name: rules-config
          mountPath: /app/config/rules.yaml
          subPath: rules.yaml
        - name: responses-config
          mountPath: /app/config/responses.yaml
          subPath: responses.yaml

        # === eBPF 必需：内核相关路径挂载 ===
        - name: sys-kernel-debug
          mountPath: /sys/kernel/debug
        - name: sys-fs-cgroup
          mountPath: /sys/fs/cgroup
        - name: lib-modules
          mountPath: /lib/modules
          readOnly: true
        - name: usr-src
          mountPath: /usr/src
          readOnly: true

        # 日志输出方便查看
        command: ["python3", "-u", "escape-respond.py"]
        args: ["-r", "/app/config/rules.yaml", "-s", "/app/config/responses.yaml"]

      volumes:
      # ConfigMap 卷
      - name: rules-config
        configMap:
          name: ebpf-rules
      - name: responses-config
        configMap:
          name: ebpf-responses

      # 宿主机内核路径
      - name: sys-kernel-debug
        hostPath:
          path: /sys/kernel/debug
      - name: sys-fs-cgroup
        hostPath:
          path: /sys/fs/cgroup
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: usr-src
        hostPath:
          path: /usr/src
```

**YAML 字段详解**：

| 字段                            | 说明                                                        |
| ------------------------------- | ----------------------------------------------------------- |
| `kind: DaemonSet`               | 控制器类型，确保每个节点一个 Pod                            |
| `selector.matchLabels`          | 用于匹配 Pod 的标签，和 `template.metadata.labels` 必须一致 |
| `hostPID: true`                 | 共享宿主机 PID namespace，eBPF 探针能看到所有进程           |
| `hostNetwork: true`             | 共享宿主机网络 namespace                                    |
| `privileged: true`              | 特权容器，允许加载 eBPF 探针                                |
| `imagePullPolicy: IfNotPresent` | 本地有镜像就不拉取（单节点开发必需）                        |
| `subPath: rules.yaml`           | 把 ConfigMap 中的单个文件挂载到指定路径，而不是挂载整个目录 |
| `hostPath`                      | 把宿主机的目录挂载进容器，eBPF 编译需要访问宿主机内核头文件 |

---

### 2.4 部署步骤

```bash
cd code/17-daemonset

# 1. 构建镜像
docker build -t ebpf-detector:latest .

# 2. 导入到 k3s 的 containerd
sudo k3s ctr images import <(docker save ebpf-detector:latest)

# 3. 创建 ConfigMap
kubectl apply -f configmap-rules.yaml
kubectl apply -f configmap-responses.yaml

# 4. 部署 DaemonSet
kubectl apply -f daemonset-ebpf.yaml

# 5. 验证 DaemonSet 状态
kubectl get daemonset
# NAME            DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE
# ebpf-detector   1         1         1       1            1

# 6. 查看 Pod 状态
kubectl get pods -l app=ebpf-detector -o wide
# NAME                  READY   STATUS    RESTARTS   AGE   IP           NODE
# ebpf-detector-xxxxx   1/1     Running   0          10s   10.42.0.x    learning-ebpf

# 7. 查看日志（确认 eBPF 探针加载成功）
kubectl logs -l app=ebpf-detector -f

# 8. 进入 Pod 调试（可选）
kubectl exec -it $(kubectl get pod -l app=ebpf-detector -o jsonpath='{.items[0].metadata.name}') -- /bin/bash
```

---

### 2.5 验证 eBPF 探针工作

在宿主机上执行一些系统调用，观察 DaemonSet Pod 的日志输出：

```bash
# 另开一个终端
kubectl logs -l app=ebpf-detector -f

# 再开一个终端，执行一些操作触发探针
ls /proc
ps aux
cat /etc/passwd
```

如果看到类似下面的输出，说明 eBPF 探针在 DaemonSet 里正常工作了：

```
[+] eBPF 探针加载成功
[*] 监控中... 检测到 mount 系统调用: PID=12345, Comm=ls
```

> ⚠️ **注意**：响应功能（pause/disconnect/kill）现在会报错，因为 k3s 使用 containerd 而不是 Docker， `responder.py` 里的 Docker SDK 调用会失败。这是正常的——Week 4 会把响应逻辑从 Docker SDK 迁移到 K8s API。

---

### 2.6 安全加固：Privileged → Capabilities

`privileged: true` 是"一把大钥匙"，生产环境应该最小化权限。

#### 替代方案

```yaml
securityContext:
  privileged: false
  capabilities:
    add:
      - SYS_ADMIN      # 加载 eBPF 程序
      - SYS_RESOURCE   # 资源限制相关
      - SYS_PTRACE     # ptrace 监控
      - NET_ADMIN      # 网络操作
      - NET_RAW        # 原始套接字
      - IPC_LOCK       # 锁定内存（eBPF maps 需要）
      - BPF            # Linux 5.8+ 专用 eBPF capability
```

> ⚠️ **注意**：capabilities 方案需要较新的内核（支持 `CAP_BPF`）。如果内核版本 < 5.8，还是需要 `privileged: true` 或 `SYS_ADMIN`。

**验证内核是否支持 CAP_BPF**：
```bash
grep CONFIG_BPF_SYSCALL /boot/config-$(uname -r)
# 应该输出 CONFIG_BPF_SYSCALL=y
```

**本项目建议**：
- **Week 2**：先用 `privileged: true`，确保功能跑通
- **Week 4（融合阶段）**：尝试降级为 capabilities，作为毕设的"安全加固"亮点

---

### 2.7 踩坑记录

| 问题                                                | 现象                              | 原因                                           | 解决                                                         |
| --------------------------------------------------- | --------------------------------- | ---------------------------------------------- | ------------------------------------------------------------ |
| `ImagePullBackOff`                                  | Pod 状态一直是 `ImagePullBackOff` | k3s 的 containerd 看不到 Docker 构建的本地镜像 | `sudo k3s ctr images import <(docker save ...)`              |
| `CrashLoopBackOff`                                  | Pod 反复重启                      | eBPF 探针加载失败（缺少内核头文件或权限不足）  | 检查 `hostPath` 挂载了 `/lib/modules` 和 `/usr/src`；检查 `privileged: true` |
| `exec format error`                                 | 容器启动报错                      | 架构不匹配（如在 ARM 上跑了 AMD64 镜像）       | 确保构建和运行在同架构机器上                                 |
| BCC 编译报错 `fatal error: 'linux/bpf.h' not found` | eBPF C 代码编译失败               | 缺少内核头文件                                 | 确认挂载了宿主机的 `/usr/src` 和 `/lib/modules`              |
| 响应功能报错 `docker.errors.DockerException`        | 检测到逃逸但响应失败              | k3s 用 containerd，没有 Docker daemon          | Week 4 会修复（迁移到 K8s API）                              |

---

### 2.8 清理

```bash
# 删除 DaemonSet
kubectl delete -f daemonset-ebpf.yaml

# 删除 ConfigMap
kubectl delete configmap ebpf-rules ebpf-responses

# 删除本地镜像（containerd 里的）
sudo k3s ctr images rm docker.io/library/ebpf-detector:latest

# 删除 Docker 镜像
docker rmi ebpf-detector:latest
```

---

### 2.9 与后续章节的衔接

| Week     | 内容                   | 本章铺垫                                                     |
| -------- | ---------------------- | ------------------------------------------------------------ |
| Week 3   | K8s 网络与逃逸面       | `hostNetwork: true` 让我们理解 Pod 网络与宿主机网络的关系      |
| Week 4   | K8s API 编程           | 本章的 Pod 就是 Week 4 要操作的对象（list/delete Pod、创建 NetworkPolicy） |
| 第四小节 | K8s 下的 eBPF 安全实践 | 把本章的 `privileged: true` 降级为精细 capabilities          |

---


## 📖 相关文档

- **上一篇**: [WEEK 1 — K8s 环境搭建](./WEEK%201.md)
- **下一篇**: [WEEK 3 — K8s 网络与逃逸面](./WEEK%203.md)
- **代码目录**: [code/17-daemonset/](../../code/17-daemonset/)
*最后更新: 2026-07-29*