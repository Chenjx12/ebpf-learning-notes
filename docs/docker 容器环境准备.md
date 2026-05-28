# docker 容器环境准备

在 Ubuntu 22.04 上安装 Docker 非常简单，而且这个版本的内核默认使用 **Cgroup v2**，这对你第六篇的实验简直是天大的好消息（不用踩 v1 的天坑了）。

以下是为你量身定制的安装与实验环境准备指南：

### 一、安装 Docker（官方推荐方式）

不要用 `apt install docker.io`，那个版本太老。用 Docker 官方源装最新稳定版：

```bash
# 1. 卸载可能存在的旧版本
sudo apt-get remove docker docker-engine docker.io containerd runc

# 2. 更新包索引并安装依赖
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# 3. 添加 Docker 官方 GPG 密钥
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# 4. 设置 Docker 官方稳定版仓库
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 5. 安装 Docker Engine
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

#### ⚠️ 关键的免sudo设置（你可能需要这个！）

在第六篇的代码里，我们用到了 `docker.from_env()`。如果你的 Python 脚本不以 root 运行，或者你的当前用户不在 docker 组里，**会报权限错误**。但是ebpf程序来说是必须用root才能执行的，那 `sudo python3` 下 `docker.from_env()` 自动就有 root 权限，根本不需要加 docker 组。但是考虑到我们后续的实验会频繁在其他终端操作 docker ，如果不加组，终端 B 的每条 docker 命令都得加 `sudo` ，就比较麻烦。

```bash
# 将当前用户加入 docker 组
sudo usermod -aG docker $USER

# 关键：让组权限立即生效（重新登录）
reboot

# 验证：不用 sudo 也能跑
docker run hello-world
```

### 二、实验该拉取哪些容器？

为了配合实验，你需要准备**三种不同形态**的容器，用来验证你的 eBPF 探针在不同场景下都能正确拿到 Cgroup ID 和 Namespace。

#### 1. 基础交互型容器：`ubuntu:22.04`

- **用途**：模拟在容器里敲命令的场景，测试对 `bash`、`ls`、`cat` 等 `execve` 事件的捕获。
- **为什么选它**：和你宿主机系统一致，行为好预测，自带 `bash`。

```bash
# 拉取镜像
docker pull ubuntu:22.04

# 实验命令：后台启动，并给它起个专属名字
docker run -itd --name test_ubuntu ubuntu:22.04

# 进入容器执行命令（触发 execve）
docker exec -it test_ubuntu bash
# 在容器里敲：
ls
cat /etc/hostname
```

#### 2. 极短生命周期容器：`alpine`

- **用途**：测试探针能否抓住“一闪而过”的短进程。
- **为什么选它**：只有 5MB，启动极快，适合做 `docker run --rm alpine ls` 这种瞬发测试。

```bash
docker pull alpine

# 实验命令：执行完立刻销毁（测试瞬态事件捕获）
docker run --rm alpine ls
```

#### 3. 常驻服务型容器：`nginx`

- **用途**：模拟真实的云原生业务容器。测试对后台守护进程及其 Worker 进程的持续监控。
- **为什么选它**：Nginx 启动后会有 `master` 和 `worker` 两种进程，非常适合验证 Python 映射表里 `Cgroup ID -> 容器名` 的绑定是否稳固。
- 当然……小小私心，如果 MVP 跑通了，后面想做可视化面板的话也要用到的

```bash
docker pull nginx

# 实验命令：后台启动
docker run -d --name my_nginx nginx

# 查看 nginx 的 worker 进程（宿主机视角）
ps aux | grep nginx
```

### 三、实验前的重要确认（避坑指南）

在 Python 代码 `sync_container_map()` 中，我们用了 `os.stat(cgroup_path)` 来获取 Inode。**在 Ubuntu 22.04 上，这个路径必须搞对！**

确认你的系统使用的是 Cgroup v2（默认是）：

```bash
mount | grep cgroup
# 如果看到 type cgroup2，那就是 v2，一切好说
```

在 Ubuntu 22.04 (Cgroup v2 + systemd) 下，Docker 容器的 Cgroup 路径格式为：

```bash
/sys/fs/cgroup/system.slice/docker-<容器长ID>.scope
```

你可以提前手动验证一下这个路径是否存在：

```bash
# 1. 启动测试容器
docker run -itd --name test_ns ubuntu

# 2. 获取长 ID
docker inspect test_ns | grep Id

# 3. 拼接路径并查看 (把 <长ID> 替换成上面获取的值)
ls /sys/fs/cgroup/system.slice/docker-<长ID>.scope/

# 4. 查看 Inode（这个数字就是你 eBPF 抓到的 cgroup_id！）
stat /sys/fs/cgroup/system.slice/docker-<长ID>.scope/
```

如果上面这一步你能顺利看到 Inode，说明你的环境 100% 啦