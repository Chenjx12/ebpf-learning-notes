# Dockerfile — eBPF 逃逸检测系统容器镜像
# 对应笔记: docs/Three-扩展/WEEK 2.md
#
# 构建: docker build -t ebpf-detector .
# 部署: kubectl apply -f daemonset.yaml

FROM ubuntu:22.04

# 安装 BCC + eBPF 运行时依赖
RUN apt-get update && apt-get install -y \
    bpfcc-tools \
    libbpfcc-dev \
    python3-bpfcc \
    python3-pip \
    python3-yaml \
    kmod \
    clang \
    llvm \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖 (Docker SDK for 响应)
RUN pip3 install docker pyyaml

# 创建工作目录
WORKDIR /app

# 复制 eBPF 探针 C 代码
COPY escape-detect.c .

# 复制 Python 程序
COPY escape-respond.py detector.py responder.py .

# 规则文件通过 ConfigMap 挂载到 /app/config/
# 不在镜像中硬编码规则
RUN mkdir -p /app/config

# 特权模式运行 (eBPF 需要)
CMD ["python3", "escape-respond.py", \
     "-r", "/app/config/rules.yaml", \
     "-s", "/app/config/responses.yaml"]
