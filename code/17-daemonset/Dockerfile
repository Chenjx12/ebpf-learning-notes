# Dockerfile — eBPF 逃逸检测系统 (BCC kprobe 版)
# 对应笔记: docs/Three-扩展/WEEK 2.md
#
# 使用 BCC kprobe__ 命名约定 (规避 kernel 6.8 tracepoint 兼容问题)
# kprobe 不需要 BCC 生成 tracepoint struct, 兼容所有内核版本

FROM ubuntu:22.04

# BCC 编译 + 运行时依赖
RUN apt-get update && apt-get install -y \
    bpfcc-tools \
    libbpfcc-dev \
    python3-bpfcc \
    python3-pip \
    python3-yaml \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install docker pyyaml

WORKDIR /app

COPY escape-detect.c .
COPY escape-respond.py detector.py responder.py .

RUN mkdir -p /app/config

CMD ["python3", "escape-respond.py", \
     "-r", "/app/config/rules.yaml", \
     "-s", "/app/config/responses.yaml"]
