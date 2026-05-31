#!/bin/bash
# perf-load-gen.sh — 生成受控 openat 负载
# 用法: bash perf-load-gen.sh <进程数> <秒数>
# 例: bash perf-load-gen.sh 4 15  → 4个进程同时跑15秒

WORKERS=${1:-4}
DURATION=${2:-15}
TARGET_DIR="/usr/lib"

echo "[LoadGen] 启动 ${WORKERS} 个工作进程，持续 ${DURATION} 秒"
echo "[LoadGen] 目标目录: ${TARGET_DIR}"

for i in $(seq 1 $WORKERS); do
    (
        END_TS=$(( $(date +%s) + DURATION ))
        while [ $(date +%s) -lt $END_TS ]; do
            find ${TARGET_DIR} -type f -name '*.so*' -exec cat {} \; 2>/dev/null
        done
    ) &
done

echo "[LoadGen] PID: $! (pgroup)"
wait
echo "[LoadGen] 完成"
