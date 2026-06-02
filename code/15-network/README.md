# eBPF 示例代码 (第九篇: 用于网络的 eBPF)

> 《Learning eBPF》第 8 章练习 — 可选章节

## 📂 文件列表

| 文件名 | 说明 | 难度 |
|--------|------|------|
| ping.bpf.c | XDP 程序 (区分 ping 请求/响应) | ⭐⭐⭐ |
| Makefile | 编译脚本 | ⭐⭐ |

## 🚀 快速开始

```bash
make
# 附加 XDP 程序到网口
sudo ip link set dev eth0 xdp obj ping.bpf.o sec xdp
# 查看
ip link show eth0
# 卸载
sudo ip link set dev eth0 xdp off
```

## 📝 练习

### 练习 1: 区分 ICMP Echo/Reply
修改 XDP `ping()` 函数，解析 ICMP 头 (`struct icmphdr`)，根据 `type` 字段 (ICMP_ECHO vs ICMP_ECHOREPLY) 输出不同 trace。

### 练习 2: xdp-tutorial (进阶)
[xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)

### 练习 3: sslsniff
用 BCC 的 [sslsniff.py](https://github.com/iovisor/bcc/blob/master/tools/sslsniff.py) 查看加密流量内容。

### 练习 4: Cilium 实验
[Cilium 入门教程](https://cilium.io/get-started/)

### 练习 5: NetworkPolicy 可视化
[networkpolicy.io](https://networkpolicy.io/) 编辑器

## 📖 相关文档

- **上一篇**: [用于安全的 eBPF](../14-security/)
- **下一篇**: [eBPF 编程](../16-programming/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)
