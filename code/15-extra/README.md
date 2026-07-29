# 补充练习代码

> Ch2/Ch3/Ch4/Ch8/Ch10 练习合集

## 📂 结构

| 子目录 | 来源 | 类型 | 状态 |
|--------|------|------|:--:|
| [ch2/](./ch2/) | Ch2 Hello World | 5 个 BCC Python 脚本 | ✅ |
| [ch3/](./ch3/) | Ch3 程序剖析 | bpftool 命令 (shell) | ✅ |
| [ch4/](./ch4/) | Ch4 bpf() 系统调用 | bpftool/strace (shell) | ✅ |
| [ch8-xdp/](./ch8-xdp/) | Ch8 网络 eBPF | XDP C 程序 | ✅ |
| [ch10-hello-go/](./ch10-hello-go/) | Ch10 eBPF 编程 | Go + cilium/ebpf | ⚠️ 需 Go |

## 🚀 快速开始

```bash
# === Ch2: BCC Python (最简单, 直接跑) ===
cd ch2
sudo python3 ex1-odd-even.py

# === Ch3: bpftool 命令 (按章节顺序执行) ===
cd ch3
bash ch3-bpftool.sh

# === Ch4: bpftool + strace ===
cd ch4
bash ch4-bpf-syscall.sh

# === Ch8: XDP ping 区分 ICMP Echo/Reply ===
cd ch8-xdp
make
sudo ./ping-xdp lo          # 加载到 lo 接口

# 另一个终端 ping 触发
ping -c 3 127.0.0.1

# 查看输出
sudo cat /sys/kernel/debug/tracing/trace_pipe

# === Ch10: Go + cilium/ebpf (需先装 Go) ===
sudo snap install go --classic   # 或 apt install golang-go
cd ch10-hello-go
go mod init hello-ebpf
go mod tidy
go build -o hello-ebpf .
sudo ./hello-ebpf
```

## 📖 相关文档

- **第二小节笔记**: [docs/Two-回顾/](../../docs/Two-回顾/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)

---

*最后更新: 2026-07-29*
