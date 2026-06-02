# 补充练习代码

> Ch2/Ch3/Ch4/Ch8/Ch10 练习合集

## 📂 结构

| 子目录/文件 | 来源 | 类型 |
|------------|------|------|
| [ch2/](./ch2/) | Ch2 Hello World | 5 个 BCC Python 脚本 |
| [ch3/](./ch3/) | Ch3 程序剖析 | bpftool 命令 (shell) |
| [ch4/](./ch4/) | Ch4 bpf() 系统调用 | bpftool/strace 命令 (shell) |
| [ch8-xdp/](./ch8-xdp/) | Ch8 网络 eBPF | XDP C 程序 (练习1) |
| [ch10-hello-go/](./ch10-hello-go/) | Ch10 eBPF 编程 | Go + cilium/ebpf (练习1) |

## 🚀 快速开始

```bash
# Ch2 (BCC, 最简单)
cd ch2
sudo python3 ex1-odd-even.py

# Ch8 XDP
cd ch8-xdp
make && sudo ./ping-xdp

# Ch10 Go
cd ch10-hello-go
go build -o hello-ebpf . && sudo ./hello-ebpf
```

## 📖 相关文档

- **第二小节笔记**: [docs/Two-回顾/](../../docs/Two-回顾/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)
