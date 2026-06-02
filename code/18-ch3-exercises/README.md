# eBPF 示例代码 (Ch3 复习练习)

> 《Learning eBPF》第 3 章练习 — eBPF 程序剖析 (bpftool 实操)

## 📝 练习

### 练习 1: ip link 附加/卸载 XDP
```bash
sudo ip link set dev eth0 xdp obj hello.bpf.o sec xdp
sudo ip link set dev eth0 xdp off
```

### 练习 2: bpftool 检查运行中程序
运行 Ch2 的 BCC 示例时, 在另一终端用 `bpftool prog list` 和 `bpftool prog dump xlated` 检查加载的程序。

### 练习 3: bpftool 检查 tail call 程序
运行 `hello-tail.py`, 用 `bpftool prog dump xlated` 对比 tail call 程序的字节码与 BPF-to-BPF 调用的差异。

### 练习 4: XDP_ABORTED 的威力 (仅思考!)
XDP 程序返回 0 = `XDP_ABORTED`, 会丢弃所有网络包。思考: 如果附加到 eth0 会怎样? (建议在容器中测试)

## 📖 相关文档

- **上一篇**: [Ch2 练习](../17-ch2-exercises/)
- **下一篇**: [Ch4 练习](../19-ch4-exercises/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)
