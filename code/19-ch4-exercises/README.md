# eBPF 示例代码 (Ch4 复习练习)

> 《Learning eBPF》第 4 章练习 — bpf() 系统调用

## 📝 练习

### 练习 1: insn_cnt 验证
确认 `BPF_PROG_LOAD` 的 `insn_cnt` 字段与 `bpftool prog dump xlated` 的指令数匹配。

### 练习 2: 同名 map 的两个实例
运行两个示例程序实例 (两个名为 `config` 的 map)。`bpftool map dump name config` 查看两个 map, `strace` 跟踪文件描述符。

### 练习 3: bpftool map update 热修改
运行时用 `bpftool map update` 修改 `config` map, 用 `sudo -u username` 验证配置变更是否生效。

### 练习 4: bpftool pin 固定程序
```bash
bpftool prog pin name hello /sys/fs/bpf/hi
# 退出程序, bpftool prog list 确认仍在
rm /sys/fs/bpf/hi  # 清理
```

### 练习 5: RAW_TRACEPOINT + strace
将 hello-buffer-config.py 转换为 `RAW_TRACEPOINT_PROBE(sys_enter)`, `strace` 观察 `BPF_RAW_TRACEPOINT_OPEN` 系统调用。

### 练习 6: opensnoop + bpftool link
运行 BCC 的 opensnoop, 用 `bpftool link list` 查看 BPF 链接, 用 `bpftool prog list` 交叉验证程序 ID。

### 练习 7: bpftool link pin
```bash
bpftool link pin id <ID> /sys/fs/bpf/mylink
# 终止 opensnoop, 确认 link 和程序仍在内核中
```

### 练习 8: Libbpf 版 hello-buffer-config
运行 Ch5 的 libbpf 版 `hello-buffer-config`, 用 `strace` 检查 `BPF_LINK_CREATE` 系统调用。

## 📖 相关文档

- **上一篇**: [Ch3 练习](../18-ch3-exercises/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)
