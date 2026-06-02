# eBPF 示例代码 (Ch2 复习练习)

> 《Learning eBPF》第 2 章练习 — BCC Hello World 变体

## 📝 练习

### 练习 1: 区分奇偶 PID
修改 `hello-buffer.py`, 对奇数和偶数 PID 输出不同 trace 消息。

### 练习 2: 多系统调用触发
将 eBPF 程序附加到多个 syscall kprobes (如 openat + write), 演示多个程序访问同一个 map。

### 练习 3: sys_enter raw tracepoint
修改 `hello-map.py`, 附加到 `sys_enter` raw tracepoint, 统计每个 UID 的总系统调用数。

### 练习 4: RAW_TRACEPOINT_PROBE 宏
用 BCC 的 `RAW_TRACEPOINT_PROBE(sys_enter)` 宏简化附加过程, 移除显式的 `attach_raw_tracepoint()`。

### 练习 5: 按系统调用类型统计
修改 hash map, 使 key 标识特定系统调用 (而非 UID), 输出每种系统调用的调用次数。

## 📖 相关文档

- **下一篇**: [Ch3 练习](../18-ch3-exercises/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)
