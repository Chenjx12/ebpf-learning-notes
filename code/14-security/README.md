# eBPF 示例代码 (第八篇: 用于安全的 eBPF)

> 《Learning eBPF》第 9 章 — 🎯 毕设核心章节

**对应笔记**: [四、用于安全的 eBPF](../../docs/Two-回顾/四、用于安全的%20eBPF.md)

## 📂 文件列表

| 文件名 | 说明 | 练习 |
|--------|------|:--:|
| `lsm_block.bpf.c` | BPF LSM 程序 — hook `path_chmod` 拒绝所有 chmod | 1, 2 |
| `ex1_lsm.c` | 加载器, 自动检测 BPF LSM 是否激活 | 1 |
| `Makefile` | 编译脚本 | — |

## 🚀 快速开始

```bash
make
sudo ./ex1_lsm lsm_block.bpf.o   # 阻断所有 chmod
```

### ⚠️ 前置: 激活 BPF LSM

`CONFIG_BPF_LSM=y` 只是编译进内核, 还需要内核命令行激活。运行加载器会自动检测并提示。

**修复 (需重启一次)**:

```bash
# 1. 编辑 grub
sudo vi /etc/default/grub

# 2. 在 GRUB_CMDLINE_LINUX 的 lsm= 值末尾加 ,bpf
#    改前: lsm=lockdown,capability,landlock,yama,apparmor
#    改后: lsm=lockdown,capability,landlock,yama,apparmor,bpf

# 3. 更新 grub 并重启
sudo update-grub && sudo reboot

# 4. 验证
cat /sys/kernel/security/lsm
# 应包含 ",bpf"
```

## 🔨 实践任务

本章笔记覆盖了完整的 eBPF 安全演进路线 (Seccomp → Falco → LSM → Tetragon)，代码聚焦于核心案例:

- [ ] **任务 1**: 启用 BPF LSM，加载 `lsm_block.bpf.o`，验证 `chmod` 被阻断
- [ ] **任务 2**: 修改 `lsm_block.bpf.c` 实现条件阻断 (如只拒绝 SUID 位设置)
- [ ] **任务 3**: 阅读笔记中的 Falco/Tetragon/TOCTOU 分析，梳理对自己毕设的改进思路

## 📖 关键工具对比

| 工具 | 机制 | 优势 | 劣势 |
|------|------|------|------|
| Seccomp-bpf | 每进程 syscall 过滤 | 最早支持 | 静态, 不能解引用指针 |
| Falco | syscall tracepoint + 规则 | 可对运行中容器应用 | 只能告警, 有 TOCTOU |
| BPF LSM | LSM hook 返回非零 | 内核态阻断, 无 TOCTOU | 需 5.7+, lsm=bpf 内核参数 |
| Tetragon | 任意内核函数 + SIGKILL | 最灵活, 同步杀死进程 | 依赖非稳定内核函数 |

## 📖 相关文档

- **上一篇**: [eBPF 程序类型与附加点](../13-prog-types/)
- **下一篇**: [补充练习](../15-extra/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)

---

*最后更新: 2026-07-29*
