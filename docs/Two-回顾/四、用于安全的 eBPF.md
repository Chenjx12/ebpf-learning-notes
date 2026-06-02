# 四、用于安全的 eBPF

> 《Learning eBPF》第 9 章精读笔记 — 🎯 直接服务毕设

---

## 笔记前置

这一章是整本书对我的毕设最有价值的一章。作者梳理了 eBPF 安全从 seccomp-bpf 到 Tetragon 的完整演进路线。读完后最大的感受: 我之前的 tracepoint + 用户态 Python 响应引擎的思路是最"原始"的那一档，有两条明显的升级路径: **BPF LSM** 和 **Tetragon 模式**。

---

## 一、安全观测 vs 通用观测

关键区别: 安全工具需要**策略 (policy)** 来区分"正常"和"恶意"。

策略必须考虑:
- 正常行为 vs 异常行为
- **错误路径**: 磁盘满 → 发网络告警 → 不是恶意行为

**上下文**对事件调查至关重要:
- 谁? (UID, 容器 ID)
- 做了什么? (系统调用, 参数)
- 结果? (返回值, 影响)

---

## 二、Seccomp-bpf — 最早的 BPF 安全机制

### 特点
- 在每个 syscall 触发时执行 BPF filter
- 四种动作: ALLOW / ERRNO / KILL_THREAD / NOTIFY (5.0+)
- **不能解引用指针** (只能看 syscall 号 + 参数原始值)
- **进程启动时一次性应用**, 运行中不可修改

### 问题
Docker 默认 seccomp profile 过于宽松，因为必须兼容"几乎所有正常容器应用"。

---

## 三、Falco — Syscall 追踪 + 规则引擎

### 架构
- 附加到 `raw_syscalls/sys_enter` 和 `sys_exit`
- 用户写规则, Falco 匹配事件 → 生成告警
- 可以**对已运行的容器**应用策略 (优于 seccomp)

### 与我毕设的对比
我在第八篇做的 `rules.yaml` + `detector.py` 本质上就是 Falco 的简化版。差异:
- Falco 的规则引擎有宏 (macros) 和列表 (lists)，比我灵活得多
- Falco 有社区维护的[规则库](https://github.com/falcosecurity/rules)

### TOCTOU 问题
> "攻击者可以在 eBPF 程序检查参数后、内核复制参数前修改数据"

**这是我之前忽略的关键安全缺陷!** tracepoint 的参数来自用户态指针，存在竞争窗口。BPF LSM 可以解决这个问题。

---

## 四、BPF LSM — 内核态阻断 (5.7+)

### 核心优势

```
Tracepoint: 参数在用户态 → TOCTOU → 只能检测
LSM hook:   参数已在内核态 → 无 TOCTOU → 可以阻断
```

### 示例

```c
SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path, umode_t mode)
{
    // 在内核操作发生前就拒绝
    return -EPERM;  // 非零 = 拒绝
}
```

### 局限性
- 需要内核 ≥ 5.7 (很多企业发行版滞后)
- 只能挂在 LSM API 明确的 hook 上，不如 kprobe 灵活
- 我的虚拟机 kernel 6.8 支持 ✅

---

## 五、Cilium Tetragon — 最激进的方案

### 核心理念
不局限于稳定的 LSM 或 syscall 接口，而是**挂到任意内核函数上**。

### TracingPolicy
Kubernetes 自定义资源，定义事件、条件、动作。例如挂到 `fd_install` (文件描述符安装完成后的函数)，此时检查文件路径已无 TOCTOU 风险。

### 同步阻断: bpf_send_signal()
```c
bpf_send_signal(SIGKILL);  // 在内核态同步杀死进程
```
比用户态响应快几个数量级——进程在恶意操作完成前就被杀死。

### 实践建议
先 audit 模式跑，确认策略无误后再开启 Sigkill —— 策略写错了会把合法进程杀了。

---

## 六、对我毕设的启示

### 可以立即做的
1. 用 `SEC("lsm/path_chmod")` 替代 tracepoint 返回 `-EPERM` (需 LSM hook 覆盖 mount/ptrace)
2. 研究 Falco 的规则宏机制，改进 `rules.yaml`
3. 把 `bpf_send_signal(SIGKILL)` 加入第九篇的响应策略

### 长期方向
4. Tetragon 的 `TracingPolicy` CRD 模式 → 写一个简化版
5. 探索 `fd_install` 等非 syscall 的 hook 点

---

## 📝 实践任务 (替代练习)

- [ ] **任务 1**: 用 BPF LSM 实现阻断
- [ ] **任务 2**: 学习 Falco 规则引擎
- [ ] **任务 3**: 研究 Tetragon TracingPolicy
- [ ] **任务 4**: 理解 TOCTOU 与 LSM 的差异

---

## 📖 相关文档

- **上一篇**: [三、eBPF 程序类型与附加点](./三、eBPF%20程序类型与附加点.md)
- **代码目录**: [code/14-security/](../../code/14-security/)
- **FAQ**: [../../FAQ.md](../../FAQ.md)

---

*最后更新: 2026-06-02*
