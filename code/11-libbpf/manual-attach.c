// manual-attach.c — 练习6: 演示手动附加 kprobe
// 当 SEC() 名不被 libbpf 识别时 (如 "custom_ksyscall"),
// 需要通过 bpf_program__attach_kprobe() 显式指定附加点
//
// 编译: 在 Makefile 中添加 manual_attach target
// 运行: sudo ./manual-attach

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "hello-buffer-config.h"
#include "manual-attach.skel.h"  // 需要先用 bpftool gen skeleton 生成

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig) { running = 0; }

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct data_t *e = data;
    printf("%-8d %-6d %-16s → %-16s  %s\n",
           e->pid, e->uid, e->command, e->path, e->message);
    return 0;
}

int main(int argc, char **argv)
{
    struct manual_attach_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct bpf_link *link = NULL;

    libbpf_set_print(libbpf_print_fn);

    // ===== 1. 打开 BPF 对象 =====
    skel = manual_attach_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // ===== 2. 加载 (CO-RE 重定位) =====
    if (manual_attach_bpf__load(skel) < 0) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    // ===== 3. ⚠️ 手动附加 (关键区别!) =====
    // 标准做法: 调用 skel__attach() 自动附加所有 SEC() 程序
    // 手动做法: 找到要附加的 kprobe 函数名, 用 bpf_program__attach_kprobe()
    //
    // 查找 execve 在内核中的实际函数名:
    //   $ grep execve /proc/kallsyms | grep sys
    //   输出类似: __x64_sys_execve 或 __arm64_sys_execve
    //
    // 也可用 BPF_KPROBE_SYSCALL 宏自动展开的 kprobe 名:
    //   x86:    "__x64_sys_execve"
    //   arm64:  "__arm64_sys_execve"

    const char *kprobe_func = "__x64_sys_execve";  // x86_64
    // const char *kprobe_func = "__arm64_sys_execve";  // ARM64

    struct bpf_program *prog = bpf_object__find_program_by_name(
        skel->obj, "hello");
    if (!prog) {
        fprintf(stderr, "Failed to find program 'hello'\n");
        goto cleanup;
    }

    link = bpf_program__attach_kprobe(prog, false /* retprobe */,
                                      kprobe_func);
    if (!link) {
        fprintf(stderr, "Failed to attach kprobe to %s\n"
                "Hint: check /proc/kallsyms for the correct function name\n",
                kprobe_func);
        goto cleanup;
    }
    printf("[*] Manually attached to kprobe:%s\n", kprobe_func);

    // ===== 4. Ring Buffer =====
    rb = ring_buffer__new(bpf_map__fd(skel->maps.output),
                          handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("%-8s %-6s %-16s → %-16s  %s\n",
           "PID", "UID", "COMM", "PATH", "MESSAGE");
    printf("----------------------------------------"
           "----------------------------------------\n");

    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) break;
    }

cleanup:
    bpf_link__destroy(link);  // 手动创建的 link 需手动销毁
    ring_buffer__free(rb);
    manual_attach_bpf__destroy(skel);
    return 0;
}
