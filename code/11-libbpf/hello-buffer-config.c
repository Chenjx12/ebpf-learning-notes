// hello-buffer-config.c — 用户态加载器 (Libbpf Skeleton 模式)
// 对应《Learning eBPF》第5章
//
// 核心流程:
//   open → 可选配置 → load → attach → poll → destroy

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "hello-buffer-config.h"
#include "hello-buffer-config.skel.h"  // bpftool gen skeleton 生成

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig) {
    running = 0;
}

// libbpf 日志回调 (打印到 stderr)
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

// Ring Buffer 事件处理回调
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct data_t *e = data;

    printf("%-8d %-6d %-16s → %-16s  %s\n",
           e->pid, e->uid, e->command, e->path, e->message);
    return 0;
}

int main(int argc, char **argv)
{
    struct hello_buffer_config_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;

    // ===== 1. 设置 libbpf 日志 =====
    libbpf_set_print(libbpf_print_fn);

    // ===== 2. 打开 BPF 对象 (读取 ELF, 不加载) =====
    skel = hello_buffer_config_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // ===== 3. 可选: 在 load 前修改全局变量 =====
    // ⚠️ 必须在 open() 之后、load() 之前!
    // 加载后 skel->data 的修改不会影响内核态
    strcpy(skel->data->message, "Hello eBPF!");

    // ===== 4. 写入 map 配置 (练习5) =====
    // 为 UID 0 (root) 设置自定义消息
    __u32 uid0 = 0;
    struct user_msg_t root_msg = { .message = "Hi root!" };
    bpf_map__update_elem(skel->maps.my_config, &uid0, sizeof(uid0), &root_msg, sizeof(root_msg), BPF_ANY);

    // 为 UID 1000 (普通用户) 设置自定义消息
    __u32 uid1000 = 1000;
    struct user_msg_t user_msg = { .message = "Hi user!" };
    bpf_map__update_elem(skel->maps.my_config, &uid1000, sizeof(uid1000), &user_msg, sizeof(user_msg), BPF_ANY);

    // ===== 5. 加载到内核 (CO-RE 重定位在此发生!) =====
    if (hello_buffer_config_bpf__load(skel) < 0) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    // ===== 6. 附加到事件 =====
    if (hello_buffer_config_bpf__attach(skel) < 0) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // ===== 7. 设置 Ring Buffer 消费 =====
    rb = ring_buffer__new(bpf_map__fd(skel->maps.output),
                          handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // ===== 8. 信号处理 =====
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("%-8s %-6s %-16s → %-16s  %s\n",
           "PID", "UID", "COMM", "PATH", "MESSAGE");
    printf("----------------------------------------"
           "----------------------------------------\n");

    // ===== 9. 事件循环 =====
    while (running) {
        int err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    hello_buffer_config_bpf__destroy(skel);
    return 0;
}
