// ex4_tracepoint.c — 练习4: 自定义 tracepoint 附加
// 对应《Learning eBPF》第7章
//
// 用法: sudo ./ex4_tracepoint <tp.bpf.o> <category> <name>
//
// 功能: 手动指定 tracepoint 的 category 和 name 进行附加
//       可附加到任意 available_events 中的 tracepoint
//
// 关键 API: bpf_program__attach_tracepoint(prog, category, name)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t running = 1;
static void sig_handler(int sig) { running = 0; }

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;

    if (argc < 4) {
        fprintf(stderr, "用法: sudo %s <tp.bpf.o> <category> <name>\n\n", argv[0]);
        fprintf(stderr, "示例:\n");
        fprintf(stderr, "  sudo %s tp_custom.bpf.o sched sched_process_exec\n", argv[0]);
        fprintf(stderr, "  sudo %s tp_custom.bpf.o syscalls sys_enter_openat\n", argv[0]);
        fprintf(stderr, "  sudo %s tp_custom.bpf.o syscalls sys_enter_execve\n", argv[0]);
        fprintf(stderr, "\n💡 可用 tracepoint 列表:\n");
        fprintf(stderr, "  sudo cat /sys/kernel/debug/tracing/available_events | head -20\n");
        return 1;
    }

    // ===== 1. 打开 & 加载 =====
    obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) { fprintf(stderr, "❌ 无法打开: %s\n", argv[1]); return 1; }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "❌ 加载失败: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    printf("✅ BPF 程序已加载到内核\n");

    // ===== 2. 手动附加 tracepoint =====
    prog = bpf_object__find_program_by_name(obj, "custom_tp");
    if (!prog) prog = bpf_object__next_program(obj, NULL);
    if (!prog) { fprintf(stderr, "❌ 未找到程序\n"); bpf_object__close(obj); return 1; }

    printf("📌 程序: %s\n", bpf_program__name(prog));
    printf("🔗 手动附加 tracepoint → %s/%s ...\n", argv[2], argv[3]);

    link = bpf_program__attach_tracepoint(prog, argv[2], argv[3]);
    if (!link) {
        fprintf(stderr, "❌ tracepoint 附加失败: %s\n", strerror(errno));
        fprintf(stderr, "   ⚠️  检查是否存在: cat /sys/kernel/debug/tracing/available_events | grep %s/%s\n",
                argv[2], argv[3]);
        bpf_object__close(obj);
        return 1;
    }
    printf("✅ tracepoint 已附加到 %s/%s\n", argv[2], argv[3]);

    // ===== 3. 等待 =====
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("\n⏸️  运行中, 按 Ctrl-C 停止\n");
    printf("   查看输出: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

    while (running) sleep(1);

    bpf_link__destroy(link);
    bpf_object__close(obj);
    printf("🧹 已清理\n");
    return 0;
}
