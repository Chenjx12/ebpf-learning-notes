// ex2_selective.c — 练习2: 选择性加载单个程序
// 对应《Learning eBPF》第7章
//
// 用法: sudo ./ex2_selective <file.bpf.o> <程序名>
//
// 功能: 从多程序 .bpf.o 中只加载**一个**指定程序
//       不删除其他程序的源码, 用 autoload=false 禁用
//
// 关键 API: bpf_program__set_autoload(prog, false/true)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;

    if (argc < 3) {
        fprintf(stderr, "用法: sudo %s <file.bpf.o> <程序名>\n\n", argv[0]);
        fprintf(stderr, "示例: sudo %s prog_types.bpf.o kprobe_openat\n", argv[0]);
        fprintf(stderr, "       sudo %s prog_types.bpf.o tracepoint_exec\n", argv[0]);
        fprintf(stderr, "       sudo %s prog_types.bpf.o raw_tp_openat\n", argv[0]);
        return 1;
    }

    // ===== 1. 打开 BPF 对象 =====
    obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        fprintf(stderr, "❌ 无法打开: %s\n", argv[1]);
        return 1;
    }

    // ===== 2. 遍历所有程序, 只启用指定的那一个 =====
    // 关键步骤: bpf_program__set_autoload(prog, false) 告诉 libbpf
    // "不要加载这个程序", 然后只启用目标程序
    int found = 0;
    bpf_object__for_each_program(prog, obj) {
        if (strcmp(bpf_program__name(prog), argv[2]) == 0) {
            found = 1;
            // 目标程序保持 autoload=true (默认)
        } else {
            // 禁用其他所有程序
            bpf_program__set_autoload(prog, false);
            printf("⏭️  跳过: %s (autoload = false)\n",
                   bpf_program__name(prog));
        }
    }

    if (!found) {
        fprintf(stderr, "❌ 未找到程序: %s\n", argv[2]);
        fprintf(stderr, "   可用程序:\n");
        bpf_object__for_each_program(prog, obj) {
            fprintf(stderr, "     - %s\n", bpf_program__name(prog));
        }
        bpf_object__close(obj);
        return 1;
    }

    // ===== 3. 加载 (只加载 target) =====
    printf("✅ 加载: %s (autoload = true)\n", argv[2]);
    printf("⏳ 正在加载到内核...\n");

    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "❌ 加载失败: %s (err=%d)\n", strerror(-err), -err);
        bpf_object__close(obj);
        return 1;
    }
    printf("✅ 程序已加载到内核!\n\n");

    // ===== 4. 附加到事件 =====
    // bpf_object__attach() 只附加 autoload=true 的程序
    struct bpf_link *link = NULL;
    bpf_object__for_each_program(prog, obj) {
        // 只有 target 的 autoload=true, 所以这只会附加 target
        // 如果 SEC() 的命名不支持自动附加, 需要手动 attach
        link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "⚠️  自动附加失败 (%s), 尝试手动...\n",
                    bpf_program__name(prog));
        } else {
            printf("🔗 已附加: %s\n", bpf_program__name(prog));
            break;
        }
    }

    if (!link) {
        fprintf(stderr, "❌ 无法附加程序 (可能需要手动指定函数名)\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("\n⏸️  程序运行中, 按 Ctrl-C 停止...\n");
    printf("   查看输出: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");
    sleep(30);

    bpf_link__destroy(link);
    bpf_object__close(obj);
    printf("🧹 已清理\n");
    return 0;
}
