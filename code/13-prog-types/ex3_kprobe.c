// ex3_kprobe.c — 练习3: 手动 kprobe 附加
// 对应《Learning eBPF》第7章
//
// 用法: sudo ./ex3_kprobe <kprobe.bpf.o> [内核函数名]
//
// 功能: 从用户态手动指定 kprobe 目标函数 (不从 SEC 自动解析)
//       如果未指定函数名，列出 /proc/kallsyms 供参考
//
// 使用场景:
//   - 程序使用通用 SEC("kprobe") 而非 SEC("kprobe/<func>")
//   - 想动态决定挂钩哪个函数
//   - Fentry 不可用时的备选方案
//
// 关键 API:
//   bpf_program__attach_kprobe(prog, retprobe, func_name)

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
    const char *func_name;

    if (argc < 2) {
        fprintf(stderr, "用法: sudo %s <kprobe.bpf.o> [内核函数名]\n\n", argv[0]);
        fprintf(stderr, "示例:\n");
        fprintf(stderr, "  # 挂钩 do_sys_openat2 (每次文件打开都触发)\n");
        fprintf(stderr, "  sudo %s kprobe_custom.bpf.o do_sys_openat2\n\n", argv[0]);
        fprintf(stderr, "  # 挂钩 __x64_sys_execve (每次 execve 触发)\n");
        fprintf(stderr, "  sudo %s kprobe_custom.bpf.o __x64_sys_execve\n\n", argv[0]);
        fprintf(stderr, "  # 不指定函数名, 列出 /proc/kallsyms 前 20 行\n");
        fprintf(stderr, "  sudo %s kprobe_custom.bpf.o\n", argv[0]);
        return 1;
    }

    func_name = argc >= 3 ? argv[2] : NULL;
    if (!func_name) {
        printf("📋 未指定函数名, /proc/kallsyms 前 20 个可导出函数:\n");
        FILE *fp = fopen("/proc/kallsyms", "r");
        if (!fp) { perror("fopen /proc/kallsyms"); return 1; }
        char line[256];
        for (int i = 0; i < 20 && fgets(line, sizeof(line), fp); i++) {
            // 格式: <addr> <type> <name>
            // type: T/t = text (可 kprobe), W/w = weak
            char *p = line;
            while (*p && *p != ' ') p++;
            *p = '\0'; p++;
            char type = *p;
            p += 2; // skip type + space
            char *name = p;
            name[strcspn(name, "\n")] = '\0';
            if (type == 'T' || type == 't' || type == 'W' || type == 'w')
                printf("  [%c] %s\n", type, name);
        }
        fclose(fp);
        printf("\n💡 用法: sudo %s %s <函数名>\n", argv[0], argv[1]);
        return 0;
    }

    // ===== 1. 打开 BPF 对象 =====
    obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        fprintf(stderr, "❌ 无法打开: %s\n", argv[1]);
        return 1;
    }

    // ===== 2. 加载到内核 =====
    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "❌ 加载失败: %s (err=%d)\n", strerror(-err), -err);
        bpf_object__close(obj);
        return 1;
    }
    printf("✅ BPF 程序已加载到内核\n");

    // ===== 3. 手动附加 kprobe =====
    // 从 .bpf.o 中取第一个程序 (或按名字查找)
    prog = bpf_object__find_program_by_name(obj, "custom_kprobe");
    if (!prog) {
        // 如果没找到, 取第一个程序
        prog = bpf_object__next_program(obj, NULL);
    }

    if (!prog) {
        fprintf(stderr, "❌ 未找到任何程序\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("📌 程序: %s\n", bpf_program__name(prog));
    printf("🔗 手动附加 kprobe → %s ...\n", func_name);

    link = bpf_program__attach_kprobe(prog, false /* retprobe? */, func_name);
    if (!link) {
        fprintf(stderr, "❌ kprobe 附加失败: %s\n", strerror(errno));
        fprintf(stderr, "   ⚠️  函数名可能不存在, 请检查: cat /proc/kallsyms | grep %s\n",
                func_name);
        bpf_object__close(obj);
        return 1;
    }
    printf("✅ kprobe 已附加到 %s\n", func_name);

    // ===== 4. 等待信号 =====
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("\n⏸️  运行中, 按 Ctrl-C 停止\n");
    printf("   查看输出: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

    while (running) sleep(1);

    // ===== 5. 清理 =====
    bpf_link__destroy(link);
    bpf_object__close(obj);
    printf("🧹 已清理\n");
    return 0;
}
