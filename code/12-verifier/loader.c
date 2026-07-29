// loader.c — 通用 eBPF 验证器练习加载器
// 对应《Learning eBPF》第6章练习
//
// 用法: sudo ./loader <file.bpf.o>
//
// 功能: 加载指定的 BPF 对象文件，打印详细的验证器日志
//       - 验证通过 → 显示成功信息
//       - 验证拒绝 → 显示完整的验证器错误日志

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>

// 抑制 libbpf 自身的日志 (验证器日志通过 kernel_log_buf 获取)
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    // 只打印 WARN 和 ERROR，跳过 INFO/DEBUG (减少噪音)
    if (level <= LIBBPF_WARN)
        return vfprintf(stderr, format, args);
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    int err;

    if (argc < 2) {
        fprintf(stderr, "用法: sudo %s <file.bpf.o>\n\n", argv[0]);
        fprintf(stderr, "示例:\n");
        fprintf(stderr, "  sudo %s ex1_boundary.bpf.o       # 练习1: NULL 解引用 (拒绝)\n", argv[0]);
        fprintf(stderr, "  sudo %s ex2_bounded_loop.bpf.o   # 练习2: 有界循环 (通过)\n", argv[0]);
        fprintf(stderr, "  sudo %s ex3_unbounded_loop.bpf.o # 练习3: 无界循环 (拒绝)\n", argv[0]);
        fprintf(stderr, "  sudo %s ex4_wrong_helper.bpf.o   # 练习4: helper 白名单 (拒绝)\n", argv[0]);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    // 设置验证器详细日志: kernel_log_level=1 输出每条指令的寄存器状态
    char log_buf[1024 * 1024];  // 1 MB 日志缓冲区
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
        .kernel_log_buf   = log_buf,
        .kernel_log_size  = sizeof(log_buf),
        .kernel_log_level = 1,
    );

    // ===== 打开 BPF 对象 =====
    obj = bpf_object__open_file(argv[1], &opts);
    if (!obj) {
        fprintf(stderr, "❌ 无法打开 BPF 对象文件: %s\n", argv[1]);
        return 1;
    }

    // ===== 加载 (验证器在这里运行) =====
    err = bpf_object__load(obj);

    // ===== 输出结果 =====
    fprintf(stderr, "\n");
    fprintf(stderr, "╔══════════════════════════════════════╗\n");
    fprintf(stderr, "║  📂 文件: %-26s ║\n", argv[1]);

    if (err) {
        fprintf(stderr, "║  ❌ 结果: 验证器拒绝                  ║\n");
        fprintf(stderr, "║  错误码: %-3d (%-22s) ║\n", -err, strerror(-err));
        fprintf(stderr, "╚══════════════════════════════════════╝\n\n");

        // 打印内核验证器详细日志
        fprintf(stderr, "────── 验证器详细日志 ──────\n");
        if (log_buf[0] != '\0') {
            fprintf(stderr, "%s\n", log_buf);
        }
        fprintf(stderr, "──────────────────────────────\n\n");
        fprintf(stderr, "💡 验证器成功阻止了不安全的程序加载到内核。\n");
        fprintf(stderr, "   请仔细阅读上方日志中的错误描述，理解拒绝原因。\n");
    } else {
        fprintf(stderr, "║  ✅ 结果: 验证器通过                  ║\n");
        fprintf(stderr, "╚══════════════════════════════════════╝\n\n");
        if (log_buf[0] != '\0') {
            fprintf(stderr, "────── 验证器日志 ──────\n");
            fprintf(stderr, "%s\n", log_buf);
            fprintf(stderr, "──────────────────────────\n");
        }
    }

    bpf_object__close(obj);
    return 0;
}
