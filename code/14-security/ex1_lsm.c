// ex1_lsm.c — BPF LSM 加载器
// 对应《Learning eBPF》第9章
//
// 用法: sudo ./ex1_lsm lsm_block.bpf.o
//
// 加载后会阻止所有 chmod 操作, 直到 Ctrl-C 卸载
// 测试: 在新终端执行 chmod 777 /tmp/test → Permission denied

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

    if (argc < 2) {
        fprintf(stderr, "用法: sudo %s <lsm.bpf.o>\n", argv[0]);
        fprintf(stderr, "示例: sudo %s lsm_block.bpf.o\n", argv[0]);
        return 1;
    }

    // ===== 0. 检查 BPF LSM 是否启用 =====
    // CONFIG_BPF_LSM=y 只是编译进内核, 还需要 lsm=...,bpf 才真正激活
    FILE *fp = fopen("/sys/kernel/security/lsm", "r");
    if (fp) {
        char line[256] = {0};
        (void)!fgets(line, sizeof(line), fp);
        fclose(fp);
        if (!strstr(line, "bpf")) {
            printf("⚠️  BPF LSM 未激活! (活跃 LSM: %s)", line);
            printf("\n   CONFIG_BPF_LSM=y 已编译, 但内核未启用 bpf LSM.\n");
            printf("   程序会加载成功, 但 LSM hook 不会被内核调用!\n\n");
            printf("   修复方法 (需重启):\n");
            printf("   1. sudo vi /etc/default/grub\n");
            printf("   2. 找到 GRUB_CMDLINE_LINUX, 在 lsm= 值末尾添加 ,bpf\n");
            printf("      例如: lsm=lockdown,capability,landlock,yama,apparmor,bpf\n");
            printf("   3. sudo update-grub && sudo reboot\n\n");
        }
    }

    // ===== 1. 打开 & 加载 =====
    obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        fprintf(stderr, "❌ 无法打开: %s\n", argv[1]);
        return 1;
    }

    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "❌ 加载失败: %s (err=%d)\n", strerror(-err), -err);
        fprintf(stderr, "   ⚠️  需要: kernel ≥ 5.7, CONFIG_BPF_LSM=y\n");
        bpf_object__close(obj);
        return 1;
    }
    printf("✅ LSM 程序已加载到内核\n");

    // ===== 2. 附加到 LSM hook =====
    prog = bpf_object__find_program_by_name(obj, "block_chmod");
    if (!prog) prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "❌ 未找到程序\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "❌ 附加失败: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    printf("🔗 LSM 已附加到 path_chmod\n");
    printf("   🛡️  所有 chmod 操作已被阻断!\n\n");

    // ===== 3. 等待卸载 =====
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("⏸️  运行中, 按 Ctrl-C 卸载\n");
    printf("   测试 (另一个终端): chmod 777 /tmp/test\n");
    printf("   预期结果: chmod: changing permissions of '/tmp/test': Operation not permitted\n\n");

    while (running) sleep(1);

    // ===== 4. 清理 =====
    bpf_link__destroy(link);
    bpf_object__close(obj);
    printf("🧹 LSM 已卸载, chmod 恢复正常\n");
    return 0;
}
