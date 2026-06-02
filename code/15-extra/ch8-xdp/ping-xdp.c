// ping-xdp.c — Ch8 练习1: XDP 用户态加载器
// 使用方法:
//   sudo ./ping-xdp                    (加载到 eth0)
//   sudo ./ping-xdp eth0               (指定网口)
//   在另一终端 sudo cat /sys/kernel/debug/tracing/trace_pipe  看输出

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include "ping-xdp.skel.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig) { running = 0; }

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct ping_xdp_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    const char *ifname = (argc > 1) ? argv[1] : "eth0";
    int ifindex;

    libbpf_set_print(libbpf_print_fn);

    // 1. 获取网口索引
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Failed to get ifindex for %s\n", ifname);
        return 1;
    }

    // 2. 打开 + 加载
    skel = ping_xdp_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 3. 附加 XDP 程序 (⚠️ 一个网口只能有一个 XDP 程序!)
    link = bpf_program__attach_xdp(skel->progs.ping, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP to %s\n"
                "Hint: 可能已有 XDP 程序附加, 先卸载:\n"
                "  sudo ip link set dev %s xdp off\n", ifname, ifname);
        goto cleanup;
    }
    printf("[*] XDP 程序已附加到 %s (ifindex=%d)\n", ifname, ifindex);
    printf("[*] 查看输出: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("[*] 卸载:    sudo ip link set dev %s xdp off\n", ifname);

    // 4. 等待 Ctrl-C
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("[*] 按 Ctrl-C 退出...\n");
    while (running) {
        sleep(1);
    }

cleanup:
    bpf_link__destroy(link);
    ping_xdp_bpf__destroy(skel);
    printf("[*] 已卸载 XDP 程序\n");
    return 0;
}
