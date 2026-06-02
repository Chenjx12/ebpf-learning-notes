// ping-xdp.bpf.c — Ch8 练习1: XDP 程序区分 ICMP Echo/Reply
// 解析 ICMP 头, 根据 type 字段输出不同的 bpf_printk 消息
//   ICMP_ECHO (type=8):  ping 请求
//   ICMP_ECHOREPLY (type=0): ping 响应

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>   // struct ethhdr, ETH_P_IP
#include <linux/ip.h>          // struct iphdr
#include <linux/icmp.h>        // struct icmphdr, ICMP_ECHO, ICMP_ECHOREPLY

SEC("xdp")
int ping(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. 以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. 只处理 IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // 3. IP 头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 4. 只处理 ICMP
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // 5. ICMP 头 (紧跟在 IP 头后)
    struct icmphdr *icmp = (void *)(ip + 1);
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    // 6. 区分 Echo Request vs Echo Reply
    switch (icmp->type) {
    case ICMP_ECHO:       // type=8  ping 请求
        bpf_printk("📤 PING REQUEST");
        break;
    case ICMP_ECHOREPLY:  // type=0  ping 响应
        bpf_printk("📥 PING REPLY");
        break;
    default:
        bpf_printk("📡 ICMP type=%d", icmp->type);
        break;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
