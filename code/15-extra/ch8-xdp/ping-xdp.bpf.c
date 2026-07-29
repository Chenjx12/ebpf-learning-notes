// ping-xdp.bpf.c — Ch8 练习1: XDP 程序区分 ICMP Echo/Reply
// 解析 ICMP 头, 根据 type 字段输出不同的 bpf_printk 消息
//   ICMP_ECHO (type=8):  ping 请求
//   ICMP_ECHOREPLY (type=0): ping 响应
//
// 注意: XDP 程序不需要 vmlinux.h (不需要内核内部结构体)
//       只需要解析网络包头的 <linux/if_ether.h> <linux/ip.h> <linux/icmp.h>

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
// 不要 #include <linux/icmp.h> — 它会级联引入 glibc 头文件 (BPF 目标不兼容)
// 直接内联需要的 ICMP 定义:
#define IPPROTO_ICMP    1
#define ICMP_ECHO       8
#define ICMP_ECHOREPLY  0

struct icmphdr {
    __u8  type;
    __u8  code;
    __sum16 checksum;
    union {
        struct { __be16 id; __be16 sequence; } echo;
        __be32 gateway;
        struct { __be16 __unused; __be16 mtu; } frag;
    } un;
};

// bpf_htons 在 <bpf/bpf_endian.h> 中
#include <bpf/bpf_endian.h>

SEC("xdp")
int ping(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. 以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. 只处理 IPv4 (ETH_P_IP = 0x0800, htons → 0x0008 on LE)
    if (eth->h_proto != bpf_htons(ETH_P_IP))
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
        bpf_printk("PING REQUEST");
        break;
    case ICMP_ECHOREPLY:  // type=0  ping 响应
        bpf_printk("PING REPLY");
        break;
    default:
        bpf_printk("ICMP type=%d", icmp->type);
        break;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
