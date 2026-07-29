// ex1_list.c — 练习1: 列出 BPF 对象文件中所有程序的类型
// 对应《Learning eBPF》第7章
//
// 用法: sudo ./ex1_list <file.bpf.o>
//
// 功能: 打开 .bpf.o 文件, 遍历所有程序, 打印:
//       - 程序名称
//       - BPF_PROG_TYPE (程序类型)
//       - expected_attach_type (附加类型, 如 BPF_TRACE_KPROBE)
//       - autoload 状态
//
// 关键 API:
//   bpf_object__for_each_program()
//   bpf_program__name() / type() / expected_attach_type()

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>

// prog_type → 人类可读名称
static const char *prog_type_str(enum bpf_prog_type t)
{
    switch (t) {
    case BPF_PROG_TYPE_KPROBE:            return "KPROBE";
    case BPF_PROG_TYPE_TRACEPOINT:        return "TRACEPOINT";
    case BPF_PROG_TYPE_RAW_TRACEPOINT:    return "RAW_TRACEPOINT";
    case BPF_PROG_TYPE_TRACING:           return "TRACING (fentry/fexit)";
    case BPF_PROG_TYPE_XDP:               return "XDP";
    case BPF_PROG_TYPE_SCHED_CLS:         return "SCHED_CLS (TC)";
    case BPF_PROG_TYPE_LSM:               return "LSM";
    case BPF_PROG_TYPE_SOCKET_FILTER:     return "SOCKET_FILTER";
    case BPF_PROG_TYPE_CGROUP_SKB:        return "CGROUP_SKB";
    case BPF_PROG_TYPE_PERF_EVENT:        return "PERF_EVENT";
    case BPF_PROG_TYPE_UNSPEC:            return "UNSPEC (未指定)";
    default:                              return "(other)";
    }
}

static const char *attach_type_str(enum bpf_attach_type t)
{
    if (t == 0) return "(none / auto)";
    switch (t) {
    case BPF_TRACE_FENTRY:          return "fentry";
    case BPF_TRACE_FEXIT:           return "fexit";
    case BPF_TRACE_RAW_TP:          return "raw_tp";
    case BPF_LSM_MAC:               return "lsm_mac";
    case BPF_XDP:                   return "xdp";
    case BPF_CGROUP_INET_INGRESS:   return "cgroup_skb";
    case BPF_TRACE_ITER:            return "trace_iter";
    default:                        return "(other)";
    }
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;

    if (argc < 2) {
        fprintf(stderr, "用法: sudo %s <file.bpf.o>\n", argv[0]);
        fprintf(stderr, "示例: sudo %s prog_types.bpf.o\n", argv[0]);
        return 1;
    }

    obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        fprintf(stderr, "❌ 无法打开: %s\n", argv[1]);
        return 1;
    }

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║  📂 %-47s ║\n", argv[1]);
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║ %-20s │ %-18s │ %-12s ║\n", "程序名", "BPF_PROG_TYPE", "附加类型");

    int count = 0;
    bpf_object__for_each_program(prog, obj) {
        printf("║ %-20s │ %-18s │ %-12s ║\n",
               bpf_program__name(prog),
               prog_type_str(bpf_program__type(prog)),
               attach_type_str(bpf_program__expected_attach_type(prog)));
        count++;
    }

    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\n共 %d 个程序\n", count);

    bpf_object__close(obj);
    return 0;
}
