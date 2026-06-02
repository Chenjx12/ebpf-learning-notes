// hello-buffer-config.h — 内核态和用户态共享的数据结构
// 对应《Learning eBPF》第5章 CO-RE/Libbpf 示例

#ifndef __HELLO_BUFFER_CONFIG_H__
#define __HELLO_BUFFER_CONFIG_H__

// 从内核传到用户态的事件数据结构
struct data_t {
    int  pid;
    int  uid;
    char command[16];    // 进程名 (bpf_get_current_comm)
    char message[12];    // 问候语 (来自全局变量或 map 配置)
    char path[16];       // execve 的文件路径
};

// 用户态可配置的每 UID 消息
struct user_msg_t {
    char message[12];
};

#endif /* __HELLO_BUFFER_CONFIG_H__ */
