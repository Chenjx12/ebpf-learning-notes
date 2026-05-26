def setup_tail_calls(bpf_obj, program_map):
    """设置尾调用映射表"""
    for index, prog_name in program_map.items():
        # 查找子程序的 fd
        prog = bpf_obj.load_func(prog_name, BPF.TRACEPOINT)
        # 更新尾调用映射表
        bpf_obj["tail_call_table"][ct.c_int(index)] = ct.c_int(prog.fd)
