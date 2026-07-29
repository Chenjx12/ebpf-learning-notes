# Makefile — eBPF 程序类型与附加点练习 (第7章)

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu

CLANG    ?= clang
CFLAGS   := -Wall -O2 -g
LDFLAGS  := -L/usr/lib64 -lbpf -lelf -lz
BPF_CFLAGS := -target bpf -D __TARGET_ARCH_$(ARCH) $(INCLUDES) -Wall -O2 -g

# BPF 对象文件
PROG_TYPES_OBJ := prog_types.bpf.o
KPROBE_OBJ     := kprobe_custom.bpf.o
TP_OBJ         := tp_custom.bpf.o

# 用户态可执行文件
EX1 := ex1_list
EX2 := ex2_selective
EX3 := ex3_kprobe
EX4 := ex4_tracepoint
BINS := $(EX1) $(EX2) $(EX3) $(EX4)

.PHONY: all clean generate-vmlinux help

all: $(PROG_TYPES_OBJ) $(KPROBE_OBJ) $(TP_OBJ) $(BINS)
	@echo ""
	@echo "  ✅ 全部编译完成!"
	@echo ""
	@echo "  练习列表:"
	@echo "    sudo ./ex1_list prog_types.bpf.o            # 查看程序类型"
	@echo "    sudo ./ex2_selective prog_types.bpf.o <prog> # 选择性加载"
	@echo "    sudo ./ex3_kprobe kprobe_custom.bpf.o <func> # 手动 kprobe"
	@echo "    sudo ./ex4_tracepoint tp_custom.bpf.o <cat> <name>  # 手动 tracepoint"

# ===== 编译 eBPF 程序 =====
$(PROG_TYPES_OBJ): prog_types.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@
	@echo "  ✅ $@"

$(KPROBE_OBJ): kprobe_custom.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@
	@echo "  ✅ $@"

$(TP_OBJ): tp_custom.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@
	@echo "  ✅ $@"

# ===== 编译用户态程序 =====
$(EX1): ex1_list.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  ✅ $@"

$(EX2): ex2_selective.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  ✅ $@"

$(EX3): ex3_kprobe.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  ✅ $@"

$(EX4): ex4_tracepoint.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  ✅ $@"

# ===== vmlinux.h =====
vmlinux.h:
	@if [ -f ../11-libbpf/vmlinux.h ]; then \
		echo "  📋 从 ../11-libbpf/ 复制 vmlinux.h"; \
		cp ../11-libbpf/vmlinux.h .; \
	else \
		echo "  🔧 生成 vmlinux.h"; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

generate-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo "  ✅ vmlinux.h generated"

clean:
	rm -f $(PROG_TYPES_OBJ) $(KPROBE_OBJ) $(TP_OBJ) $(BINS)
	@echo "  🧹 Cleaned"

help:
	@echo "用法:"
	@echo "  make                       编译所有练习"
	@echo "  make generate-vmlinux      重新生成 vmlinux.h"
	@echo "  sudo ./ex1_list prog_types.bpf.o              练习1: 查看程序类型"
	@echo "  sudo ./ex2_selective prog_types.bpf.o <name>  练习2: 选择性加载"
	@echo "  sudo ./ex3_kprobe kprobe_custom.bpf.o <func>  练习3: 手动 kprobe"
	@echo "  sudo ./ex4_tracepoint tp_custom.bpf.o <c> <n> 练习4: 手动 tracepoint"
	@echo "  make clean                 清理编译产物"
