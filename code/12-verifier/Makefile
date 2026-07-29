# Makefile — eBPF 验证器练习 (第6章)
# 编译所有练习的 .bpf.o 文件和加载器

# 架构检测
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu

# 工具链
CLANG    ?= clang
CFLAGS   := -Wall -O2 -g
LDFLAGS  := -L/usr/lib64 -lbpf -lelf -lz
BPF_CFLAGS := -target bpf -D __TARGET_ARCH_$(ARCH) $(INCLUDES) -Wall -O2 -g

# 练习文件
EX1_OBJ := ex1_boundary.bpf.o
EX2_OBJ := ex2_bounded_loop.bpf.o
EX3_OBJ := ex3_unbounded_loop.bpf.o
EX4_OBJ := ex4_wrong_helper.bpf.o
BPF_OBJS := $(EX1_OBJ) $(EX2_OBJ) $(EX3_OBJ) $(EX4_OBJ)

LOADER   := loader

.PHONY: all clean generate-vmlinux help

all: $(BPF_OBJS) $(LOADER)
	@echo ""
	@echo "  ✅ 全部编译完成!"
	@echo "  用法:  sudo ./loader <exercise.bpf.o>"
	@echo ""
	@echo "  练习列表:"
	@echo "    ./loader $(EX1_OBJ)   # 练习1: NULL 指针解引用 (预期拒绝)"
	@echo "    ./loader $(EX2_OBJ)   # 练习2: 有界循环 (预期通过)"
	@echo "    ./loader $(EX3_OBJ)   # 练习3: 无界循环 (预期拒绝)"
	@echo "    ./loader $(EX4_OBJ)   # 练习4: helper 白名单 (预期拒绝)"

# ===== 编译 eBPF 程序 (.bpf.c → .bpf.o) =====
$(EX1_OBJ): ex1_boundary.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@
	@echo "  ✅ $@"

$(EX2_OBJ): ex2_bounded_loop.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@
	@echo "  ✅ $@"

$(EX3_OBJ): ex3_unbounded_loop.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@
	@echo "  ✅ $@"

$(EX4_OBJ): ex4_wrong_helper.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@
	@echo "  ✅ $@"

# ===== 编译用户态加载器 =====
$(LOADER): loader.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  ✅ $@"

# ===== 生成 vmlinux.h =====
# 优先从 Ch5 复制 (如果存在且不旧), 否则重新生成
vmlinux.h:
	@if [ -f ../11-libbpf/vmlinux.h ]; then \
		echo "  📋 从 ../11-libbpf/ 复制 vmlinux.h"; \
		cp ../11-libbpf/vmlinux.h .; \
	else \
		echo "  🔧 生成 vmlinux.h (需要 bpftool)"; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

generate-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo "  ✅ vmlinux.h generated"

# ===== 清理 =====
clean:
	rm -f $(BPF_OBJS) $(LOADER)
	@echo "  🧹 Cleaned"

# ===== 帮助 =====
help:
	@echo "用法:"
	@echo "  make                       编译所有练习和加载器"
	@echo "  make generate-vmlinux      重新生成 vmlinux.h"
	@echo "  sudo ./loader ex1_boundary.bpf.o     运行练习1"
	@echo "  sudo ./loader ex2_bounded_loop.bpf.o 运行练习2"
	@echo "  sudo ./loader ex3_unbounded_loop.bpf.o 运行练习3"
	@echo "  sudo ./loader ex4_wrong_helper.bpf.o 运行练习4"
	@echo "  make clean                 清理编译产物"
	@echo ""
	@echo "所有练习的详细说明见:"
	@echo "  ../../docs/Two-回顾/二、eBPF 验证器.md"
