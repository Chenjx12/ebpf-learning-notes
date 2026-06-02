# Makefile — CO-RE / Libbpf 编译脚本
# 对应《Learning eBPF》第5章

# 架构检测
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu

# 工具链
CLANG    ?= clang
BPFTOOL  ?= bpftool
CFLAGS   := -Wall -O2 -g
BPF_CFLAGS := -target bpf -D __TARGET_ARCH_$(ARCH) $(INCLUDES) -Wall -O2 -g

# 主程序
BPF_OBJ  := hello-buffer-config.bpf.o
SKEL_H   := hello-buffer-config.skel.h
USER_BIN := hello-buffer-config

# 练习6: 手动附加
MANUAL_BPF_OBJ  := manual-attach.bpf.o
MANUAL_SKEL_H   := manual-attach.skel.h
MANUAL_BIN      := manual-attach

.PHONY: all manual-attach-all clean generate-vmlinux help

all: $(USER_BIN)

manual-attach-all: $(MANUAL_BIN)

# ===== 1. 编译 eBPF 内核程序 (.bpf.c → .bpf.o) =====
$(BPF_OBJ): hello-buffer-config.bpf.c hello-buffer-config.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@
	@echo "  ✅ eBPF object compiled: $@"

# ===== 2. 生成 BPF Skeleton 头文件 =====
$(SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@
	@echo "  ✅ Skeleton header generated: $@"

# ===== 3. 编译用户态加载器 =====
$(USER_BIN): hello-buffer-config.c $(SKEL_H) hello-buffer-config.h
	$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf -lz
	@echo "  ✅ Userspace loader compiled: $@"

# ===== 练习6: 手动附加版本 =====
$(MANUAL_BPF_OBJ): manual-attach.bpf.c hello-buffer-config.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@
	@echo "  ✅ [Exercise 6] eBPF object compiled: $@"

$(MANUAL_SKEL_H): $(MANUAL_BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@
	@echo "  ✅ [Exercise 6] Skeleton header generated: $@"

$(MANUAL_BIN): manual-attach.c $(MANUAL_SKEL_H) hello-buffer-config.h
	$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf -lz
	@echo "  ✅ [Exercise 6] Manual-attach loader compiled: $@"

# ===== 生成 vmlinux.h (CO-RE 必需) =====
generate-vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo "  ✅ vmlinux.h generated"

# ===== 清理 =====
clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(USER_BIN)
	rm -f $(MANUAL_BPF_OBJ) $(MANUAL_SKEL_H) $(MANUAL_BIN)
	@echo "  🧹 Cleaned"

# ===== 帮助 =====
help:
	@echo "用法:"
	@echo "  make generate-vmlinux   生成 vmlinux.h (首次运行前必须)"
	@echo "  make                   编译主程序 (hello-buffer-config)"
	@echo "  make manual-attach-all  编译练习6 (手动附加版本)"
	@echo "  sudo ./hello-buffer-config     运行主程序"
	@echo "  sudo ./manual-attach           运行练习6"
	@echo "  make clean              清理编译产物"
