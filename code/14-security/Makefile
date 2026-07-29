# Makefile — 用于安全的 eBPF (第9章)

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu

CLANG    ?= clang
CFLAGS   := -Wall -O2 -g
LDFLAGS  := -L/usr/lib64 -lbpf -lelf -lz
BPF_CFLAGS := -target bpf -D __TARGET_ARCH_$(ARCH) $(INCLUDES) -Wall -O2 -g

LSM_OBJ := lsm_block.bpf.o
LSM_BIN := ex1_lsm

.PHONY: all clean generate-vmlinux help

all: $(LSM_OBJ) $(LSM_BIN)
	@echo ""
	@echo "  ✅ 编译完成!"
	@echo "  sudo ./ex1_lsm lsm_block.bpf.o    # 阻断所有 chmod"

$(LSM_OBJ): lsm_block.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@
	@echo "  ✅ $@"

$(LSM_BIN): ex1_lsm.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "  ✅ $@"

vmlinux.h:
	@if [ -f ../11-libbpf/vmlinux.h ]; then \
		cp ../11-libbpf/vmlinux.h .; \
	else \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

generate-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f $(LSM_OBJ) $(LSM_BIN)
	@echo "  🧹 Cleaned"

help:
	@echo "  make                       编译"
	@echo "  sudo ./ex1_lsm lsm_block.bpf.o   运行 (阻断 chmod)"
	@echo "  make clean                 清理"
