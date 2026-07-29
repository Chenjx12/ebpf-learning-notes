# Makefile — Ch8 练习1: XDP ping 区分 ICMP Echo/Reply

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu

CLANG    ?= clang
BPFTOOL  ?= bpftool
CFLAGS   := -Wall -O2 -g
BPF_CFLAGS := -target bpf -D __TARGET_ARCH_$(ARCH) $(INCLUDES) -Wall -O2 -g

BPF_OBJ  := ping-xdp.bpf.o
SKEL_H   := ping-xdp.skel.h
USER_BIN := ping-xdp

.PHONY: all clean

all: $(USER_BIN)

$(BPF_OBJ): ping-xdp.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@
	@echo "  ✅ XDP object compiled: $@"

$(SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@
	@echo "  ✅ Skeleton generated: $@"

$(USER_BIN): ping-xdp.c $(SKEL_H)
	$(CC) $(CFLAGS) -o $@ $< -L/usr/lib64 -lbpf -lelf -lz
	@echo "  ✅ Loader compiled: $@"

generate-vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo "  ✅ vmlinux.h generated"

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(USER_BIN)
	@echo "  🧹 Cleaned"
