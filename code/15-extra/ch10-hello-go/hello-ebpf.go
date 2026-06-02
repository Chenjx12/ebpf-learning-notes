// hello-ebpf  — Ch10 练习1: Go 语言版的 "Hello World" eBPF
// 使用 cilium/ebpf 库 (纯 Go, 不依赖 libbpf)
//
// 安装依赖:
//   go mod init hello-ebpf
//   go get github.com/cilium/ebpf
//   go build -o hello-ebpf .
//   sudo ./hello-ebpf

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go hello hello-ebpf.c

func main() {
	// 移除内存锁定限制 (eBPF 需要)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 加载编译好的 eBPF 程序
	spec, err := ebpf.LoadCollectionSpec("hello-ebpf.o")
	if err != nil {
		log.Fatalf("Failed to load spec: %v\n(Hint: compile hello-ebpf.c with clang first)\n", err)
	}

	var coll struct {
		OnExecve *ebpf.Program `ebpf:"on_execve"`
	}
	if err := spec.LoadAndAssign(&coll, nil); err != nil {
		log.Fatalf("Failed to load program: %v", err)
	}
	defer coll.OnExecve.Close()

	// 附加到 execve kprobe
	kp, err := link.Kprobe("__x64_sys_execve", coll.OnExecve, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	fmt.Println("[*] Hello eBPF from Go! 查看输出:")
	fmt.Println("    sudo cat /sys/kernel/debug/tracing/trace_pipe")
	fmt.Println("[*] 按 Ctrl-C 退出...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n[*] 退出")
}
