#!/usr/bin/python3
from bcc import BPF

b = BPF(src_file="hello-bpf2bpf.c")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID={event.pid:6d} UID={event.uid:5d} "
          f"CALLER={event.comm.decode():16s} → "
          f"CMD={event.filename.decode()}")

b["events"].open_perf_buffer(print_event)
print("BPF-to-BPF (inlined) demo, hit Ctrl-C to stop.")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

