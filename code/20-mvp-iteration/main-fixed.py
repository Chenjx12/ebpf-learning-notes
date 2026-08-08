#!/usr/bin/env python3
"""
eBPF Container Guard — Fixed Entry Point (v0.1.1, working)

This is a pointer to the fixed version.
Full source: https://github.com/Chenjx12/ebpf-container-guard/releases/tag/v0.1.1

7 fixes over main-broken.py:
1. Correct imports: EscapeDetector, ResponseEngine
2. Full eBPF lifecycle: BPF(src_file=...), ring_buffer, poll loop
3. Container identity: PID map + cgroup inode + /proc fallback
4. Background refresh thread (5s interval)
5. PTRACE_MAP: 20+ request constants
6. Detection→Response pipeline: check_event → print_alert → handle_alert
7. Path resolution: __file__-based, works regardless of CWD

Later versions tracked via GitHub Releases:
  v0.2.0: 5 probes × 8 rules × 3-tier detection (rules → matrix → AI)
  https://github.com/Chenjx12/ebpf-container-guard/releases
"""

if __name__ == '__main__':
    print("See https://github.com/Chenjx12/ebpf-container-guard/releases")
