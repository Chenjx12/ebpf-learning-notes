#!/usr/bin/env python3
"""
eBPF Container Guard - Main Entry Point

Copyright (c) 2026 chenjx12
Licensed under the MIT License. See LICENSE for details.

========================================
⚠️ 这是 MVP v0.1.0 的问题版本（修复前）
========================================

问题清单:
1. import 了不存在的类名: DetectionEngine, DockerResponder
   实际类是 EscapeDetector, ResponseEngine
2. 调用不存在的方法: detector.start(), responder.on_alert()
3. 完全没有 eBPF 加载代码 (缺少 BPF(src_file=...))
4. 缺少 Ring Buffer 事件消费循环
5. 缺少容器身份映射 (PID map, cgroup map)
6. 缺少 ptrace 请求常量映射表 (PTRACE_MAP)
7. 检测-响应管线从未串联

修复后的版本见: ../../ebpf-container-guard/main.py
迭代记录见: ../../docs/Four-融合/MVP迭代记录.md
========================================
"""

import argparse
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from detector.engine import DetectionEngine
from responder.docker_responder import DockerResponder


def main():
    parser = argparse.ArgumentParser(
        description='🛡️  eBPF Container Guard - Real-time container escape detection and response'
    )
    parser.add_argument(
        '--rules',
        default='config/rules.yaml',
        help='Path to detection rules YAML file (default: config/rules.yaml)'
    )
    parser.add_argument(
        '--responses',
        default='config/responses.yaml',
        help='Path to response strategies YAML file (default: config/responses.yaml)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Validate config files exist
    rules_path = Path(args.rules)
    responses_path = Path(args.responses)

    if not rules_path.exists():
        print(f"❌ Error: Rules file not found: {rules_path}")
        sys.exit(1)

    if not responses_path.exists():
        print(f"❌ Error: Responses file not found: {responses_path}")
        sys.exit(1)

    try:
        # Initialize components
        print("🛡️  Initializing eBPF Container Guard...")
        detector = DetectionEngine(str(rules_path), verbose=args.verbose)
        responder = DockerResponder(str(responses_path))

        # Start monitoring
        print(f"✅ Detection engine loaded with rules from: {rules_path}")
        print(f"✅ Response engine loaded with strategies from: {responses_path}")
        print("\n🔍 Starting real-time monitoring... (Press Ctrl+C to stop)\n")

        # Register alert handler
        detector.start(responder.on_alert)

    except KeyboardInterrupt:
        print("\n\n⚠️  Received interrupt signal, shutting down...")
        print("👋 eBPF Container Guard stopped.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
