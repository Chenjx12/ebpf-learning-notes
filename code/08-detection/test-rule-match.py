# test-rule-match.py
from detector import EscapeDetector

detector = EscapeDetector('rules.yaml')

# 模拟ptrace事件
test_event = {
    'event_type': 'ptrace',
    'request': 'PTRACE_ATTACH',
    'target_pid': 1
}

matched = detector.check_event(test_event)
print(f"匹配规则数: {len(matched)}")
if matched:
    print(f"规则名称: {matched[0]['name']}")
else:
    print("❌ 未匹配任何规则!")
