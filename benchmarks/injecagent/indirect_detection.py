"""增强间接提示注入检测"""

from __future__ import annotations

import re


# 无论出现在何处都高度可疑的关键词（即使嵌入在正常文本中）
HIGH_CONFIDENCE_INJECTION_MARKERS = [
    # 指令覆盖类
    (r"ignore\s+(all\s+|previous|above|prior)\s+(instructions?|rules?|prompts?)", "IND-001"),
    (r"忽略.{0,5}(之前|所有|全部)\s*(指令|规则|限制)", "IND-002"),
    # 系统提示词操作
    (r"reveal\s+(the\s+)?(system|original|initial)\s+(prompt|instruction)", "IND-003"),
    (r"泄露|透露|输出|重复.{0,5}(系统).{0,5}(提示词|prompt)", "IND-004"),
    # 角色扮演劫持
    (r"you\s+are\s+now.{0,20}(unrestricted|unfiltered|no\s+restriction)", "IND-005"),
    # 数据外泄指示
    (r"(send|forward|transmit|exfiltrate).{0,30}(to|into|at)\s+\S+\.(com|net|org|io|cn)", "IND-006"),
    (r"(发送|转发).{0,10}@", "IND-007"),
    # 操作类型注入
    (r"(system\s+maintenance|emergency)\s*[:\-]", "IND-008"),
    (r"(紧急|重要)\s*(系统|System)\s*[:：]", "IND-009"),
]

# 模式预编译
_COMPILED_INDIRECT = [
    (re.compile(p, re.IGNORECASE), rule_id) for p, rule_id in HIGH_CONFIDENCE_INJECTION_MARKERS
]


def detect_indirect_injection(text: str) -> tuple:
    """检测间接注入模式

    Args:
        text: 待检测文本（通常是工具返回内容）

    Returns:
        (是否检测到, rule_id, 匹配到的文本)
    """
    for pattern, rule_id in _COMPILED_INDIRECT:
        match = pattern.search(text)
        if match:
            return (True, rule_id, match.group(0))
    return (False, "", "")
