"""第一层：输入围栏，防御直接提示注入（Direct Prompt Injection）

检测内容：
- 指令覆盖（ignore previous instructions）
- 角色劫持（你现在是/act as）
- 越狱模板特征
- 编码绕过（Base64/Unicode）
- 多语言混淆

检测策略：规则引擎（关键词 + 正则）
"""

from __future__ import annotations

import re
from typing import Any, Optional

from guardrails.base import (
    BaseGuard,
    GuardLevel,
    GuardResult,
    GuardSeverity,
)


# ============ 注入模式规则库 ============

# 指令覆盖类模式
INSTRUCTION_OVERRIDE_PATTERNS: list[tuple[str, str]] = [
    # (pattern, rule_id)
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)", "INST-001"),
    (r"forget\s+(everything|all|previous|instructions?)", "INST-002"),
    (r"disregard\s+(the\s+)?(previous|above|system)\s+(instructions?|prompts?)", "INST-003"),
    (r"override\s+(all\s+)?(previous|safety|security)\s+(instructions?|rules?|prompts?)", "INST-004"),
    (r"(don't|do\s+not)\s+(follow|obey|listen\s+to)\s+(the\s+)?(previous|system|above)", "INST-005"),
    (r"(stop|cease)\s+(following|obeying|using)\s+(your\s+)?(previous|original)\s+(instructions?|programming?)", "INST-006"),
    (r"new\s+(instructions?|rules?|prompts?)\s*[:：]", "INST-007"),
    (r"from\s+now\s+on,?\s+(ignore|forget|disregard)", "INST-008"),
    (r"(系统提示|system\s*prompt)\s*(：|:)\s*(忽略|忘掉|无视|override)", "INST-009"),
    (r"(所有|全部)\s*(指令|规则|instructions?)\s*(清空|重置|忽略|override)", "INST-010"),
]

# 角色劫持类模式
ROLE_HIJACK_PATTERNS: list[tuple[str, str]] = [
    (r"你(现在)?是\s*[\"]?([^。，,]+)", "ROLE-001"),  # "你现在是XXX"
    (r"act\s+as\s+(a\s+)?([^,.。，]+)", "ROLE-002"),
    (r"pretend\s+(you\s+are|to\s+be)\s+([^,.。，]+)", "ROLE-003"),
    (r"you\s+are\s+now\s+([^,.。，]+)", "ROLE-004"),
    (r"assume\s+(the\s+)?role\s+of\s+([^,.。，]+)", "ROLE-005"),
    (r"切换(到)?模式\s*[:：]?\s*(.*)", "ROLE-006"),
    (r"(become|transform\s+into)\s+(a\s+)?([^,.。，]+)", "ROLE-007"),
    (r"(免瘟疫|DAN|AIM|STAN|DEVIL)", "ROLE-008"),  # 已知越狱模板名
]

# 越狱模板特征
JAILBREAK_PATTERNS: list[tuple[str, str]] = [
    (r"DAN\s*(模式|6\.0|7\.0|8\.0|9\.0|10\.0)", "JAIL-001"),
    (r"aim\s*(模式)?", "JAIL-002"),
    (r"STAN\s*(模式)?", "JAIL-003"),
    (r"免瘟疫\s*模式", "JAIL-004"),
    (r"(jailbreak|jail\s*break)\s*(mode|模式|成功|！)", "JAIL-005"),
    (r"无任何(限制|restrictions?|限制条件)", "JAIL-006"),
    (r"可以?(做任何事|做任何事情|talk\s+about\s+anything)", "JAIL-007"),
    (r"(不受|没有)\s*(任何)?(安全|伦理|道德|内容)\s*(限制|限制|policy|policies)", "JAIL-008"),
    (r"没有道德(约束|限制)", "JAIL-009"),
    (r"(扮演|扮演)\s*(一个)?\s*?(邪恶|evil|不良|bad)\s*(的)?(角色|AI|助手|assistant)", "JAIL-010"),
]

# 编码绕过特征
ENCODING_BYPASS_PATTERNS: list[tuple[str, str]] = [
    (r"base64\s*(编码|encode|解码|decode)", "ENC-001"),
    (r"Unicode\s*(编码|encode|编码)", "ENC-002"),
    (r"十六进制.*(编码|encode)", "ENC-003"),
    (r"rot13", "ENC-004"),
    (r"(解码|decrypt|decipher|decode)\s*(我?的?|this|following)\s*(消息|message)", "ENC-005"),
    (r"\[.*?(encode|decode|encrypt|decrypt).*?(base64|hex|url)", "ENC-006"),
    (r"<script.*?>", "ENC-007"),
]


class InputGuard(BaseGuard):
    """输入围栏 - 防御直接提示注入

    使用规则引擎（正则匹配）进行检测，零延迟，覆盖常见注入模式。

    使用方式：
        guard = InputGuard()
        result = await guard.check("ignore previous instructions")
        # result.severity == GuardSeverity.BLOCK
    """

    def __init__(
        self,
        enabled: bool = True,
        config: Optional[dict[str, Any]] = None,
        custom_patterns: Optional[list[tuple[str, str]]] = None,
    ):
        super().__init__(level=GuardLevel.INPUT, enabled=enabled, config=config)
        # 编译所有模式
        self._compile_patterns()
        # 用户自定义模式
        self._custom_patterns: list[tuple[re.Pattern, str]] = []
        if custom_patterns:
            for pattern, rule_id in custom_patterns:
                self._custom_patterns.append((re.compile(pattern, re.IGNORECASE), rule_id))

    def _compile_patterns(self) -> None:
        """预编译所有正则模式"""
        self._compiled_override = [
            (re.compile(p, re.IGNORECASE), rule_id) for p, rule_id in INSTRUCTION_OVERRIDE_PATTERNS
        ]
        self._compiled_role = [
            (re.compile(p, re.IGNORECASE), rule_id) for p, rule_id in ROLE_HIJACK_PATTERNS
        ]
        self._compiled_jailbreak = [
            (re.compile(p, re.IGNORECASE), rule_id) for p, rule_id in JAILBREAK_PATTERNS
        ]
        self._compiled_encoding = [
            (re.compile(p, re.IGNORECASE), rule_id) for p, rule_id in ENCODING_BYPASS_PATTERNS
        ]

    async def check(self, data: Any, context: Optional[dict[str, Any]] = None) -> GuardResult:
        """对输入文本进行注入检测

        Args:
            data: 用户输入文本
            context: 额外上下文（暂未使用）

        Returns:
            GuardResult: PASS/WARN/BLOCK
        """
        if not self.enabled:
            return GuardResult.pass_result(level=self.level, message="guard disabled")

        if not isinstance(data, str):
            data = str(data)

        text = data.strip()
        if not text:
            return GuardResult.pass_result(level=self.level, message="empty input")

        # 按优先级依次检测：指令覆盖 → 角色劫持 → 越狱模板 → 编码绕过
        checkers = [
            ("instruction_override", self._compiled_override, GuardSeverity.BLOCK),
            ("role_hijack", self._compiled_role, GuardSeverity.BLOCK),
            ("jailbreak", self._compiled_jailbreak, GuardSeverity.BLOCK),
            ("encoding_bypass", self._compiled_encoding, GuardSeverity.WARN),
        ]

        for rule_category, patterns, severity in checkers:
            result = self._check_patterns(text, patterns, rule_category, severity)
            if result:
                return result

        # 自定义模式检测
        result = self._check_patterns(text, self._custom_patterns, "custom", GuardSeverity.WARN)
        if result:
            return result

        return GuardResult.pass_result(level=self.level, message="no injection detected")

    def _check_patterns(
        self,
        text: str,
        patterns: list[tuple[re.Pattern, str]],
        category: str,
        severity: GuardSeverity,
    ) -> Optional[GuardResult]:
        """用一组模式检测文本，返回第一个命中结果"""
        for pattern, rule_id in patterns:
            match = pattern.search(text)
            if match:
                matched_text = match.group(0)
                if severity == GuardSeverity.BLOCK:
                    return GuardResult.block_result(
                        level=self.level,
                        message=f"Potential prompt injection detected [{category}]: '{matched_text}'",
                        rule_id=rule_id,
                        details={
                            "category": category,
                            "matched_text": matched_text,
                            "match_groups": match.groups(),
                            "input_length": len(text),
                        },
                    )
                else:
                    return GuardResult.warn_result(
                        level=self.level,
                        message=f"Suspicious content detected [{category}]: '{matched_text}'",
                        rule_id=rule_id,
                        details={
                            "category": category,
                            "matched_text": matched_text,
                            "input_length": len(text),
                        },
                    )
        return None


# 便捷同步检测函数
def check_input(text: str, **kwargs: Any) -> GuardResult:
    """同步版本的输入检测（方便脚本使用）"""
    import asyncio
    guard = InputGuard(**kwargs)
    return asyncio.run(guard.check(text))
