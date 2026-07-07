"""MCP 工具投毒扫描器

检测恶意 MCP Server 在工具描述中隐藏的注入指令。

参考来源：
- mcp-injection-experiments (Invariant Labs)
- mcp-scan (Invariant Labs)
"""

from __future__ import annotations

import re
from typing import Optional

from guardrails.base import GuardLevel, GuardResult
from guardrails.tool_call import ToolCall

# 工具描述中的可疑模式（隐藏指令）
DESCRIPTION_INJECTION_PATTERNS: list[tuple[str, str]] = [
    # 角色扮演诱导
    (r"(you\s+are\s+now|act\s+as|pretend\s+you\s+are|become\s+a)\s+\w+", "MCP-001"),
    (r"(你现在是|扮演|假装你是|转变为)", "MCP-002"),
    # 指令覆盖
    (r"(ignore|disregard|forget|override)\s+(previous|all|previous|system)", "MCP-003"),
    (r"(忽略|无视|忘记|覆盖)(所有|之前|系统)", "MCP-004"),
    # 数据外泄指示
    (r"(send|forward|transmit|exfiltrate)\s+(to|data|emails|files)", "MCP-005"),
    (r"(发送|转发|泄露|外带)(到|数据|邮件|文件)", "MCP-006"),
    # 执行非预期操作
    (r"(steal|leak|copy|delete)\s+(credentials|keys|secrets|emails|files)", "MCP-007"),
    (r"(窃取|泄露|复制|删除)(凭证|密钥|密码|邮件|文件)", "MCP-008"),
    # 协议混淆
    (r"<system>", "MCP-009"),
    (r"\[INST\]", "MCP-010"),
    (r"<<<", "MCP-011"),
    # 隐藏 URL
    (r"https?://[^\s\"']+", "MCP-012"),  # 描述中的可疑 URL
]

# HTML 注入模式（可能绕过 UI 渲染）
HTML_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"<iframe", "MCP-HTML-001"),
    (r"<script", "MCP-HTML-002"),
    (r"on(load|error|click)\s*=", "MCP-HTML-003"),
    (r"javascript\s*:", "MCP-HTML-004"),
]


class MCPDescriptionScanner:
    """MCP 工具描述投毒扫描器"""

    # 合理描述的最大长度（字符）
    MAX_DESCRIPTION_LENGTH = 2000
    # 描述中 URL 的最大数量
    MAX_URLS = 2

    def __init__(
        self,
        strict_mode: bool = False,
        extra_sensitive_patterns: Optional[list[str]] = None,
    ) -> None:
        """
        Args:
            strict_mode: 严格模式（更激进的阻断策略）
            extra_sensitive_patterns: 额外的敏感模式正则列表
        """
        self.strict_mode = strict_mode
        self._compiled_patterns = [
            (re.compile(p, re.IGNORECASE), rule_id)
            for p, rule_id in DESCRIPTION_INJECTION_PATTERNS
        ]
        self._compiled_html = [
            (re.compile(p, re.IGNORECASE), rule_id)
            for p, rule_id in HTML_INJECTION_PATTERNS
        ]
        self._extra_patterns: list[tuple[re.Pattern, str]] = []
        if extra_sensitive_patterns:
            for i, p in enumerate(extra_sensitive_patterns):
                self._extra_patterns.append((re.compile(p, re.IGNORECASE), f"MCP-CUSTOM-{i:03d}"))

    def check(self, call: ToolCall) -> Optional[GuardResult]:
        """扫描工具描述文本"""
        description = call.tool_description
        if not description or not isinstance(description, str):
            return None

        # 1. 长度异常检测
        if len(description) > self.MAX_DESCRIPTION_LENGTH:
            return GuardResult.warn_result(
                level=GuardLevel.TOOL,
                message=f"Tool description exceeds max length ({len(description)} > {self.MAX_DESCRIPTION_LENGTH})",
                rule_id="MCP-LENGTH",
                details={
                    "tool_name": call.tool_name,
                    "description_length": len(description),
                },
            )

        # 2. HTML 注入检测（优先！HTML injection is always BLOCK）
        for pattern, rule_id in self._compiled_html:
            if pattern.search(description):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message="HTML injection in tool description",
                    rule_id=rule_id,
                    details={"tool_name": call.tool_name},
                )

        # 3. 注入模式检测
        for pattern, rule_id in self._compiled_patterns:
            match = pattern.search(description)
            if match:
                if self.strict_mode:
                    return GuardResult.block_result(
                        level=GuardLevel.TOOL,
                        message=f"Hidden instruction in tool description: '{match.group(0)[:30]}'",
                        rule_id=rule_id,
                        details={
                            "tool_name": call.tool_name,
                            "matched": match.group(0),
                            "description_preview": description[:100],
                        },
                    )
                else:
                    return GuardResult.warn_result(
                        level=GuardLevel.TOOL,
                        message=f"Suspicious content in tool description: '{match.group(0)[:30]}'",
                        rule_id=rule_id,
                        details={
                            "tool_name": call.tool_name,
                            "matched": match.group(0),
                        },
                    )

        # 4. URL 数量检测
        url_pattern = re.compile(r"https?://[^\s\"']+")
        urls = url_pattern.findall(description)
        if len(urls) > self.MAX_URLS:
            return GuardResult.warn_result(
                level=GuardLevel.TOOL,
                message=f"Too many URLs in description ({len(urls)} > {self.MAX_URLS})",
                rule_id="MCP-URL-COUNT",
                details={"tool_name": call.tool_name, "url_count": len(urls)},
            )

        # 5. 自定义敏感模式检测
        for pattern, rule_id in self._extra_patterns:
            if pattern.search(description):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Custom sensitive pattern matched in description",
                    rule_id=rule_id,
                    details={"tool_name": call.tool_name},
                )

        return None
