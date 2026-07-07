"""网络请求安全检查器（SSRF 防护）"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

from guardrails.base import GuardLevel, GuardResult
from guardrails.tool_call import ToolCall

# 内网 IP 模式（SSRF 防护）
INTERNAL_IP_PATTERNS: list[tuple[str, str]] = [
    (r"https?://127\.\d+\.\d+\.\d+", "NET-001"),  # loopback
    (r"https?://10\.\d+\.\d+\.\d+", "NET-002"),  # 私网 A 类
    (r"https?://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", "NET-003"),  # 私网 B 类
    (r"https?://192\.168\.\d+\.\d+", "NET-004"),  # 私网 C 类
    (r"https?://169\.254\.\d+\.\d+", "NET-005"),  # link-local
    (r"https?://\[?::1\]?", "NET-006"),  # IPv6 loopback
    (r"https?://\[?fc00:", "NET-007"),  # IPv6 私网
    (r"https?://0\.0\.0\.0", "NET-008"),
    (r"https?://localhost", "NET-009"),
    (r"https?://\[?::ffff:127\.", "NET-010"),
]

# 敏感云服务元数据端点
METADATA_ENDPOINTS: list[tuple[str, str]] = [
    (r"169\.254\.169\.254", "NET-META-001"),  # AWS / GCP / Azure
    (r"metadata\.google\.internal", "NET-META-002"),
]


class NetworkChecker:
    """网络请求安全检查器（防止 SSRF）"""

    def __init__(
        self,
        allow_private: bool = False,
        allowed_domains: Optional[list[str]] = None,
        blocked_domains: Optional[list[str]] = None,
    ) -> None:
        self.allow_private = allow_private
        self.allowed_domains = allowed_domains or []
        self.blocked_domains = blocked_domains or []
        self._compiled_ips = [
            (re.compile(p), rule_id) for p, rule_id in INTERNAL_IP_PATTERNS
        ]
        self._compiled_meta = [
            (re.compile(p), rule_id) for p, rule_id in METADATA_ENDPOINTS
        ]

    def check(self, call: ToolCall) -> Optional[GuardResult]:
        """检查网络请求"""
        url_keys = ["url", "endpoint", "uri", "address", "host"]
        for key in url_keys:
            if key in call.tool_args and isinstance(call.tool_args[key], str):
                result = self._check_url(key, call.tool_args[key])
                if result:
                    return result
        return None

    def _check_url(self, arg_name: str, url: str) -> Optional[GuardResult]:
        """检查单个 URL"""
        # 元数据端点检测（总是阻断）
        for pattern, rule_id in self._compiled_meta:
            if pattern.search(url):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Cloud metadata endpoint blocked: {url}",
                    rule_id=rule_id,
                    details={"arg": arg_name, "url": url},
                )

        # 私网 IP 检测
        if not self.allow_private:
            for pattern, rule_id in self._compiled_ips:
                if pattern.search(url):
                    return GuardResult.block_result(
                        level=GuardLevel.TOOL,
                        message=f"SSRF: internal network address blocked: {url}",
                        rule_id=rule_id,
                        details={"arg": arg_name, "url": url},
                    )

        # 域名白名单检查
        if self.allowed_domains:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            is_allowed = False
            for domain in self.allowed_domains:
                if hostname == domain or hostname.endswith("." + domain):
                    is_allowed = True
                    break
            if not is_allowed:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Domain not in whitelist: {hostname}",
                    rule_id="NET-WHITELIST",
                    details={"arg": arg_name, "url": url, "hostname": hostname},
                )

        # 域名黑名单检查
        if self.blocked_domains:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            for domain in self.blocked_domains:
                if hostname == domain or hostname.endswith("." + domain):
                    return GuardResult.block_result(
                        level=GuardLevel.TOOL,
                        message=f"Domain in blacklist: {hostname}",
                        rule_id="NET-BLACKLIST",
                        details={"arg": arg_name, "url": url},
                    )

        return None
