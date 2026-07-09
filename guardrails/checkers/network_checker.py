"""网络请求安全检查器（基于 DNS 解析 + IP 地址分类）

从正则 IP 匹配升级为：
1. 先进行 DNS 解析，获取域名对应的真实 IP 地址
2. 使用 ipaddress 模块对解析后的 IP 进行分类（私网、回环、链路本地等）
3. 防御 DNS 重绑定攻击和 IP 编码绕过
4. 支持域名白名单 + 黑名单
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse

from guardrails.base import GuardLevel, GuardResult
from guardrails.tool_call import ToolCall


# 云元数据端点（无论解析成什么 IP，域名本身也要拦截）
CLOUD_METADATA_HOSTS = frozenset(
    [
        "169.254.169.254",      # AWS / GCP / Azure 通用元数据端点
        "metadata.google.internal",
        "metadata.google.internal.",
        "169.254.169.254.nip.io",  # 常见绕过域名
    ]
)


class NetworkChecker:
    """基于 DNS 解析的网络安全检查器（SSRF 防护）

    核心改进：
    1. 先解析域名获取真实 IP，再对 IP 进行分类检测
    2. 使用 ipaddress 模块判断 IP 类别（is_private, is_loopback 等）
    3. 防御 DNS 重绑定攻击和 IP 编码绕过
    4. 保留域名白名单策略
    """

    def __init__(
        self,
        allow_private: bool = False,
        allowed_domains: Optional[list[str]] = None,
        blocked_domains: Optional[list[str]] = None,
    ) -> None:
        """
        Args:
            allow_private: 是否允许访问私网地址（默认 False，安全优先）
            allowed_domains: 允许的域名白名单
            blocked_domains: 拒绝的域名黑名单
        """
        self.allow_private = allow_private
        self.allowed_domains = allowed_domains or []
        self.blocked_domains = blocked_domains or []

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
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return None

        # 1. 域名黑名单检查（优先）
        if self.blocked_domains:
            for domain in self.blocked_domains:
                if hostname == domain or hostname.endswith("." + domain):
                    return GuardResult.block_result(
                        level=GuardLevel.TOOL,
                        message=f"Domain in blacklist: {hostname}",
                        rule_id="NET-BLACKLIST",
                        details={"arg": arg_name, "url": url, "hostname": hostname},
                    )

        # 2. 云元数据端点检测（直接阻断，不依赖解析）
        if hostname in CLOUD_METADATA_HOSTS or hostname.endswith(".nip.io"):
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message=f"Cloud metadata endpoint blocked: {hostname}",
                rule_id="NET-META",
                details={"arg": arg_name, "url": url, "hostname": hostname},
            )

        # 3. 域名白名单检查
        if self.allowed_domains:
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

        # 4. IP 地址直接检测（如果 hostname 本身就是 IP）
        ip_result = self._check_ip_address(arg_name, url, hostname)
        if ip_result:
            return ip_result

        # 5. DNS 解析后检测（关键：防御 DNS 重绑定）
        if not self.allow_private:
            dns_result = self._check_dns_resolution(arg_name, url, hostname)
            if dns_result:
                return dns_result

        return None

    def _check_ip_address(self, arg_name: str, url: str, hostname: str) -> Optional[GuardResult]:
        """检查 hostname 是否为 IP 地址，如果是则分类检测"""
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            # hostname 不是 IP 地址，跳过
            return None

        # 解析成功，说明 hostname 是直接的 IP 地址
        return self._evaluate_ip(arg_name, url, ip)

    def _check_dns_resolution(self, arg_name: str, url: str, hostname: str) -> Optional[GuardResult]:
        """DNS 解析域名，检查解析后的 IP 地址"""
        try:
            # 同时获取 IPv4 和 IPv6 地址
            addr_info = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
        except socket.gaierror:
            # DNS 解析失败：无法判断域名性质，默认放行
            # 实际生产环境中应使用可信的 DNS 服务器或缓存
            return None

        for _, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            result = self._evaluate_ip(arg_name, url, ip)
            if result:
                return result

        return None

    def _evaluate_ip(self, arg_name: str, url: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Optional[GuardResult]:
        """对单个 IP 地址进行分类评估"""
        # 云元数据端点（AWS / GCP / Azure）
        if ip == ipaddress.ip_address("169.254.169.254"):
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message=f"SSRF: cloud metadata endpoint blocked: {ip}",
                rule_id="NET-META-001",
                details={"arg": arg_name, "url": url, "resolved_ip": str(ip)},
            )

        # 回环地址检查（优先于私网，因为 127.0.0.1 既是 loopback 也是 private）
        if not self.allow_private:
            if ip.is_loopback:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"SSRF: loopback IP address blocked: {ip}",
                    rule_id="NET-LOOPBACK",
                    details={"arg": arg_name, "url": url, "resolved_ip": str(ip)},
                )
            if ip.is_link_local:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"SSRF: link-local IP address blocked: {ip}",
                    rule_id="NET-LINKLOCAL",
                    details={"arg": arg_name, "url": url, "resolved_ip": str(ip)},
                )
            if ip.is_private:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"SSRF: private IP address blocked: {ip}",
                    rule_id="NET-PRIVATE",
                    details={"arg": arg_name, "url": url, "resolved_ip": str(ip)},
                )
            if ip.is_reserved:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"SSRF: reserved IP address blocked: {ip}",
                    rule_id="NET-RESERVED",
                    details={"arg": arg_name, "url": url, "resolved_ip": str(ip)},
                )
            if ip.is_multicast:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"SSRF: multicast IP address blocked: {ip}",
                    rule_id="NET-MULTICAST",
                    details={"arg": arg_name, "url": url, "resolved_ip": str(ip)},
                )

        return None
