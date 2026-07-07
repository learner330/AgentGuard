"""第三层：工具围栏 ToolGuard

防御目标：在 Agent 调用工具之前，审查调用参数是否合规，防止工具越权和工具投毒。

检测内容：
- 文件读写：路径白名单、目录穿越
- Shell：命令黑名单、危险参数
- 网络：SSRF、域名白名单
- 数据库：SQL 注入
- MCP：工具描述语义扫描
"""

from __future__ import annotations

import os
import re
from typing import Any, Optional, Protocol

from guardrails.base import (
    BaseGuard,
    GuardLevel,
    GuardResult,
    GuardSeverity,
)
from guardrails.tool_call import (
    DATABASE_TOOLS,
    FILE_TOOLS,
    MCP_TOOLS,
    NETWORK_TOOLS,
    SHELL_TOOLS,
    ToolCall,
)
from guardrails.checkers import (
    ShellChecker,
    NetworkChecker,
    SQLChecker,
    MCPDescriptionScanner,
)


class Checker(Protocol):
    """检查器协议"""
    def check(self, call: ToolCall) -> Optional[GuardResult]: ...


# ============ 文件路径检查器 ============

# 危险的路径模式
DANGEROUS_PATH_PATTERNS: list[tuple[str, str]] = [
    (r"\.\./", "PATH-001"),              # 目录穿越
    (r"\.\.\|", "PATH-001"),
    (r"\.\.\\\\", "PATH-001"),
    (r"/etc/(passwd|shadow|hosts)", "PATH-002"),  # 敏感系统文件
    (r"/proc/", "PATH-003"),             # proc 文件系统
    (r"/sys/", "PATH-004"),              # sys 文件系统
    (r"/dev/", "PATH-005"),              # dev 文件系统
    (r"C:\\Windows\\System32", "PATH-006"),  # Windows 系统目录
    (r"\.(ssh|gnupg|aws|docker)", "PATH-007"),  # 敏感配置目录
]

# 敏感文件扩展名
SENSITIVE_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx",  # 证书
    ".env", ".secret",                # 配置
    ".shadow", ".passwd",             # 密码
}


class FileSystemChecker:
    """文件操作安全检查器"""

    def __init__(
        self,
        allowed_paths: Optional[list[str]] = None,
        blocked_paths: Optional[list[str]] = None,
        allow_sensitive_ext: bool = False,
    ) -> None:
        self.allowed_paths = allowed_paths or []
        self.blocked_paths = blocked_paths or ["/etc", "/proc", "/sys", "/dev"]
        self.allow_sensitive_ext = allow_sensitive_ext
        self._compiled_patterns = [
            (re.compile(p), rule_id) for p, rule_id in DANGEROUS_PATH_PATTERNS
        ]

    def check(self, call: ToolCall) -> Optional[GuardResult]:
        """检查文件操作"""
        # 提取路径参数
        path_keys = ["path", "file_path", "filepath", "src", "dest", "src_path", "dest_path"]
        paths: list[tuple[str, str]] = []
        for key in path_keys:
            if key in call.tool_args and isinstance(call.tool_args[key], str):
                paths.append((key, call.tool_args[key]))

        if not paths:
            return None

        for arg_name, path in paths:
            result = self._check_path(arg_name, path)
            if result:
                return result
        return None

    def _check_path(self, arg_name: str, path: str) -> Optional[GuardResult]:
        """检查单个路径"""
        # 1. 目录穿越检测
        if ".." in path or "~" in path:
            normalized = os.path.normpath(path)
            if ".." in path.split(os.sep):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Directory traversal detected in '{arg_name}': {path}",
                    rule_id="PATH-001",
                    details={"arg": arg_name, "path": path},
                )

        # 2. 已知危险模式检测
        for pattern, rule_id in self._compiled_patterns:
            if pattern.search(path):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Dangerous path pattern in '{arg_name}': {path}",
                    rule_id=rule_id,
                    details={"arg": arg_name, "path": path, "matched": pattern.pattern},
                )

        # 3. 敏感扩展名检测
        if not self.allow_sensitive_ext:
            ext = os.path.splitext(path)[1].lower()
            if ext in SENSITIVE_EXTENSIONS:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Access to sensitive file type blocked: {path}",
                    rule_id="PATH-008",
                    details={"arg": arg_name, "path": path, "extension": ext},
                )

        # 4. 路径白名单检查
        if self.allowed_paths:
            is_allowed = False
            for allowed in self.allowed_paths:
                if path.startswith(allowed):
                    is_allowed = True
                    break
            if not is_allowed:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Path '{path}' not in allowed paths list",
                    rule_id="PATH-009",
                    details={"arg": arg_name, "path": path},
                )

        return None


class ToolGuard(BaseGuard):
    """第三层：工具围栏

    在 Agent 调用工具之前，审查调用参数是否合规，防止工具越权和工具投毒。

    使用方式：
        guard = ToolGuard()
        call = ToolCall(tool_name="read_file", tool_args={"path": "/etc/passwd"})
        result = await guard.check(call)
        # result.severity == GuardSeverity.BLOCK

    自定义检查器：
        guard = ToolGuard(checkers=[FileSystemChecker(), ShellChecker()])

    按工具类型自动路由：
        guard = ToolGuard(auto_route=True)
    """

    def __init__(
        self,
        enabled: bool = True,
        config: Optional[dict[str, Any]] = None,
        checkers: Optional[list[Checker]] = None,
        auto_route: bool = True,
        allowed_paths: Optional[list[str]] = None,
        extra_blocked_commands: Optional[list[str]] = None,
        allow_private_networks: bool = False,
        allowed_domains: Optional[list[str]] = None,
        allow_sql_write: bool = False,
        mcp_strict_mode: bool = False,
    ) -> None:
        super().__init__(level=GuardLevel.TOOL, enabled=enabled, config=config)

        self._checkers: list[Checker] = checkers or []

        if auto_route:
            self._checkers.extend([
                FileSystemChecker(allowed_paths=allowed_paths),
                ShellChecker(extra_blocked=extra_blocked_commands),
                NetworkChecker(
                    allow_private=allow_private_networks,
                    allowed_domains=allowed_domains,
                ),
                SQLChecker(allow_write=allow_sql_write),
                MCPDescriptionScanner(strict_mode=mcp_strict_mode),
            ])

    async def check(
        self, data: Any, context: Optional[dict[str, Any]] = None
    ) -> GuardResult:
        """检查工具调用"""
        if not self.enabled:
            return GuardResult.pass_result(level=self.level, message="guard disabled")

        if isinstance(data, dict):
            data = ToolCall(**data)
        elif not isinstance(data, ToolCall):
            return GuardResult.pass_result(
                level=self.level,
                message=f"Unsupported type: {type(data).__name__}",
            )

        # 优先用工具类型专用检查器
        routed = _route_checker(data.tool_name)
        if routed:
            result = routed.check(data)
            if result:
                return result

        # 执行所有配置的检查器
        for checker in self._checkers:
            result = checker.check(data)
            if result:
                return result

        return GuardResult.pass_result(level=self.level, message="tool call approved")

    def add_checker(self, checker: Checker) -> None:
        """添加自定义检查器"""
        self._checkers.append(checker)


def _route_checker(tool_name: str) -> Optional[Checker]:
    """根据工具名返回专用检查器"""
    name = tool_name.lower()
    file_names = {t.lower() for t in FILE_TOOLS}
    shell_names = {t.lower() for t in SHELL_TOOLS}
    net_names = {t.lower() for t in NETWORK_TOOLS}
    db_names = {t.lower() for t in DATABASE_TOOLS}
    mcp_names = {t.lower() for t in MCP_TOOLS}

    if name in file_names:
        return FileSystemChecker()
    if name in shell_names:
        return ShellChecker()
    if name in net_names:
        return NetworkChecker()
    if name in db_names:
        return SQLChecker()
    if name in mcp_names:
        return MCPDescriptionScanner()
    return None


def check_tool(
    tool_name: str,
    tool_args: dict[str, Any],
    tool_description: Optional[str] = None,
    **kwargs: Any,
) -> GuardResult:
    """同步版本的工具检测"""
    import asyncio
    guard = ToolGuard(**kwargs)
    call = ToolCall(
        tool_name=tool_name,
        tool_args=tool_args,
        tool_description=tool_description,
    )
    return asyncio.run(guard.check(call))
