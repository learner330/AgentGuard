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
    FileSystemChecker,
    ShellChecker,
    NetworkChecker,
    SQLChecker,
    MCPDescriptionScanner,
)


class Checker(Protocol):
    """检查器协议"""
    def check(self, call: ToolCall) -> Optional[GuardResult]: ...


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

    按工具类型自动路由（复用已配置的检查器实例）：
        guard = ToolGuard(auto_route=True, allowed_paths=["/workspace"])
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

        # 预计算工具名集合（用于路由）
        self._file_names = {t.lower() for t in FILE_TOOLS}
        self._shell_names = {t.lower() for t in SHELL_TOOLS}
        self._net_names = {t.lower() for t in NETWORK_TOOLS}
        self._db_names = {t.lower() for t in DATABASE_TOOLS}
        self._mcp_names = {t.lower() for t in MCP_TOOLS}

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

        # 优先用工具类型专用检查器（复用已配置的实例，保留用户配置）
        routed = self._route_checker(data.tool_name)
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

    def _route_checker(self, tool_name: str) -> Optional[Checker]:
        """根据工具名从已配置的检查器中匹配专用检查器

        复用 self._checkers 中已有配置的实例，避免丢失用户的自定义参数
        （如 allowed_paths、allow_private_networks 等）。
        """
        name = tool_name.lower()

        type_map: dict[str, type] = {}
        if name in self._file_names:
            type_map = {FileSystemChecker: True}
        elif name in self._shell_names:
            type_map = {ShellChecker: True}
        elif name in self._net_names:
            type_map = {NetworkChecker: True}
        elif name in self._db_names:
            type_map = {SQLChecker: True}
        elif name in self._mcp_names:
            type_map = {MCPDescriptionScanner: True}
        else:
            return None

        for checker in self._checkers:
            if type(checker) in type_map:
                return checker
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
