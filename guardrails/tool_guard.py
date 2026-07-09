"""工具围栏 ToolGuard

防御目标：在 Agent 调用工具之前，审查调用参数是否合规，防止工具越权和工具投毒。
同时监控工具调用模式，检测循环攻击。

检测内容：
- 文件读写：路径白名单、目录穿越
- Shell：命令黑名单、危险参数
- 网络：SSRF、域名白名单
- 数据库：SQL 注入
- MCP：工具描述语义扫描
- 循环攻击：工具调用频率/重复检测
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
    """工具围栏

    在 Agent 调用工具之前，审查调用参数是否合规，防止工具越权和工具投毒。
    同时追踪工具调用历史，检测循环攻击。

    使用方式：
        guard = ToolGuard()
        call = ToolCall(tool_name="read_file", tool_args={"path": "/etc/passwd"})
        result = await guard.check(call)
        # result.severity == GuardSeverity.BLOCK

    自定义检查器：
        guard = ToolGuard(checkers=[FileSystemChecker(), ShellChecker()])

    按工具类型自动路由（复用已配置的检查器实例）：
        guard = ToolGuard(auto_route=True, allowed_paths=["/workspace"])

    新会话重置调用历史：
        guard.reset_history()
    """

    def __init__(
        self,
        enabled: bool = True,
        config: Optional[dict[str, Any]] = None,
        checkers: Optional[list[Checker]] = None,
        auto_route: bool = True,
        allowed_paths: Optional[list[str]] = None,  # 向下兼容别名
        allowed_base_paths: Optional[list[str]] = None,
        extra_blocked_commands: Optional[list[str]] = None,  # 向下兼容，Shell 现为白名单
        allow_private_networks: bool = False,
        allowed_domains: Optional[list[str]] = None,
        allow_sql_write: bool = False,
        mcp_strict_mode: bool = False,
        loop_detection: bool = True,
        loop_window_size: int = 20,
        loop_frequency_threshold: Optional[int] = None,
        loop_identical_threshold: int = 3,
    ) -> None:
        super().__init__(level=GuardLevel.TOOL, enabled=enabled, config=config)

        self._checkers: list[Checker] = checkers or []

        # 兼容旧参数名 allowed_paths
        effective_base_paths = allowed_base_paths or allowed_paths

        if auto_route:
            self._checkers.extend([
                FileSystemChecker(allowed_base_paths=effective_base_paths),
                ShellChecker(),  # 白名单策略，不再接受黑名单参数
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

        # 循环检测配置
        self._loop_detection = loop_detection
        self._loop_window_size = loop_window_size
        self._loop_frequency_threshold = (
            loop_frequency_threshold
            if loop_frequency_threshold is not None
            else max(3, loop_window_size // 2)
        )
        self._loop_identical_threshold = loop_identical_threshold

        # 内部调用历史
        self._call_history: list[dict[str, Any]] = []

    async def check(
        self, data: Any, context: Optional[dict[str, Any]] = None
    ) -> GuardResult:
        """检查工具调用

        依次执行：
        1. 循环攻击检测（基于历史调用模式）
        2. 工具类型专用检查器
        3. 所有配置的检查器
        """
        if not self.enabled:
            return GuardResult.pass_result(level=self.level, message="guard disabled")

        if isinstance(data, dict):
            data = ToolCall(**data)
        elif not isinstance(data, ToolCall):
            return GuardResult.pass_result(
                level=self.level,
                message=f"Unsupported type: {type(data).__name__}",
            )

        # 1. 循环攻击检测
        result = self._check_loop_attack(data)
        if result:
            return result

        # 2. 优先用工具类型专用检查器（复用已配置的实例，保留用户配置）
        routed = self._route_checker(data.tool_name)
        if routed:
            result = routed.check(data)
            if result:
                return result

        # 3. 执行所有配置的检查器
        for checker in self._checkers:
            result = checker.check(data)
            if result:
                return result

        # 记录到历史
        self._record_call(data)

        return GuardResult.pass_result(level=self.level, message="tool call approved")

    def add_checker(self, checker: Checker) -> None:
        """添加自定义检查器"""
        self._checkers.append(checker)

    def reset_history(self) -> None:
        """重置调用历史（新会话开始时调用）"""
        self._call_history.clear()

    # ============ 循环攻击检测 ============

    def _record_call(self, call: ToolCall) -> None:
        """记录一次工具调用到历史"""
        entry = {
            "tool_name": call.tool_name,
            "args": call.tool_args,
        }
        self._call_history.append(entry)
        # 只保留最近 N 条记录
        if len(self._call_history) > self._loop_window_size:
            self._call_history = self._call_history[-self._loop_window_size:]

    def _check_loop_attack(self, call: ToolCall) -> Optional[GuardResult]:
        """检测循环攻击（频率异常 + 重复调用）

        基于客观的运行时数据，不依赖 LLM 文本内容，具有实际检测价值。
        """
        if not self._loop_detection:
            return None

        history = self._call_history
        if len(history) < 3:
            return None

        # 1. 频率检测：最近 N 次调用中，同一工具被调用次数超过阈值
        recent = history[-self._loop_window_size:]
        if len(recent) >= 3:
            tool_counts: dict[str, int] = {}
            for entry in recent:
                tool_name = entry.get("tool_name", "unknown")
                tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
            # 将当前调用也计入
            current_name = call.tool_name
            tool_counts[current_name] = tool_counts.get(current_name, 0) + 1

            for tool_name, count in tool_counts.items():
                if count >= self._loop_frequency_threshold:
                    return GuardResult.block_result(
                        level=self.level,
                        message=(
                            f"Loop attack detected: '{tool_name}' called "
                            f"{count} times in last {len(recent)} calls "
                            f"(threshold: {self._loop_frequency_threshold})"
                        ),
                        rule_id="TOOL-LOOP-001",
                        details={
                            "tool_name": tool_name,
                            "call_count": count,
                            "window_size": len(recent),
                            "threshold": self._loop_frequency_threshold,
                        },
                    )

        # 2. 重复检测：连续 N 次完全相同（工具名+参数一致）
        if len(history) >= self._loop_identical_threshold:
            last_n = history[-self._loop_identical_threshold:]
            if (
                all(e.get("tool_name") == call.tool_name for e in last_n)
                and all(str(e.get("args")) == str(call.tool_args) for e in last_n)
            ):
                return GuardResult.block_result(
                    level=self.level,
                    message=(
                        f"Identical tool call repeated {len(last_n) + 1} times "
                        f"— possible loop: {call.tool_name}"
                    ),
                    rule_id="TOOL-LOOP-002",
                    details={
                        "tool_name": call.tool_name,
                        "args": call.tool_args,
                        "repeat_count": len(last_n) + 1,
                    },
                )

        return None

    # ============ 内部方法 ============

    def _route_checker(self, tool_name: str) -> Optional[Checker]:
        """根据工具名从已配置的检查器中匹配专用检查器"""
        name = tool_name.lower()

        type_map: dict[type, bool] = {}
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
