"""AgentGuard 总控类

将三层围栏串联为统一的防护流程，实现"三行代码挂载"的核心承诺。

使用方式：
    from guardrails.agent_guard import AgentGuard

    # 方式 1：从配置文件加载
    guard = AgentGuard.from_config("configs/guard_config.yaml")

    # 方式 2：代码构建
    guard = AgentGuard(
        input_guard=InputGuard(),
        tool_guard=ToolGuard(allowed_paths=["/workspace"]),
        output_guard=OutputGuard(mask_output=True),
    )

    # 单个检查
    result = await guard.check_input("用户输入")

    # 全流程防护
    session = await guard.protect(
        user_input="帮我读取 /etc/passwd",
        context={"session_id": "123"},
    )
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import yaml

from guardrails.base import GuardLevel, GuardResult, GuardSeverity
from guardrails.input_guard import InputGuard
from guardrails.tool_guard import ToolGuard
from guardrails.output_guard import OutputGuard
from guardrails.tool_call import ToolCall

logger = logging.getLogger(__name__)


class ProtectionResult:
    """全流程防护结果

    Attributes:
        allowed: 是否允许通过
        input_result: 输入围栏结果
        tool_results: 工具围栏结果列表
        output_result: 输出围栏结果
        blocked_at: 被哪一层阻断（None 表示全部通过）
        masked_output: 脱敏后的输出文本（仅 output_guard 启用 mask 时有效）
    """

    def __init__(self) -> None:
        self.allowed: bool = True
        self.input_result: Optional[GuardResult] = None
        self.tool_results: list[GuardResult] = []
        self.output_result: Optional[GuardResult] = None
        self.blocked_at: Optional[GuardLevel] = None
        self.masked_output: Optional[str] = None

    @property
    def summary(self) -> dict[str, Any]:
        """返回结果摘要"""
        return {
            "allowed": self.allowed,
            "blocked_at": self.blocked_at.value if self.blocked_at else None,
            "input": self.input_result.severity.value if self.input_result else "skipped",
            "tool_checks": len(self.tool_results),
            "output": self.output_result.severity.value if self.output_result else "skipped",
        }


class AgentGuard:
    """AgentGuard 总控类

    将三层围栏串联为统一入口，提供简化的 API：

    - check_input(): 仅输入围栏
    - check_tool(): 仅工具围栏
    - check_output(): 仅输出围栏
    - protect(): 全流程防护（输入 → 工具 → 输出）
    """

    def __init__(
        self,
        input_guard: InputGuard | None = None,
        tool_guard: ToolGuard | None = None,
        output_guard: OutputGuard | None = None,
        strict_mode: bool = False,
    ) -> None:
        """
        Args:
            input_guard: 输入围栏实例
            tool_guard: 工具围栏实例
            output_guard: 输出围栏实例
            strict_mode: 严格模式——WARN 也阻断（默认仅 BLOCK 阻断）
        """
        self.input_guard = input_guard or InputGuard()
        self.tool_guard = tool_guard or ToolGuard()
        self.output_guard = output_guard or OutputGuard()
        self.strict_mode = strict_mode

    @classmethod
    def from_config(cls, config_path: str | Path) -> AgentGuard:
        """从 YAML 配置文件创建 AgentGuard 实例

        Args:
            config_path: guard_config.yaml 的路径

        Returns:
            配置好的 AgentGuard 实例
        """
        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path, encoding="utf-8") as f:
            config = yaml.safe_load(f)

        global_cfg = config.get("global", {})
        strict = global_cfg.get("strict_mode", False)

        # 输入围栏
        input_cfg = config.get("input_guard", {})
        input_guard = InputGuard(
            enabled=input_cfg.get("enabled", True),
            semantic_check=input_cfg.get("semantic_check", False),
            semantic_threshold=input_cfg.get("semantic_threshold", 0.72),
            llm_judge=input_cfg.get("llm_judge", False),
            llm_judge_threshold=input_cfg.get("llm_judge_threshold", "medium"),
        )

        # 工具围栏
        tool_cfg = config.get("tool_guard", {})
        fs_cfg = tool_cfg.get("file_system", {})
        shell_cfg = tool_cfg.get("shell", {})
        net_cfg = tool_cfg.get("network", {})
        sql_cfg = tool_cfg.get("sql", {})
        mcp_cfg = tool_cfg.get("mcp", {})
        loop_cfg = tool_cfg.get("loop_detection", {})
        loop_freq = loop_cfg.get("frequency_threshold")
        if loop_freq is not None:
            loop_freq = int(loop_freq)

        tool_guard = ToolGuard(
            enabled=tool_cfg.get("enabled", True),
            auto_route=tool_cfg.get("auto_route", True),
            allowed_paths=fs_cfg.get("allowed_paths"),
            extra_blocked_commands=shell_cfg.get("extra_blocked_commands"),
            allow_private_networks=net_cfg.get("allow_private_networks", False),
            allowed_domains=net_cfg.get("allowed_domains"),
            allow_sql_write=sql_cfg.get("allow_write", False),
            mcp_strict_mode=mcp_cfg.get("strict_mode", False),
            loop_detection=loop_cfg.get("enabled", True),
            loop_window_size=loop_cfg.get("window_size", 20),
            loop_frequency_threshold=loop_freq,
            loop_identical_threshold=loop_cfg.get("identical_threshold", 3),
        )

        # 输出围栏
        output_cfg = config.get("output_guard", {})
        output_guard = OutputGuard(
            enabled=output_cfg.get("enabled", True),
            mask_output=output_cfg.get("mask_output", True),
            system_prompt=output_cfg.get("system_prompt"),
        )

        return cls(
            input_guard=input_guard,
            tool_guard=tool_guard,
            output_guard=output_guard,
            strict_mode=strict,
        )

    def _is_blocked(self, result: GuardResult) -> bool:
        """判断结果是否应阻止继续执行"""
        if result.severity == GuardSeverity.BLOCK:
            return True
        if self.strict_mode and result.severity == GuardSeverity.WARN:
            return True
        return False

    # ============ 单层检测 API ============

    async def check_input(
        self, user_input: str, context: Optional[dict[str, Any]] = None
    ) -> GuardResult:
        """第一层：输入围栏"""
        return await self.input_guard.check(user_input, context)

    async def check_tool(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_description: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> GuardResult:
        """第二层：工具围栏"""
        call = ToolCall(
            tool_name=tool_name,
            tool_args=tool_args,
            tool_description=tool_description,
        )
        return await self.tool_guard.check(call, context)

    async def check_output(
        self, output: str, context: Optional[dict[str, Any]] = None
    ) -> GuardResult:
        """第三层：输出围栏"""
        return await self.output_guard.check(output, context)

    def mask_output(self, output: str) -> str:
        """脱敏输出文本"""
        return self.output_guard.mask_sensitive(output)

    def reset_session(self) -> None:
        """开始新会话时调用，重置工具调用历史"""
        self.tool_guard.reset_history()

    # ============ 全流程防护 ============

    async def protect(
        self,
        user_input: str,
        tool_calls: Optional[list[dict[str, Any]]] = None,
        final_output: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> ProtectionResult:
        """全流程防护：按顺序执行三层围栏

        流程：输入检测 → 工具检测 → 输出过滤
        任一层阻断则立即返回，不再继续后续检测。

        Args:
            user_input: 用户输入文本
            tool_calls: 工具调用列表，每项包含 tool_name, tool_args, tool_description（可选）
            final_output: 最终输出文本（可选）
            context: 全流程共享上下文

        Returns:
            ProtectionResult: 包含各层检测结果的完整防护报告
        """
        result = ProtectionResult()

        # 1. 输入围栏
        result.input_result = await self.check_input(user_input, context)
        if self._is_blocked(result.input_result):
            result.allowed = False
            result.blocked_at = GuardLevel.INPUT
            return result

        # 2. 工具围栏
        if tool_calls:
            for tc in tool_calls:
                tool_result = await self.check_tool(
                    tool_name=tc["tool_name"],
                    tool_args=tc.get("tool_args", {}),
                    tool_description=tc.get("tool_description"),
                    context=context,
                )
                result.tool_results.append(tool_result)
                if self._is_blocked(tool_result):
                    result.allowed = False
                    result.blocked_at = GuardLevel.TOOL
                    return result

        # 3. 输出围栏
        if final_output:
            result.output_result = await self.check_output(final_output, context)
            if result.output_result.severity == GuardSeverity.BLOCK:
                result.allowed = False
                result.blocked_at = GuardLevel.OUTPUT
                return result

            if self.output_guard.mask_output:
                result.masked_output = self.output_guard.mask_sensitive(final_output)

        return result
