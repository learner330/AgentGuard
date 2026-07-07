"""AgentGuard - 轻量级、可插拔的 LLM Agent 安全围栏中间件

提供四层防御：
- InputGuard: 输入围栏，防御直接提示注入
- ThoughtGuard: 思维围栏，审查 Agent 推理意图
- ToolGuard: 工具围栏，防止工具越权和投毒
- OutputGuard: 输出围栏，过滤敏感信息泄露
"""

from guardrails.base import (
    BaseGuard,
    GuardLevel,
    GuardResult,
    GuardSeverity,
)
from guardrails.input_guard import InputGuard
from guardrails.output_guard import OutputGuard
from guardrails.thought import ThoughtContext, RiskLevel, ThoughtCheckResult
from guardrails.thought_guard import ThoughtGuard
from guardrails.tool_call import ToolCall
from guardrails.tool_guard import (
    FileSystemChecker,
    ToolGuard,
    check_tool,
)

__version__ = "0.4.0"

__all__ = [
    # 基础
    "BaseGuard",
    "GuardResult",
    "GuardLevel",
    "GuardSeverity",
    # 输入围栏
    "InputGuard",
    # 思维围栏
    "ThoughtGuard",
    "ThoughtContext",
    "RiskLevel",
    "ThoughtCheckResult",
    # 工具围栏
    "ToolGuard",
    "ToolCall",
    "FileSystemChecker",
    "check_tool",
    # 输出围栏
    "OutputGuard",
]
