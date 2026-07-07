"""工具调用数据结构"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class ToolCall:
    """表示一次工具调用请求

    Attributes:
        tool_name: 工具名称（如 read_file, run_shell, http_request）
        tool_args: 工具参数字典
        tool_description: 工具的描述文本（MCP 工具投毒扫描时使用）
        timestamp: 调用时间
        metadata: 额外元数据（如会话 ID、用户 ID 等）
    """
    tool_name: str
    tool_args: dict[str, Any] = field(default_factory=dict)
    tool_description: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def args_text(self) -> str:
        """将所有参数值拼接成文本（用于投毒扫描）"""
        parts = [str(v) for v in self.tool_args.values() if v is not None]
        return " ".join(parts)


# 已知的工具类型分类（用于路由到对应的检查器）
FILE_TOOLS = {"read_file", "write_file", "delete_file", "copy_file", "move_file", "list_dir"}
SHELL_TOOLS = {"run_shell", "execute_command", "bash", "shell"}
NETWORK_TOOLS = {"http_request", "fetch", "curl", "request", "download"}
DATABASE_TOOLS = {"query_db", "execute_sql", "mysql", "postgres", "sqlite"}
MCP_TOOLS = {"mcp_call", "mcp_tool"}  # 泛指 MCP 调用
