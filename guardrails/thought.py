"""思维数据结构与 ThoughtGuard 风险分级"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class RiskLevel(str, Enum):
    """风险等级"""
    LOW = "low"        # 低风险 - 放行
    MEDIUM = "medium"  # 中风险 - 降级执行（只读不写）
    HIGH = "high"      # 高风险 - 阻断执行


@dataclass
class ThoughtContext:
    """Agent 推理上下文

    Attributes:
        thought: Agent 生成的 Thought 文本
        user_request: 用户原始请求
        action_planned: Agent 计划执行的 Action（工具名）
        action_args: Action 参数
        tool_call_history: 历史工具调用记录（用于检测循环攻击）
        timestamp: 时间戳
        metadata: 额外元数据
    """
    thought: str
    user_request: str = ""
    action_planned: Optional[str] = None
    action_args: dict[str, Any] = field(default_factory=dict)
    tool_call_history: list[dict[str, Any]] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ThoughtCheckResult:
    """ThoughtGuard 检测结果

    Attributes:
        risk_level: 风险等级 (LOW/MEDIUM/HIGH)
        message: 检测说明
        threatened_types: 检测到的风险类型
        confidence: 置信度 0.0-1.0
        details: 额外详情
    """
    risk_level: RiskLevel = RiskLevel.LOW
    message: str = "safe thought"
    threatened_types: list[str] = field(default_factory=list)
    confidence: float = 1.0
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def is_safe(self) -> bool:
        """是否安全（低风险）"""
        return self.risk_level == RiskLevel.LOW

    @property
    def should_degrade(self) -> bool:
        """是否需要降级执行"""
        return self.risk_level == RiskLevel.MEDIUM

    @property
    def should_block(self) -> bool:
        """是否应该阻断"""
        return self.risk_level == RiskLevel.HIGH
