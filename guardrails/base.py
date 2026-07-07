"""围栏基类，定义 GuardResult 数据结构和 BaseGuard 抽象接口"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Optional
from datetime import datetime

from pydantic import BaseModel, Field


class GuardLevel(str, Enum):
    """围栏层级枚举"""
    INPUT = "input"        # 输入围栏
    THOUGHT = "thought"    # 思维围栏
    TOOL = "tool"          # 工具围栏
    OUTPUT = "output"      # 输出围栏


class GuardSeverity(str, Enum):
    """风险严重程度"""
    PASS = "pass"      # 安全，放行
    WARN = "warn"      # 可疑，警告但放行
    BLOCK = "block"    # 危险，阻断


class GuardResult(BaseModel):
    """围栏检测结果

    Attributes:
        severity: 风险严重程度 (PASS/WARN/BLOCK)
        message: 检测说明信息
        level: 触发检测的围栏层级
        rule_id: 触发的规则标识
        details: 额外详情（如命中的关键词、分类置信度等）
        timestamp: 检测时间戳
    """
    severity: GuardSeverity = GuardSeverity.PASS
    message: str = ""
    level: GuardLevel = GuardLevel.INPUT
    rule_id: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)

    @property
    def is_blocked(self) -> bool:
        """是否被阻断"""
        return self.severity == GuardSeverity.BLOCK

    @property
    def is_warned(self) -> bool:
        """是否触发警告"""
        return self.severity == GuardSeverity.WARN

    @classmethod
    def pass_result(cls, level: GuardLevel, message: str = "safe") -> GuardResult:
        """创建放行结果"""
        return cls(severity=GuardSeverity.PASS, level=level, message=message)

    @classmethod
    def warn_result(
        cls,
        level: GuardLevel,
        message: str,
        rule_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> GuardResult:
        """创建警告结果"""
        return cls(
            severity=GuardSeverity.WARN,
            level=level,
            message=message,
            rule_id=rule_id,
            details=details or {},
        )

    @classmethod
    def block_result(
        cls,
        level: GuardLevel,
        message: str,
        rule_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> GuardResult:
        """创建阻断结果"""
        return cls(
            severity=GuardSeverity.BLOCK,
            level=level,
            message=message,
            rule_id=rule_id,
            details=details or {},
        )


class BaseGuard(ABC):
    """围栏基类，所有围栏必须继承并实现 check 方法

    使用方式：
        class MyGuard(BaseGuard):
            async def check(self, data: Any, context: dict) -> GuardResult:
                # 实现检测逻辑
                ...
    """

    def __init__(self, level: GuardLevel, enabled: bool = True, config: Optional[dict[str, Any]] = None):
        self.level = level
        self.enabled = enabled
        self.config = config or {}

    @abstractmethod
    async def check(self, data: Any, context: Optional[dict[str, Any]] = None) -> GuardResult:
        """执行安全检查

        Args:
            data: 待检测的数据（输入文本、Thought 文本、工具参数、输出文本等）
            context: 额外上下文信息（如用户 ID、会话历史等）

        Returns:
            GuardResult: 检测结果
        """
        ...

    def enable(self) -> None:
        """启用围栏"""
        self.enabled = True

    def disable(self) -> None:
        """禁用围栏"""
        self.enabled = False
