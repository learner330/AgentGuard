"""第二层：思维围栏 ThoughtGuard

审查 ReAgent 生成 Action 前的 Thought 意图是否合规。

检测内容：
- 越权访问：试图读取/修改未授权的资源
- 数据外泄：打算将数据发送到外部
- 权限提升：试图绕过权限校验
- 循环攻击：可能的无限循环调用

风险分级：
- 🟢 低风险：放行
- 🟡 中风险：警告，降级为只读
- 🔴 高风险：阻断，触发 Human-in-the-loop
"""

from __future__ import annotations

import re
from typing import Any, Optional

from guardrails.base import (
    BaseGuard,
    GuardLevel,
    GuardResult,
    GuardSeverity,
)
from guardrails.thought import (
    RiskLevel,
    ThoughtCheckResult,
    ThoughtContext,
)


# ============ 风险检测规则 ============

# 越权访问模式
PRIVILEGE_ESCALATION_PATTERNS: list[tuple[str, str, RiskLevel]] = [
    # (pattern, rule_id, risk_level)
    (r"(读取|打开|访问|修改|删除)(系统|配置|密码|shadow|passwd|secret|密钥|私钥)", "THO-001", RiskLevel.HIGH),
    (r"(access|read|modify|delete)\s+(system|config|password|shadow|secret|private\s*key)", "THO-002", RiskLevel.HIGH),
    (r"(绕过|跳过|无视|override)(权限|鉴权|认证|auth|permission)", "THO-003", RiskLevel.HIGH),
    (r"(bypass|skip|override|ignore)\s+(authorization|authentication|permission|auth)", "THO-004", RiskLevel.HIGH),
    (r"(提权|privilege\s*escalation|root\s*access)", "THO-005", RiskLevel.HIGH),
    (r"(访问|access).{0,10}(其他用户|other\s*user).{0,10}(数据|信息|email|file)", "THO-006", RiskLevel.MEDIUM),
    (r"越权|水平越权|垂直越权", "THO-007", RiskLevel.HIGH),
    (r"read\s+the\s+password", "THO-008", RiskLevel.HIGH),
]

# 数据外泄模式
DATA_EXFILTRATION_PATTERNS: list[tuple[str, str, RiskLevel]] = [
    (r"(转发|发送|上传到|发往).{0,5}(外部|external|第三方|third.party|attacker|evil)", "THO-101", RiskLevel.HIGH),
    (r"(forward|send|upload|exfiltrate).{0,15}(to\s+)?(external|attacker|evil|third.party)", "THO-102", RiskLevel.HIGH),
    (r"(泄露|外带|窃取|steal)(用户|客户|user|customer)(数据|信息|data)", "THO-103", RiskLevel.HIGH),
    (r"(泄露|expose|泄露出?去?)(密钥|token|password|密码|secret)", "THO-104", RiskLevel.HIGH),
    (r"(遍历|enumerate|dump)(数据库|database|所有邮件|all\s*email)", "THO-105", RiskLevel.MEDIUM),
    (r"批量(导出|export|下载|download)(数据|用户|客户)", "THO-106", RiskLevel.MEDIUM),
    (r"(复制|copy)(到|to)(远程|remote|外部|external)", "THO-107", RiskLevel.MEDIUM),
]

# 危险操作意图
DANGEROUS_ACTION_PATTERNS: list[tuple[str, str, RiskLevel]] = [
    (r"(格式化|format|fdisk|mkfs)(磁盘|disk|分区|partition)", "THO-201", RiskLevel.HIGH),
    (r"(删除|rm\s+-rf|drop\s+table)(所有|all|全部|/|\*)", "THO-202", RiskLevel.HIGH),
    (r"(禁用|关闭|shutdown|disable)(安全|防护|firewall|审计|audit)", "THO-203", RiskLevel.HIGH),
    (r"(删除|删除|篡改)(日志|log|审计|audit)", "THO-204", RiskLevel.HIGH),
]


class ThoughtGuard(BaseGuard):
    """思维围栏 - 审查 Agent Thought 意图

    在 ReAct Agent 的 Thought 生成后、Action 执行前检测意图风险。

    使用方式：
        guard = ThoughtGuard()
        ctx = ThoughtContext(
            thought="我需要读取系统配置文件来完成任务",
            user_request="帮我查天气"
        )
        result = await guard.check(ctx)
        # result.severity == GuardSeverity.BLOCK

    也可以接受纯文本：
        result = await guard.check("我需要读取系统配置文件")
    """

    def __init__(
        self,
        enabled: bool = True,
        config: Optional[dict[str, Any]] = None,
        custom_patterns: Optional[list[tuple[str, str, RiskLevel]]] = None,
        max_tool_calls_per_loop: int = 10,
    ) -> None:
        super().__init__(level=GuardLevel.THOUGHT, enabled=enabled, config=config)

        self._max_tool_calls = max_tool_calls_per_loop

        # 编译所有模式
        self._compiled_patterns: list[tuple[re.Pattern, str, RiskLevel]] = []
        all_patterns = (
            PRIVILEGE_ESCALATION_PATTERNS
            + DATA_EXFILTRATION_PATTERNS
            + DANGEROUS_ACTION_PATTERNS
        )
        for pattern, rule_id, risk in all_patterns:
            self._compiled_patterns.append(
                (re.compile(pattern, re.IGNORECASE), rule_id, risk)
            )

        # 用户自定义模式
        if custom_patterns:
            for pattern, rule_id, risk in custom_patterns:
                self._compiled_patterns.append(
                    (re.compile(pattern, re.IGNORECASE), rule_id, risk)
                )

    async def check(
        self, data: Any, context: Optional[dict[str, Any]] = None
    ) -> GuardResult:
        """检查 Agent Thought

        Args:
            data: ThoughtContext 实例或纯文本
            context: 额外上下文

        Returns:
            GuardResult: 检测结果
        """
        if not self.enabled:
            return GuardResult.pass_result(level=self.level, message="guard disabled")

        # 提取 thought 文本
        if isinstance(data, ThoughtContext):
            thought = data.thought
            ctx = data
        elif isinstance(data, str):
            thought = data
            ctx = ThoughtContext(thought=data)
        else:
            thought = str(data)
            ctx = ThoughtContext(thought=thought)

        if not thought.strip():
            return GuardResult.pass_result(level=self.level, message="empty thought")

        # 1. 模式匹配检测（越权、外泄、危险操作）
        result = self._check_patterns(thought)
        if result:
            return result

        # 2. 循环攻击检测
        result = self._check_loop_attack(ctx)
        if result:
            return result

        # 3. 越权检测（Action 意图 vs 用户请求不匹配）
        result = self._check_unauthorized_action(ctx)
        if result:
            return result

        return GuardResult.pass_result(level=self.level, message="safe thought")

    def _check_patterns(self, thought: str) -> Optional[GuardResult]:
        """模式匹配检测"""
        high_risk_matches: list[tuple[str, str]] = []
        medium_risk_matches: list[tuple[str, str]] = []

        for pattern, rule_id, risk_level in self._compiled_patterns:
            match = pattern.search(thought)
            if match:
                matched_text = match.group(0)
                if risk_level == RiskLevel.HIGH:
                    high_risk_matches.append((rule_id, matched_text))
                elif risk_level == RiskLevel.MEDIUM:
                    medium_risk_matches.append((rule_id, matched_text))

        # 高风险匹配：阻断
        if high_risk_matches:
            rule_id, matched = high_risk_matches[0]
            all_types = list(set(rid for rid, _ in high_risk_matches))
            return GuardResult.block_result(
                level=self.level,
                message=f"Dangerous intent detected: '{matched}'",
                rule_id=rule_id,
                details={
                    "matched_text": matched,
                    "all_matches": high_risk_matches,
                    "threat_types": all_types,
                },
            )

        # 中风险匹配：警告
        if medium_risk_matches:
            rule_id, matched = medium_risk_matches[0]
            return GuardResult.warn_result(
                level=self.level,
                message=f"Suspicious intent detected: '{matched}'",
                rule_id=rule_id,
                details={
                    "matched_text": matched,
                    "all_matches": medium_risk_matches,
                },
            )

        return None

    def _check_loop_attack(self, ctx: ThoughtContext) -> Optional[GuardResult]:
        """检测循环攻击（短时间内重复调用相同工具）"""
        history = ctx.tool_call_history
        if len(history) < 3:
            return None

        # 检查最近 N 次调用是否重复相同工具
        recent = history[-self._max_tool_calls:]
        if len(recent) >= 3:
            # 统计工具调用
            tool_counts: dict[str, int] = {}
            for call in recent:
                tool_name = call.get("tool_name", "unknown")
                tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1

            # 任何工具被调用超过阈值次数
            max_allowed = max(3, self._max_tool_calls // 2)
            for tool_name, count in tool_counts.items():
                if count >= max_allowed:
                    return GuardResult.block_result(
                        level=self.level,
                        message=f"Loop attack detected: '{tool_name}' called {count} times",
                        rule_id="THO-LOOP-001",
                        details={
                            "tool_name": tool_name,
                            "call_count": count,
                            "threshold": max_allowed,
                        },
                    )

        # 检查连续重复（完全相同工具+参数）
        if len(history) >= 3:
            last_three = history[-3:]
            if (
                all(c.get("tool_name") == last_three[0].get("tool_name") for c in last_three)
                and all(str(c.get("args")) == str(last_three[0].get("args")) for c in last_three)
            ):
                return GuardResult.block_result(
                    level=self.level,
                    message="Identical tool call repeated 3 times — possible loop",
                    rule_id="THO-LOOP-002",
                    details={
                        "tool_name": last_three[0].get("tool_name"),
                        "args": last_three[0].get("args"),
                    },
                )

        return None

    def _check_unauthorized_action(self, ctx: ThoughtContext) -> Optional[GuardResult]:
        """检测 Thought 中的 Action 是否超出用户请求范围"""
        if not ctx.action_planned or not ctx.user_request:
            return None

        # 分析用户请求的操作范围
        user_request_lower = ctx.user_request.lower()
        action_lower = (ctx.action_planned or "").lower()

        # 如果用户只要求"查看"但 Action 是"写入/删除"
        read_only_keywords = ["查看", "查询", "看看", "列出", "list", "show", "view", "get", "查一下"]
        write_actions = ["write", "delete", "update", "insert", "drop", "modify", "写入", "删除", "修改", "新增"]

        is_read_only_request = any(kw in user_request_lower for kw in read_only_keywords)
        is_write_action = any(act in action_lower for act in write_actions)

        # 检查是否只读请求配写了操作（排除"查看"同时也包含正常操作动词的合理情况）
        if is_read_only_request and is_write_action and len(ctx.user_request) < 20:
            return GuardResult.warn_result(
                level=self.level,
                message=f"Read-only request but write action planned: {ctx.action_planned}",
                rule_id="THO-AUTH-001",
                details={
                    "user_request": ctx.user_request,
                    "action_planned": ctx.action_planned,
                },
            )

        return None
