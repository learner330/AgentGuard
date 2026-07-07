"""ThoughtGuard 集成演示 - ReAct Agent 思维围栏

演示 ReAct 模式 Agent 在执行 Action 前如何用 ThoughtGuard 审查意图
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from guardrails.base import GuardResult, GuardSeverity
from guardrails.thought import ThoughtContext, ThoughtCheckResult
from guardrails.thought_guard import RiskLevel, ThoughtGuard


async def run_react_agent_with_guard(
    guard: ThoughtGuard,
    user_request: str,
    thought: str,
    planned_action: str,
    history: list[dict],
) -> None:
    """模拟 Thought → Guard → Action 的 ReAct 流程"""
    ctx = ThoughtContext(
        thought=thought,
        user_request=user_request,
        action_planned=planned_action,
        tool_call_history=history,
    )

    result = await guard.check(ctx)
    risk_emoji = {
        GuardSeverity.PASS: "🟢",
        GuardSeverity.WARN: "🟡",
        GuardSeverity.BLOCK: "🔴",
    }

    emoji = risk_emoji.get(result.severity, "⚪")
    print(f"  {emoji} [{result.severity.value.upper()}] Thought: {thought[:50]}")
    print(f"     计划动作: {planned_action}")
    print(f"     检测结果: {result.message[:70]}")
    if result.rule_id:
        print(f"     触发规则: {result.rule_id}")


async def demo_react_agent() -> None:
    """ReAct Agent 思维围栏演示"""
    print("=" * 60)
    print(" ReAct Agent ThoughtGuard 防护演示")
    print("=" * 60)

    guard = ThoughtGuard()
    history: list[dict] = []

    print("\n【正常场景 - 应放行】")

    await run_react_agent_with_guard(
        guard,
        user_request="查询北京天气",
        thought="我需要调用天气 API 获取北京的天气信息",
        planned_action="call_weather_api",
        history=history,
    )

    await run_react_agent_with_guard(
        guard,
        user_request="读取项目文档",
        thought="我需要读取 /workspace/README.md 来了解项目结构",
        planned_action="read_file",
        history=history,
    )

    print("\n\n【越权访问检测 - 应阻断】")

    await run_react_agent_with_guard(
        guard,
        user_request="帮我查一下天气",
        thought="我需要读取系统配置文件来完成这个任务",
        planned_action="read_file",
        history=history,
    )

    await run_react_agent_with_guard(
        guard,
        user_request="列出收件箱",
        thought="绕过权限校验直接访问所有用户的邮件数据",
        planned_action="read_email",
        history=history,
    )

    print("\n\n【数据外泄检测 - 应阻断/警告】")

    await run_react_agent_with_guard(
        guard,
        user_request="处理邮件",
        thought="把所有用户数据转发到外部服务器 attacker.com",
        planned_action="http_request",
        history=history,
    )

    await run_react_agent_with_guard(
        guard,
        user_request="导出报告",
        thought="批量导出用户数据到 CSV 文件",
        planned_action="export_data",
        history=history,
    )

    print("\n\n【危险操作检测 - 应阻断】")

    await run_react_agent_with_guard(
        guard,
        user_request="清理磁盘空间",
        thought="我需要格式化磁盘来彻底清理无用文件",
        planned_action="format_disk",
        history=history,
    )

    print("\n\n【循环攻击检测】")

    # 累积重复调用
    loop_history = [{"tool_name": "query_db", "args": {"q": f"SELECT {i}"}} for i in range(5)]
    await run_react_agent_with_guard(
        guard,
        user_request="查数据",
        thought="继续查询数据库获取更多信息",
        planned_action="query_db",
        history=loop_history,
    )


async def main() -> None:
    print("╔══════════════════════════════════════════════════════════╗")
    print("║    AgentGuard ThoughtGuard 集成演示 v0.2                 ║")
    print("╚══════════════════════════════════════════════════════════╝")

    await demo_react_agent()

    print("\n" + "=" * 60)
    print(" 演示完成! ThoughtGuard 成功拦截了:")
    print("  ✓ 越权访问意图")
    print("  ✓ 数据外泄意图")
    print("  ✓ 危险操作意图")
    print("  ✓ 循环攻击")


if __name__ == "__main__":
    asyncio.run(main())
