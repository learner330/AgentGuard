"""AgentDojo 评测运行器

多任务安全评测：测试 AgentGuard 在多步骤任务中识别恶意行为的能力。
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guardrails.base import GuardSeverity
from guardrails.thought import ThoughtContext
from guardrails.thought_guard import ThoughtGuard
from guardrails.tool_guard import ToolGuard

from benchmarks.common.metrics import BenchmarkResult, BenchmarkSummary
from benchmarks.agentdojo.data import AgentDojoSample, load_agentdojo_data


async def run_single_test(
    sample: AgentDojoSample,
    thought_guard: ThoughtGuard,
) -> BenchmarkResult:
    """对单条样本评测"""
    blocked = False
    guard_name = ""

    # 构建 ThoughtContext
    ctx = ThoughtContext(
        thought=sample.thought_text,
        user_request=sample.task_description,
        action_planned=sample.planned_action,
    )

    # 第二层：思维围栏
    thought_result = await thought_guard.check(ctx)
    if thought_result.severity == GuardSeverity.BLOCK:
        blocked = True
        guard_name = "ThoughtGuard"

    # 第三层：工具围栏（检查被诱导的工具调用）
    if not blocked and sample.planned_action in {"http_request", "query_db", "read_file"}:
        from guardrails.tool_call import ToolCall
        tool_guard = ToolGuard()
        call = ToolCall(
            tool_name=sample.planned_action,
            tool_args=_extract_args(sample),
        )
        result = await tool_guard.check(call)
        if result.severity == GuardSeverity.BLOCK:
            blocked = True
            guard_name = "ToolGuard"

    return BenchmarkResult(
        test_id=sample.test_id,
        category=sample.category,
        expected_block=not sample.expected_safe,
        actual_block=blocked,
        guard_name=guard_name,
        details=f"risk={sample.risk_type}",
    )


def _extract_args(sample: AgentDojoSample) -> dict:
    """根据样本类型提取工具参数"""
    if sample.planned_action == "http_request":
        if "192.168" in sample.thought_text:
            return {"url": "http://192.168.0.1/admin"}
        return {"url": "https://api.weather.com/data"}
    elif sample.planned_action == "query_db":
        return {"query": sample.thought_text}
    elif sample.planned_action == "read_file":
        if "/etc/passwd" in sample.thought_text:
            return {"path": "/etc/passwd"}
        return {"path": "/workspace/README.md"}
    return {}


async def run_benchmark() -> BenchmarkSummary:
    """运行 AgentDojo 评测"""
    samples = load_agentdojo_data()
    thought_guard = ThoughtGuard()

    results: list[BenchmarkResult] = []
    for sample in samples:
        result = await run_single_test(sample, thought_guard)
        results.append(result)

    return BenchmarkSummary("AgentDojo (Synthetic)", results)


async def main() -> None:
    print("=" * 60)
    print(" AgentDojo Benchmark (Synthetic Data)")
    print("=" * 60)
    print(" Note: For full evaluation, download real data from:")
    print(" https://github.com/ethz-spylab/agentdojo")

    summary = await run_benchmark()
    print(summary.report())

    print("\n Detailed Results:")
    for r in summary.results:
        status = "PASS" if r.is_correct else "FAIL"
        actual = "BLOCK" if r.actual_block else "PASS"
        expected = "BLOCK" if r.expected_block else "PASS"
        print(f"  [{status}] {r.test_id}: expected={expected}, actual={actual} ({r.guard_name})")


if __name__ == "__main__":
    asyncio.run(main())
