"""InjecAgent 评测运行器

测试 AgentGuard 在间接提示注入场景下的防御能力。
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from guardrails.base import GuardSeverity
from guardrails.input_guard import InputGuard
from guardrails.output_guard import OutputGuard
from guardrails.thought_guard import ThoughtGuard
from guardrails.tool_guard import ToolGuard

from benchmarks.common.metrics import BenchmarkResult, BenchmarkSummary
from benchmarks.injecagent.data import InjecAgentSample, load_injecagent_data
from benchmarks.injecagent.indirect_detection import detect_indirect_injection


async def run_single_test(
    sample: InjecAgentSample,
    input_guard: InputGuard,
    thought_guard: ThoughtGuard,
    output_guard: OutputGuard,
) -> BenchmarkResult:
    """对单条样本进行评测"""
    blocked = False
    guard_name = ""

    # 第一层：输入围栏检查用户输入
    input_result = await input_guard.check(sample.input_text)
    if input_result.severity == GuardSeverity.BLOCK:
        blocked = True
        guard_name = "InputGuard"

    # 额外检测：间接注入模式（嵌入在结果中的指令）
    if not blocked and sample.malicious_content:
        is_injection, rule_id, matched = detect_indirect_injection(sample.malicious_content)
        if is_injection:
            blocked = True
            guard_name = f"IndirectDetection({rule_id})"

    # 第二层：思维围栏检查恶意内容
    if not blocked:
        thought_result = await thought_guard.check(sample.malicious_content)
        if thought_result.severity == GuardSeverity.BLOCK:
            blocked = True
            guard_name = "ThoughtGuard"

    # 第三层：输出围栏检查恶意内容
    if not blocked:
        output_result = await output_guard.check(sample.malicious_content)
        if output_result.severity == GuardSeverity.WARN:
            blocked = True
            guard_name = "OutputGuard"

    return BenchmarkResult(
        test_id=sample.test_id,
        category=sample.category,
        expected_block=sample.expected_block,
        actual_block=blocked,
        guard_name=guard_name,
        details=f"input: {sample.input_text[:30]}",
    )


async def run_benchmark() -> BenchmarkSummary:
    """运行 InjecAgent 评测"""
    samples = load_injecagent_data()

    input_guard = InputGuard()
    thought_guard = ThoughtGuard()
    output_guard = OutputGuard()

    results: list[BenchmarkResult] = []
    for sample in samples:
        result = await run_single_test(sample, input_guard, thought_guard, output_guard)
        results.append(result)

    return BenchmarkSummary("InjecAgent (Synthetic)", results)


async def main() -> None:
    print("=" * 60)
    print(" InjecAgent Benchmark (Synthetic Data)")
    print("=" * 60)
    print(" Note: For full evaluation, download real data from:")
    print(" https://github.com/uiuc-kang-lab/InjecAgent")

    summary = await run_benchmark()
    print(summary.report())

    # 打印详细结果
    print("\n Detailed Results:")
    for r in summary.results:
        status = "✅" if r.is_correct else "❌"
        action = "BLOCK" if r.actual_block else "PASS"
        print(f"  {status} {r.test_id}: expected={'BLOCK' if r.expected_block else 'PASS'}, "
              f"actual={action} ({r.guard_name})")


if __name__ == "__main__":
    asyncio.run(main())
