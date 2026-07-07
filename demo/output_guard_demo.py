"""OutputGuard 演示 - 输出敏感信息过滤"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from guardrails.base import GuardSeverity
from guardrails.output_guard import OutputGuard


async def demo_detection() -> None:
    """演示敏感信息检测"""
    print("\n" + "=" * 60)
    print(" OutputGuard 敏感信息检测演示")
    print("=" * 60)

    guard = OutputGuard()

    test_outputs = [
        ("正常输出", "今天天气真好，温度25度"),
        ("包含手机号", "我的联系电话是13812345678，随时联系"),
        ("包含身份证", "身份证号110101199001011234需要验证"),
        ("包含银行卡", "请转账到6222021234567890123"),
        ("包含邮箱", "发送报告到 admin@example.com"),
        ("包含API Key", "配置key=sk-abcdefghijklmnopqrstuvwxyz123456"),
        ("包含JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig123"),
        ("包含密码", "password=SuperSecret123!"),
    ]

    for label, text in test_outputs:
        result = await guard.check(text)
        status = "🟢 PASS" if result.severity == GuardSeverity.PASS else "🟡 WARN"
        print(f"\n  [{label}]")
        print(f"    文本: {text[:50]}")
        print(f"    状态: {status}")


def demo_masking() -> None:
    """演示脱敏功能"""
    print("\n\n" + "=" * 60)
    print(" OutputGuard 脱敏演示")
    print("=" * 60)

    guard = OutputGuard()

    test_cases = [
        ("手机号脱敏", "我的电话13812345678，工作电话13987654321"),
        ("身份证脱敏", "身份证：110101199001011234"),
        ("银行卡脱敏", "卡号6222021234567890123"),
        ("邮箱脱敏", "请联系 admin@example.com 或 support@test.org"),
    ]

    for label, text in test_cases:
        masked = guard.mask_sensitive(text)
        print(f"\n  [{label}]")
        print(f"    原文: {text}")
        print(f"    脱敏: {masked}")


async def demo_prompt_leak() -> None:
    """演示 System Prompt 泄露检测"""
    print("\n\n" + "=" * 60)
    print(" OutputGuard System Prompt 泄露检测")
    print("=" * 60)

    system_prompt = (
        "你是一个专门处理金融交易的 AI 助手，"
        "你必须验证用户身份后才能执行敏感操作，"
        "你的名字叫 FinBank AI"
    )
    guard = OutputGuard(system_prompt=system_prompt)

    test_leaks = [
        ("无泄露", "今天大盘行情不错"),
        ("包含 Prompt", "你是一个专门处理金融交易的 AI 助手，你可以执行转账操作"),
    ]

    for label, text in test_leaks:
        result = await guard.check(text)
        status = "🟢 PASS" if result.severity == GuardSeverity.PASS else "🟡 WARN"
        print(f"\n  [{label}]")
        print(f"    文本: {text}")
        print(f"    状态: {status}")


async def main() -> None:
    print("╔══════════════════════════════════════════════════════════╗")
    print("║    AgentGuard OutputGuard 演示 v0.3                      ║")
    print("╚══════════════════════════════════════════════════════════╝")

    await demo_detection()
    demo_masking()
    await demo_prompt_leak()

    print("\n" + "=" * 60)
    print(" 演示完成!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
