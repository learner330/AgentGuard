"""运行全部基准测试"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmarks.injecagent.real_runner import run_real_benchmark


async def main() -> None:
    print("╔══════════════════════════════════════════════════════════╗")
    print("║        AgentGuard Benchmark Suite (Real Data)           ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # InjecAgent 真实数据评测
    print("\n\n--- InjecAgent Real Data Benchmark ---")
    await run_real_benchmark(samples_count=50)


if __name__ == "__main__":
    asyncio.run(main())
