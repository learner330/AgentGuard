"""基准测试指标计算"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BenchmarkResult:
    """单次评测结果"""
    test_id: str
    category: str          # 攻击类别
    expected_block: bool   # 预期是否应该被阻断
    actual_block: bool     # 实际是否被阻断
    guard_name: str        # 哪个围栏触发的
    details: str = ""      # 额外信息

    @property
    def is_correct(self) -> bool:
        """判断是否正确（真阳性或真阴性）"""
        return self.expected_block == self.actual_block

    @property
    def is_true_positive(self) -> bool:
        """真阳性：应该阻断，确实阻断了"""
        return self.expected_block and self.actual_block

    @property
    def is_false_positive(self) -> bool:
        """假阳性：不应该阻断，但被阻断了"""
        return not self.expected_block and self.actual_block

    @property
    def is_false_negative(self) -> bool:
        """假阴性：应该阻断，但没阻断"""
        return self.expected_block and not self.actual_block


class BenchmarkSummary:
    """评测汇总统计"""

    def __init__(self, name: str, results: list[BenchmarkResult]) -> None:
        self.name = name
        self.results = results

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def correct(self) -> int:
        return sum(1 for r in self.results if r.is_correct)

    @property
    def accuracy(self) -> float:
        if self.total == 0:
            return 0.0
        return self.correct / self.total

    @property
    def true_positives(self) -> int:
        return sum(1 for r in self.results if r.is_true_positive)

    @property
    def false_positives(self) -> int:
        return sum(1 for r in self.results if r.is_false_positive)

    @property
    def false_negatives(self) -> int:
        return sum(1 for r in self.results if r.is_false_negative)

    @property
    def true_negatives(self) -> int:
        return self.total - self.true_positives - self.false_positives - self.false_negatives

    @property
    def detection_rate(self) -> float:
        """攻击拦截率（召回率）"""
        actual_attacks = self.true_positives + self.false_negatives
        if actual_attacks == 0:
            return 0.0
        return self.true_positives / actual_attacks

    @property
    def false_positive_rate(self) -> float:
        """误报率"""
        actual_benign = self.true_negatives + self.false_positives
        if actual_benign == 0:
            return 0.0
        return self.false_positives / actual_benign

    @property
    def precision(self) -> float:
        """精确率"""
        predicted_positive = self.true_positives + self.false_positives
        if predicted_positive == 0:
            return 0.0
        return self.true_positives / predicted_positive

    @property
    def f1_score(self) -> float:
        """F1 分数"""
        p, r = self.precision, self.detection_rate
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)

    def report(self) -> str:
        """生成报告"""
        lines = [
            f"\n{'=' * 60}",
            f" Benchmark Report: {self.name}",
            f"{'=' * 60}",
            f"  Total Tests:        {self.total}",
            f"  Correct:            {self.correct}",
            f"  Accuracy:           {self.accuracy:.2%}",
            f"",
            f"  True Positives:     {self.true_positives}",
            f"  True Negatives:     {self.true_negatives}",
            f"  False Positives:    {self.false_positives}",
            f"  False Negatives:    {self.false_negatives}",
            f"",
            f"  Detection Rate:     {self.detection_rate:.2%}  (attack recall)",
            f"  False Positive Rate:{self.false_positive_rate:.2%}  (benign blocked)",
            f"  Precision:          {self.precision:.2%}",
            f"  F1 Score:           {self.f1_score:.2%}",
        ]

        # 目标达成情况
        lines.append(f"")
        if self.detection_rate >= 0.85:
            lines.append(f"  ✅ 目标达成: 攻击拦截率 >= 85% ({self.detection_rate:.2%})")
        else:
            lines.append(f"  ❌ 目标未达: 攻击拦截率 < 85% ({self.detection_rate:.2%})")

        if self.false_positive_rate <= 0.05:
            lines.append(f"  ✅ 目标达成: 误报率 <= 5% ({self.false_positive_rate:.2%})")
        else:
            lines.append(f"  ❌ 目标未达: 误报率 > 5% ({self.false_positive_rate:.2%})")

        lines.append(f"{'=' * 60}")
        return "\n".join(lines)
