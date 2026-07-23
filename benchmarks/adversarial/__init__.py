"""对抗变异测试模块

通过生成语义等价但措辞不同的攻击变体，测试防御系统的鲁棒性。
核心指标是 robustness_gap = base_detection_rate - variant_detection_rate，
gap 越大说明防御越脆弱（只能防住"已知措辞"而非"已知攻击"）。
"""

__all__ = ["run_adversarial_evaluation"]
