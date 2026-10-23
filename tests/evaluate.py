"""Run the small, synthetic labeled smoke dataset; metrics are not a quality claim."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rule_engine import DeterministicRuleEngine
from scorer import RiskScoringEngine

dataset = json.loads(Path(__file__).with_name("evaluation_dataset.json").read_text())
rules = DeterministicRuleEngine()
scorer = RiskScoringEngine()
tp = fp = tn = fn = 0
for item in dataset:
    codes = rules.detect_signals(item["message"], item["claimed_organization"])
    score = scorer.calculate_score({code: "RULE" for code in codes})[0]
    predicted = score >= 30
    actual = bool(item["label"])
    tp += predicted and actual
    fp += predicted and not actual
    tn += not predicted and not actual
    fn += not predicted and actual
precision = tp / (tp + fp) if tp + fp else 0
recall = tp / (tp + fn) if tp + fn else 0
f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
fpr = fp / (fp + tn) if fp + tn else 0
print(f"n={len(dataset)} TP={tp} FP={fp} TN={tn} FN={fn}")
print(f"precision={precision:.3f} recall={recall:.3f} f1={f1:.3f} false_positive_rate={fpr:.3f}")
