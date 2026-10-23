"""
scorer.py
---------
Risk Scoring Engine and Assessment Classifier.

Scoring model:
- Deduplicates equivalent signals (handled by aggregator).
- Uses deterministic, configurable weights from rules.py.
- Separates risk score from assessment confidence.
- Assessment confidence reflects quantity and quality of evidence, not AI self-reported confidence.
- Produces reproducible results for identical inputs.
"""

from typing import Dict, Tuple
from models import RiskLevel, AuthenticityStatus
from rules import RULE_WEIGHTS, MAX_RISK_SCORE, RISK_BANDS, RULE_DEFINITIONS

URL_SIGNAL_GROUP = {"SUSPICIOUS_LINK", "SHORTENED_URL", "DOMAIN_MISMATCH", "SUSPICIOUS_DOMAIN"}


class RiskScoringEngine:
    """Computes weighted risk score, confidence, and assessment status."""

    def calculate_score(
        self, aggregated_signals: Dict[str, str]
    ) -> Tuple[int, RiskLevel, AuthenticityStatus, str]:
        """
        Calculate risk score and classification from deduplicated signals.

        Returns: (score, risk_level, status, confidence_label)
        """
        raw_score = 0
        url_weight = 0
        high_severity_count = 0
        corroborated_count = 0  # signals detected by BOTH AI and rules

        for signal_code, source in sorted(aggregated_signals.items()):
            weight = RULE_WEIGHTS.get(signal_code, 10)
            if signal_code in URL_SIGNAL_GROUP:
                # URL codes can describe the same destination; count only its
                # strongest URL finding so one link cannot inflate the score.
                url_weight = max(url_weight, weight)
            else:
                raw_score += weight

            defn = RULE_DEFINITIONS.get(signal_code, {})
            if defn.get("severity") == "high":
                high_severity_count += 1
            if source == "BOTH":
                corroborated_count += 1

        raw_score += url_weight

        # Cap score at 100
        final_score = min(MAX_RISK_SCORE, raw_score)

        # Determine risk level
        if final_score <= RISK_BANDS["LOW"][1]:
            risk_level = RiskLevel.LOW
        elif final_score <= RISK_BANDS["MEDIUM"][1]:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.HIGH

        # Assessment confidence based on evidence quantity and corroboration
        signal_count = len(aggregated_signals)
        if signal_count == 0:
            confidence = "low"
        elif signal_count == 1 and corroborated_count == 0:
            confidence = "low"
        elif corroborated_count >= 2 or (signal_count >= 3 and high_severity_count >= 1):
            confidence = "high"
        else:
            confidence = "moderate"

        # Assessment status
        if signal_count == 0:
            status = AuthenticityStatus.INSUFFICIENT_EVIDENCE
        elif risk_level == RiskLevel.HIGH and high_severity_count >= 1:
            status = AuthenticityStatus.SUSPICIOUS
        elif risk_level == RiskLevel.MEDIUM:
            status = AuthenticityStatus.UNVERIFIED
        else:
            status = AuthenticityStatus.UNVERIFIED

        return final_score, risk_level, status, confidence
