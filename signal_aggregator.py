"""
signal_aggregator.py
--------------------
Signal Aggregator & Deduplication Engine.

Merges AI semantic signals and deterministic rule signals WITHOUT double-counting.
Tracks detection provenance ('AI', 'RULE', or 'BOTH').
When both AI and rules detect the same signal, the weight is counted once
but confidence in that finding increases.
"""

from typing import Set, Dict, Optional
from models import SemanticFeatures
from rules import (
    OTP_REQUEST, CREDENTIAL_REQUEST, URGENCY, PAYMENT_REQUEST,
    ACCOUNT_THREAT, AUTHORITY_IMPERSONATION, REWARD_BAIT,
    REMOTE_ACCESS_REQUEST, LINK_CLICK_REQUEST,
)


class SignalAggregator:
    """Consolidates signals from AI and deterministic rule detection."""

    @staticmethod
    def map_ai_features_to_signals(features: SemanticFeatures) -> Set[str]:
        """Convert boolean semantic features from AI into standard signal codes."""
        ai_signals: Set[str] = set()
        if features.otp_request:
            ai_signals.add(OTP_REQUEST)
        if features.credential_request:
            ai_signals.add(CREDENTIAL_REQUEST)
        if features.urgency:
            ai_signals.add(URGENCY)
        if features.payment_request:
            ai_signals.add(PAYMENT_REQUEST)
        if features.account_kyc_threat or features.threat:
            ai_signals.add(ACCOUNT_THREAT)
        # A generic reference to a bank/organization is not evidence of impersonation.
        # Require the AI to also identify the message as social engineering or threat.
        if features.authority_impersonation and (features.social_engineering or features.threat):
            ai_signals.add(AUTHORITY_IMPERSONATION)
        if features.reward_bait:
            ai_signals.add(REWARD_BAIT)
        if features.remote_access_request:
            ai_signals.add(REMOTE_ACCESS_REQUEST)
        if features.link_click_request:
            ai_signals.add(LINK_CLICK_REQUEST)
        return ai_signals

    def aggregate(
        self,
        ai_features: Optional[SemanticFeatures],
        rule_signals: Set[str],
    ) -> Dict[str, str]:
        """
        Merge AI and rule signals into deduplicated dict: signal_code -> source.

        If AI detected is_safety_advice=True, AI signals that overlap with
        safety advice topics (OTP, credentials) are suppressed to prevent
        false positives from the AI side.
        """
        ai_signals: Set[str] = set()

        if ai_features is not None:
            try:
                ai_signals = self.map_ai_features_to_signals(ai_features)

                # If AI determined this is safety advice, suppress AI-side
                # credential/OTP signals to avoid false positives
                if ai_features.is_safety_advice:
                    ai_signals.discard(OTP_REQUEST)
                    ai_signals.discard(CREDENTIAL_REQUEST)
                    ai_signals.discard(PAYMENT_REQUEST)
            except Exception:
                # Malformed AI features — proceed with rules only
                ai_signals = set()

        # Union of all unique signal codes
        all_codes = ai_signals.union(rule_signals)

        aggregated: Dict[str, str] = {}
        for code in sorted(all_codes):
            in_ai = code in ai_signals
            in_rule = code in rule_signals
            if in_ai and in_rule:
                source = "BOTH"
            elif in_ai:
                source = "AI"
            else:
                source = "RULE"
            aggregated[code] = source

        return aggregated
