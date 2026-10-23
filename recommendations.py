"""
recommendations.py
------------------
Actionable Recommendation Generator for Senior Citizens.

Recommendations depend on actual findings, not generic advice.
Uses simple, respectful language suitable for elderly users.
"""

from typing import List, Dict
from rules import (
    OTP_REQUEST, CREDENTIAL_REQUEST, URGENCY, PAYMENT_REQUEST,
    ACCOUNT_THREAT, AUTHORITY_IMPERSONATION, SUSPICIOUS_LINK,
    REWARD_BAIT, SHORTENED_URL, DOMAIN_MISMATCH, SUSPICIOUS_DOMAIN,
    REMOTE_ACCESS_REQUEST, LINK_CLICK_REQUEST,
)

# General safety recommendation (used when no specific signals found)
GENERAL_RECOMMENDATION = (
    "Always verify unexpected messages through an independent official channel "
    "before taking any action."
)

# Signal-specific recommendations
RECOMMENDATION_CATALOG = {
    OTP_REQUEST: (
        "Do not share your OTP, PIN, or verification code with anyone. "
        "No bank or company will ever ask for your OTP through a message or call."
    ),
    CREDENTIAL_REQUEST: (
        "Never share your password, PIN, or login details with anyone. "
        "Change your password immediately if you have already shared it."
    ),
    ACCOUNT_THREAT: (
        "Do not panic about account threats in messages. Check your account status "
        "by logging into the official app or visiting your bank branch directly."
    ),
    SUSPICIOUS_LINK: (
        "Do not click on suspicious links. Instead, type the official website address "
        "directly in your browser or use the official app."
    ),
    SHORTENED_URL: (
        "Do not open shortened or hidden links from unknown senders. "
        "Ask a trusted family member or friend to check it for you."
    ),
    DOMAIN_MISMATCH: (
        "The link in this message leads to an unofficial website. "
        "Do not enter any personal details on this website."
    ),
    SUSPICIOUS_DOMAIN: (
        "The web address looks suspicious or tries to mimic a trusted website. "
        "Do not visit it or enter any information."
    ),
    PAYMENT_REQUEST: (
        "Never transfer money or pay processing fees to claim rewards or unblock services. "
        "Legitimate organizations do not ask for fees through messages."
    ),
    URGENCY: (
        "Take your time. Scammers use urgency to discourage checking. Verify any "
        "deadline through the organization's official app or contact details."
    ),
    AUTHORITY_IMPERSONATION: (
        "Verify the sender by contacting the organization directly using the phone number "
        "on your bank card, official website, or a number you already trust."
    ),
    REWARD_BAIT: (
        "Be sceptical of unexpected prize or reward messages. "
        "If you did not enter a contest, you probably did not win one."
    ),
    REMOTE_ACCESS_REQUEST: (
        "Never install apps or give remote access to your phone or computer based on a message. "
        "If you need tech support, contact the official support number yourself."
    ),
    LINK_CLICK_REQUEST: (
        "Be cautious about clicking links in unexpected messages. "
        "Navigate to websites by typing the address yourself."
    ),
}


class RecommendationGenerator:
    """Generates actionable safety recommendations based on detected signals."""

    @staticmethod
    def generate_recommendations(aggregated_signals: Dict[str, str]) -> List[str]:
        """Build deduplicated list of safety tips matching detected signals."""
        recs = []

        # Add signal-specific recommendations in priority order
        priority_order = [
            OTP_REQUEST, CREDENTIAL_REQUEST, PAYMENT_REQUEST,
            REMOTE_ACCESS_REQUEST, DOMAIN_MISMATCH, SUSPICIOUS_LINK,
            SUSPICIOUS_DOMAIN, SHORTENED_URL, ACCOUNT_THREAT,
            URGENCY, AUTHORITY_IMPERSONATION, REWARD_BAIT,
            LINK_CLICK_REQUEST,
        ]

        for signal_code in priority_order:
            if signal_code in aggregated_signals and signal_code in RECOMMENDATION_CATALOG:
                recs.append(RECOMMENDATION_CATALOG[signal_code])

        # Contact recommendation for high-impact threats
        high_impact = {OTP_REQUEST, CREDENTIAL_REQUEST, ACCOUNT_THREAT, PAYMENT_REQUEST}
        if high_impact.intersection(aggregated_signals.keys()):
            recs.append(
                "Contact the organization directly using a phone number from your "
                "official bank statement, card, or the organization's verified website."
            )

        # Fallback if no specific signals
        if not recs:
            recs.append(GENERAL_RECOMMENDATION)

        return recs
