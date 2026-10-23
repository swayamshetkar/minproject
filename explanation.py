"""
explanation.py
--------------
Human-Readable Explanation Generator for Senior Citizens.

Each finding explains:
1. What was detected.
2. Why it may be concerning.
3. What evidence supports the finding.
4. What the finding does not prove.
"""

from typing import Dict, List
from rules import (
    OTP_REQUEST, CREDENTIAL_REQUEST, URGENCY, PAYMENT_REQUEST,
    ACCOUNT_THREAT, AUTHORITY_IMPERSONATION, SUSPICIOUS_LINK,
    REWARD_BAIT, SHORTENED_URL, DOMAIN_MISMATCH, SUSPICIOUS_DOMAIN,
    REMOTE_ACCESS_REQUEST, LINK_CLICK_REQUEST, RULE_DEFINITIONS,
)


# Senior-friendly explanations (what + why)
EXPLANATION_CATALOG = {
    OTP_REQUEST: (
        "This message asks you to share a one-time password (OTP) or verification code. "
        "Legitimate organizations never ask you to share OTPs over messages or calls."
    ),
    CREDENTIAL_REQUEST: (
        "This message asks for your password, PIN, or other login details. "
        "No genuine bank or company will ask for your password through a message."
    ),
    ACCOUNT_THREAT: (
        "This message threatens to block, suspend, or close your account. "
        "Scammers often use threats to pressure you into acting without thinking."
    ),
    URGENCY: (
        "This message creates pressure to act immediately with tight deadlines. "
        "Scammers use urgency to prevent you from verifying the message independently."
    ),
    PAYMENT_REQUEST: (
        "This message asks you to transfer money, pay a fee, or buy gift cards. "
        "Be very cautious of unexpected payment requests, especially from unknown senders."
    ),
    AUTHORITY_IMPERSONATION: (
        "This message claims to be from an official organization such as a bank, "
        "government agency, or telecom provider. Scammers frequently impersonate authorities."
    ),
    SUSPICIOUS_LINK: (
        "This message contains a link with suspicious characteristics. "
        "The link may use an unusual web address designed to look like a trusted website."
    ),
    SHORTENED_URL: (
        "This message uses a shortened link (like bit.ly) which hides where it actually leads. "
        "Shortened links can disguise dangerous websites."
    ),
    DOMAIN_MISMATCH: (
        "The web address in this message does not match the official website of the organization "
        "the message claims to represent. This is a common sign of phishing."
    ),
    SUSPICIOUS_DOMAIN: (
        "The web address uses an IP address, suspicious domain, or deceptive structure "
        "that mimics a trusted organization's website."
    ),
    REWARD_BAIT: (
        "This message promises prizes, lottery winnings, or unexpected rewards. "
        "If you did not enter a contest, you probably did not win one."
    ),
    REMOTE_ACCESS_REQUEST: (
        "This message asks you to install an app or give someone remote access to your device. "
        "Scammers use remote access to steal information or money from your accounts."
    ),
    LINK_CLICK_REQUEST: (
        "This message specifically asks you to click a link or open an attachment. "
        "Be cautious about clicking links in unexpected messages."
    ),
}


class ExplanationGenerator:
    """Generates senior-friendly explanations and overall assessment summaries."""

    @staticmethod
    def get_explanation(signal_code: str) -> str:
        """Return human-readable explanation for a signal code."""
        return EXPLANATION_CATALOG.get(
            signal_code,
            f"An unusual pattern was detected in the message.",
        )

    @staticmethod
    def get_limitation(signal_code: str) -> str:
        """Return the documented limitation for a signal."""
        defn = RULE_DEFINITIONS.get(signal_code, {})
        return defn.get("limitations", "This finding alone does not prove the message is fraudulent.")

    @staticmethod
    def generate_overall_explanation(
        risk_level: str,
        signal_codes: List[str],
        ai_used: bool,
    ) -> str:
        """Generate a plain-language overall summary."""
        count = len(signal_codes)
        if count == 0:
            return (
                "No significant suspicious indicators were found in this message. "
                "However, always verify unexpected messages through official channels."
            )

        # Build summary based on most concerning signals
        high_priority = [c for c in signal_codes if c in (
            OTP_REQUEST, CREDENTIAL_REQUEST, PAYMENT_REQUEST, REMOTE_ACCESS_REQUEST
        )]

        if risk_level == "HIGH":
            intro = "This message shows multiple strong signs of a potential scam."
        elif risk_level == "MEDIUM":
            intro = "This message contains some concerning signs that deserve caution."
        else:
            intro = "This message has minor indicators worth noting."

        details = []
        if OTP_REQUEST in signal_codes or CREDENTIAL_REQUEST in signal_codes:
            details.append("It asks for sensitive information like OTPs or passwords")
        if PAYMENT_REQUEST in signal_codes:
            details.append("It requests a payment or money transfer")
        if ACCOUNT_THREAT in signal_codes:
            details.append("It threatens action against your account")
        if URGENCY in signal_codes:
            details.append("It pressures you to act immediately")
        if DOMAIN_MISMATCH in signal_codes:
            details.append("The link does not match the claimed organization's website")

        if details:
            detail_text = ". ".join(details) + "."
        else:
            detail_text = f"{count} suspicious indicator(s) were identified."

        mode = "AI-assisted and rule-based" if ai_used else "rule-based"
        disclaimer = f" This assessment used {mode} analysis and is not a guarantee."

        return f"{intro} {detail_text}{disclaimer}"

    @staticmethod
    def get_standard_limitations(ai_used: bool) -> List[str]:
        """Return standard limitation notices for the response."""
        limitations = [
            "This is an automated assessment, not a definitive verdict. "
            "It identifies suspicious patterns but cannot verify the sender's identity.",
        ]
        if ai_used:
            limitations.append(
                "AI analysis was used. The message text was sent to an external AI service "
                "for semantic analysis. See privacy documentation for details."
            )
        else:
            limitations.append(
                "Only rule-based analysis was used. Some subtle scam tactics may not be detected."
            )
        limitations.append(
            "A low risk score does not guarantee a message is safe. "
            "Always verify unexpected messages through official channels."
        )
        return limitations
