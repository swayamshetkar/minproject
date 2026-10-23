"""
rule_engine.py
--------------
Deterministic Rule Engine with context-aware detection.

Key improvement over original: Checks for negation context to avoid flagging
safety advice messages (e.g., "never share your OTP") as threats.
Does NOT treat every URL as SUSPICIOUS_LINK — only URLs with suspicious characteristics.
"""

import re
from typing import Set, Optional, Dict, List
from rules import (
    OTP_REQUEST, CREDENTIAL_REQUEST, URGENCY, PAYMENT_REQUEST,
    ACCOUNT_THREAT, AUTHORITY_IMPERSONATION, SUSPICIOUS_LINK,
    REWARD_BAIT, SHORTENED_URL, DOMAIN_MISMATCH, SUSPICIOUS_DOMAIN,
    REMOTE_ACCESS_REQUEST, LINK_CLICK_REQUEST, NEGATION_PHRASES,
)
from url_analyzer import URLAnalyzer


class DeterministicRuleEngine:
    """
    Context-aware deterministic rule engine.
    Uses regex + negation context checks to reduce false positives.
    """

    # Regex patterns
    OTP_REGEX = re.compile(
        r'\b(otp|one[- ]?time password|verification code|security code)\b', re.IGNORECASE
    )
    CREDENTIAL_REGEX = re.compile(
        r'\b(password|pin|login details|secret key|cvv|card number|account number)\b', re.IGNORECASE
    )
    URGENCY_REGEX = re.compile(
        r'\b(immediately|right now|within \d+ (hours?|mins?|minutes?)|'
        r'urgent(ly)?|expire[sd]?|last chance|act now|hurry|deadline today)\b', re.IGNORECASE
    )
    PAYMENT_REGEX = re.compile(
        r'\b(pay|transfer|processing fee|gift card|send money|deposit|'
        r'advance fee|registration fee|clearance fee)\b', re.IGNORECASE
    )
    ACCOUNT_THREAT_REGEX = re.compile(
        r'\b(kyc.{0,20}(expir|block|suspend|deactivat)|'
        r'account.{0,20}(block|suspend|deactivat|restrict|terminat|clos)|'
        r'(block|suspend|deactivat|restrict|terminat).{0,20}account|'
        r'will be blocked|will be suspended|will be deactivated)\b', re.IGNORECASE
    )
    AUTHORITY_REGEX = re.compile(
        r'\b(reserve bank|rbi|income tax department|it department|'
        r'trai|telecom authority|police|customs|court|'
        r'ministry|government of india|support team)\b', re.IGNORECASE
    )
    REWARD_REGEX = re.compile(
        r'\b(lottery|winner|won|prize|congratulations.{0,30}(won|select|chosen)|'
        r'claim your|free money|jackpot|lucky draw)\b', re.IGNORECASE
    )
    REMOTE_ACCESS_REGEX = re.compile(
        r'\b(install.{0,20}(app|application|software|anydesk|teamviewer)|'
        r'download.{0,20}(app|application|software)|'
        r'remote access|screen share|anydesk|teamviewer|quicksupport)\b', re.IGNORECASE
    )
    LINK_CLICK_REGEX = re.compile(
        r'\b(click.{0,15}(link|here|below|url)|'
        r'open.{0,15}(link|attachment)|'
        r'visit.{0,15}(link|url)|tap.{0,15}(link|here))\b', re.IGNORECASE
    )

    def __init__(self):
        self.url_analyzer = URLAnalyzer()

    def _has_negation_context(self, text: str, match_start: int, window: int = 80) -> bool:
        """
        Check if a regex match occurs within a negation/advisory context.
        Looks backward from the match position for negation phrases.
        """
        # Get text window before the match
        start = max(0, match_start - window)
        context = text[start:match_start].lower()
        return any(neg in context for neg in NEGATION_PHRASES)

    def _is_advisory_message(self, text: str) -> bool:
        """Check if the overall message is safety advice rather than a threat."""
        lower = text.lower()
        advisory_indicators = 0
        threat_indicators = 0

        for neg in NEGATION_PHRASES:
            if neg in lower:
                advisory_indicators += 1

        # Check for imperative threat language
        threat_patterns = [
            r'click.{0,15}(this|the).{0,15}link',
            r'enter.{0,15}(your|the).{0,15}(otp|pin|password)',
            r'share.{0,15}(your|the).{0,15}(otp|pin|password|code)',
            r'send.{0,15}(your|the).{0,15}(otp|pin|password)',
            r'tell me.{0,15}(your|the).{0,15}(otp|code)',
        ]
        for pattern in threat_patterns:
            if re.search(pattern, lower):
                threat_indicators += 1

        # If advisory language dominates and no direct threat commands
        return advisory_indicators >= 2 and threat_indicators == 0

    def detect_signals(self, message: str, claimed_org: Optional[str] = None) -> Set[str]:
        """Execute deterministic rules with context awareness. Returns signal codes."""
        signals: Set[str] = set()
        lower = message.lower()
        is_advisory = self._is_advisory_message(message)

        # 1. OTP Request — with negation check
        match = self.OTP_REGEX.search(lower)
        if match and not is_advisory:
            if not self._has_negation_context(lower, match.start()):
                signals.add(OTP_REQUEST)

        # 2. Credential Request — with negation check
        match = self.CREDENTIAL_REGEX.search(lower)
        if match and not is_advisory:
            if not self._has_negation_context(lower, match.start()):
                signals.add(CREDENTIAL_REQUEST)

        # 3. Urgency
        if self.URGENCY_REGEX.search(lower):
            signals.add(URGENCY)
        elif self.ACCOUNT_THREAT_REGEX.search(lower) and re.search(r'\btoday\b', lower):
            signals.add(URGENCY)

        # 4. Payment Request — with negation check
        match = self.PAYMENT_REGEX.search(lower)
        if match and not is_advisory:
            if not self._has_negation_context(lower, match.start()):
                signals.add(PAYMENT_REQUEST)

        # 5. Account Threat (contextual regex, not just keyword)
        if self.ACCOUNT_THREAT_REGEX.search(lower):
            signals.add(ACCOUNT_THREAT)

        # 6. Authority Impersonation
        if self.AUTHORITY_REGEX.search(lower):
            signals.add(AUTHORITY_IMPERSONATION)

        # 7. Reward Bait
        if self.REWARD_REGEX.search(lower):
            signals.add(REWARD_BAIT)

        # 8. Remote Access Request
        if self.REMOTE_ACCESS_REGEX.search(lower):
            signals.add(REMOTE_ACCESS_REQUEST)

        # 9. Link Click Request — with negation check
        match = self.LINK_CLICK_REGEX.search(lower)
        if match:
            if not self._has_negation_context(lower, match.start()):
                signals.add(LINK_CLICK_REQUEST)

        # 10. URL Analysis (only flags genuinely suspicious URLs, not all URLs)
        url_result = self.url_analyzer.analyze(message, claimed_org)
        if url_result.has_suspicious_domain:
            signals.add(SUSPICIOUS_LINK)
        if url_result.has_shortened_url:
            signals.add(SHORTENED_URL)
        if url_result.has_domain_mismatch:
            signals.add(DOMAIN_MISMATCH)
        if url_result.has_ip_url or url_result.has_deceptive_subdomain:
            signals.add(SUSPICIOUS_DOMAIN)

        return signals

    def detect_evidence(self, message: str, claimed_org: Optional[str] = None) -> Dict[str, str]:
        """Return one short supporting excerpt per deterministic finding."""
        signals = self.detect_signals(message, claimed_org)
        patterns = {
            OTP_REQUEST: self.OTP_REGEX, CREDENTIAL_REQUEST: self.CREDENTIAL_REGEX,
            URGENCY: self.URGENCY_REGEX, PAYMENT_REQUEST: self.PAYMENT_REGEX,
            ACCOUNT_THREAT: self.ACCOUNT_THREAT_REGEX, AUTHORITY_IMPERSONATION: self.AUTHORITY_REGEX,
            REWARD_BAIT: self.REWARD_REGEX, REMOTE_ACCESS_REQUEST: self.REMOTE_ACCESS_REGEX,
            LINK_CLICK_REQUEST: self.LINK_CLICK_REGEX,
        }
        evidence = {}
        for code in signals:
            match = patterns.get(code).search(message) if code in patterns else None
            if match:
                evidence[code] = match.group(0)[:160]
            elif code in {SUSPICIOUS_LINK, SHORTENED_URL, DOMAIN_MISMATCH, SUSPICIOUS_DOMAIN}:
                evidence[code] = "URL characteristics found"
            else:
                account_match = self.ACCOUNT_THREAT_REGEX.search(message)
                if code == URGENCY and account_match:
                    evidence[code] = account_match.group(0)[:160]
                else:
                    evidence[code] = "Related message wording detected"
        return evidence
