"""
rules.py
--------
Central configuration defining rule IDs, metadata, weights, and risk score threshold bands.
Each rule has: unique ID, name, description, severity weight, and documented limitations.
"""


# --- Signal Code Constants ---
OTP_REQUEST = "OTP_REQUEST"
CREDENTIAL_REQUEST = "CREDENTIAL_REQUEST"
URGENCY = "URGENCY"
PAYMENT_REQUEST = "PAYMENT_REQUEST"
ACCOUNT_THREAT = "ACCOUNT_THREAT"
AUTHORITY_IMPERSONATION = "AUTHORITY_IMPERSONATION"
SUSPICIOUS_LINK = "SUSPICIOUS_LINK"
REWARD_BAIT = "REWARD_BAIT"
SHORTENED_URL = "SHORTENED_URL"
DOMAIN_MISMATCH = "DOMAIN_MISMATCH"
SUSPICIOUS_DOMAIN = "SUSPICIOUS_DOMAIN"
REMOTE_ACCESS_REQUEST = "REMOTE_ACCESS_REQUEST"
LINK_CLICK_REQUEST = "LINK_CLICK_REQUEST"


# --- Rule Metadata ---
RULE_DEFINITIONS = {
    OTP_REQUEST: {
        "name": "OTP / Verification Code Request",
        "description": "The message asks the recipient to share an OTP or verification code.",
        "weight": 60,
        "severity": "high",
        "limitations": "Cannot verify whether the sender legitimately needs the code. "
                       "Some services send OTP reminders that mention OTPs without requesting them.",
    },
    CREDENTIAL_REQUEST: {
        "name": "Password / PIN / Credential Request",
        "description": "The message asks for passwords, PINs, login details, or secret keys.",
        "weight": 35,
        "severity": "high",
        "limitations": "Password reset emails from legitimate services may mention credentials.",
    },
    PAYMENT_REQUEST: {
        "name": "Payment or Money Transfer Request",
        "description": "The message requests a payment, fee, money transfer, or gift card purchase.",
        "weight": 25,
        "severity": "high",
        "limitations": "Legitimate invoices and payment reminders also request payment.",
    },
    ACCOUNT_THREAT: {
        "name": "Account Threat or KYC Pressure",
        "description": "The message threatens account suspension, blocking, or KYC expiration.",
        "weight": 20,
        "severity": "medium",
        "limitations": "Legitimate banks do send KYC reminders, though usually without extreme urgency.",
    },
    DOMAIN_MISMATCH: {
        "name": "Domain Does Not Match Claimed Organization",
        "description": "The URL domain differs from known official domains of the claimed organization.",
        "weight": 25,
        "severity": "high",
        "limitations": "Organizations may use third-party domains for campaigns. "
                       "A mismatch is strong evidence but not conclusive proof of fraud.",
    },
    SUSPICIOUS_LINK: {
        "name": "Suspicious URL Characteristics",
        "description": "The message contains a URL with suspicious features (IP address, suspicious TLD, excessive hyphens).",
        "weight": 20,
        "severity": "medium",
        "limitations": "Some legitimate services use unusual TLDs or IP addresses.",
    },
    URGENCY: {
        "name": "Artificial Urgency or Deadline Pressure",
        "description": "The message pressures immediate action with tight deadlines.",
        "weight": 15,
        "severity": "medium",
        "limitations": "Legitimate messages about appointments, deliveries, or deadlines "
                       "also convey urgency.",
    },
    AUTHORITY_IMPERSONATION: {
        "name": "Authority or Organization Impersonation",
        "description": "The message claims to represent a bank, government agency, or official body.",
        "weight": 15,
        "severity": "medium",
        "limitations": "Mentioning an organization is not proof of impersonation. "
                       "Legitimate messages from organizations also mention their name.",
    },
    REWARD_BAIT: {
        "name": "Prize, Reward, or Lottery Bait",
        "description": "The message promises unexpected prizes, lottery winnings, or free money.",
        "weight": 15,
        "severity": "medium",
        "limitations": "Legitimate promotional offers and cashback notifications exist.",
    },
    SHORTENED_URL: {
        "name": "URL Shortener Used",
        "description": "The message contains a shortened URL that hides the real destination.",
        "weight": 10,
        "severity": "low",
        "limitations": "URL shorteners are widely used for legitimate purposes (social media, marketing).",
    },
    SUSPICIOUS_DOMAIN: {
        "name": "Suspicious Domain Pattern",
        "description": "The URL uses an IP address, suspicious TLD, or deceptive subdomain structure.",
        "weight": 15,
        "severity": "medium",
        "limitations": "Some internal or development URLs legitimately use IP addresses.",
    },
    REMOTE_ACCESS_REQUEST: {
        "name": "Remote Access or App Installation Request",
        "description": "The message asks the recipient to install an app or grant remote access.",
        "weight": 30,
        "severity": "high",
        "limitations": "Legitimate IT support may request remote access through official channels.",
    },
    LINK_CLICK_REQUEST: {
        "name": "Request to Click a Link",
        "description": "The message explicitly asks the user to click a link or open an attachment.",
        "weight": 10,
        "severity": "low",
        "limitations": "Many legitimate messages include links. This is a supporting indicator only.",
    },
}

# Rule Weights (derived from definitions for backward compatibility)
RULE_WEIGHTS = {code: defn["weight"] for code, defn in RULE_DEFINITIONS.items()}

# Maximum score cap
MAX_RISK_SCORE = 100

# Risk Threshold Bands
# 0-29   -> LOW
# 30-59  -> MEDIUM
# 60-100 -> HIGH
RISK_BANDS = {
    "LOW": (0, 29),
    "MEDIUM": (30, 59),
    "HIGH": (60, 100),
}

# Negation patterns — phrases that indicate the message is WARNING AGAINST
# the threat rather than PERFORMING the threat
NEGATION_PHRASES = [
    "never share", "do not share", "don't share", "dont share",
    "never give", "do not give", "don't give", "dont give",
    "never reveal", "do not reveal", "don't reveal",
    "never tell", "do not tell", "don't tell",
    "never disclose", "do not disclose", "don't disclose",
    "never enter", "do not enter", "don't enter",
    "never send", "do not send", "don't send",
    "never transfer", "do not transfer", "don't transfer",
    "never click", "do not click", "don't click",
    "never pay", "do not pay", "don't pay",
    "be careful", "be cautious", "be aware", "beware",
    "protect your", "keep your", "guard your",
    "security tip", "safety tip", "reminder",
    "for your safety", "for your security", "for your protection",
]
