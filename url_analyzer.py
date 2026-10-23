"""
url_analyzer.py
---------------
Deterministic URL analysis: extracts URLs, checks shorteners, suspicious domains,
IP-based hosts, deceptive subdomains, and organization domain mismatches.

SECURITY: All analysis is passive. No URLs are fetched, opened, or resolved.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Optional
from models import UrlAnalysisResult


# Known URL shortener domains (exact match required)
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rb.gy", "cutt.ly", "tiny.cc", "shorturl.at", "t.ly",
    "short.io", "surl.li", "rebrand.ly",
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    ".top", ".xyz", ".cc", ".work", ".click", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".live", ".info", ".buzz", ".surf",
    ".icu", ".rest", ".cam", ".monster",
}

# Known official domains for organization verification
OFFICIAL_ORGANIZATION_DOMAINS = {
    "hdfc bank": ["hdfcbank.com", "hdfcbank.net"],
    "hdfc": ["hdfcbank.com", "hdfcbank.net"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "bank.sbi"],
    "state bank of india": ["sbi.co.in", "onlinesbi.sbi", "bank.sbi"],
    "icici bank": ["icicibank.com"],
    "icici": ["icicibank.com"],
    "axis bank": ["axisbank.com"],
    "paytm": ["paytm.com"],
    "income tax": ["incometax.gov.in"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "kotak bank": ["kotak.com"],
    "kotak": ["kotak.com"],
    "phonepe": ["phonepe.com"],
    "google pay": ["pay.google.com"],
    "gpay": ["pay.google.com"],
}

# IP address regex
IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$')

# URL extraction regex
URL_REGEX = re.compile(
    r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
    re.IGNORECASE,
)


def _extract_registered_domain(hostname: str) -> str:
    """
    Extract the registered domain from a hostname.
    Example: 'login.secure.hdfcbank.com.attacker.top' -> 'attacker.top'
    This prevents deceptive subdomain attacks.
    """
    hostname = hostname.lower().rstrip('.')
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return hostname
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return hostname
    except ValueError:
        pass
    parts = hostname.split('.')
    if len(parts) <= 2:
        return hostname
    # Handle .co.in, .gov.in, .org.in type TLDs
    compound_tlds = {'.co.in', '.gov.in', '.org.in', '.ac.in', '.net.in',
                     '.co.uk', '.org.uk', '.co.za'}
    if len(parts) >= 3:
        possible_compound = '.' + '.'.join(parts[-2:])
        if possible_compound in compound_tlds:
            return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


class URLAnalyzer:
    """Deterministic inspector for URLs embedded in user messages. No URLs are fetched."""

    def analyze(self, message: str, claimed_org: Optional[str] = None) -> UrlAnalysisResult:
        """Parse URLs from message and evaluate security signals passively."""
        found_urls = URL_REGEX.findall(message)
        if not found_urls:
            return UrlAnalysisResult(has_url=False, claimed_org=claimed_org)

        has_shortened = False
        has_suspicious = False
        has_mismatch = False
        has_ip = False
        has_deceptive = False
        detected_domains: List[str] = []
        domain_details: List[dict] = []

        for raw_url in found_urls:
            formatted_url = raw_url if raw_url.startswith("http") else f"http://{raw_url}"
            try:
                parsed = urlparse(formatted_url)
            except Exception:
                has_suspicious = True
                continue

            hostname = (parsed.hostname or "").lower().rstrip(".")
            if not hostname:
                has_suspicious = True
                continue

            try:
                hostname = hostname.encode("idna").decode("ascii")
            except UnicodeError:
                has_suspicious = True
                continue
            try:
                parsed.port  # validate malformed/out-of-range ports
            except ValueError:
                has_suspicious = True
                continue

            registered_domain = _extract_registered_domain(hostname)
            detected_domains.append(hostname)
            detail = {"url": raw_url, "hostname": hostname, "registered_domain": registered_domain}

            # Check 1: Shortened URL — exact domain match, not substring
            if registered_domain in SHORTENER_DOMAINS or hostname in SHORTENER_DOMAINS:
                has_shortened = True
                detail["is_shortener"] = True

            # Check 2: IP-based URL
            try:
                ipaddress.ip_address(hostname.strip("[]"))
                has_ip = True
                has_suspicious = True
                detail["is_ip"] = True
            except ValueError:
                pass

            # Check 3: Suspicious TLD
            has_suspicious_tld = any(
                ('.' + registered_domain).endswith(tld) for tld in SUSPICIOUS_TLDS
            )
            if has_suspicious_tld:
                has_suspicious = True
                detail["suspicious_tld"] = True

            # Check 4: Excessive hyphens (>2 in registered domain)
            if registered_domain.count('-') > 2:
                has_suspicious = True
                detail["excessive_hyphens"] = True

            # Check 5: Credentials in URL (user:pass@host)
            if parsed.username or parsed.password:
                has_suspicious = True
                detail["has_credentials"] = True

            # Check 6: Deceptive subdomain — hostname contains known org domain
            # but registered domain is different
            if claimed_org:
                org_key = claimed_org.strip().lower()
                official_domains = OFFICIAL_ORGANIZATION_DOMAINS.get(org_key, [])
                for official in official_domains:
                    # The trusted name appears as a label, but is not the actual
                    # registered domain (e.g. hdfcbank.com.attacker.test).
                    if official in hostname and registered_domain != official:
                        has_deceptive = True
                        detail["deceptive_subdomain"] = True

            # Check 7: Domain mismatch with claimed organization
            if claimed_org:
                org_key = claimed_org.strip().lower()
                official_domains = OFFICIAL_ORGANIZATION_DOMAINS.get(org_key, [])
                if official_domains:
                    domain_matches = any(registered_domain == official for official in official_domains)
                    if not domain_matches:
                        has_mismatch = True
                        detail["domain_mismatch"] = True

            domain_details.append(detail)

        return UrlAnalysisResult(
            has_url=True,
            urls_found=found_urls,
            has_shortened_url=has_shortened,
            has_suspicious_domain=has_suspicious,
            has_domain_mismatch=has_mismatch,
            has_ip_url=has_ip,
            has_deceptive_subdomain=has_deceptive,
            claimed_org=claimed_org,
            detected_domains=detected_domains,
            domain_details=domain_details,
        )
