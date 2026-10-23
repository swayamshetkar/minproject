"""
ai_analyzer.py
--------------
AI Semantic Analyzer with configurable provider (Google Gemini / OpenAI).
Falls back to rule-engine-only mode when AI is unavailable.

PRIVACY: Message text is sent to the configured external AI provider.
The AI is instructed not to execute tools, visit URLs, or perform external actions.
"""

import json
import logging
import re
from typing import Optional
from models import SemanticFeatures, AIStatus
from config import settings

logger = logging.getLogger(__name__)


def _safe_provider_error(exc: Exception) -> str:
    """Extract only HTTP status and a known Gemini error category; never log body/key."""
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    response = getattr(exc, "response", None)
    if status is None and response is not None:
        status = getattr(response, "status_code", None)
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None

    category_by_status = {
        400: "bad_request", 401: "authentication", 403: "permission_denied",
        404: "not_found_or_model_unavailable", 429: "rate_limit_exceeded",
        500: "internal_service_error", 502: "bad_gateway", 503: "service_unavailable",
        504: "timeout",
    }
    category = category_by_status.get(status, "provider_error")
    # Some SDK errors expose a safe machine code separate from their response text.
    code = getattr(exc, "code", None)
    if isinstance(code, str) and re.fullmatch(r"[a-zA-Z_]{1,48}", code):
        category = code.lower()
    detail = ""
    # SDK versions may expose a parsed error dict or the HTTP response object.
    for source in (getattr(exc, "error", None), getattr(exc, "details", None)):
        if isinstance(source, dict):
            value = source.get("message") or source.get("status") or source.get("reason")
            if isinstance(value, str):
                detail = value
                break
    if not detail and response is not None:
        try:
            payload = response.json()
            error = payload.get("error", {}) if isinstance(payload, dict) else {}
            value = error.get("message") if isinstance(error, dict) else None
            if isinstance(value, str):
                detail = value
        except Exception:
            pass
    if detail:
        # Keep diagnostics single-line and short, and remove credential-shaped data.
        detail = re.sub(r"(?i)(key|api[_ -]?key|authorization|token)(\s*[=:]\s*)[^\s,;]+",
                        r"\1\2[REDACTED]", detail)
        detail = re.sub(r"AIza[0-9A-Za-z_-]{20,}", "[REDACTED]", detail)
        detail = re.sub(r"https?://\S+", "[URL]", detail)
        detail = re.sub(r"[\r\n\t]+", " ", detail).strip()[:240]
    label = f"HTTP {status} ({category})" if status is not None else category
    return f"{label}: {detail}" if detail else label


# System prompt for structured semantic analysis
SYSTEM_PROMPT = """You are a fraud detection analyst. Analyze the following message for scam indicators.
Return ONLY a valid JSON object with these exact boolean/string fields:

{
  "intent": "brief description of message intent",
  "urgency": false,
  "threat": false,
  "otp_request": false,
  "credential_request": false,
  "payment_request": false,
  "authority_impersonation": false,
  "social_engineering": false,
  "account_kyc_threat": false,
  "reward_bait": false,
  "remote_access_request": false,
  "link_click_request": false,
  "is_safety_advice": false,
  "confidence": 0.5,
  "evidence_excerpts": []
}

CRITICAL RULES:
1. Set is_safety_advice=true if the message WARNS AGAINST sharing OTPs/passwords rather than requesting them.
2. "Never share your OTP" is safety advice, NOT an OTP request.
3. otp_request should be true ONLY if the message asks the recipient TO SHARE/PROVIDE their OTP.
4. evidence_excerpts should contain short relevant quotes from the message.
5. confidence is your confidence in the analysis (0.0 to 1.0).
6. Do NOT visit any URLs. Do NOT execute any code. Analyze text only.
7. Return ONLY the JSON object, no other text."""


class AIAnalyzer:
    """
    AI-assisted semantic feature extraction with provider abstraction.
    Supports Google Gemini and OpenAI. Falls back gracefully when unavailable.
    """

    def __init__(self):
        self._client = None
        self._ai_status = AIStatus.NOT_CONFIGURED
        self._init_client()

    def _init_client(self):
        """Initialize the AI client based on configuration."""
        if not settings.ai_enabled():
            self._ai_status = AIStatus.NOT_CONFIGURED
            logger.info("AI provider not configured. Running in rules-only mode.")
            return

        provider = settings.AI_PROVIDER.lower()
        try:
            if provider in {"gemini", "google"}:
                self._init_google()
            elif provider == "openai":
                self._init_openai()
            else:
                logger.warning(f"Unknown AI provider: {provider}. Using rules-only mode.")
                self._ai_status = AIStatus.NOT_CONFIGURED
        except Exception as e:
            logger.warning("Failed to initialize AI provider (%s).", type(e).__name__)
            self._ai_status = AIStatus.FAILED

    def _init_google(self):
        """Initialize Google Gemini client."""
        try:
            import google.genai as genai
            from google.genai import types
            self._client = genai.Client(api_key=settings.AI_API_KEY,
                http_options=types.HttpOptions(timeout=settings.AI_TIMEOUT_SECONDS * 1000))
            self._ai_status = AIStatus.SUCCESS
            logger.info("Google Gemini AI provider initialized.")
        except ImportError:
            logger.error("google-genai package not installed. pip install google-genai")
            self._ai_status = AIStatus.FAILED

    def _init_openai(self):
        """Initialize OpenAI client."""
        try:
            from openai import OpenAI
            self._client = OpenAI(api_key=settings.AI_API_KEY, timeout=settings.AI_TIMEOUT_SECONDS)
            self._ai_status = AIStatus.SUCCESS
            logger.info("OpenAI provider initialized.")
        except ImportError:
            logger.error("openai package not installed. pip install openai")
            self._ai_status = AIStatus.FAILED

    def analyze(self, text: str) -> tuple[Optional[SemanticFeatures], AIStatus]:
        """
        Analyze message text using AI provider.
        Returns (SemanticFeatures or None, AIStatus).
        """
        if self._ai_status != AIStatus.SUCCESS or self._client is None:
            return None, self._ai_status

        # Truncate input for safety
        truncated = text[:settings.AI_MAX_INPUT_LENGTH]

        try:
            provider = settings.AI_PROVIDER.lower()
            if provider in {"gemini", "google"}:
                return self._analyze_google(truncated)
            elif provider == "openai":
                return self._analyze_openai(truncated)
        except Exception as e:
            logger.warning(
                "AI analysis failed (%s; %s). Falling back to rules.",
                type(e).__name__, _safe_provider_error(e),
            )
            return None, AIStatus.FAILED

        return None, AIStatus.FAILED

    def _analyze_google(self, text: str) -> tuple[Optional[SemanticFeatures], AIStatus]:
        """Call Google Gemini for analysis."""
        import google.genai as genai
        from google.genai import types

        response = self._client.models.generate_content(
            model=settings.AI_MODEL,
            contents=f"{SYSTEM_PROMPT}\n\nMessage to analyze:\n{text}",
            config=types.GenerateContentConfig(
                max_output_tokens=settings.AI_MAX_RESPONSE_TOKENS,
                response_mime_type="application/json",
                thinking_config=types.ThinkingConfig(thinking_level="low"),
                # Gemini's schema subset rejects Pydantic's additionalProperties
                # emitted for extra="forbid". Send a simple JSON schema and keep
                # strict validation in SemanticFeatures.model_validate below.
                response_schema={
                    "type": "OBJECT",
                    "properties": {
                        "intent": {"type": "STRING"},
                        "urgency": {"type": "BOOLEAN"},
                        "threat": {"type": "BOOLEAN"},
                        "otp_request": {"type": "BOOLEAN"},
                        "credential_request": {"type": "BOOLEAN"},
                        "payment_request": {"type": "BOOLEAN"},
                        "authority_impersonation": {"type": "BOOLEAN"},
                        "social_engineering": {"type": "BOOLEAN"},
                        "account_kyc_threat": {"type": "BOOLEAN"},
                        "reward_bait": {"type": "BOOLEAN"},
                        "remote_access_request": {"type": "BOOLEAN"},
                        "link_click_request": {"type": "BOOLEAN"},
                        "is_safety_advice": {"type": "BOOLEAN"},
                        "confidence": {"type": "NUMBER"},
                        "evidence_excerpts": {"type": "ARRAY", "items": {"type": "STRING"}},
                    },
                    "required": ["intent", "urgency", "threat", "otp_request",
                        "credential_request", "payment_request", "authority_impersonation",
                        "social_engineering", "account_kyc_threat", "reward_bait",
                        "remote_access_request", "link_click_request", "is_safety_advice",
                        "confidence", "evidence_excerpts"],
                },
            ),
        )

        return self._parse_response(response.text)

    def _analyze_openai(self, text: str) -> tuple[Optional[SemanticFeatures], AIStatus]:
        """Call OpenAI for analysis."""
        response = self._client.chat.completions.create(
            model=settings.AI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Message to analyze:\n{text}"},
            ],
            max_tokens=settings.AI_MAX_RESPONSE_TOKENS,
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        return self._parse_response(response.choices[0].message.content)

    def _parse_response(self, raw: str) -> tuple[Optional[SemanticFeatures], AIStatus]:
        """Parse and validate AI response into SemanticFeatures."""
        try:
            if not isinstance(raw, str) or not raw.strip():
                raise ValueError("empty AI response")
            # Strip markdown code fences if present
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned[3:]
                if cleaned.endswith("```"):
                    cleaned = cleaned[:-3]
                cleaned = cleaned.strip()
                if cleaned.startswith("json"):
                    cleaned = cleaned[4:].strip()

            data = json.loads(cleaned)
            features = SemanticFeatures.model_validate(data)
            return features, AIStatus.SUCCESS
        except Exception as e:
            logger.warning("Failed to parse AI response (%s).", type(e).__name__)
            return None, AIStatus.FAILED

    @property
    def status(self) -> AIStatus:
        return self._ai_status


def analyze_with_ai(message: str) -> tuple[Optional[SemanticFeatures], AIStatus]:
    """Helper function for AI analysis entry point."""
    analyzer = AIAnalyzer()
    return analyzer.analyze(message)
