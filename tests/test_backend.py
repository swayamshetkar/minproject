from fastapi.testclient import TestClient

from main import app, service
from models import AIStatus, SemanticFeatures, RiskLevel
from rule_engine import DeterministicRuleEngine
from scorer import RiskScoringEngine
from signal_aggregator import SignalAggregator
from rules import OTP_REQUEST, CREDENTIAL_REQUEST, URGENCY
from url_analyzer import URLAnalyzer
from config import Settings, settings
from ai_analyzer import AIAnalyzer
from ai_analyzer import _safe_provider_error

client = TestClient(app)


def test_api_rules_only_pipeline(monkeypatch):
    monkeypatch.setattr(service.ai_analyzer, "analyze", lambda text: (None, AIStatus.NOT_CONFIGURED))
    response = client.post("/api/v1/analyze/message", json={"message": "Tell me the OTP you received now."})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "HIGH"
    assert any(x["signal_code"] == OTP_REQUEST and x["evidence"] for x in data["signals"])
    assert data["ai_status"] == "NOT_CONFIGURED"


def test_empty_whitespace_and_invalid_body():
    assert client.post("/api/v1/analyze/message", json={"message": "   "}).status_code == 422
    assert client.post("/api/v1/analyze/message", json={"message": ""}).status_code == 422
    assert client.post("/api/v1/analyze/message", data="{").status_code == 422


def test_oversized_message():
    response = client.post("/api/v1/analyze/message", json={"message": "x" * 10001})
    assert response.status_code in (413, 422)


def test_benign_otp_warning_not_request():
    signals = DeterministicRuleEngine().detect_signals(
        "Never share your OTP or PIN with anyone. Contact your bank through its official number."
    )
    assert OTP_REQUEST not in signals
    assert CREDENTIAL_REQUEST not in signals


def test_obvious_scam_signals():
    signals = DeterministicRuleEngine().detect_signals(
        "Congratulations! Claim your prize. Pay a processing fee immediately at http://bad-prize.top"
    )
    assert {"REWARD_BAIT", "PAYMENT_REQUEST", "URGENCY", "SUSPICIOUS_LINK"} <= signals


def test_kyc_otp_and_benign_deadline():
    engine = DeterministicRuleEngine()
    assert {"ACCOUNT_THREAT", "URGENCY"} <= engine.detect_signals(
        "Your bank account will be blocked today unless you complete KYC using this link."
    )
    assert OTP_REQUEST in engine.detect_signals("Tell me the OTP you received to unblock your account.")
    assert URGENCY not in engine.detect_signals("Your appointment is tomorrow at 10:00.")


def test_urls_shortener_ip_mismatch_and_deceptive_suffix():
    analyzer = URLAnalyzer()
    assert analyzer.analyze("https://bit.ly/abc").has_shortened_url
    assert analyzer.analyze("http://192.168.1.3/login").has_ip_url
    result = analyzer.analyze("https://hdfcbank.com.attacker.test/", "HDFC Bank")
    assert result.has_domain_mismatch and result.has_deceptive_subdomain
    assert analyzer.analyze("https://not-hdfcbank.com/", "HDFC Bank").has_domain_mismatch


def test_url_ports_credentials_and_malformed():
    analyzer = URLAnalyzer()
    assert analyzer.analyze("http://user:pass@example.test:99999/").has_suspicious_domain
    assert analyzer.analyze("https://example.test:99999/").has_suspicious_domain
    assert not analyzer.analyze("words without a link").has_url


def test_domain_boundary_and_official_subdomain():
    analyzer = URLAnalyzer()
    assert not analyzer.analyze("https://secure.hdfcbank.com", "HDFC Bank").has_domain_mismatch
    assert analyzer.analyze("https://hdfcbank.com.attacker.test", "HDFC Bank").has_domain_mismatch


def test_aggregation_deduplicates_ai_and_rule():
    result = SignalAggregator().aggregate(SemanticFeatures(otp_request=True), {OTP_REQUEST})
    assert result == {OTP_REQUEST: "BOTH"}
    assert RiskScoringEngine().calculate_score(result)[0] == 60


def test_authority_impersonation_requires_independent_scam_context():
    aggregator = SignalAggregator()
    generic_mention = SemanticFeatures(authority_impersonation=True)
    assert "AUTHORITY_IMPERSONATION" not in aggregator.aggregate(generic_mention, set())
    explicit_scam_claim = SemanticFeatures(
        authority_impersonation=True, social_engineering=True
    )
    assert aggregator.aggregate(explicit_scam_claim, set()) == {
        "AUTHORITY_IMPERSONATION": "AI"
    }


def test_score_boundaries_and_cap():
    engine = RiskScoringEngine()
    assert engine.calculate_score({"x": "RULE", "y": "RULE", "z": "RULE"})[0:2] == (30, RiskLevel.MEDIUM)
    assert engine.calculate_score({"x": "RULE", "y": "RULE", "z": "RULE", "w": "RULE", "v": "RULE", "u": "RULE"})[0:2] == (60, RiskLevel.HIGH)
    assert engine.calculate_score({f"x{i}": "RULE" for i in range(20)})[0] == 100
    assert engine.calculate_score({"SUSPICIOUS_LINK": "RULE", "DOMAIN_MISMATCH": "RULE", "SUSPICIOUS_DOMAIN": "RULE"})[0] == 25


def test_ai_malformed_output_fails_closed():
    features, status = service.ai_analyzer._parse_response('{"otp_request": "yes", "unexpected": true}')
    assert features is None and status == AIStatus.FAILED


def test_health_endpoint():
    assert client.get("/health").json()["status"] == "healthy"


def test_gemini_settings_supported_and_env_key_not_printed(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.setenv("AI_API_KEY", "private-test-key")
    monkeypatch.setenv("AI_MODEL", "gemini-3.8-flash")
    # Settings are loaded from backend environment variables at import/startup.
    assert settings.AI_PROVIDER == "gemini"
    # Environment changes after import do not mutate class-level settings.
    assert settings.AI_MODEL == "gemini-3.5-flash-lite"
    assert settings.ai_enabled()


def test_gemini_success_uses_configured_model_and_structured_json(monkeypatch):
    analyzer = AIAnalyzer()
    analyzer._ai_status = AIStatus.SUCCESS
    calls = {}
    class Models:
        def generate_content(self, **kwargs):
            calls.update(kwargs)
            class Response:
                text = '{"intent":"request","otp_request":true,"evidence_excerpts":["send OTP"]}'
            return Response()
    class Client:
        models = Models()
    analyzer._client = Client()
    monkeypatch.setattr(settings, "AI_PROVIDER", "gemini")
    features, status = analyzer.analyze("send OTP")
    assert status == AIStatus.SUCCESS and features.otp_request
    assert calls["model"] == settings.AI_MODEL
    assert calls["config"].response_mime_type == "application/json"
    schema = calls["config"].response_schema
    assert schema["type"] == "OBJECT"
    assert "additionalProperties" not in schema
    assert "additional_properties" not in str(schema).lower()
    assert schema["properties"]["otp_request"]["type"] == "BOOLEAN"
    assert str(calls["config"].thinking_config.thinking_level).lower().endswith("low")


def test_invalid_credentials_and_provider_errors_fall_back_without_leaking(monkeypatch, caplog):
    analyzer = AIAnalyzer()
    analyzer._ai_status = AIStatus.SUCCESS
    class Models:
        def generate_content(self, **kwargs):
            raise RuntimeError("private-test-key rejected")
    class Client:
        models = Models()
    analyzer._client = Client()
    monkeypatch.setattr(settings, "AI_PROVIDER", "gemini")
    features, status = analyzer.analyze("hello")
    assert features is None and status == AIStatus.FAILED
    assert "private-test-key" not in caplog.text


def test_provider_error_diagnostic_uses_status_without_exception_text():
    class ProviderError(Exception):
        status_code = 401
        error = {"status": "UNAUTHENTICATED"}
    exc = ProviderError("secret-key=private-test-key; full response body")
    diagnostic = _safe_provider_error(exc)
    assert "401" in diagnostic and "UNAUTHENTICATED" in diagnostic
    assert "private-test-key" not in diagnostic
    assert "full response body" not in diagnostic


def test_provider_error_diagnostic_extracts_and_redacts_sdk_response():
    class Response:
        status_code = 400
        def json(self):
            return {"error": {"message": "Invalid API key=AIza012345678901234567890123456789012345"}}
    class ProviderError(Exception):
        response = Response()
    diagnostic = _safe_provider_error(ProviderError("raw exception includes secrets"))
    assert "HTTP 400" in diagnostic
    assert "Invalid" in diagnostic
    assert "AIza" not in diagnostic


def test_malformed_ai_output_and_rules_only_fallback_are_reported(monkeypatch):
    features, status = service.ai_analyzer._parse_response('{"otp_request":"yes","unexpected":true}')
    assert features is None and status == AIStatus.FAILED
    monkeypatch.setattr(service.ai_analyzer, "analyze", lambda text: (None, AIStatus.FAILED))
    response = client.post("/api/v1/analyze/message", json={"message": "Pay the processing fee immediately."})
    data = response.json()
    assert data["ai_status"] == "FALLBACK"
    assert any("AI semantic analysis failed" in item for item in data["limitations"])
    assert any(x["signal_code"] == "PAYMENT_REQUEST" for x in data["signals"])


def test_urgency_evidence_does_not_claim_url_when_none_present():
    evidence = DeterministicRuleEngine().detect_evidence(
        "Your account will be blocked today unless you complete KYC."
    )
    assert URGENCY in evidence
    assert evidence[URGENCY] != "URL characteristics found"
    assert "blocked" in evidence[URGENCY].lower()


def test_gemini_initialization_with_invalid_credentials_is_lazy(monkeypatch):
    # Construction only creates the SDK client; authentication errors happen on request.
    import ai_analyzer
    class FakeTypes:
        class HttpOptions:
            def __init__(self, **kwargs): self.kwargs = kwargs
    class FakeGenai:
        class Client:
            def __init__(self, **kwargs): self.kwargs = kwargs
    monkeypatch.setattr(settings, "AI_PROVIDER", "gemini")
    monkeypatch.setattr(settings, "AI_API_KEY", "invalid-key")
    monkeypatch.setattr(settings, "ai_enabled", lambda: True)
    import sys, types
    google = types.ModuleType("google")
    google.genai = FakeGenai
    sub = types.ModuleType("google.genai")
    sub.types = FakeTypes
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.genai", sub)
    analyzer = ai_analyzer.AIAnalyzer()
    assert analyzer.status == AIStatus.SUCCESS
    assert analyzer._client.kwargs["api_key"] == "invalid-key"
