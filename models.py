"""
models.py
---------
Pydantic data models for API requests, responses, and internal signal representations.
"""

import uuid
from enum import Enum
from typing import List, Optional, Dict
from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AuthenticityStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    SUSPICIOUS = "SUSPICIOUS"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class AIStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    FALLBACK = "FALLBACK"


class SemanticFeatures(BaseModel):
    """Structured output extracted by the AI Analyzer."""
    model_config = ConfigDict(extra="forbid")
    intent: Optional[str] = Field(None, description="Inferred primary message intent")
    urgency: bool = Field(False, description="Whether the message conveys immediate urgency")
    threat: bool = Field(False, description="Whether the message contains threats or negative consequences")
    otp_request: bool = Field(False, description="Whether the message asks for an OTP")
    credential_request: bool = Field(False, description="Whether credentials are requested")
    payment_request: bool = Field(False, description="Whether payment or money transfer is requested")
    authority_impersonation: bool = Field(False, description="Whether an official authority is impersonated")
    social_engineering: bool = Field(False, description="Whether manipulation techniques are detected")
    account_kyc_threat: bool = Field(False, description="Whether account suspension or KYC expiry is threatened")
    reward_bait: bool = Field(False, description="Whether prizes or rewards are promised")
    remote_access_request: bool = Field(False, description="Whether remote access or app install is requested")
    link_click_request: bool = Field(False, description="Whether the user is asked to click a link")
    is_safety_advice: bool = Field(False, description="Whether the message is warning/advising AGAINST threats")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="AI self-reported confidence")
    evidence_excerpts: List[str] = Field(default_factory=list, max_length=12, description="Short excerpts supporting findings")


class UrlAnalysisResult(BaseModel):
    """Structured findings from deterministic URL analysis."""
    has_url: bool = False
    urls_found: List[str] = Field(default_factory=list)
    has_shortened_url: bool = False
    has_suspicious_domain: bool = False
    has_domain_mismatch: bool = False
    has_ip_url: bool = False
    has_deceptive_subdomain: bool = False
    claimed_org: Optional[str] = None
    detected_domains: List[str] = Field(default_factory=list)
    domain_details: List[Dict] = Field(default_factory=list)


class SignalDetail(BaseModel):
    """Individual risk indicator attached to the final analysis response."""
    signal_code: str = Field(..., description="Unique technical code for the signal")
    signal_name: str = Field("", description="Human-readable name of the signal")
    weight: int = Field(..., description="Numerical weight assigned to this risk indicator")
    detected_by: str = Field(..., description="Source of detection: 'AI', 'RULE', or 'BOTH'")
    explanation: str = Field(..., description="Senior-friendly human readable explanation")
    evidence: str = Field("", description="Supporting excerpt or evidence")
    limitations: str = Field("", description="What this finding does not prove")


class AnalyzeRequest(BaseModel):
    """API Request Payload for POST /api/v1/analyze/message"""
    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        examples=["Your KYC has expired. Your account will be blocked today."],
    )
    claimed_organization: Optional[str] = Field(
        None,
        max_length=200,
        examples=["HDFC Bank"],
        description="Optional claimed organization name for domain cross-checking",
    )


class AnalyzeResponse(BaseModel):
    """API Response Payload for POST /api/v1/analyze/message"""
    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    risk_score: int = Field(..., ge=0, le=100, description="Final aggregate risk score (0 to 100)")
    risk_level: RiskLevel = Field(..., description="Risk categorization: LOW, MEDIUM, HIGH")
    assessment_confidence: str = Field(
        "moderate",
        description="How much evidence supports this assessment: low, moderate, high",
    )
    assessment_status: AuthenticityStatus = Field(
        AuthenticityStatus.UNVERIFIED,
        description="UNVERIFIED, SUSPICIOUS, or INSUFFICIENT_EVIDENCE",
    )
    overall_explanation: str = Field("", description="Plain-language summary of the assessment")
    signals: List[SignalDetail] = Field(default_factory=list, description="Detected risk signals")
    recommendations: List[str] = Field(default_factory=list, description="Actionable safety guidance")
    limitations: List[str] = Field(
        default_factory=list,
        description="Important caveats about what this assessment cannot determine",
    )
    ai_status: AIStatus = Field(
        AIStatus.NOT_CONFIGURED,
        description="Whether AI analysis succeeded, failed, or was not configured",
    )
