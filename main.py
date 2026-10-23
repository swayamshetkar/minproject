"""
main.py
-------
FastAPI application entry point for the Senior Citizen Digital Safety Companion.

Endpoints:
- POST /api/v1/analyze/message — Analyze a message for scam indicators
- GET /health — Application health check
- GET /api/v1/health — API health check

Run locally: uvicorn main:app --host 0.0.0.0 --port 8000
"""

import logging
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from config import settings
from models import (
    AnalyzeRequest, AnalyzeResponse, SignalDetail, AIStatus,
)
from ai_analyzer import AIAnalyzer
from rule_engine import DeterministicRuleEngine
from signal_aggregator import SignalAggregator
from scorer import RiskScoringEngine
from explanation import ExplanationGenerator
from recommendations import RecommendationGenerator
from rules import RULE_WEIGHTS, RULE_DEFINITIONS

# --- Logging ---
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# --- FastAPI App ---
app = FastAPI(
    title="Senior Citizen Digital Safety Companion",
    description=(
        "Analyzes messages for potential scam, phishing, and fraud indicators. "
        "Provides risk assessment with plain-language explanations for senior citizens."
    ),
    version="1.0.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# --- Service Layer ---
class ScamRiskAnalyzerService:
    """Main analysis pipeline service."""

    def __init__(self):
        self.ai_analyzer = AIAnalyzer()
        self.rule_engine = DeterministicRuleEngine()
        self.aggregator = SignalAggregator()
        self.scoring_engine = RiskScoringEngine()

    def analyze_message(self, request: AnalyzeRequest) -> AnalyzeResponse:
        """Execute the full hybrid analysis pipeline."""
        message = request.message.strip()
        claimed_org = request.claimed_organization

        if not message or message.isspace():
            raise ValueError("Message cannot be empty or whitespace only.")

        # Log without exposing full content
        if settings.LOG_MESSAGES:
            logger.info(f"Analyzing message ({len(message)} chars)")
        else:
            logger.info(f"Analyzing message ({len(message)} chars) [content not logged]")

        # Step 1: AI Analysis (may return None if unavailable)
        ai_features, ai_status = self.ai_analyzer.analyze(message)

        # Step 2: Deterministic Rule Engine
        rule_evidence = self.rule_engine.detect_evidence(message, claimed_org)
        rule_signals = set(rule_evidence)

        # Step 3: Signal Aggregation & Deduplication
        aggregated_signals = self.aggregator.aggregate(ai_features, rule_signals)

        # Step 4: Risk Scoring
        score, risk_level, status, confidence = self.scoring_engine.calculate_score(
            aggregated_signals
        )

        # Step 5: Build signal details with explanations
        ai_used = ai_status == AIStatus.SUCCESS
        signal_details = []
        for code, source in aggregated_signals.items():
            defn = RULE_DEFINITIONS.get(code, {})
            signal_details.append(
                SignalDetail(
                    signal_code=code,
                    signal_name=defn.get("name", code),
                    weight=RULE_WEIGHTS.get(code, 10),
                    detected_by=source,
                    explanation=ExplanationGenerator.get_explanation(code),
                    evidence=rule_evidence.get(
                        code,
                        (ai_features.evidence_excerpts[0][:160]
                         if source == "AI" and ai_features and ai_features.evidence_excerpts
                         else "Semantic indicator identified by AI" if source == "AI" else ""),
                    ),
                    limitations=ExplanationGenerator.get_limitation(code),
                )
            )

        # Step 6: Recommendations
        recommendations = RecommendationGenerator.generate_recommendations(aggregated_signals)

        # Step 7: Overall explanation and limitations
        overall = ExplanationGenerator.generate_overall_explanation(
            risk_level.value, list(aggregated_signals.keys()), ai_used
        )
        limitations = ExplanationGenerator.get_standard_limitations(ai_used)

        # Map AI status for response
        if ai_status == AIStatus.SUCCESS:
            response_ai_status = AIStatus.SUCCESS
        elif ai_status == AIStatus.NOT_CONFIGURED:
            response_ai_status = AIStatus.NOT_CONFIGURED
        else:
            response_ai_status = AIStatus.FALLBACK

        if response_ai_status == AIStatus.FALLBACK:
            limitations.append(
                "AI semantic analysis failed or was unavailable for this request; this result uses rule-based analysis only."
            )

        return AnalyzeResponse(
            risk_score=score,
            risk_level=risk_level,
            assessment_confidence=confidence,
            assessment_status=status,
            overall_explanation=overall,
            signals=signal_details,
            recommendations=recommendations,
            limitations=limitations,
            ai_status=response_ai_status,
        )


# Initialize service
service = ScamRiskAnalyzerService()


# --- Error Handlers ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {type(exc).__name__}")
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Please try again."},
    )


# --- Endpoints ---
@app.get("/")
async def root():
    """Simple landing response for platform probes and API discovery."""
    return {"name": "Senior Citizen Digital Safety Companion API", "health": "/health", "docs": "/docs"}


class HealthResponse(BaseModel):
    status: str
    ai_configured: bool
    ai_provider: str


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Application health check."""
    return HealthResponse(
        status="healthy",
        ai_configured=settings.ai_enabled(),
        ai_provider=settings.AI_PROVIDER if settings.ai_enabled() else "none",
    )


@app.get("/api/v1/health", response_model=HealthResponse)
async def api_health_check():
    """API health check."""
    return HealthResponse(
        status="healthy",
        ai_configured=settings.ai_enabled(),
        ai_provider=settings.AI_PROVIDER if settings.ai_enabled() else "none",
    )


@app.post("/api/v1/analyze/message", response_model=AnalyzeResponse)
def analyze_message(request: AnalyzeRequest):
    """
    Analyze a message for potential scam, phishing, or fraud indicators.

    The user submits a message (SMS, WhatsApp, email text) and optionally
    the claimed organization. The system returns a risk assessment with
    explanations and recommendations.

    **Privacy Note**: If AI is configured, the message text is sent to the
    configured external AI provider for semantic analysis.
    """
    # Validate message length
    if len(request.message) > settings.MAX_REQUEST_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Message too long. Maximum {settings.MAX_REQUEST_SIZE} characters.",
        )

    if not request.message.strip():
        raise HTTPException(status_code=422, detail="Message cannot be empty or whitespace only.")

    try:
        return service.analyze_message(request)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.middleware("http")
async def enforce_body_limit(request: Request, call_next):
    """Reject oversized bodies before JSON parsing; do not read/store content here."""
    declared = request.headers.get("content-length")
    if declared:
        try:
            if int(declared) > settings.MAX_REQUEST_SIZE + 2048:
                return JSONResponse(status_code=413, content={"detail": "Request body too large."})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length."})
    return await call_next(request)
