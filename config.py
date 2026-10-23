"""
config.py
---------
Centralized configuration for the Senior Citizen Digital Safety Companion.
Reads from environment variables with sensible defaults.
"""

import os
from typing import List, Optional

from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""

    # AI Provider
    # `gemini` is the preferred public name; `google` remains a compatibility alias.
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "none").strip().lower()
    AI_API_KEY: Optional[str] = os.getenv("AI_API_KEY")
    AI_MODEL: str = os.getenv("AI_MODEL", "gemini-2.0-flash")
    AI_TIMEOUT_SECONDS: int = int(os.getenv("AI_TIMEOUT_SECONDS", "15"))
    AI_MAX_INPUT_LENGTH: int = int(os.getenv("AI_MAX_INPUT_LENGTH", "5000"))
    AI_MAX_RESPONSE_TOKENS: int = int(os.getenv("AI_MAX_RESPONSE_TOKENS", "1024"))

    # Server
    # Render injects PORT and requires binding on all interfaces.
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    # Set this to the deployed frontend URL(s), comma separated. Keep localhost
    # defaults for local development; Render's own hostname is not a browser origin
    # unless the frontend is served from this same service.
    CORS_ORIGINS: List[str] = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,"
        "https://frontend-m6mogfnwm-swayamshetkars-projects.vercel.app,"
        "https://frontend-five-chi-82.vercel.app",
    ).split(",")
    CORS_ORIGINS = [origin.strip() for origin in CORS_ORIGINS if origin.strip()]
    MAX_REQUEST_SIZE: int = int(os.getenv("MAX_REQUEST_SIZE", "10000"))  # characters

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_MESSAGES: bool = os.getenv("LOG_MESSAGES", "false").lower() == "true"

    @classmethod
    def ai_enabled(cls) -> bool:
        """Check if AI is configured and available."""
        return cls.AI_PROVIDER in {"gemini", "google", "openai"} and bool(cls.AI_API_KEY)


settings = Settings()
