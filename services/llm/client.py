import logging
from typing import Literal

from core.config import settings

logger = logging.getLogger(__name__)

LLMUseCase = Literal[
    "patch_recommendation",
    "code_recommendation",
    "technical_report",
    "executive_report",
]


class LLMClient:
    """Centralized LLM adapter restricted to recommendation and report generation."""

    ALLOWED_USE_CASES: set[str] = {
        "patch_recommendation",
        "code_recommendation",
        "technical_report",
        "executive_report",
    }

    def __init__(self, provider: str = "openai") -> None:
        self.provider = provider

    def generate(self, use_case: LLMUseCase, prompt: str) -> str:
        """Generate text for allowed non-research use cases."""

        if use_case not in self.ALLOWED_USE_CASES:
            raise ValueError(f"LLM use case is not allowed: {use_case}")
        if self.provider == "openai" and settings.OPENAI_API_KEY:
            return self._generate_openai(prompt)
        logger.info("LLM provider unavailable; returning deterministic fallback for %s", use_case)
        return self._fallback(use_case, prompt)

    def _generate_openai(self, prompt: str) -> str:
        try:
            from openai import OpenAI

            client = OpenAI(api_key=settings.OPENAI_API_KEY)
            response = client.responses.create(model="gpt-4.1-mini", input=prompt)
            return response.output_text
        except Exception as exc:
            logger.exception("OpenAI generation failed")
            raise RuntimeError("OpenAI generation failed") from exc

    @staticmethod
    def _fallback(use_case: str, prompt: str) -> str:
        return f"{use_case}: LLM provider is not configured. Source prompt length={len(prompt)}."
