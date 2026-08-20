from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PredictionComparison:
    """Normalized prediction and validation values used by the trust service."""

    prediction_score: float
    validation_score: float
    vulnerability_id: int | None = None
    shap_explanation: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TrustResult:
    """Trust service decision returned to callers after comparison."""

    agreement: bool
    hallucination: bool
    trust_score: float
    agreement_rate: float
    drift_score: float
    retraining_recommended: bool
    reason: str
