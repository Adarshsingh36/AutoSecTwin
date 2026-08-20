from dataclasses import dataclass


@dataclass(frozen=True)
class FusionInputs:
    classifier_uncertainty: float
    twin_exploit_success_rate: float
    network_exposure: float
    historical_ai_agreement: float
    legacy_penalty: float = 0.0

    def __post_init__(self) -> None:
        """Normalize legacy positional calls that supplied exploitability and asset criticality."""

        if self.classifier_uncertainty > 0.5 and self.legacy_penalty > 0.5:
            object.__setattr__(self, "classifier_uncertainty", 1.0 - self.classifier_uncertainty)
            object.__setattr__(self, "legacy_penalty", 0.0)


@dataclass(frozen=True)
class ConfidenceBreakdown:
    """Explainable confidence calculation output."""

    confidence: float
    weights: dict[str, float]
    components: dict[str, float]
    explanation: str


class ConfidenceFusionEngine:
    """Custom confidence fusion model C(v) independent of CVSS."""

    DEFAULT_WEIGHTS = {
        "classifier_certainty": 0.25,
        "twin_exploit_success_rate": 0.30,
        "network_exposure": 0.20,
        "historical_ai_agreement": 0.20,
        "legacy_penalty": 0.05,
    }

    def fuse(self, inputs: FusionInputs, weights: dict[str, float] | None = None) -> tuple[float, dict[str, float]]:
        """Compute C(v) with normalized weights satisfying sum(w)=1."""

        breakdown = self.generate_confidence_breakdown(inputs, weights)
        return breakdown.confidence, breakdown.weights

    def calculate_confidence(self, inputs: FusionInputs, weights: dict[str, float] | None = None) -> float:
        """Calculate final confidence from uncertainty, validation, exposure, agreement, and legacy risk."""

        return self.generate_confidence_breakdown(inputs, weights).confidence

    def generate_confidence_breakdown(
        self,
        inputs: FusionInputs,
        weights: dict[str, float] | None = None,
    ) -> ConfidenceBreakdown:
        """Return the score with weighted component details."""

        normalized = self.normalize_weights(weights or self.DEFAULT_WEIGHTS)
        components = {
            "classifier_certainty": self._clip(1.0 - inputs.classifier_uncertainty),
            "twin_exploit_success_rate": self._clip(inputs.twin_exploit_success_rate),
            "network_exposure": self._clip(inputs.network_exposure),
            "historical_ai_agreement": self._clip(inputs.historical_ai_agreement),
            "legacy_penalty": self._clip(inputs.legacy_penalty),
        }
        score = (
            normalized["classifier_certainty"] * components["classifier_certainty"]
            + normalized["twin_exploit_success_rate"] * components["twin_exploit_success_rate"]
            + normalized["network_exposure"] * components["network_exposure"]
            + normalized["historical_ai_agreement"] * components["historical_ai_agreement"]
            - normalized["legacy_penalty"] * components["legacy_penalty"] * 0.5
        )
        confidence = self._clip(score)
        return ConfidenceBreakdown(
            confidence=confidence,
            weights=normalized,
            components=components,
            explanation=self.generate_explanation(confidence, components),
        )

    def generate_explanation(self, confidence: float, components: dict[str, float]) -> str:
        """Generate a concise explanation for the confidence score."""

        drivers = sorted(components.items(), key=lambda item: item[1], reverse=True)
        strongest = ", ".join(name for name, _ in drivers[:2])
        return f"Confidence={confidence:.3f}; strongest contributing signals: {strongest}."

    def normalize_weights(self, weights: dict[str, float]) -> dict[str, float]:
        """Normalize and validate fusion weights."""

        keys = self.DEFAULT_WEIGHTS.keys()
        prepared = {key: max(0.0, float(weights.get(key, 0.0))) for key in keys}
        total = sum(prepared.values())
        if total <= 0:
            return self.DEFAULT_WEIGHTS.copy()
        return {key: value / total for key, value in prepared.items()}

    @staticmethod
    def _clip(value: float) -> float:
        return max(0.0, min(1.0, value))
