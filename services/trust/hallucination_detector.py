class HallucinationDetector:
    """Detects unsupported high-confidence exploitability predictions."""

    def detect_hallucination(self, prediction_score: float, validation_score: float) -> tuple[bool, str, str]:
        """Compare prediction and validation to flag likely hallucination.

        Args:
            prediction_score: Classifier exploitability probability.
            validation_score: Digital twin exploit validation score.

        Returns:
            Tuple of hallucination flag, severity, and human-readable reason.
        """

        delta = prediction_score - validation_score
        if prediction_score >= 0.75 and validation_score <= 0.25:
            return True, "high", "High exploitability prediction was not supported by validation."
        if delta >= 0.45:
            return True, "medium", "Prediction materially exceeded validation evidence."
        return False, "low", "Prediction and validation are within the accepted trust band."
