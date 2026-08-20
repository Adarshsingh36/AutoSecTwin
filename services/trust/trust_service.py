from __future__ import annotations

from sqlalchemy.orm import Session

from database.models.trust import HallucinationLog, TrustMetric
from services.trust.agreement_tracker import AgreementTracker
from services.trust.drift_monitor import DriftMonitor
from services.trust.hallucination_detector import HallucinationDetector
from services.trust.trust_models import PredictionComparison, TrustResult


class TrustService:
    """Compares AI predictions against twin validation and records trust signals."""

    AGREEMENT_THRESHOLD = 0.30

    def __init__(self, db: Session) -> None:
        self.db = db
        self.detector = HallucinationDetector()
        self.tracker = AgreementTracker(db)
        self.drift_monitor = DriftMonitor(db)

    def compare_prediction(self, comparison: PredictionComparison) -> TrustResult:
        """Compare an ML prediction with exploit validation evidence.

        Args:
            comparison: Prediction, validation, SHAP, and metadata payload.

        Returns:
            Trust result containing agreement, hallucination, and drift state.
        """

        agreement = abs(comparison.prediction_score - comparison.validation_score) <= self.AGREEMENT_THRESHOLD
        hallucination, severity, reason = self.detect_hallucination(
            comparison.prediction_score,
            comparison.validation_score,
        )
        trust_score = self._calculate_trust_score(comparison.prediction_score, comparison.validation_score, agreement)
        self.update_statistics(comparison, agreement, hallucination, severity, reason, trust_score)
        agreement_rate = self.calculate_agreement()
        drift = self.drift_monitor.detect_model_drift(agreement_rate)
        self.db.commit()
        return TrustResult(
            agreement=agreement,
            hallucination=hallucination,
            trust_score=trust_score,
            agreement_rate=agreement_rate,
            drift_score=drift.drift_score,
            retraining_recommended=drift.retraining_recommended,
            reason=reason,
        )

    def calculate_agreement(self) -> float:
        """Return the persisted classifier agreement rate."""

        rate = self.tracker.calculate_agreement()
        self.tracker.record(rate)
        return rate

    def detect_hallucination(self, prediction_score: float, validation_score: float) -> tuple[bool, str, str]:
        """Detect whether a prediction is unsupported by validation evidence."""

        return self.detector.detect_hallucination(prediction_score, validation_score)

    def update_statistics(
        self,
        comparison: PredictionComparison,
        agreement: bool,
        hallucination: bool,
        severity: str,
        reason: str,
        trust_score: float,
    ) -> TrustMetric:
        """Persist trust metric and hallucination evidence.

        Args:
            comparison: Prediction comparison payload.
            agreement: Whether prediction and validation agree.
            hallucination: Whether hallucination was detected.
            severity: Hallucination severity.
            reason: Explanation for the decision.
            trust_score: Final trust score.

        Returns:
            Persisted trust metric row.
        """

        metric = TrustMetric(
            vulnerability_id=comparison.vulnerability_id,
            prediction_score=comparison.prediction_score,
            validation_score=comparison.validation_score,
            agreement=agreement,
            trust_score=trust_score,
            shap_explanation=comparison.shap_explanation,
            metadata_json=comparison.metadata,
        )
        self.db.add(metric)
        if hallucination:
            self.db.add(
                HallucinationLog(
                    vulnerability_id=comparison.vulnerability_id,
                    prediction_score=comparison.prediction_score,
                    validation_score=comparison.validation_score,
                    severity=severity,
                    reason=reason,
                    metadata_json=comparison.metadata,
                )
            )
        return metric

    def get_trust_metrics(self) -> dict[str, float | int]:
        """Return aggregate trust metrics for API consumers."""

        total = self.db.query(TrustMetric).count()
        hallucinations = self.db.query(HallucinationLog).count()
        agreement_rate = self.tracker.calculate_agreement()
        return {
            "total_comparisons": total,
            "hallucinations": hallucinations,
            "agreement_rate": agreement_rate,
        }

    @staticmethod
    def _calculate_trust_score(prediction_score: float, validation_score: float, agreement: bool) -> float:
        distance_penalty = abs(prediction_score - validation_score)
        agreement_bonus = 0.15 if agreement else 0.0
        return max(0.0, min(1.0, 1.0 - distance_penalty + agreement_bonus))
