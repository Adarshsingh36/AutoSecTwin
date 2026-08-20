from sqlalchemy.orm import Session

from database.models.trust import AgreementHistory, ModelDrift


class DriftMonitor:
    """Calculates model drift from agreement-rate degradation."""

    def __init__(self, db: Session, model_name: str = "exploitability") -> None:
        self.db = db
        self.model_name = model_name

    def detect_model_drift(self, current_agreement: float) -> ModelDrift:
        """Persist and return the current drift state.

        Args:
            current_agreement: Current classifier-to-validation agreement rate.

        Returns:
            Persisted model drift row.
        """

        baseline_row = (
            self.db.query(AgreementHistory)
            .filter(AgreementHistory.model_name == self.model_name)
            .order_by(AgreementHistory.id.asc())
            .first()
        )
        baseline = baseline_row.agreement_rate if baseline_row else current_agreement
        drift_score = max(0.0, baseline - current_agreement)
        row = ModelDrift(
            model_name=self.model_name,
            drift_score=drift_score,
            baseline_agreement=baseline,
            current_agreement=current_agreement,
            retraining_recommended=drift_score >= 0.20 or current_agreement < 0.65,
        )
        self.db.add(row)
        return row
