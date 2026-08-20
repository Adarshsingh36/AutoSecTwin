from __future__ import annotations

from sqlalchemy.orm import Session

from database.models.trust import AgreementHistory, TrustMetric


class AgreementTracker:
    """Tracks historical classifier agreement with exploit validation."""

    def __init__(self, db: Session, model_name: str = "exploitability") -> None:
        self.db = db
        self.model_name = model_name

    def calculate_agreement(self) -> float:
        """Return the current agreement rate over persisted trust metrics.

        Returns:
            A value from 0.0 to 1.0. Empty history is treated as fully unknown
            and returns 0.0.
        """

        rows = self.db.query(TrustMetric).all()
        if not rows:
            return 0.0
        matches = sum(1 for row in rows if row.agreement)
        return matches / len(rows)

    def record(self, agreement_rate: float) -> AgreementHistory:
        """Persist an agreement-rate snapshot.

        Args:
            agreement_rate: Current agreement rate.

        Returns:
            The persisted agreement history row.
        """

        sample_size = self.db.query(TrustMetric).count()
        history = AgreementHistory(
            model_name=self.model_name,
            agreement_rate=agreement_rate,
            sample_size=sample_size,
        )
        self.db.add(history)
        return history
