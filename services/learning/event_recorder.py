from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from database.models.learning_event import LearningEvent
from services.learning.continuous_learning import ContinuousLearningEngine

logger = logging.getLogger(__name__)
_engine = ContinuousLearningEngine()


def record_learning_event(
    db: Session,
    *,
    event_type: str,
    source: str,
    label: str | None = None,
    payload: dict[str, Any] | None = None,
    notes: str | None = None,
) -> LearningEvent | None:
    """Persist workflow feedback for future calibration; never retrain inline."""

    try:
        event = LearningEvent(
            event_type=event_type,
            source=source,
            label=label,
            payload=_engine.normalize_event(payload),
            notes=notes,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event
    except Exception:
        db.rollback()
        logger.exception("Could not persist learning event %s from %s", event_type, source)
        return None