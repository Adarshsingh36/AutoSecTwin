"""
Remediation queue -- the terminus of the approval workflow diagram:

    Recommendation -> Review Package -> Human Approval -> Remediation Queue

An approved Remediation sits at status=APPROVED until something executes
it (either automatically, if settings.REMEDIATION_AUTO_APPLY is on, or via
POST /remediations/{id}/execute). This module is the read side of that
queue -- what's waiting, and how old is the oldest item -- used by
dashboards/operators deciding what needs attention, and by anything that
wants to drain the queue (an operator manually triggering execution, or a
periodic sweep, neither of which is built yet beyond manual dispatch).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy.orm import Session

from database.models.remediation import Remediation
from services.remediation import status as remediation_status


def list_queued_remediations(db: Session) -> Sequence[Remediation]:
    """Remediations that have been approved but not yet executed, oldest first."""

    return (
        db.query(Remediation)
        .filter(Remediation.status == remediation_status.APPROVED)
        .order_by(Remediation.created_at.asc())
        .all()
    )


def queue_depth(db: Session) -> int:
    return (
        db.query(Remediation)
        .filter(Remediation.status == remediation_status.APPROVED)
        .count()
    )


def oldest_queued_age_seconds(db: Session) -> float | None:
    """How long the oldest approved-but-not-yet-executed remediation has
    been waiting. None if the queue is empty.
    """

    oldest = (
        db.query(Remediation)
        .filter(Remediation.status == remediation_status.APPROVED)
        .order_by(Remediation.created_at.asc())
        .first()
    )

    if oldest is None or oldest.created_at is None:
        return None

    created_at = oldest.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)

    return (datetime.now(timezone.utc) - created_at).total_seconds()
