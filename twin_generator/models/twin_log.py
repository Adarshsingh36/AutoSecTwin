"""
SQLAlchemy model: twin_logs

Append-only audit trail for a twin instance's lifecycle: every state
transition, health check result, and error raised by the Twin Orchestrator,
Docker Twin Engine, VM Twin Engine, Legacy Profiler, or Twin Monitor is
recorded here for traceability and post-incident review.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from twin_generator.models.base import Base
from twin_generator.utils.enums import TwinLogEvent


class TwinLog(Base):
    """A single timestamped event in a twin's lifecycle."""

    __tablename__ = "twin_logs"
    __table_args__ = (
        Index("ix_twin_logs_twin_id", "twin_id"),
        Index("ix_twin_logs_timestamp", "timestamp"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    twin_id: Mapped[int] = mapped_column(
        ForeignKey("twin_instances.id", ondelete="CASCADE"),
        nullable=False,
        doc="The twin_instances.id this log entry belongs to.",
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    event: Mapped[TwinLogEvent] = mapped_column(
        String(32),
        nullable=False,
        doc="Canonical event type, e.g. 'health_check_failed'.",
    )

    details: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Free-text context: error messages, health check output, state deltas.",
    )

    twin: Mapped["TwinInstance"] = relationship(  # noqa: F821 - forward ref, see below
        "TwinInstance",
        back_populates="logs",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return f"<TwinLog id={self.id} twin_id={self.twin_id} event={self.event}>"
