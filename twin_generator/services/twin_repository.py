"""
Repository layer for the Twin Orchestrator: twin_instances + twin_logs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session
from twin_generator.models.twin_instance import TwinInstance
from twin_generator.models.twin_log import TwinLog
from twin_generator.utils.enums import TwinLogEvent, TwinStatus


class TwinRepository:
    """Async CRUD access to twin_instances, plus append-only twin_logs writes."""

    def __init__(self, session: Session):
        self._session = session

    def create(self, twin: TwinInstance) -> TwinInstance:
        self._session.add(twin)
        self._session.flush()
        self._session.refresh(twin)
        return twin

    def get_by_id(self, twin_id: int) -> Optional[TwinInstance]:
        return self._session.get(TwinInstance, twin_id)

    def get_by_uuid(self, twin_uuid: UUID) -> Optional[TwinInstance]:
        stmt = select(TwinInstance).where(TwinInstance.uuid == twin_uuid)
        result = self._session.execute(stmt)
        return result.scalar_one_or_none()

    def list_all(self,cve=None) -> Sequence[TwinInstance]:
        stmt = select(TwinInstance).order_by(TwinInstance.created_at.desc())
        result = self._session.execute(stmt)
        return result.scalars().all()

    def list_expired(self, cutoff: datetime) -> Sequence[TwinInstance]:
        """Twins past their destroy_at that aren't already being/been torn down."""
        stmt = select(TwinInstance).where(
            TwinInstance.destroy_at.is_not(None),
            TwinInstance.destroy_at <= cutoff,
            TwinInstance.status.not_in([TwinStatus.DESTROYED.value, TwinStatus.DESTROYING.value]),
        )
        result = self._session.execute(stmt)
        return result.scalars().all()

    def save(self, twin: TwinInstance) -> TwinInstance:
        """Flush pending in-place attribute changes on an already-tracked twin."""
        self._session.flush()
        self._session.refresh(twin)
        return twin

    def add_log(
        self, twin_id: int, event: TwinLogEvent, details: Optional[str] = None
    ) -> TwinLog:
        log = TwinLog(twin_id=twin_id, event=event.value, details=details)
        self._session.add(log)
        self._session.flush()
        return log
