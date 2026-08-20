"""
Repository layer for twin_registry (CVE Image Registry).

Pure data access -- no business rules here. The service layer above this
decides what counts as a duplicate, what happens when a lookup misses, etc.
"""

from __future__ import annotations
from typing import Optional, Sequence
from sqlalchemy import select
from sqlalchemy.orm import Session
from twin_generator.models.twin_registry import TwinRegistry


class RegistryRepository:
    """Async CRUD access to the twin_registry table."""

    def __init__(self, session: Session):
        self._session = session

    def create(self, entry):
        self._session.add(entry)

        print("BEFORE COMMIT")

        self._session.commit()

        print("AFTER COMMIT")
        self._session.flush()

        self._session.refresh(entry)

        print("ENTRY ID =", entry.id)

        return entry
    
    def get_by_id(self, entry_id: int) -> Optional[TwinRegistry]:
        return self._session.get(TwinRegistry, entry_id)

    def list_all(self, cve=None):
        print("SESSION =", self._session)

        stmt = select(TwinRegistry).order_by(TwinRegistry.id)

        if cve:
            stmt = stmt.where(TwinRegistry.cve == cve)

        print(stmt)

        result = self._session.execute(stmt)

        rows = result.scalars().all()

        print("ROWS =", rows)

        return rows

    def find_duplicate(
        self, cve: str, image: str, version: Optional[str]
    ) -> Optional[TwinRegistry]:
        stmt = select(TwinRegistry).where(
            TwinRegistry.cve == cve,
            TwinRegistry.image == image,
            TwinRegistry.version == version,
        )
        result = self._session.execute(stmt)
        return result.scalar_one_or_none()

    def delete(self, entry: TwinRegistry) -> None:
        self._session.delete(entry)
        self._session.flush()

    def list_for_cve(self, cve: str) -> Sequence[TwinRegistry]:
        """Used by the Twin Orchestrator/Docker Twin Engine to pick an image for a CVE."""
        return self.list_all(cve=cve)
