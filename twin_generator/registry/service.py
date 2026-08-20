"""
Service layer for the CVE Image Registry.

Owns the business rules the router shouldn't know about: duplicate
detection, partial updates, and the "no mapping for this CVE" case that the
Twin Orchestrator relies on when deciding whether Docker can even attempt
a reproduction.
"""

from __future__ import annotations

from typing import Optional, Sequence

import structlog
from sqlalchemy.orm import Session
from twin_generator.models.twin_registry import TwinRegistry
from twin_generator.registry.repository import RegistryRepository
from twin_generator.schemas.twin_registry import RegistryEntryCreate, RegistryEntryUpdate
from twin_generator.utils.exceptions import (
    DuplicateRegistryEntryError,
    NoRegistryEntryForCveError,
    RegistryEntryNotFoundError,
)

logger = structlog.get_logger(__name__)


class RegistryService:
    """Business logic for creating, listing, updating, and deleting CVE->image mappings."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._repo = RegistryRepository(session)

    def create_entry(self, payload: RegistryEntryCreate) -> TwinRegistry:
        existing = self._repo.find_duplicate(payload.cve, payload.image, payload.version)
        if existing is not None:
            raise DuplicateRegistryEntryError(payload.cve, payload.image, payload.version)

        entry = TwinRegistry(
            cve=payload.cve,
            image=payload.image,
            environment=payload.environment.value if payload.environment else None,
            version=payload.version,
            notes=payload.notes,
        )
        created = self._repo.create(entry)
        logger.info("registry_entry_created", cve=created.cve, image=created.image, id=created.id)
        return created

    def list_entries(self, cve: Optional[str] = None) -> Sequence[TwinRegistry]:
        return self._repo.list_all(cve=cve)

    def get_entry(self, entry_id: int) -> TwinRegistry:
        entry = self._repo.get_by_id(entry_id)
        if entry is None:
            raise RegistryEntryNotFoundError(entry_id)
        return entry

    def update_entry(self, entry_id: int, payload: RegistryEntryUpdate) -> TwinRegistry:
        entry = self.get_entry(entry_id)

        if payload.image is not None:
            entry.image = payload.image
        if payload.environment is not None:
            entry.environment = payload.environment.value
        if payload.version is not None:
            entry.version = payload.version
        if payload.notes is not None:
            entry.notes = payload.notes

        self._session.flush()
        self._session.refresh(entry)
        logger.info("registry_entry_updated", id=entry.id, cve=entry.cve)
        return entry

    def delete_entry(self, entry_id: int) -> None:
        entry = self.get_entry(entry_id)
        self._repo.delete(entry)
        logger.info("registry_entry_deleted", id=entry_id, cve=entry.cve)

    def resolve_image_for_cve(self, cve):
        print("=" * 60)
        print("Searching registry for:", cve)

        entries = self._repo.list_for_cve(cve)

        print("Found:", entries)
        print("=" * 60)

        if not entries:
            raise NoRegistryEntryForCveError(cve)

        return entries[-1]