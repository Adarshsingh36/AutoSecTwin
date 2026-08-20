"""
Repository layer for legacy_profiles: the local End-of-Life reference data
the Legacy Profiler compares detected software/version against.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from twin_generator.models.legacy_profile import LegacyProfile


class LegacyProfileRepository:
    """Read/write access to the legacy_profiles table."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def find(self, software: str, version: str) -> Optional[LegacyProfile]:
        stmt = select(LegacyProfile).where(
            LegacyProfile.product == software,
            LegacyProfile.version == version,
        )
        result = self._session.execute(stmt)
        return result.scalar_one_or_none()

    def create(self, profile: LegacyProfile) -> LegacyProfile:
        self._session.add(profile)
        self._session.flush()
        self._session.refresh(profile)
        return profile