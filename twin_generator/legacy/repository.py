
"""
Repository layer for legacy_profiles.

The project database model stores:
    product     -> software
    unsupported -> inverse of supported
    eol         -> eol_date

The repository translates between the generator's public terminology and
the existing database representation.
"""

from __future__ import annotations

from datetime import date
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from twin_generator.models.legacy_profile import LegacyProfile


class LegacyProfileRepository:
    """Read/write access to the project's legacy_profiles table."""

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

    @staticmethod
    def software(profile: LegacyProfile) -> str:
        return profile.product

    @staticmethod
    def supported(profile: LegacyProfile) -> Optional[bool]:
        if profile.unsupported is None:
            return None
        return not profile.unsupported

    @staticmethod
    def eol_date(profile: LegacyProfile) -> Optional[date]:
        return profile.eol
