
"""
Legacy Profiler service.

Compares a detected (software, version) pair against the local
legacy_profiles End-of-Life reference table.
"""

from __future__ import annotations

from datetime import date

import structlog
from sqlalchemy.orm import Session

from twin_generator.legacy.repository import LegacyProfileRepository
from twin_generator.models.legacy_profile import LegacyProfile
from twin_generator.schemas.legacy_profile import LegacyCheckResponse
from twin_generator.utils.enums import LegacyFlag

logger = structlog.get_logger(__name__)


class LegacyProfilerService:
    def __init__(self, session: Session) -> None:
        self._repo = LegacyProfileRepository(session)

    def check(self, software: str, version: str) -> LegacyCheckResponse:
        profile = self._repo.find(software, version)

        if profile is None:
            logger.info(
                "legacy_check_unknown",
                software=software,
                version=version,
            )
            return LegacyCheckResponse(
                software=software,
                version=version,
                classification=LegacyFlag.UNKNOWN,
                eol_date=None,
                matched_profile_id=None,
            )

        classification = self._classify(profile)

        logger.info(
            "legacy_check_matched",
            software=software,
            version=version,
            classification=classification.value,
            profile_id=profile.id,
        )

        return LegacyCheckResponse(
            software=software,
            version=version,
            classification=classification,
            eol_date=profile.eol,
            matched_profile_id=profile.id,
        )

    @staticmethod
    def _classify(profile: LegacyProfile) -> LegacyFlag:
        """
        Database representation:

            unsupported=True  -> LEGACY
            unsupported=False -> SUPPORTED
            unsupported=None   -> use EOL date
        """

        if profile.unsupported is True:
            return LegacyFlag.LEGACY

        if profile.unsupported is False:
            return LegacyFlag.SUPPORTED

        if profile.eol is not None:
            return (
                LegacyFlag.LEGACY
                if profile.eol < date.today()
                else LegacyFlag.SUPPORTED
            )

        return LegacyFlag.UNKNOWN
