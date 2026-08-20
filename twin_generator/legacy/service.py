"""
Legacy Profiler service.

Compares a detected (software, version) pair against the local
legacy_profiles End-of-Life reference table and classifies it as
Legacy / Supported / Unknown.

Per spec, this classification is metadata only: it flags legacy systems for
downstream awareness (the Twin Orchestrator sets TwinInstance.legacy_flag
from this result) but never blocks or delays twin creation itself.
"""

from __future__ import annotations

from datetime import date
from typing import Optional

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
            logger.info("legacy_check_unknown", software=software, version=version)
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
            eol_date=profile.eol_date,
            matched_profile_id=profile.id,
        )

    @staticmethod
    def _classify(profile: LegacyProfile) -> LegacyFlag:
        # An explicit `supported` flag on the reference row is authoritative.
        if profile.supported is True:
            return LegacyFlag.SUPPORTED
        if profile.supported is False:
            return LegacyFlag.LEGACY

        # No explicit flag: fall back to comparing eol_date against today.
        if profile.eol_date is not None:
            return LegacyFlag.LEGACY if profile.eol_date < date.today() else LegacyFlag.SUPPORTED

        return LegacyFlag.UNKNOWN
