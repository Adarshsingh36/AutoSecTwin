"""
Unit tests for LegacyProfilerService. Repository is mocked -- these test
the classification rules only.
"""

from __future__ import annotations

from datetime import date, timedelta
from unittest.mock import MagicMock

import pytest

from twin_generator.legacy.service import LegacyProfilerService
from twin_generator.models.legacy_profile import LegacyProfile
from twin_generator.utils.enums import LegacyFlag


@pytest.fixture
def service() -> LegacyProfilerService:
    svc = LegacyProfilerService(session=MagicMock())
    svc._repo = MagicMock()
    return svc


def test_unknown_when_no_matching_profile(
    service: LegacyProfilerService,
) -> None:
    service._repo.find.return_value = None

    result = service.check("Windows Server", "2003")

    assert result.classification == LegacyFlag.UNKNOWN
    assert result.matched_profile_id is None


def test_supported_when_flag_true(
    service: LegacyProfilerService,
) -> None:
    service._repo.find.return_value = LegacyProfile(
        id=1,
        software="Ubuntu",
        version="24.04",
        supported=True,
        eol_date=None,
    )

    result = service.check("Ubuntu", "24.04")

    assert result.classification == LegacyFlag.SUPPORTED
    assert result.matched_profile_id == 1


def test_legacy_when_flag_false(
    service: LegacyProfilerService,
) -> None:
    service._repo.find.return_value = LegacyProfile(
        id=2,
        software="Windows Server",
        version="2003",
        supported=False,
    )

    result = service.check("Windows Server", "2003")

    assert result.classification == LegacyFlag.LEGACY


def test_legacy_when_eol_date_in_past_and_flag_unset(
    service: LegacyProfilerService,
) -> None:
    service._repo.find.return_value = LegacyProfile(
        id=3,
        software="Apache Struts",
        version="2.3",
        supported=None,
        eol_date=date.today() - timedelta(days=1),
    )

    result = service.check("Apache Struts", "2.3")

    assert result.classification == LegacyFlag.LEGACY


def test_supported_when_eol_date_in_future_and_flag_unset(
    service: LegacyProfilerService,
) -> None:
    service._repo.find.return_value = LegacyProfile(
        id=4,
        software="Node.js",
        version="20",
        supported=None,
        eol_date=date.today() + timedelta(days=365),
    )

    result = service.check("Node.js", "20")

    assert result.classification == LegacyFlag.SUPPORTED


def test_unknown_when_no_flag_and_no_eol_date(
    service: LegacyProfilerService,
) -> None:
    service._repo.find.return_value = LegacyProfile(
        id=5,
        software="Custom App",
        version="1.0",
        supported=None,
        eol_date=None,
    )

    result = service.check("Custom App", "1.0")

    assert result.classification == LegacyFlag.UNKNOWN