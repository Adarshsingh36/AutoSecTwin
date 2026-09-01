"""
Integration test for the Legacy Profiler HTTP endpoint, run against a real
(in-memory SQLite) database -- no mocks.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from twin_generator.models.legacy_profile import LegacyProfile


def test_check_returns_unknown_for_unseen_software(
    client: TestClient,
) -> None:
    response = client.post(
        "/legacy/check",
        json={
            "software": "Mystery OS",
            "version": "1.0",
        },
    )

    assert response.status_code == 200
    assert response.json()["classification"] == "unknown"


def test_check_returns_legacy_for_seeded_eol_software(
    client: TestClient,
    session: Session,
) -> None:
    session.add(
        LegacyProfile(
            product="Windows Server",
            version="2003",
            unsupported=True,
            vendor="Microsoft",
        )
    )
    session.flush()

    response = client.post(
        "/legacy/check",
        json={
            "software": "Windows Server",
            "version": "2003",
        },
    )

    assert response.status_code == 200

    body = response.json()
    assert body["classification"] == "legacy"
    assert body["matched_profile_id"] is not None
