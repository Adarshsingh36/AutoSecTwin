"""
Tests for Phase 1's schema additions: Remediation.target_twin_id and the
Approval -> recommendation/twin/remediation linkage.

These test that the columns exist, persist, and are reachable through the
API routes -- not the full execute/revalidate pipeline itself (covered in
tests/unit/test_patch_executor.py, test_docker_patch_handler.py, and the
Phase 5 approval-workflow/pipeline tests). The twin fixture here uses
provider="docker" (not "TwinGenerator"), so any remediation auto-dispatch
triggered by REMEDIATION_AUTO_APPLY during these tests will correctly stop
at MANUAL_ACTION_REQUIRED (twin not recognized as AutoSecTwin-managed)
rather than attempting real execution -- that's expected, not a bug.
"""

import uuid

from fastapi.testclient import TestClient

from database.models.asset import Asset
from database.models.recommendation import Recommendation
from database.models.twin import Twin
from database.models.vulnerability import Vulnerability
from database.session import SessionLocal
from main import app

client = TestClient(app)


def _make_vulnerability_recommendation_and_twin():
    db = SessionLocal()
    try:
        asset = Asset(name="test-host", asset_type="server")
        db.add(asset)
        db.commit()
        db.refresh(asset)

        vulnerability = Vulnerability(
            asset_id=asset.id,
            cve_id=f"CVE-TEST-{uuid.uuid4().hex[:8]}",
            title="Test vulnerability",
        )
        db.add(vulnerability)
        db.commit()
        db.refresh(vulnerability)

        recommendation = Recommendation(
            vulnerability_id=vulnerability.id,
            recommendation_type="patch",
            title="Upgrade",
            content="Upgrade to the fixed version.",
        )
        db.add(recommendation)
        db.commit()
        db.refresh(recommendation)

        twin = Twin(
            asset_id=asset.id,
            name="test-twin",
            provider="docker",
            status="running",
        )
        db.add(twin)
        db.commit()
        db.refresh(twin)

        return vulnerability.id, recommendation.id, twin.id
    finally:
        db.close()


def test_remediation_create_persists_target_twin_id():
    vulnerability_id, recommendation_id, twin_id = (
        _make_vulnerability_recommendation_and_twin()
    )

    response = client.post(
        "/remediations/",
        json={
            "vulnerability_id": vulnerability_id,
            "recommendation_id": recommendation_id,
            "target_twin_id": twin_id,
            "action": "Replace twin with fixed image",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["target_twin_id"] == twin_id
    assert body["execution_authorized"] is False
    assert body["target_modified"] is False
    assert body["executor"] is None
    assert body["handler"] is None


def test_remediation_create_without_target_twin_id_still_works():
    """Backward compatibility: target_twin_id is nullable at the schema
    level -- only the (future) execution layer refuses to run without it.
    """

    vulnerability_id, _, _ = _make_vulnerability_recommendation_and_twin()

    response = client.post(
        "/remediations/",
        json={
            "vulnerability_id": vulnerability_id,
            "action": "Manual review required",
        },
    )

    assert response.status_code == 200
    assert response.json()["target_twin_id"] is None


def test_approval_create_persists_full_traceability_chain():
    vulnerability_id, recommendation_id, twin_id = (
        _make_vulnerability_recommendation_and_twin()
    )

    response = client.post(
        "/approvals/",
        json={
            "vulnerability_id": vulnerability_id,
            "recommendation_id": recommendation_id,
            "target_twin_id": twin_id,
            "fixed_version": "5.17.6",
            "requested_action": "apply_patch",
            "requested_by": "security-analyst",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["recommendation_id"] == recommendation_id
    assert body["target_twin_id"] == twin_id
    assert body["remediation_id"] is None  # not yet linked to a remediation
    assert body["status"] == "pending"


def test_approval_decision_still_works_after_schema_change():
    """Note: as of Phase 5, workflow.request_approval() requires
    target_twin_id and fixed_version -- this test now provides both,
    since an approval with neither is no longer a valid request (the
    whole point of this project's remediation work is that every
    approval is traceable to a specific twin and a specific version)."""

    vulnerability_id, _, twin_id = _make_vulnerability_recommendation_and_twin()

    created = client.post(
        "/approvals/",
        json={
            "vulnerability_id": vulnerability_id,
            "target_twin_id": twin_id,
            "fixed_version": "5.17.6",
            "requested_action": "apply_patch",
        },
    )
    approval_id = created.json()["id"]

    response = client.patch(
        f"/approvals/{approval_id}/decision",
        json={"status": "approved", "decided_by": "security-lead"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "approved"
    assert body["decided_by"] == "security-lead"
    assert body["remediation_id"] is not None  # approval creates a Remediation row now
