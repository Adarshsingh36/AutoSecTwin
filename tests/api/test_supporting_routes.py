from database.models.asset import Asset
from database.models.vulnerability import Vulnerability


def _seed_vulnerability(db) -> Vulnerability:
    asset = Asset(name="Test Asset", asset_type="Server", hostname="host1")
    db.add(asset)
    db.commit()

    vuln = Vulnerability(asset_id=asset.id, cve_id="CVE-2017-0144", title="EternalBlue", severity="CRITICAL", cvss_score=9.8)
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


# ---------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------


def test_approval_create_decide_and_list(client, db):
    vuln = _seed_vulnerability(db)

    create_resp = client.post(
        "/approvals/",
        json={"vulnerability_id": vuln.id, "requested_action": "apply_remediation", "requested_by": "analyst1"},
    )
    assert create_resp.status_code == 200, create_resp.text
    approval_id = create_resp.json()["id"]
    assert create_resp.json()["status"] == "pending"

    decide_resp = client.patch(
        f"/approvals/{approval_id}/decision",
        json={"status": "approved", "decided_by": "manager1", "decision_reason": "Looks safe."},
    )
    assert decide_resp.status_code == 200
    assert decide_resp.json()["status"] == "approved"
    assert decide_resp.json()["decided_by"] == "manager1"

    list_resp = client.get("/approvals/")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1


def test_approval_decide_404_for_missing_id(client):
    response = client.patch(
        "/approvals/999999/decision",
        json={"status": "approved", "decided_by": "manager1"},
    )
    assert response.status_code == 404


def test_approvals_legacy_and_hallucination_queues_start_empty(client):
    assert client.get("/approvals/legacy").json() == []
    assert client.get("/approvals/hallucinations").json() == []


# ---------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------


def test_confidence_calculate_does_not_persist(client, db):
    response = client.post(
        "/confidence/calculate",
        json={
            "vulnerability_id": 1,
            "exploitability_probability": 0.9,
            "validation_score": 0.8,
            "exposure_score": 0.7,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert 0.0 <= body["confidence"] <= 1.0
    assert round(sum(body["weights"].values()), 6) == 1.0

    from database.models.confidence import Confidence

    assert db.query(Confidence).count() == 0


def test_confidence_create_persists_and_lists(client, db):
    vuln = _seed_vulnerability(db)

    response = client.post(
        "/confidence/",
        json={"vulnerability_id": vuln.id, "exploitability_probability": 0.9, "validation_score": 0.85},
    )

    assert response.status_code == 200, response.text
    assert response.json()["vulnerability_id"] == vuln.id

    list_resp = client.get("/confidence/")
    assert len(list_resp.json()) == 1


# ---------------------------------------------------------------------
# Learning
# ---------------------------------------------------------------------


def test_learning_event_create_and_list(client):
    response = client.post(
        "/learning/",
        json={
            "event_type": "closed_loop_outcome",
            "source": "test",
            "label": "validated",
            "confidence_before": 0.9,
            "confidence_after": 0.1,
            "payload": {"cve_id": "CVE-2017-0144"},
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["event_type"] == "closed_loop_outcome"

    list_resp = client.get("/learning/")
    assert len(list_resp.json()) == 1


# ---------------------------------------------------------------------
# Recommendation
# ---------------------------------------------------------------------


def test_recommendation_generate_patch_type(client, db):
    vuln = _seed_vulnerability(db)

    response = client.post(
        "/recommendation/generate",
        json={"vulnerability_id": vuln.id, "recommendation_type": "patch", "context": {"vendor": "Microsoft"}},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["vulnerability_id"] == vuln.id
    assert "Microsoft" in body["content"]


# ---------------------------------------------------------------------
# Trust
# ---------------------------------------------------------------------


def test_trust_compare_and_statistics(client, db):
    vuln = _seed_vulnerability(db)

    compare_resp = client.post(
        "/trust/compare",
        json={"vulnerability_id": vuln.id, "prediction_score": 0.9, "validation_score": 0.85},
    )
    assert compare_resp.status_code == 200, compare_resp.text
    body = compare_resp.json()
    assert body["agreement"] is True
    assert body["hallucination"] is False

    stats_resp = client.get("/trust/statistics")
    assert stats_resp.status_code == 200
    assert stats_resp.json()["total_comparisons"] == 1

    drift_resp = client.get("/trust/drift")
    assert drift_resp.status_code == 200
    assert isinstance(drift_resp.json(), list)


def test_trust_compare_detects_hallucination_on_large_gap(client, db):
    vuln = _seed_vulnerability(db)

    response = client.post(
        "/trust/compare",
        json={"vulnerability_id": vuln.id, "prediction_score": 0.95, "validation_score": 0.05},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["agreement"] is False
    assert body["hallucination"] is True


# ---------------------------------------------------------------------
# Legacy profiling
# ---------------------------------------------------------------------


def test_legacy_profile_create_and_fetch(client, db):
    create_resp = client.post(
        "/legacy/profile",
        json={"vendor": "Microsoft", "product": "Windows Server", "version": "2008 R2"},
    )

    assert create_resp.status_code == 200, create_resp.text
    body = create_resp.json()
    assert body["vendor"].lower() == "microsoft"
    assert isinstance(body["compensating_controls"], list)

    get_resp = client.get(f"/legacy/{body['id']}")
    assert get_resp.status_code == 200
    assert get_resp.json()["product"].lower() == "windows server"


def test_legacy_profile_404_for_missing_id(client):
    response = client.get("/legacy/999999")
    assert response.status_code == 404
