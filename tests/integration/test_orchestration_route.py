"""
Integration tests for POST /orchestration/run and GET /orchestration/jobs.

Runs with MOCK_MODE + TASK_QUEUE_BACKEND=inline so no live Docker,
Digital Twin Generator, Metasploit RPC, or Redis is required -- this
verifies the orchestration wiring itself (routing, job persistence,
status transitions), not the real infrastructure integrations, which are
covered separately once those pieces are real (Phase 3 onward).
"""

import time
import uuid

from fastapi.testclient import TestClient

from core.config import settings
from database.models.asset import Asset
from database.models.exploit import Exploit
from database.models.vulnerability import Vulnerability
from database.session import SessionLocal
from main import app

client = TestClient(app)


def _make_vulnerability_with_exploit(db) -> Vulnerability:
    asset = Asset(
        name="test-activemq-host",
        asset_type="server",
        hostname="activemq-test",
        software="ActiveMQ",
        version="5.17.3",
        environment="docker",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    # cve_id is unique -- suffix it so repeated calls across tests (and
    # across test runs against the same sqlite file) never collide.
    unique_cve_id = f"CVE-2023-46604-{uuid.uuid4().hex[:8]}"

    vulnerability = Vulnerability(
        asset_id=asset.id,
        cve_id=unique_cve_id,
        title="Apache ActiveMQ OpenWire RCE",
        cvss_score=9.8,
        severity="CRITICAL",
    )
    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)

    exploit = Exploit(
        vulnerability_id=vulnerability.id,
        source="metasploit",
        module_name="exploit/multi/misc/apache_activemq_rce_cve_2023_46604",
        title="Apache ActiveMQ OpenWire RCE",
        reliability_score=0.9,
    )
    db.add(exploit)
    db.commit()

    return vulnerability


def test_run_orchestration_for_missing_vulnerability_returns_404():
    response = client.post("/orchestration/run", json={"vulnerability_id": 999999})
    assert response.status_code == 404


def test_run_orchestration_happy_path_completes_via_inline_dispatch():
    assert settings.MOCK_MODE is True, "This test requires MOCK_MODE=true"

    db = SessionLocal()
    try:
        vulnerability = _make_vulnerability_with_exploit(db)
        vulnerability_id = vulnerability.id
    finally:
        db.close()

    response = client.post(
        "/orchestration/run", json={"vulnerability_id": vulnerability_id}
    )
    assert response.status_code == 202
    body = response.json()
    # Under an async backend (inline BackgroundTasks, or a real Celery
    # worker) the job is still "queued" when this response is returned.
    # Under Celery's eager mode (CELERY_TASK_ALWAYS_EAGER=true, used by
    # this test suite when TASK_QUEUE_BACKEND=celery) the task runs
    # synchronously inside .delay() itself, so it may already be
    # "completed" by the time we get a response. Both are correct --
    # only the timing differs.
    assert body["status"] in ("queued", "running", "completed")
    assert body["vulnerability_id"] == vulnerability_id
    job_id = body["id"]

    # Inline BackgroundTasks execute after the response is sent, in the
    # same test process -- poll briefly for completion rather than assume
    # it's instantaneous.
    deadline = time.monotonic() + 10
    final_body = None
    while time.monotonic() < deadline:
        status_response = client.get(f"/orchestration/jobs/{job_id}")
        assert status_response.status_code == 200
        final_body = status_response.json()
        if final_body["status"] in ("completed", "failed"):
            break
        time.sleep(0.2)

    assert final_body is not None
    assert final_body["status"] == "completed", final_body.get("error_message")
    assert final_body["dispatch_backend"] == "inline"
    summary = final_body["result_summary"]
    assert summary["vulnerability_id"] == vulnerability_id
    assert summary["twin_id"] is not None
    assert summary["exploit_id"] is not None
    assert summary["validation_id"] is not None
    assert summary["next_step"] in (
        "awaiting_human_approval",
        "not_validated_no_recommendation_generated",
    )


def test_get_missing_orchestration_job_returns_404():
    response = client.get("/orchestration/jobs/999999")
    assert response.status_code == 404


def test_list_orchestration_jobs_filters_by_vulnerability():
    db = SessionLocal()
    try:
        vulnerability = _make_vulnerability_with_exploit(db)
        vulnerability_id = vulnerability.id
    finally:
        db.close()

    client.post("/orchestration/run", json={"vulnerability_id": vulnerability_id})

    response = client.get(
        "/orchestration/jobs", params={"vulnerability_id": vulnerability_id}
    )
    assert response.status_code == 200
    jobs = response.json()
    assert len(jobs) >= 1
    assert all(job["vulnerability_id"] == vulnerability_id for job in jobs)
