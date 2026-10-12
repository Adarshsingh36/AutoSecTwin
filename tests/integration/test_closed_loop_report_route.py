"""
Integration test for POST /reports/closed-loop/{remediation_id}, and that
its output renders via the EXISTING generic GET /reports/{id}/html and
GET /reports/{id}/pdf routes -- confirming no second report generator or
render path was created.
"""

import uuid

from fastapi.testclient import TestClient

from database.models.asset import Asset
from database.models.remediation import Remediation
from database.models.vulnerability import Vulnerability
from database.session import SessionLocal
from main import app
from services.remediation import status as remediation_status

client = TestClient(app)


def _seed_minimal_remediation():
    db = SessionLocal()
    try:
        asset = Asset(name="test-host", asset_type="server")
        db.add(asset)
        db.commit()
        db.refresh(asset)

        vulnerability = Vulnerability(
            asset_id=asset.id,
            cve_id=f"CVE-2023-46604-{uuid.uuid4().hex[:6]}",
            title="ActiveMQ RCE",
        )
        db.add(vulnerability)
        db.commit()
        db.refresh(vulnerability)

        remediation = Remediation(
            vulnerability_id=vulnerability.id,
            action="Upgrade to 5.17.6",
            status=remediation_status.PLANNED,
        )
        db.add(remediation)
        db.commit()
        db.refresh(remediation)

        return remediation.id
    finally:
        db.close()


def test_create_closed_loop_report_for_missing_remediation_returns_404():
    response = client.post("/reports/closed-loop/999999")
    assert response.status_code == 404


def test_create_closed_loop_report_and_render_html_and_pdf():
    remediation_id = _seed_minimal_remediation()

    create_response = client.post(f"/reports/closed-loop/{remediation_id}")
    assert create_response.status_code == 200
    report = create_response.json()
    assert report["report_type"] == "closed_loop"
    report_id = report["id"]

    html_response = client.get(f"/reports/{report_id}/html")
    assert html_response.status_code == 200
    assert "<html" in html_response.text

    pdf_response = client.get(f"/reports/{report_id}/pdf")
    assert pdf_response.status_code == 200
    assert pdf_response.content[:4] == b"%PDF"
