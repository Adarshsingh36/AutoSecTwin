import io
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.base import Base
from database.models.report import Report
from services.reporting.report_generator import ReportGenerator


def test_render_html_from_closed_loop_report():
    generator = ReportGenerator()
    content = generator.generate_closed_loop_report(
        title="AutoSecTwin Closed-Loop Report: CVE-2017-0144",
        vulnerability=type("V", (), {"cve_id": "CVE-2017-0144", "cvss_score": 9.8, "epss_score": 0.9, "kev_listed": True, "description": "SMB RCE", "asset": None})(),
        twin=type("T", (), {"id": 1, "environment": "docker", "ip_address": "10.0.0.5", "twin_image": "img", "health": "healthy", "status": "ready"})(),
        exploit=type("E", (), {"module_name": "windows/smb/ms17_010_eternalblue"})(),
        initial_validation=type("Val", (), {"status": "validated", "validation_score": 0.8, "analysis": "ok", "evidence": {}})(),
        remediation=type("R", (), {"action": "patch", "status": "verified", "applied_at": None, "verification_score": 0.05})(),
        revalidation=type("Rv", (), {"status": "failed", "validation_score": 0.0})(),
        revalidation_comparison="Initial score: 0.80 -> Post-remediation score: 0.00. Result: RESOLVED",
        final_status="remediated",
        audit_trail=[{"action": "workflow_started", "entity_type": "vulnerability", "entity_id": 1, "details": {}, "created_at": None}],
        exploitability_probability=0.91,
        mock_mode=True,
    )

    html = generator.render_html(content)

    assert "<html" in html
    assert "CVE-2017-0144" in html
    assert "remediated" in html
    assert "RESOLVED" in html
    # No raw JSON braces should leak into the top-level page structure --
    # nested structures render as tables/lists, not a giant text dump.
    assert "<table>" in html


def test_render_html_handles_malformed_json_gracefully():
    generator = ReportGenerator()
    html = generator.render_html("not valid json {{{")
    assert "<html" in html
    assert "not valid json" in html


def test_render_pdf_produces_a_real_parseable_pdf():
    """Renders an actual PDF (reportlab, pure Python -- no system deps)
    and verifies it with an independent parser (pypdf) rather than just
    checking the bytes start with %PDF, to prove the document is genuinely
    well-formed and the report content actually made it into the pages.
    """

    from pypdf import PdfReader

    generator = ReportGenerator()
    content = generator.generate_closed_loop_report(
        title="AutoSecTwin Closed-Loop Report: CVE-2017-0144",
        vulnerability=type("V", (), {"cve_id": "CVE-2017-0144", "cvss_score": 9.8, "epss_score": 0.9, "kev_listed": True, "description": "SMB RCE", "asset": None})(),
        twin=type("T", (), {"id": 1, "environment": "docker", "ip_address": "10.0.0.5", "twin_image": "img", "health": "healthy", "status": "ready"})(),
        exploit=type("E", (), {"module_name": "windows/smb/ms17_010_eternalblue"})(),
        initial_validation=type("Val", (), {"status": "validated", "validation_score": 0.8, "analysis": "ok", "evidence": {}})(),
        remediation=type("R", (), {"action": "patch", "status": "verified", "applied_at": None, "verification_score": 0.05})(),
        revalidation=type("Rv", (), {"status": "failed", "validation_score": 0.0})(),
        revalidation_comparison="Initial score: 0.80 -> Post-remediation score: 0.00. Result: RESOLVED",
        final_status="remediated",
        audit_trail=[{"action": "workflow_started", "entity_type": "vulnerability", "entity_id": 1, "details": {}, "created_at": None}],
        exploitability_probability=0.91,
        mock_mode=True,
    )

    pdf_bytes = generator.render_pdf(content)

    assert pdf_bytes.startswith(b"%PDF")

    reader = PdfReader(io.BytesIO(pdf_bytes))
    assert len(reader.pages) >= 1

    full_text = "\n".join(page.extract_text() for page in reader.pages)
    assert "CVE-2017-0144" in full_text
    assert "RESOLVED" in full_text
    assert "remediated" in full_text


def test_render_pdf_handles_empty_and_malformed_content():
    generator = ReportGenerator()

    empty_pdf = generator.render_pdf(json.dumps({"title": "Empty Report"}))
    assert empty_pdf.startswith(b"%PDF")

    malformed_pdf = generator.render_pdf("not valid json {{{")
    assert malformed_pdf.startswith(b"%PDF")


@pytest.fixture()
def client_with_report(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine)

    import database.session as db_session_module
    monkeypatch.setattr(db_session_module, "SessionLocal", TestSession)

    from api.dependencies import get_db
    from main import app

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    db = TestSession()
    content = json.dumps({"title": "Test Report", "report_type": "technical", "summary": "A summary", "findings": {"cve": "CVE-2017-0144"}})
    report = Report(report_type="technical", title="Test Report", content=content, format="json")
    db.add(report)
    db.commit()
    db.refresh(report)
    report_id = report.id
    db.close()

    yield TestClient(app), report_id

    app.dependency_overrides.clear()


def test_report_html_endpoint_renders_page(client_with_report):
    client, report_id = client_with_report

    response = client.get(f"/reports/{report_id}/html")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Test Report" in response.text
    assert "CVE-2017-0144" in response.text


def test_report_html_endpoint_404_for_missing_report(client_with_report):
    client, _ = client_with_report

    response = client.get("/reports/999999/html")

    assert response.status_code == 404


def test_report_pdf_endpoint_downloads_real_pdf(client_with_report):
    from pypdf import PdfReader

    client, report_id = client_with_report

    response = client.get(f"/reports/{report_id}/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "attachment" in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF")

    reader = PdfReader(io.BytesIO(response.content))
    full_text = "\n".join(page.extract_text() for page in reader.pages)
    assert "CVE-2017-0144" in full_text


def test_report_pdf_endpoint_404_for_missing_report(client_with_report):
    client, _ = client_with_report

    response = client.get("/reports/999999/pdf")

    assert response.status_code == 404
