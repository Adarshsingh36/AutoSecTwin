"""
Tests for the closed-loop technical report: data gathering
(closed_loop_report_service.build_closed_loop_report), the 15-section
structure, and HTML/PDF rendering not crashing on real data shapes.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from database.base import Base
from database.models.approval import Approval
from database.models.asset import Asset
from database.models.exploit import Exploit
from database.models.recommendation import Recommendation
from database.models.remediation import Remediation
from database.models.twin import Twin
from database.models.validation import Validation
from database.models.vulnerability import Vulnerability
from services.reporting.closed_loop_report_service import build_closed_loop_report
from services.reporting.cve_knowledge import get_cve_technical_explanation
from services.reporting.report_generator import ReportGenerator
from services.remediation import status as remediation_status

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    future=True,
)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture
def db():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def _seed_full_chain(db):
    """Build a complete, realistic chain: vulnerability -> exploit ->
    initial validation -> recommendation -> approval -> remediation
    (verified, with old/new twin) -> revalidation."""

    asset = Asset(name="activemq-prod-mirror", asset_type="server")
    db.add(asset)
    db.commit()
    db.refresh(asset)

    vulnerability = Vulnerability(
        asset_id=asset.id,
        cve_id="CVE-2023-46604",
        title="Apache ActiveMQ OpenWire RCE",
        cvss_score=9.8,
        epss_score=0.94,
        severity="CRITICAL",
        kev_listed=True,
        exploitability_probability=0.91,
        threat_intelligence_score=0.88,
    )
    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)

    exploit = Exploit(
        vulnerability_id=vulnerability.id,
        source="metasploit",
        module_name="multi/misc/apache_activemq_rce_cve_2023_46604",
        title="ActiveMQ OpenWire RCE",
        reliability_score=0.9,
    )
    db.add(exploit)
    db.commit()
    db.refresh(exploit)

    old_twin = Twin(
        asset_id=asset.id,
        name="twin-activemq-vulnerable",
        provider="TwinGenerator",
        status="destroyed",
        environment="docker",
        twin_image="autosectwin/activemq:5.17.3",
        ip_address="172.18.0.5",
        network="twin-net-abc",
        health="healthy",
    )
    db.add(old_twin)
    db.commit()
    db.refresh(old_twin)

    new_twin = Twin(
        asset_id=asset.id,
        name="twin-activemq-fixed",
        provider="TwinGenerator",
        status="ready",
        environment="docker",
        twin_image="apache/activemq-classic:5.17.6",
        ip_address="172.18.0.9",
        network="twin-net-def",
        health="healthy",
    )
    db.add(new_twin)
    db.commit()
    db.refresh(new_twin)

    initial_validation = Validation(
        vulnerability_id=vulnerability.id,
        exploit_id=exploit.id,
        twin_id=old_twin.id,
        status="validated",
        validation_score=0.8,
        phase="initial",
        analysis="Validation status=validated; marker_hits=3; score=0.800",
        evidence={
            "module_type": "exploit",
            "module_name": "multi/misc/apache_activemq_rce_cve_2023_46604",
            "target": "172.18.0.5:61616",
            "exit_code": 0,
            "markers": ["shell_opened", "callback_received", "proof_obtained", "version_confirmed"],
            "session_id": 1,
            "session_type": "meterpreter",
            "execution_outcome": "session_established",
            "user": "root",
            "hostname": "twin-activemq-vulnerable",
            "operating_system": "Linux twin-activemq 5.15.0 x86_64",
            "architecture": "x64",
            "working_directory": "/opt/activemq",
            "detected_version": "5.17.3",
            "stdout": "[*] Started reverse TCP handler\n[*] Meterpreter session 1 opened\n",
            "stderr": "",
        },
    )
    db.add(initial_validation)
    db.commit()
    db.refresh(initial_validation)

    recommendation = Recommendation(
        vulnerability_id=vulnerability.id,
        recommendation_type="patch",
        title="Upgrade Apache ActiveMQ to 5.17.6",
        content="Upgrade the broker to 5.17.6 or later, which removes the unsafe class instantiation path.",
        provider="rule_based",
    )
    db.add(recommendation)
    db.commit()
    db.refresh(recommendation)

    approval = Approval(
        vulnerability_id=vulnerability.id,
        recommendation_id=recommendation.id,
        target_twin_id=old_twin.id,
        requested_action="apply_patch",
        requested_by="security-analyst",
        status="approved",
        decided_by="security-lead",
        decision_reason="Fixed version confirmed available in registry.",
        decided_at=datetime.now(timezone.utc),
        context={"fixed_version": "5.17.6", "review_package": {"limitations": ["Example limitation note."]}},
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)

    revalidation = Validation(
        vulnerability_id=vulnerability.id,
        exploit_id=exploit.id,
        twin_id=new_twin.id,
        status="failed",
        validation_score=0.0,
        phase="revalidation",
        analysis="Validation status=failed; marker_hits=0; score=0.000; execution_outcome=confirmed_no_session",
        evidence={
            "execution_outcome": "confirmed_no_session",
            "detected_version": "5.17.6",
            "markers": [],
            "stderr": "Exploit completed, but no session was created.",
        },
    )
    db.add(revalidation)
    db.commit()
    db.refresh(revalidation)

    remediation = Remediation(
        vulnerability_id=vulnerability.id,
        recommendation_id=recommendation.id,
        target_twin_id=new_twin.id,
        action="Upgrade to 5.17.6",
        status=remediation_status.VERIFIED,
        executor="PatchExecutor",
        handler="DockerPatchHandler",
        execution_authorized=True,
        target_modified=True,
        verification_score=0.0,
        execution_started_at=datetime.now(timezone.utc),
        execution_completed_at=datetime.now(timezone.utc),
        verified_at=datetime.now(timezone.utc),
        evidence={
            "old_twin_id": old_twin.id,
            "new_twin_id": new_twin.id,
            "old_image": "autosectwin/activemq:5.17.3",
            "new_image": "apache/activemq-classic:5.17.6",
            "old_version": "5.17.3",
            "new_version": "5.17.6",
            "before_after": {
                "before": {
                    "twin_id": old_twin.id, "version": "5.17.3", "validation_id": initial_validation.id,
                    "status": "validated", "validation_score": 0.8, "exploit_result": "successful",
                },
                "after": {
                    "twin_id": new_twin.id, "version": "5.17.6", "validation_id": revalidation.id,
                    "status": "not_exploitable", "validation_score": 0.0, "exploit_result": "not_exploitable",
                },
                "resolved": True,
            },
            "revalidation_comparison": "Initial score: 0.80 -> Post-remediation score: 0.00 (improvement=0.80). Result: RESOLVED",
        },
    )
    db.add(remediation)
    db.commit()
    db.refresh(remediation)

    approval.remediation_id = remediation.id
    db.commit()

    return remediation


# ---------------------------------------------------------
# CVE knowledge
# ---------------------------------------------------------


def test_known_cve_returns_real_attack_chain():
    explanation = get_cve_technical_explanation("CVE-2023-46604")
    assert explanation["available"] is True
    assert "OpenWire" in explanation["affected_component"]
    assert any("ClassPathXmlApplicationContext" in step for step in explanation["attack_chain"])


def test_unknown_cve_is_honest_about_missing_data():
    explanation = get_cve_technical_explanation("CVE-9999-00000")
    assert explanation["available"] is False
    assert "does not have a curated technical explanation" in explanation["note"]


# ---------------------------------------------------------
# build_closed_loop_report
# ---------------------------------------------------------


def test_build_closed_loop_report_has_all_15_sections(db):
    remediation = _seed_full_chain(db)

    content = build_closed_loop_report(db, remediation.id)
    body = json.loads(content)

    expected_sections = [
        "1_executive_summary", "2_system_under_test", "3_vulnerability_technical_analysis",
        "4_detection_pipeline", "5_exploit_technical_execution", "6_evidence_collected",
        "7_validation_engine", "8_recommendation", "9_human_approval",
        "10_remediation_execution", "11_revalidation", "12_before_vs_after",
        "13_final_security_state", "14_limitations", "15_technical_appendix",
    ]
    for section in expected_sections:
        assert section in body, f"missing section {section}"


def test_report_pulls_real_evidence_not_fabricated(db):
    remediation = _seed_full_chain(db)

    content = build_closed_loop_report(db, remediation.id)
    body = json.loads(content)

    evidence = body["6_evidence_collected"]
    assert evidence["user"] == "root"
    assert evidence["hostname"] == "twin-activemq-vulnerable"
    assert evidence["shell_established"] is True

    appendix = body["15_technical_appendix"]["database_ids"]
    assert appendix["vulnerability_id"] is not None
    assert appendix["remediation_id"] == remediation.id


def test_report_final_state_reflects_resolved(db):
    remediation = _seed_full_chain(db)

    content = build_closed_loop_report(db, remediation.id)
    body = json.loads(content)

    assert body["13_final_security_state"]["resolved"] is True
    assert body["12_before_vs_after"]["resolved"] is True
    assert body["12_before_vs_after"]["after"]["status"] == "not_exploitable"


def test_report_includes_audit_trail_from_real_timestamps(db):
    remediation = _seed_full_chain(db)

    content = build_closed_loop_report(db, remediation.id)
    body = json.loads(content)

    audit_trail = body["15_technical_appendix"]["audit_trail"]
    assert len(audit_trail) > 0
    event_names = [e["event"] for e in audit_trail]
    assert "Approval decided" in event_names
    assert "Remediation execution completed" in event_names


def test_build_closed_loop_report_raises_for_missing_remediation(db):
    with pytest.raises(ValueError, match="not found"):
        build_closed_loop_report(db, 999999)


# ---------------------------------------------------------
# Rendering
# ---------------------------------------------------------


def test_render_html_does_not_crash_and_contains_key_evidence(db):
    remediation = _seed_full_chain(db)
    content = build_closed_loop_report(db, remediation.id)

    html = ReportGenerator().render_html(content, title="Test Report")

    assert "<html" in html
    assert "root" in html  # the evidenced user
    assert "ClassPathXmlApplicationContext" in html  # CVE technical explanation present
    assert "Resolved: True" in html


def test_render_pdf_does_not_crash_and_produces_bytes(db):
    remediation = _seed_full_chain(db)
    content = build_closed_loop_report(db, remediation.id)

    pdf_bytes = ReportGenerator().render_pdf(content, title="Test Report")

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes[:4] == b"%PDF"
    assert len(pdf_bytes) > 1000


def test_render_html_mock_mode_banner_only_when_simulated(db):
    remediation = _seed_full_chain(db)
    content = build_closed_loop_report(db, remediation.id)

    html = ReportGenerator().render_html(content)

    # Seeded evidence has no "simulated": true anywhere, so the banner DIV
    # itself must not render (the CSS class definition is always present
    # in <style>, so we check for the div tag specifically, not the
    # substring "mock-banner" which would always match).
    assert '<div class="mock-banner">' not in html
