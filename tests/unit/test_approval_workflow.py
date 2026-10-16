"""
Tests for services/approval/workflow.py against a real in-memory DB.
"""

import json
import sys
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
from database.models.recommendation import Recommendation
from database.models.report import Report
from database.models.remediation import Remediation
from database.models.twin import Twin
from database.models.validation import Validation
from database.models.vulnerability import Vulnerability
from services.approval import workflow
from services.approval.workflow import ApprovalWorkflowError
from services.approval.response_parser import interpret_human_response
from services.remediation import status as remediation_status
from services.reporting.workflow_report_service import create_approval_decision_report

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


def _seed(db, with_initial_validation=True):
    asset = Asset(name="activemq-host", asset_type="server")
    db.add(asset)
    db.commit()
    db.refresh(asset)

    vulnerability = Vulnerability(asset_id=asset.id, cve_id="CVE-2023-46604", title="ActiveMQ RCE")
    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)

    twin = Twin(
        asset_id=asset.id,
        name="twin-activemq",
        provider="TwinGenerator",
        status="ready",
        environment="docker",
        twin_image="autosectwin/activemq:5.17.3",
    )
    db.add(twin)
    db.commit()
    db.refresh(twin)

    recommendation = Recommendation(
        vulnerability_id=vulnerability.id,
        recommendation_type="patch",
        title="Upgrade ActiveMQ",
        content="Upgrade to 5.17.6",
    )
    db.add(recommendation)
    db.commit()
    db.refresh(recommendation)

    if with_initial_validation:
        validation = Validation(
            vulnerability_id=vulnerability.id,
            exploit_id=None,
            twin_id=twin.id,
            status="validated",
            validation_score=0.8,
            phase="initial",
            evidence={"execution_outcome": "session_established"},
        )
        db.add(validation)
        db.commit()

    return vulnerability, twin, recommendation


# ---------------------------------------------------------
# build_review_package
# ---------------------------------------------------------


def test_build_review_package_includes_all_required_fields(db):
    vulnerability, twin, recommendation = _seed(db)

    package = workflow.build_review_package(
        db,
        vulnerability_id=vulnerability.id,
        target_twin_id=twin.id,
        fixed_version="5.17.6",
        recommendation_id=recommendation.id,
    )

    assert package.cve_id == "CVE-2023-46604"
    assert package.target_twin_name == "twin-activemq"
    assert package.current_version == "5.17.3"
    assert package.fixed_version == "5.17.6"
    assert package.recommendation_title == "Upgrade ActiveMQ"
    assert package.validation_status == "validated"
    assert package.validation_score == 0.8
    assert package.exploit_evidence == {"execution_outcome": "session_established"}


def test_build_review_package_notes_missing_validation_as_limitation(db):
    vulnerability, twin, recommendation = _seed(db, with_initial_validation=False)

    package = workflow.build_review_package(
        db,
        vulnerability_id=vulnerability.id,
        target_twin_id=twin.id,
        fixed_version="5.17.6",
    )

    assert any("No initial validation" in limitation for limitation in package.limitations)


def test_build_review_package_requires_target_twin_id(db):
    vulnerability, twin, recommendation = _seed(db)

    with pytest.raises(ApprovalWorkflowError, match="target_twin_id"):
        workflow.build_review_package(
            db, vulnerability_id=vulnerability.id, target_twin_id=None, fixed_version="5.17.6"
        )


def test_build_review_package_requires_fixed_version(db):
    vulnerability, twin, recommendation = _seed(db)

    with pytest.raises(ApprovalWorkflowError, match="fixed_version"):
        workflow.build_review_package(
            db, vulnerability_id=vulnerability.id, target_twin_id=twin.id, fixed_version=""
        )


# ---------------------------------------------------------
# request_approval / decide
# ---------------------------------------------------------


def test_request_approval_attaches_review_package_to_context(db):
    vulnerability, twin, recommendation = _seed(db)

    approval = workflow.request_approval(
        db,
        vulnerability_id=vulnerability.id,
        target_twin_id=twin.id,
        fixed_version="5.17.6",
        recommendation_id=recommendation.id,
        requested_by="analyst",
    )

    assert approval.status == "pending"
    assert approval.context["fixed_version"] == "5.17.6"
    assert "review_package" in approval.context
    assert approval.context["review_package"]["cve_id"] == "CVE-2023-46604"


def test_decide_approved_creates_linked_remediation(db):
    vulnerability, twin, recommendation = _seed(db)
    approval = workflow.request_approval(
        db,
        vulnerability_id=vulnerability.id,
        target_twin_id=twin.id,
        fixed_version="5.17.6",
        recommendation_id=recommendation.id,
    )

    decided = workflow.decide(
        db, approval_id=approval.id, decision="approved", decided_by="security-lead"
    )

    assert decided.status == "approved"
    assert decided.remediation_id is not None

    remediation = db.query(Remediation).filter(Remediation.id == decided.remediation_id).first()
    assert remediation is not None
    assert remediation.status == remediation_status.APPROVED
    assert remediation.target_twin_id == twin.id
    assert remediation.recommendation_id == recommendation.id
    assert remediation.vulnerability_id == vulnerability.id


def test_decide_rejected_never_creates_remediation(db):
    vulnerability, twin, recommendation = _seed(db)
    approval = workflow.request_approval(
        db,
        vulnerability_id=vulnerability.id,
        target_twin_id=twin.id,
        fixed_version="5.17.6",
        recommendation_id=recommendation.id,
    )

    decided = workflow.decide(
        db,
        approval_id=approval.id,
        decision="rejected",
        decided_by="security-lead",
        decision_reason="Fixed version not yet validated internally.",
    )

    assert decided.status == "rejected"
    assert decided.remediation_id is None

    remediation_count = db.query(Remediation).count()
    assert remediation_count == 0

    report = create_approval_decision_report(db, decided)
    content = json.loads(report.content)
    assert content["findings"]["human_decision"]["status"] == "rejected"
    assert "remains unresolved" in content["findings"]["outcome"]
    assert db.query(Report).filter(Report.id == report.id).count() == 1


def test_decide_already_decided_approval_raises(db):
    vulnerability, twin, recommendation = _seed(db)
    approval = workflow.request_approval(
        db, vulnerability_id=vulnerability.id, target_twin_id=twin.id, fixed_version="5.17.6"
    )
    workflow.decide(db, approval_id=approval.id, decision="approved", decided_by="lead-1")

    with pytest.raises(ApprovalWorkflowError, match="already been decided"):
        workflow.decide(db, approval_id=approval.id, decision="rejected", decided_by="lead-2")


def test_decide_invalid_status_raises(db):
    vulnerability, twin, recommendation = _seed(db)
    approval = workflow.request_approval(
        db, vulnerability_id=vulnerability.id, target_twin_id=twin.id, fixed_version="5.17.6"
    )

    with pytest.raises(ApprovalWorkflowError, match="approved.*rejected"):
        workflow.decide(db, approval_id=approval.id, decision="maybe", decided_by="lead")


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("Yes, proceed with the recommendation.", "approved"),
        ("I approve because the report supports these changes.", "approved"),
        ("No, leave the finding unresolved.", "rejected"),
        ("I do not approve because the impact is unverified.", "rejected"),
        ("Please change the proposal to restrict FTP access.", "revision_requested"),
        ("I need more information.", "unclear"),
    ],
)
def test_interpret_human_response(response, expected):
    assert interpret_human_response(response) == expected
