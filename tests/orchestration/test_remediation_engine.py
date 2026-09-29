from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.config import settings
from database.base import Base
from database.models.asset import Asset
from database.models.twin import Twin
from database.models.vulnerability import Vulnerability
from services.remediation.remediation_engine import RemediationEngine


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture()
def vulnerability(db_session):
    asset = Asset(name="Test Asset", asset_type="Server", hostname="host1")
    db_session.add(asset)
    db_session.commit()

    vuln = Vulnerability(
        asset_id=asset.id,
        cve_id="CVE-2017-0144",
        title="EternalBlue",
        severity="CRITICAL",
        cvss_score=9.8,
    )
    db_session.add(vuln)
    db_session.commit()
    return vuln


@pytest.fixture()
def twin(db_session):
    t = Twin(name="test-twin", provider="docker", external_twin_id="123", environment="docker", ip_address="10.0.0.5", status="ready", health="healthy")
    db_session.add(t)
    db_session.commit()
    return t


def test_remediation_lifecycle_recommend_plan_apply_mock_mode(db_session, vulnerability, twin, monkeypatch):
    monkeypatch.setattr(settings, "MOCK_MODE", True)

    engine = RemediationEngine()

    remediation = engine.recommend(db_session, vulnerability)
    assert remediation.status == "recommended"
    assert remediation.action

    remediation = engine.plan(db_session, remediation)
    assert remediation.status == "planned"

    remediation = engine.apply(db_session, remediation, twin)
    assert remediation.status == "applied"
    assert remediation.applied_at is not None
    assert remediation.evidence["simulated"] is True
    assert remediation.evidence["target_twin_id"] == twin.id


def test_remediation_apply_outside_mock_mode_does_not_fabricate_success(db_session, vulnerability, twin, monkeypatch):
    """Outside MOCK_MODE, without a config-management channel into the
    twin, the engine must not claim the remediation was actually applied."""

    monkeypatch.setattr(settings, "MOCK_MODE", False)

    engine = RemediationEngine()
    remediation = engine.recommend(db_session, vulnerability)
    remediation = engine.apply(db_session, remediation, twin)

    assert remediation.status == "planned"
    assert remediation.evidence["simulated"] is False


def test_remediation_mark_failed_and_verified(db_session, vulnerability, twin):
    engine = RemediationEngine()
    remediation = engine.recommend(db_session, vulnerability)

    failed = engine.mark_failed(db_session, remediation, "vulnerable service still reachable")
    assert failed.status == "failed"
    assert failed.evidence["failure_reason"] == "vulnerable service still reachable"

    verified = engine.mark_verified(db_session, remediation, verification_score=0.05)
    assert verified.status == "verified"
    assert verified.verification_score == pytest.approx(0.05)
    assert verified.verified_at is not None


def test_classify_remediation_type_uses_hint_or_falls_back():
    engine = RemediationEngine()

    hinted = SimpleNamespace(title="", description="", metadata_json={"remediation_type": "firewall_network_restriction"})
    assert engine.classify_remediation_type(hinted) == "firewall_network_restriction"

    credential_vuln = SimpleNamespace(title="Default credential exposure", description="", metadata_json=None)
    assert engine.classify_remediation_type(credential_vuln) == "credential_hardening"

    unknown = SimpleNamespace(title="Something else entirely", description="", metadata_json=None)
    assert engine.classify_remediation_type(unknown) == "patch_update"
