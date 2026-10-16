from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.base import Base
from database.models.asset import Asset
from database.models.exploit import Exploit
from database.models.vulnerability import Vulnerability
from services.orchestration.closed_loop_orchestrator import (
    ClosedLoopOrchestrationError,
    ClosedLoopOrchestrator,
)


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _seed_vulnerability(db, with_exploit: bool = True) -> Vulnerability:
    asset = Asset(
        name="Legacy File Server",
        asset_type="Server",
        hostname="fileserver01",
        software="Windows Server",
        version="2008 R2",
        environment="production",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    vulnerability = Vulnerability(
        asset_id=asset.id,
        cve_id="CVE-2017-0144",
        title="EternalBlue SMB RCE",
        description="Remote code execution in SMBv1",
        cvss_score=9.8,
        epss_score=0.94,
        severity="CRITICAL",
        kev_listed=True,
        metadata_json={"epss_percentile": 0.99},
    )
    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)

    if with_exploit:
        db.add(
            Exploit(
                vulnerability_id=vulnerability.id,
                source="metasploit",
                module_name="windows/smb/ms17_010_eternalblue",
                title="MS17-010 EternalBlue",
                reliability_score=0.9,
                requires_auth=False,
                metadata_json={"module_type": "exploit"},
            )
        )
        db.commit()

    return vulnerability


class _ProvisioningStub:
    async def provision(self, vulnerability_id, ttl_seconds=None):
        return SimpleNamespace(
            id=23,
            name="test-twin",
            provider="test",
            status="running",
            endpoint=None,
        )

    async def wait_until_ready(self, twin):
        return twin


class _ValidationStub:
    def __init__(self, status="validated", ready=True, reasons=None):
        self.status = status
        self.ready = ready
        self.reasons = reasons or []

    async def validate(self, db, exploit, twin):
        return SimpleNamespace(
            validation=SimpleNamespace(
                id=41,
                vulnerability_id=exploit.vulnerability_id,
                phase="initial",
                status=self.status,
                validation_score=0.9,
                analysis="test validation result",
                evidence={
                    "execution_outcome": (
                        "session_established"
                        if self.status == "validated"
                        else "confirmed_no_session"
                    ),
                    "session_id": "test-session" if self.status == "validated" else None,
                },
            ),
            readiness=SimpleNamespace(ready=self.ready, reasons=self.reasons),
        )


class _RecommendationStub:
    def __init__(self):
        self.calls = []

    def generate(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(
            id=57,
            title="Upgrade vulnerable product",
            content="Upgrade to a vendor-fixed release.",
            provider="test",
        )


def _make_orchestrator(db, validation=None, recommendation=None):
    recommendation = recommendation or _RecommendationStub()
    orchestrator = ClosedLoopOrchestrator(
        db,
        provisioning_service=_ProvisioningStub(),
        validation_orchestrator=validation or _ValidationStub(),
        recommendation_engine=recommendation,
    )
    return orchestrator, recommendation


@pytest.mark.asyncio
async def test_validated_ready_run_generates_recommendation(db_session):
    vulnerability = _seed_vulnerability(db_session)
    orchestrator, recommendation = _make_orchestrator(db_session)

    summary = await orchestrator.run(vulnerability.id, ttl_seconds=60)

    assert summary["validation_status"] == "validated"
    assert summary["validation_score"] == 0.9
    assert summary["next_step"] == "awaiting_human_review"
    assert summary["recommendation_id"] == 57
    assert summary["report_id"] is not None
    assert summary["approval_id"] is not None
    assert summary["review_url"] == f"/approvals/{summary['approval_id']}/review"
    assert recommendation.calls == [
        {
            "vulnerability_id": vulnerability.id,
            "recommendation_type": "patch",
        }
    ]


@pytest.mark.asyncio
async def test_validated_run_with_fixed_version_requests_approval(db_session, monkeypatch):
    from services.orchestration import closed_loop_orchestrator

    vulnerability = _seed_vulnerability(db_session)
    requested = {}
    approval_stub = SimpleNamespace(
        id=68,
        status="pending",
        requested_action="apply_patch",
        context={"review_package": {}},
    )

    def fake_request_approval(db, **kwargs):
        requested.update(kwargs)
        return approval_stub

    monkeypatch.setattr(closed_loop_orchestrator, "request_approval", fake_request_approval)
    orchestrator, _ = _make_orchestrator(db_session)

    summary = await orchestrator.run(vulnerability.id, fixed_version=" 5.17.6 ")

    assert summary["next_step"] == "awaiting_human_approval"
    assert summary["approval_id"] == 68
    assert requested["fixed_version"] == "5.17.6"
    assert approval_stub.context["report_id"] == summary["report_id"]
    assert approval_stub.context["review_package"]["report_id"] == summary["report_id"]


@pytest.mark.asyncio
async def test_run_stops_when_no_exploit_is_mapped(db_session):
    vulnerability = _seed_vulnerability(db_session, with_exploit=False)
    orchestrator, _ = _make_orchestrator(db_session)

    with pytest.raises(ClosedLoopOrchestrationError, match="No Exploit is mapped"):
        await orchestrator.run(vulnerability.id)


@pytest.mark.asyncio
async def test_run_stops_when_readiness_gate_fails(db_session):
    vulnerability = _seed_vulnerability(db_session)
    validation = _ValidationStub(
        status="inconclusive",
        ready=False,
        reasons=["required target option is missing"],
    )
    orchestrator, recommendation = _make_orchestrator(db_session, validation)

    summary = await orchestrator.run(vulnerability.id)

    assert summary["next_step"] == "not_ready_for_execution"
    assert summary["readiness_reasons"] == ["required target option is missing"]
    assert recommendation.calls == []


@pytest.mark.asyncio
async def test_unvalidated_run_does_not_generate_recommendation(db_session):
    vulnerability = _seed_vulnerability(db_session)
    validation = _ValidationStub(status="failed")
    orchestrator, recommendation = _make_orchestrator(db_session, validation)

    summary = await orchestrator.run(vulnerability.id)

    assert summary["next_step"] == "not_validated_no_recommendation_generated"
    assert "recommendation_id" not in summary
    assert recommendation.calls == []
