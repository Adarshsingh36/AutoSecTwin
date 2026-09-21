import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.base import Base
from database.models.asset import Asset
from database.models.exploit import Exploit
from database.models.orchestration_job import OrchestrationJob
from database.models.report import Report
from database.models.validation import Validation
from database.models.vulnerability import Vulnerability

from core.config import settings
from services.orchestration.closed_loop_orchestrator import ClosedLoopOrchestrator, OrchestrationError


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


@pytest.fixture(autouse=True)
def mock_mode_enabled(monkeypatch):
    """Force MOCK_MODE for the duration of each test so no real Metasploit
    RPC daemon or Digital Twin Generator is required."""

    monkeypatch.setattr(settings, "MOCK_MODE", True)
    monkeypatch.setattr(settings, "TWIN_HEALTH_TIMEOUT_SECONDS", 5.0)
    monkeypatch.setattr(settings, "TWIN_HEALTH_POLL_INTERVAL_SECONDS", 0.01)
    yield


class _StubPredictor:
    """Deterministic exploitability predictor for orchestrator tests."""

    def __init__(self, probability: float = 0.93):
        self.probability = probability

    def predict(self, vulnerability):
        return self.probability


class _FailingPredictor:
    def predict(self, vulnerability):
        raise RuntimeError("model artifact corrupted")


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
        exploit = Exploit(
            vulnerability_id=vulnerability.id,
            source="metasploit",
            module_name="windows/smb/ms17_010_eternalblue",
            title="MS17-010 EternalBlue",
            reliability_score=0.9,
            requires_auth=False,
            metadata_json={"module_type": "exploit"},
        )
        db.add(exploit)
        db.commit()

    return vulnerability


def _make_job(db, vulnerability_id: int) -> OrchestrationJob:
    job = OrchestrationJob(job_id="test-job-1", vulnerability_id=vulnerability_id)
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


@pytest.mark.asyncio
async def test_closed_loop_end_to_end_resolves_after_remediation(db_session):
    """The full acceptance-test scenario from the spec: a vulnerability is
    predicted exploitable, validated against a twin, remediated, and the
    revalidation shows it is no longer exploitable.
    """

    vulnerability = _seed_vulnerability(db_session)
    job = _make_job(db_session, vulnerability.id)

    orchestrator = ClosedLoopOrchestrator(predictor=_StubPredictor(0.93))
    result = await orchestrator.run(db_session, job)

    db_session.refresh(job)

    assert job.status == "completed"
    assert job.stage == "completed"
    assert job.progress == 100

    assert result.exploitability_probability == pytest.approx(0.93)
    assert result.summary["initial_validation_status"] == "validated"
    assert result.summary["remediation_status"] == "verified"
    assert result.summary["revalidation_result"] == "resolved"
    assert result.final_status == "remediated"

    # Both the initial and post-remediation validation rows must be persisted
    # (evidence-driven, not overwritten in place).
    validations = db_session.query(Validation).filter(Validation.vulnerability_id == vulnerability.id).all()
    phases = {v.phase for v in validations}
    assert phases == {"initial", "revalidation"}

    initial = next(v for v in validations if v.phase == "initial")
    revalidated = next(v for v in validations if v.phase == "revalidation")
    assert initial.status == "validated"
    assert revalidated.status != "validated"
    assert revalidated.validation_score < initial.validation_score

    # A closed-loop report must have been generated and persisted from the
    # actual database rows.
    report = db_session.query(Report).filter(Report.vulnerability_id == vulnerability.id).first()
    assert report is not None
    assert '"final_status": "remediated"' in report.content
    assert vulnerability.cve_id in report.content


@pytest.mark.asyncio
async def test_closed_loop_stops_cleanly_when_model_fails(db_session):
    """Exploitability model failures must fail the job cleanly, not crash
    the process or fabricate a heuristic score."""

    vulnerability = _seed_vulnerability(db_session)
    job = _make_job(db_session, vulnerability.id)

    orchestrator = ClosedLoopOrchestrator(predictor=_FailingPredictor())

    with pytest.raises(OrchestrationError):
        await orchestrator.run(db_session, job)

    db_session.refresh(job)
    assert job.status == "failed"
    assert job.stage == "assessment"
    assert "model artifact corrupted" in job.error


@pytest.mark.asyncio
async def test_closed_loop_stops_when_no_exploit_candidate_exists(db_session):
    """Without a mapped, Metasploit-ready exploit the loop must not proceed
    to twin provisioning or execution."""

    vulnerability = _seed_vulnerability(db_session, with_exploit=False)
    job = _make_job(db_session, vulnerability.id)

    orchestrator = ClosedLoopOrchestrator(predictor=_StubPredictor(0.8))

    with pytest.raises(OrchestrationError) as exc_info:
        await orchestrator.run(db_session, job)

    assert exc_info.value.stage == "exploit_selection"

    db_session.refresh(job)
    assert job.status == "failed"
    assert job.stage == "exploit_selection"


@pytest.mark.asyncio
async def test_closed_loop_skips_remediation_when_not_validated(db_session, monkeypatch):
    """If the controlled validation is inconclusive/failed, remediation and
    revalidation must be skipped rather than acting on an unconfirmed
    finding."""

    from services.validation.validation_engine import ValidationEngine

    vulnerability = _seed_vulnerability(db_session)
    job = _make_job(db_session, vulnerability.id)

    # Force the validation engine to always report "failed" regardless of
    # the simulated Metasploit evidence, to exercise the skip branch.
    monkeypatch.setattr(
        ValidationEngine,
        "analyze",
        lambda self, evidence: ("failed", 0.1, "forced failure for test"),
    )

    orchestrator = ClosedLoopOrchestrator(predictor=_StubPredictor(0.8))
    result = await orchestrator.run(db_session, job)

    assert result.summary["initial_validation_status"] == "failed"
    assert result.remediation_id is None
    assert result.revalidation_id is None
    assert result.final_status == "not_exploitable"
