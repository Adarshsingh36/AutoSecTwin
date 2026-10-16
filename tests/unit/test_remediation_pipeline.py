"""
Tests for services/remediation/pipeline.py. PatchExecutor and
RevalidationEngine are patched at the pipeline module level (both are
already covered by their own dedicated test files); these tests verify
the pipeline's own control flow and state transitions against a real
in-memory DB.
"""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from database.base import Base
from database.models.asset import Asset
from database.models.exploit import Exploit
from database.models.remediation import Remediation
from database.models.twin import Twin
from database.models.validation import Validation
from database.models.vulnerability import Vulnerability
from services.remediation import status as remediation_status
from services.remediation import tasks as remediation_tasks
from services.remediation.pipeline import run_remediation_pipeline, run_revalidation_only
from services.revalidation.revalidation_engine import RevalidationSummary

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


def _seed(db, with_initial_validation=True, with_exploit=True):
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
        name="twin-fixed",
        provider="TwinGenerator",
        status="ready",
        environment="docker",
        twin_image="apache/activemq-classic:5.17.6",
    )
    db.add(twin)
    db.commit()
    db.refresh(twin)

    exploit = None
    if with_exploit:
        exploit = Exploit(
            vulnerability_id=vulnerability.id,
            source="metasploit",
            module_name="multi/misc/apache_activemq_rce_cve_2023_46604",
            title="ActiveMQ OpenWire RCE",
        )
        db.add(exploit)
        db.commit()
        db.refresh(exploit)

    if with_initial_validation:
        initial_validation = Validation(
            vulnerability_id=vulnerability.id,
            exploit_id=exploit.id if exploit else None,
            twin_id=1,
            status="validated",
            validation_score=0.8,
            phase="initial",
            evidence={"execution_outcome": "session_established", "detected_version": "5.17.3"},
        )
        db.add(initial_validation)
        db.commit()

    remediation = Remediation(
        vulnerability_id=vulnerability.id,
        target_twin_id=twin.id,
        action="Upgrade to 5.17.6",
        status=remediation_status.EXECUTED,
    )
    db.add(remediation)
    db.commit()
    db.refresh(remediation)

    return vulnerability, twin, remediation


def _revalidation_row(db, vulnerability_id, twin_id, status, score, execution_outcome):
    row = Validation(
        vulnerability_id=vulnerability_id,
        twin_id=twin_id,
        status=status,
        validation_score=score,
        phase="revalidation",
        evidence={"execution_outcome": execution_outcome},
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


# ---------------------------------------------------------
# run_revalidation_only
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_revalidation_resolved_marks_verified(db):
    vulnerability, twin, remediation = _seed(db)
    revalidation_row = _revalidation_row(
        db, vulnerability.id, twin.id, "failed", 0.0, "confirmed_no_session"
    )

    summary = RevalidationSummary(
        result="resolved",
        initial_validation=SimpleNamespace(),
        revalidation=revalidation_row,
        initial_score=0.8,
        revalidation_score=0.0,
        improvement=0.8,
        comparison="resolved",
    )

    with patch("services.remediation.pipeline.RevalidationEngine") as MockEngine:
        MockEngine.return_value.run = AsyncMock(return_value=summary)
        updated = await run_revalidation_only(db, remediation.id)

    assert updated.status == remediation_status.VERIFIED
    assert updated.verified_at is not None
    assert updated.evidence["before_after"]["resolved"] is True


@pytest.mark.asyncio
async def test_revalidation_still_vulnerable_marks_failed(db):
    vulnerability, twin, remediation = _seed(db)
    revalidation_row = _revalidation_row(
        db, vulnerability.id, twin.id, "validated", 0.8, "session_established"
    )

    summary = RevalidationSummary(
        result="still_vulnerable",
        initial_validation=SimpleNamespace(),
        revalidation=revalidation_row,
        initial_score=0.8,
        revalidation_score=0.8,
        improvement=0.0,
        comparison="still vulnerable",
    )

    with patch("services.remediation.pipeline.RevalidationEngine") as MockEngine:
        MockEngine.return_value.run = AsyncMock(return_value=summary)
        updated = await run_revalidation_only(db, remediation.id)

    assert updated.status == remediation_status.FAILED
    assert updated.verified_at is None


@pytest.mark.asyncio
async def test_revalidation_inconclusive_requires_manual_action(db):
    vulnerability, twin, remediation = _seed(db)
    revalidation_row = _revalidation_row(
        db, vulnerability.id, twin.id, "inconclusive", 0.0, "timeout_inconclusive"
    )

    summary = RevalidationSummary(
        result="inconclusive",
        initial_validation=SimpleNamespace(),
        revalidation=revalidation_row,
        initial_score=0.8,
        revalidation_score=0.0,
        improvement=0.8,
        comparison="inconclusive",
    )

    with patch("services.remediation.pipeline.RevalidationEngine") as MockEngine:
        MockEngine.return_value.run = AsyncMock(return_value=summary)
        updated = await run_revalidation_only(db, remediation.id)

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert updated.status != remediation_status.VERIFIED  # never verified from an inconclusive result
    assert "inconclusive" in updated.evidence["manual_action_reason"].lower()


@pytest.mark.asyncio
async def test_revalidation_without_initial_validation_requires_manual_action(db):
    vulnerability, twin, remediation = _seed(db, with_initial_validation=False)

    updated = await run_revalidation_only(db, remediation.id)

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert "No initial validation" in updated.evidence["manual_action_reason"]


@pytest.mark.asyncio
async def test_revalidation_requires_ready_replacement_twin(db):
    vulnerability, twin, remediation = _seed(db)
    twin.status = "degraded"
    twin.health = "stale"
    db.commit()

    updated = await run_revalidation_only(db, remediation.id)

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert "ready" in updated.evidence["manual_action_reason"].lower()


@pytest.mark.asyncio
async def test_revalidation_without_exploit_requires_manual_action(db):
    vulnerability, twin, remediation = _seed(db, with_exploit=False)

    updated = await run_revalidation_only(db, remediation.id)

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert "exploit" in updated.evidence["manual_action_reason"].lower()


@pytest.mark.asyncio
async def test_revalidation_without_target_twin_requires_manual_action(db):
    vulnerability, twin, remediation = _seed(db)
    remediation.target_twin_id = None
    db.commit()

    updated = await run_revalidation_only(db, remediation.id)

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED


# ---------------------------------------------------------
# run_remediation_pipeline
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_pipeline_skips_revalidation_when_execution_not_executed(db):
    vulnerability, twin, remediation = _seed(db)

    failed_remediation = SimpleNamespace(id=remediation.id, status=remediation_status.FAILED)

    with patch("services.remediation.pipeline.PatchExecutor") as MockExecutor, patch(
        "services.remediation.pipeline.RevalidationEngine"
    ) as MockEngine:
        MockExecutor.return_value.execute = AsyncMock(return_value=failed_remediation)

        result = await run_remediation_pipeline(db, remediation.id, fixed_version="5.17.6")

    assert result.status == remediation_status.FAILED
    MockEngine.return_value.run.assert_not_called()


@pytest.mark.asyncio
async def test_pipeline_runs_revalidation_when_executed(db):
    vulnerability, twin, remediation = _seed(db)

    executed_remediation = SimpleNamespace(id=remediation.id, status=remediation_status.EXECUTED)
    revalidation_row = _revalidation_row(
        db, vulnerability.id, twin.id, "failed", 0.0, "confirmed_no_session"
    )
    summary = RevalidationSummary(
        result="resolved",
        initial_validation=SimpleNamespace(),
        revalidation=revalidation_row,
        initial_score=0.8,
        revalidation_score=0.0,
        improvement=0.8,
        comparison="resolved",
    )

    with patch("services.remediation.pipeline.PatchExecutor") as MockExecutor, patch(
        "services.remediation.pipeline.RevalidationEngine"
    ) as MockEngine:
        MockExecutor.return_value.execute = AsyncMock(return_value=executed_remediation)
        MockEngine.return_value.run = AsyncMock(return_value=summary)

        result = await run_remediation_pipeline(db, remediation.id, fixed_version="5.17.6")

    assert result.status == remediation_status.VERIFIED


@pytest.mark.asyncio
async def test_pipeline_with_run_revalidation_false_stops_after_execute(db):
    vulnerability, twin, remediation = _seed(db)
    executed_remediation = SimpleNamespace(id=remediation.id, status=remediation_status.EXECUTED)

    with patch("services.remediation.pipeline.PatchExecutor") as MockExecutor, patch(
        "services.remediation.pipeline.RevalidationEngine"
    ) as MockEngine:
        MockExecutor.return_value.execute = AsyncMock(return_value=executed_remediation)

        result = await run_remediation_pipeline(
            db, remediation.id, fixed_version="5.17.6", run_revalidation=False
        )

    assert result.status == remediation_status.EXECUTED
    MockEngine.return_value.run.assert_not_called()


def test_remediation_job_persists_final_report(db, monkeypatch):
    _, _, remediation = _seed(db)
    report_calls = []

    async def fake_pipeline(session, remediation_id, fixed_version, run_revalidation=True):
        return session.get(Remediation, remediation_id)

    monkeypatch.setattr(remediation_tasks, "run_remediation_pipeline", fake_pipeline)
    monkeypatch.setattr(
        remediation_tasks,
        "persist_closed_loop_report",
        lambda session, remediation_id: (
            report_calls.append(remediation_id) or SimpleNamespace(id=73)
        ),
    )

    remediation_tasks.execute_remediation_job(
        remediation.id,
        fixed_version="5.17.6",
        run_revalidation=True,
        db=db,
    )

    assert report_calls == [remediation.id]
    assert remediation.evidence["closed_loop_report_id"] == 73
