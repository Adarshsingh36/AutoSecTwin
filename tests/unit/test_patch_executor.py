"""
Tests for PatchExecutor. Runs against a real in-memory SQLite DB (so the
precondition queries against Twin/Vulnerability/Approval/Remediation are
exercised for real); the handler itself is mocked so these tests verify
PatchExecutor's own control flow, not DockerPatchHandler's (covered
separately in test_docker_patch_handler.py).
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock

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
from database.models.remediation import Remediation
from database.models.twin import Twin
from database.models.vulnerability import Vulnerability
from services.remediation import status as remediation_status
from services.remediation.handlers.base import PartialRemediationFailure, PatchResult
from services.remediation.patch_executor import PatchExecutor


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


def _seed(db, *, twin_provider="TwinGenerator", twin_status="ready", environment="docker",
          approve=True, with_recommendation=True, asset_mismatch=False, twin_image="autosectwin/activemq:5.17.3"):
    asset = Asset(name="activemq-host", asset_type="server")
    db.add(asset)
    db.commit()
    db.refresh(asset)

    other_asset = Asset(name="other-host", asset_type="server")
    db.add(other_asset)
    db.commit()
    db.refresh(other_asset)

    vulnerability = Vulnerability(
        asset_id=asset.id, cve_id="CVE-2023-46604", title="ActiveMQ OpenWire RCE"
    )
    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)

    twin = Twin(
        asset_id=other_asset.id if asset_mismatch else asset.id,
        name="twin-activemq",
        provider=twin_provider,
        status=twin_status,
        environment=environment,
        external_twin_id=100,
        external_uuid="uuid-100",
        twin_image=twin_image,
        health="healthy",
    )
    db.add(twin)
    db.commit()
    db.refresh(twin)

    recommendation = None
    if with_recommendation:
        recommendation = Recommendation(
            vulnerability_id=vulnerability.id,
            recommendation_type="patch",
            title="Upgrade ActiveMQ",
            content="Upgrade to 5.17.6",
        )
        db.add(recommendation)
        db.commit()
        db.refresh(recommendation)

    remediation = Remediation(
        vulnerability_id=vulnerability.id,
        recommendation_id=recommendation.id if recommendation else None,
        target_twin_id=twin.id,
        action="Upgrade ActiveMQ to 5.17.6",
    )
    db.add(remediation)
    db.commit()
    db.refresh(remediation)

    if approve:
        approval = Approval(
            vulnerability_id=vulnerability.id,
            recommendation_id=recommendation.id if recommendation else None,
            target_twin_id=twin.id,
            remediation_id=remediation.id,
            requested_action="apply_patch",
            status="approved",
            context={"fixed_version": "5.17.6"},
        )
        db.add(approval)
        db.commit()
        db.add(approval)
        db.commit()

    return remediation, twin, vulnerability


def _mock_handlers(result=None, raises=None):
    handler = AsyncMock()
    if raises:
        handler.apply.side_effect = raises
    else:
        handler.apply.return_value = result
    return {"docker": handler}, handler


@pytest.mark.asyncio
async def test_successful_execution_updates_remediation(db):
    remediation, twin, vulnerability = _seed(db)
    new_result = PatchResult(
        target_modified=True,
        healthy=True,
        old_twin_id=twin.id,
        new_twin_id=999,
        old_image="autosectwin/activemq:5.17.3",
        new_image="apache/activemq-classic:5.17.6",
        old_version="5.17.3",
        new_version="5.17.6",
    )
    handlers, handler = _mock_handlers(result=new_result)

    executor = PatchExecutor(db, handlers=handlers)
    updated = await executor.execute(remediation.id, fixed_version="5.17.6")

    assert updated.status == remediation_status.EXECUTED
    assert updated.target_modified is True
    assert updated.target_twin_id == 999  # repointed to the new twin
    assert updated.execution_authorized is True
    assert updated.executor == "PatchExecutor"
    assert updated.handler == handler.__class__.__name__ or isinstance(updated.handler, str)
    assert updated.evidence["new_image"] == "apache/activemq-classic:5.17.6"
    assert updated.execution_started_at is not None
    assert updated.execution_completed_at is not None


@pytest.mark.asyncio
async def test_missing_target_twin_id_requires_manual_action(db):
    remediation, twin, vulnerability = _seed(db)
    remediation.target_twin_id = None
    db.commit()

    handlers, handler = _mock_handlers(result=None)
    executor = PatchExecutor(db, handlers=handlers)
    updated = await executor.execute(remediation.id, fixed_version="5.17.6")

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert updated.target_modified is False
    assert "target_twin_id" in updated.evidence["manual_action_reason"]
    handler.apply.assert_not_called()


@pytest.mark.asyncio
async def test_unmanaged_twin_requires_manual_action(db):
    remediation, twin, vulnerability = _seed(db, twin_provider="SomeoneElsesTool")

    handlers, handler = _mock_handlers(result=None)
    executor = PatchExecutor(db, handlers=handlers)
    updated = await executor.execute(remediation.id, fixed_version="5.17.6")

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert "not managed" in updated.evidence["manual_action_reason"]
    handler.apply.assert_not_called()


@pytest.mark.asyncio
async def test_already_destroyed_twin_requires_manual_action(db):
    remediation, twin, vulnerability = _seed(db, twin_status="destroyed")

    handlers, handler = _mock_handlers(result=None)
    executor = PatchExecutor(db, handlers=handlers)
    updated = await executor.execute(remediation.id, fixed_version="5.17.6")

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert "already been destroyed" in updated.evidence["manual_action_reason"]


@pytest.mark.asyncio
async def test_asset_mismatch_requires_manual_action(db):
    remediation, twin, vulnerability = _seed(db, asset_mismatch=True)

    handlers, handler = _mock_handlers(result=None)
    executor = PatchExecutor(db, handlers=handlers)
    updated = await executor.execute(remediation.id, fixed_version="5.17.6")

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert "does not match" in updated.evidence["manual_action_reason"]


@pytest.mark.asyncio
async def test_same_version_requires_manual_action(db):
    remediation, twin, vulnerability = _seed(db, twin_image="autosectwin/activemq:5.17.3")

    handlers, handler = _mock_handlers(result=None)
    executor = PatchExecutor(db, handlers=handlers)
    updated = await executor.execute(remediation.id, fixed_version="5.17.3")  # same as current

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert "nothing to remediate" in updated.evidence["manual_action_reason"]


@pytest.mark.asyncio
async def test_no_approval_requires_manual_action(db):
    remediation, twin, vulnerability = _seed(db, approve=False)

    handlers, handler = _mock_handlers(result=None)
    executor = PatchExecutor(db, handlers=handlers)
    updated = await executor.execute(remediation.id, fixed_version="5.17.6")

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert "no approved Approval" in updated.evidence["manual_action_reason"]
    handler.apply.assert_not_called()


@pytest.mark.asyncio
async def test_no_recommendation_requires_manual_action(db):
    remediation, twin, vulnerability = _seed(db, with_recommendation=False)

    handlers, handler = _mock_handlers(result=None)
    executor = PatchExecutor(db, handlers=handlers)
    updated = await executor.execute(remediation.id, fixed_version="5.17.6")

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert "no backing recommendation_id" in updated.evidence["manual_action_reason"]


@pytest.mark.asyncio
async def test_unsupported_environment_requires_manual_action(db):
    remediation, twin, vulnerability = _seed(db, environment="vm")

    handlers, handler = _mock_handlers(result=None)
    executor = PatchExecutor(db, handlers=handlers)
    updated = await executor.execute(remediation.id, fixed_version="5.17.6")

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    assert "No remediation handler" in updated.evidence["manual_action_reason"]


@pytest.mark.asyncio
async def test_handler_failure_marks_failed_not_manual_action(db):
    """A failure DURING execution (infrastructure problem) is distinct
    from a precondition failure -- it means FAILED, not
    MANUAL_ACTION_REQUIRED, since the setup itself was fine."""
    remediation, twin, vulnerability = _seed(db)

    handlers, handler = _mock_handlers(raises=RuntimeError("Docker daemon unreachable"))
    executor = PatchExecutor(db, handlers=handlers)
    updated = await executor.execute(remediation.id, fixed_version="5.17.6")

    assert updated.status == remediation_status.FAILED
    assert updated.target_modified is False
    assert "Docker daemon unreachable" in updated.evidence["error"]
    # Preconditions passed, so execution WAS authorized and attempted.
    assert updated.execution_authorized is True


@pytest.mark.asyncio
async def test_version_mismatch_blocks_target_update(db):
    remediation, twin, vulnerability = _seed(db)
    new_result = PatchResult(
        target_modified=True,
        healthy=True,
        old_twin_id=twin.id,
        new_twin_id=999,
        old_image="autosectwin/activemq:5.17.3",
        new_image="apache/activemq-classic:5.17.5",
        old_version="5.17.3",
        new_version="5.17.5",
        old_endpoint="172.18.0.5:61616",
        new_endpoint="172.18.0.9:61616",
        old_container_id="old-uuid-123",
        new_container_id="new-uuid-456",
    )
    handlers, handler = _mock_handlers(result=new_result)
    executor = PatchExecutor(db, handlers=handlers)

    updated = await executor.execute(remediation.id, fixed_version="5.17.6")

    assert updated.status == remediation_status.FAILED
    assert updated.target_modified is True
    assert updated.target_twin_id is None
    assert "version" in updated.evidence["error"].lower()
    assert updated.evidence["partial_failure"] is True
    assert updated.evidence["replacement_ready"] is False
    assert updated.evidence["old_twin_id"] == twin.id
    assert updated.evidence["replacement_twin_id"] == 999
    assert updated.evidence["approved_fixed_version"] == "5.17.6"
    assert updated.evidence["actual_version"] == "5.17.5"


@pytest.mark.asyncio
async def test_partial_failure_after_destroy_keeps_target_modified_true(db):
    remediation, twin, vulnerability = _seed(db)
    handlers, handler = _mock_handlers(result=None)
    handler.apply.side_effect = PartialRemediationFailure(
        "Replacement provisioning failed after original twin was destroyed.",
        target_modified=True,
        old_twin_id=twin.id,
        new_twin_id=None,
        evidence={"partial_failure": True, "replacement_ready": False},
    )
    executor = PatchExecutor(db, handlers=handlers)

    updated = await executor.execute(remediation.id, fixed_version="5.17.6")

    assert updated.status == remediation_status.FAILED
    assert updated.target_modified is True
    assert updated.target_twin_id is None
    assert updated.evidence["partial_failure"] is True


@pytest.mark.asyncio
async def test_empty_fixed_version_requires_manual_action(db):
    remediation, twin, vulnerability = _seed(db)

    handlers, handler = _mock_handlers(result=None)
    executor = PatchExecutor(db, handlers=handlers)
    updated = await executor.execute(remediation.id, fixed_version="")

    assert updated.status == remediation_status.MANUAL_ACTION_REQUIRED
    handler.apply.assert_not_called()


@pytest.mark.asyncio
async def test_remediation_not_found_raises():
    from services.remediation.patch_executor import RemediationExecutionError

    db = TestingSessionLocal()
    Base.metadata.create_all(bind=engine)
    try:
        executor = PatchExecutor(db, handlers={})
        with pytest.raises(RemediationExecutionError):
            await executor.execute(999999, fixed_version="5.17.6")
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
