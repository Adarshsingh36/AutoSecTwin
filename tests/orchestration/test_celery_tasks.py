import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.config import settings
from database.base import Base
from database.models.asset import Asset
from database.models.exploit import Exploit
from database.models.orchestration_job import OrchestrationJob
from database.models.vulnerability import Vulnerability


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def mock_mode_enabled(monkeypatch):
    monkeypatch.setattr(settings, "MOCK_MODE", True)
    monkeypatch.setattr(settings, "TWIN_HEALTH_TIMEOUT_SECONDS", 5.0)
    monkeypatch.setattr(settings, "TWIN_HEALTH_POLL_INTERVAL_SECONDS", 0.01)
    yield


def _seed_vulnerability(db) -> Vulnerability:
    asset = Asset(name="Test Asset", asset_type="Server", hostname="host1")
    db.add(asset)
    db.commit()

    vuln = Vulnerability(
        asset_id=asset.id,
        cve_id="CVE-2017-0144",
        title="EternalBlue",
        severity="CRITICAL",
        cvss_score=9.8,
        epss_score=0.9,
        kev_listed=True,
        metadata_json={"epss_percentile": 0.9},
    )
    db.add(vuln)
    db.commit()

    exploit = Exploit(
        vulnerability_id=vuln.id,
        source="metasploit",
        module_name="windows/smb/ms17_010_eternalblue",
        title="MS17-010",
        reliability_score=0.9,
        requires_auth=False,
    )
    db.add(exploit)
    db.commit()
    return vuln


def test_celery_task_runs_closed_loop_synchronously_in_eager_mode(db_session, monkeypatch):
    """Exercises the real Celery task (not a stand-in) with
    task_always_eager so it executes in-process without needing a live
    Redis broker/worker -- proving the task itself is wired correctly.
    """

    from services.tasks.celery_app import celery_app
    from services.tasks.orchestration_tasks import run_closed_loop_job

    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True

    # The task opens its own session via database.session.SessionLocal;
    # point that at our in-memory test database instead of Postgres.
    import database.session as db_session_module
    from sqlalchemy.orm import sessionmaker

    TestSessionLocal = sessionmaker(bind=db_session.get_bind())
    monkeypatch.setattr(db_session_module, "SessionLocal", TestSessionLocal)
    monkeypatch.setattr("services.tasks.orchestration_tasks.SessionLocal", TestSessionLocal)

    vulnerability = _seed_vulnerability(db_session)
    job = OrchestrationJob(job_id="celery-eager-1", vulnerability_id=vulnerability.id)
    db_session.add(job)
    db_session.commit()

    async_result = run_closed_loop_job.delay(job.job_id)

    assert async_result.result["status"] == "completed"
    assert async_result.result["final_status"] in {"remediated", "still_vulnerable", "not_exploitable", "inconclusive"}

    db_session.refresh(job)
    assert job.status == "completed"
    assert job.progress == 100

    celery_app.conf.task_always_eager = False
    celery_app.conf.task_eager_propagates = False


def test_dispatch_falls_back_to_inline_when_celery_broker_unreachable(monkeypatch):
    """If TASK_QUEUE_BACKEND=celery but .delay() raises (broker down), the
    route must fall back to BackgroundTasks rather than losing the job."""

    from fastapi import BackgroundTasks

    from api.routes.orchestration import _dispatch

    monkeypatch.setattr(settings, "TASK_QUEUE_BACKEND", "celery")

    class _BrokenDelay:
        def delay(self, job_id):
            raise ConnectionRefusedError("no broker reachable")

    monkeypatch.setattr(
        "services.tasks.orchestration_tasks.run_closed_loop_job",
        _BrokenDelay(),
        raising=False,
    )

    import sys
    import types

    fake_module = types.ModuleType("services.tasks.orchestration_tasks")
    fake_module.run_closed_loop_job = _BrokenDelay()
    monkeypatch.setitem(sys.modules, "services.tasks.orchestration_tasks", fake_module)

    background_tasks = BackgroundTasks()
    job = OrchestrationJob(job_id="fallback-1", vulnerability_id=1)

    backend = _dispatch(job, background_tasks, db=None)

    assert backend == "inline"
    assert len(background_tasks.tasks) == 1


def test_dispatch_uses_celery_when_backend_configured_and_reachable(monkeypatch):
    """When Celery dispatch succeeds, the route must not also schedule the
    inline fallback (that would run the workflow twice)."""

    from fastapi import BackgroundTasks

    from api.routes.orchestration import _dispatch

    monkeypatch.setattr(settings, "TASK_QUEUE_BACKEND", "celery")

    calls = []

    class _WorkingDelay:
        def delay(self, job_id):
            calls.append(job_id)

    import sys
    import types

    fake_module = types.ModuleType("services.tasks.orchestration_tasks")
    fake_module.run_closed_loop_job = _WorkingDelay()
    monkeypatch.setitem(sys.modules, "services.tasks.orchestration_tasks", fake_module)

    background_tasks = BackgroundTasks()
    job = OrchestrationJob(job_id="celery-ok-1", vulnerability_id=1)

    backend = _dispatch(job, background_tasks, db=None)

    assert backend == "celery"
    assert calls == ["celery-ok-1"]
    assert len(background_tasks.tasks) == 0


def test_dispatch_uses_inline_when_backend_set_to_inline(monkeypatch):
    from fastapi import BackgroundTasks

    from api.routes.orchestration import _dispatch

    monkeypatch.setattr(settings, "TASK_QUEUE_BACKEND", "inline")

    background_tasks = BackgroundTasks()
    job = OrchestrationJob(job_id="inline-1", vulnerability_id=1)

    backend = _dispatch(job, background_tasks, db=None)

    assert backend == "inline"
    assert len(background_tasks.tasks) == 1
