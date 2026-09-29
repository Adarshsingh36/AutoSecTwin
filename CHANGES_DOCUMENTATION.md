# AutoSecTwin — Closed-Loop Backend: Changed Files Documentation

This package contains **only** the files that were created or modified while
completing the AutoSecTwin backend (audit → closed-loop orchestrator →
remediation/revalidation → reporting → Celery → tests). It is meant to be
overlaid onto an existing clone of the original repository
(`https://github.com/Adarshsingh36/AutoSecTwin`) — copy these files over the
matching paths and you have the full working system.

The companion package (`AutoSecTwin-full-project.zip`) contains the entire
repository with these changes already applied, if you'd rather have a
complete working copy instead of a diff overlay.

---

## 1. Tech stack

| Layer | Technology |
|---|---|
| API framework | FastAPI (Python 3.12) |
| ORM / migrations | SQLAlchemy 2.0 + Alembic |
| Database | PostgreSQL (production) / SQLite (local dev & tests, via `DATABASE_URL_OVERRIDE`) |
| ML | XGBoost (pre-trained artifact, `ml/models/exploitability_xgb.joblib`), scikit-learn, joblib |
| Exploit orchestration | Metasploit RPC (MessagePack over HTTP) |
| Digital Twin | Twin Generator service (HTTP), consumed via `httpx` |
| Background jobs | Celery 5 + Redis (broker/result backend), with an automatic in-process `BackgroundTasks` fallback |
| Reporting | Native JSON, hand-rolled HTML renderer, PDF via `reportlab` (pure Python, no system deps) |
| Testing | pytest, pytest-asyncio, in-memory SQLite, `pypdf` (round-trip PDF verification) |

No new heavyweight infrastructure was introduced beyond what the spec
explicitly called for (Celery/Redis). Where infrastructure wasn't available
to verify in this sandbox (live Postgres, a live Metasploit RPC daemon, a
live Twin Generator, a live Redis broker), the code was built to *degrade
safely and observably* rather than pretend to work — see "Mock mode and
fallbacks" below.

---

## 2. Why each file changed — grouped by concern

### 2.1 Real bugs found by actually running the existing test suite

These aren't hypothetical fixes — each was caught by installing the
project's own dependencies and running `pytest`, then confirmed by reading
the code.

| File | Bug | Fix |
|---|---|---|
| `services/orchestration/exploit_readiness.py` | Duplicated, unused `from requests import options` import (dead code, adds an unnecessary dependency) | Removed |
| `services/orchestration/module_inspector.py` | `available=True` was hardcoded even when the Metasploit `module.info` RPC call raised — meaning a missing/unreachable module would silently pass the readiness gate | Wrapped in `try/except`; returns `available=False` with an empty option set on failure |
| `services/orchestration/validation_orchestrator.py` | `Validation` rows were constructed without `vulnerability_id`, which is a `NOT NULL` foreign key — every validation write would crash | Added `vulnerability_id=exploit.vulnerability_id` in both places `Validation(...)` is constructed |
| `database/models/legacy.py` | ORM declared `eol: Date` and `compensating_controls: Text`, but the actual Alembic migration (`0002_trust_legacy_extensions`) created them as `Boolean`/`JSON`, and `LegacyProfiler` writes a `bool`/`list` — every write crashed | Corrected column types to match the real schema and actual usage |
| `api/routes/twins.py` | Only exposed `POST /twins/{id}/destroy`; the project's own test (`tests/test_twin_provision.py`) expects `DELETE /twins/{id}` returning `{"status": ...}` | Added a `DELETE` route (kept the old `POST` route too, for backward compatibility), using the existing-but-unused `TwinDestroyResponse` schema |
| `integrations/digital_twin/twin_client.py` | Leftover debug `print()` statements; no way to poll twin health | Removed debug prints; added `get_twin_health()`; added mock mode (see below) |
| `requirements.txt` | `msgpack` is imported by `integrations/metasploit/rpc_client.py` but was never listed as a dependency | Added `msgpack==1.1.0` |
| `tests/unit/test_engines.py`, `tests/e2e/test_engine_flow.py` | Called a predictor signature (`predict(vuln, threat_score)`) and a feature-builder signature that no longer exist — the real `ExploitabilityPredictionEngine`/`FeatureEngineeringEngine` intentionally have no heuristic fallback (per the "no fake fallback" requirement) | Rewrote the tests to match the actual current API and assert against the real trained model |
| `api/routes/exploits.py` | `GET /exploits/` silently ignored a `vulnerability_id` filter — always returned every exploit | Added real query-param filtering |
| `.env.example` | Listed variable names (`DATABASE_URL`, `METASPLOIT_RPC_HOST`, `DIGITAL_TWIN_API_BASE_URL`, ...) that `core.config.Settings` never actually reads — silently ignored | Rewritten to match the real `Settings` fields, plus documentation of the new orchestration variables |

### 2.2 The closed-loop orchestrator (the core deliverable)

| File | Role |
|---|---|
| `services/orchestration/closed_loop_orchestrator.py` **(new)** | The central coordinator: `ClosedLoopOrchestrator.run(db, job)` walks vulnerability → exploitability prediction → exploit selection → twin provisioning → readiness wait → controlled validation → remediation → revalidation → report → learning feedback → twin cleanup, updating an `OrchestrationJob` row after every stage. Deliberately thin — it calls existing services rather than reimplementing their logic, per "use dedicated services with clear responsibilities, not one giant function." |
| `database/models/orchestration_job.py` **(new)** | Job-tracking row: `status` (queued/running/completed/failed/cancelled), `stage`, `progress`, `message`, `result_json`, `error`, timestamps, `queue_backend`. This is what makes `POST /orchestration/run` non-blocking and pollable. |
| `api/routes/orchestration.py` **(new)** | `POST /orchestration/run` (returns immediately with a job id), `GET /orchestration/{job_id}` (poll), `GET /orchestration/` (list). Dispatches to Celery by default, with automatic fallback to `BackgroundTasks` if the broker is unreachable (see 2.4). |
| `main.py` | Registered the new `orchestration` router. |
| `database/migrations/versions/0003_closed_loop_orchestration.py` **(new)** | Adds the `orchestration_jobs` table and a `phase` column on `validations` (see 2.3). |
| `database/migrations/versions/0004_orchestration_queue_backend.py` **(new)** | Adds `orchestration_jobs.queue_backend`, recording whether a given run actually executed via Celery or the inline fallback — for audit/debugging. |

### 2.3 Remediation & revalidation (previously disconnected stubs)

| File | What changed |
|---|---|
| `services/remediation/remediation_engine.py` | Rebuilt with a real, persisted lifecycle: `recommended → planned → applied → verified` / `failed`. Critically, `apply()` **does not fabricate success** outside `MOCK_MODE` — without a real configuration-management channel into the Digital Twin, it honestly reports `planned` with an explanation, rather than claiming a change was made that wasn't. |
| `services/revalidation/revalidation_engine.py` | Rebuilt to actually **re-run** `ValidationOrchestrator` against the twin after remediation and compare before/after scores, rather than a bare heuristic. Reuses the `Validation` table via a new `phase` column (`"initial"` / `"revalidation"`) instead of creating a duplicate table, per the "don't duplicate existing tables" requirement. The old `verify(validation_score)` heuristic method is preserved for backward compatibility with the pre-existing `/remediations/{id}/revalidate` endpoint. |
| `database/models/validation.py` | Added the `phase` column (see above). |
| `api/schemas/autosectwin.py` | Added `phase` to `ValidationResponse` so the API surfaces the initial-vs-revalidation distinction. |
| `services/orchestration/exploit_executor.py` | In `MOCK_MODE`, tags the Metasploit options with a `_simulated_remediated` hint derived from `twin.health`, so a revalidation run against a twin whose vulnerable service was (simulated-)remediated produces a realistic "no longer exploitable" result. This hint is never sent outside mock mode. |

### 2.4 Mock mode, task queue, and other infrastructure

| File | Role |
|---|---|
| `core/config.py` | New settings: `MOCK_MODE`, `TWIN_HEALTH_POLL_INTERVAL_SECONDS`, `TWIN_HEALTH_TIMEOUT_SECONDS`, `REMEDIATION_AUTO_APPLY`, `ORCHESTRATION_DESTROY_TWIN_AFTER_RUN`, `ENFORCE_DIGITAL_TWIN_BOUNDARY`, `TASK_QUEUE_BACKEND`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`, `CELERY_TASK_ALWAYS_EAGER`, `DATABASE_URL_OVERRIDE`. |
| `integrations/digital_twin/twin_client.py` | `MOCK_MODE` returns a deterministic, clearly `simulated: True`-tagged fake twin instead of calling the real Twin Generator. |
| `integrations/metasploit/rpc_client.py` | `MOCK_MODE` returns deterministic module metadata and execution evidence instead of calling a real Metasploit RPC daemon — including the "vulnerability resolved after remediation" branch described above. |
| `services/twin_provisioning_service.py` | Added `wait_until_ready()`: polls twin health with a timeout, raising a clean `HTTPException` (502/504) on failure/timeout instead of hanging. |
| `services/tasks/celery_app.py` **(new)** | Celery application, configured from `Settings`. |
| `services/tasks/orchestration_tasks.py` **(new)** | `run_closed_loop_job` Celery task — the real worker-side entry point for a closed-loop run. |
| `services/reporting/report_generator.py` | Added `generate_closed_loop_report()` (assembles the full report from persisted DB rows only — never runtime variables), `render_html()`, and `render_pdf()` (via `reportlab`, pure Python). |
| `api/routes/reports.py` | Added `GET /reports/{id}/html` and `GET /reports/{id}/pdf`. |

### 2.5 Tests

| File | Coverage |
|---|---|
| `tests/conftest.py` **(new)** | Shared `client`/`db` fixtures: in-memory SQLite + `MOCK_MODE` forced on, wired into the real FastAPI app via dependency override. |
| `tests/orchestration/test_closed_loop_orchestrator.py` **(new)** | Full end-to-end runs of `ClosedLoopOrchestrator` (happy path resolves after remediation; model-failure handling; missing-exploit handling; skip-remediation-when-not-validated). |
| `tests/orchestration/test_remediation_engine.py` **(new)** | Lifecycle transitions, mock-vs-real honesty, classification logic. |
| `tests/orchestration/test_module_inspector_and_mock_rpc.py` **(new)** | The `available=False`-on-failure fix, and mock-mode RPC evidence (including the remediated-vs-not branch). |
| `tests/orchestration/test_report_generator.py` **(new)** | HTML and **PDF** rendering — the PDF tests parse the output back with an independent library (`pypdf`) and assert the extracted text matches, not just that the bytes start with `%PDF`. |
| `tests/orchestration/test_celery_tasks.py` **(new)** | Runs the real Celery task in eager mode (no live Redis needed); tests the dispatch fallback logic for broker-unreachable / celery-ok / inline-forced cases. |
| `tests/api/test_domain_routes.py` **(new)** | CRUD + 404s for vulnerabilities, exploits (incl. the filtering fix), validations (incl. a regression check for the `vulnerability_id` NOT NULL bug), remediation, twins. |
| `tests/api/test_supporting_routes.py` **(new)** | CRUD + 404s for approvals, confidence, learning events, recommendations, trust, legacy profiling. |
| `tests/unit/test_engines.py`, `tests/e2e/test_engine_flow.py` | Rewritten to match the real predictor/feature-builder API (see 2.1). |

---

## 3. Verification performed (not just written — actually run)

- **77/77 tests pass** (`pytest tests/`), ~90% coverage across `api/`, `services/`, `database/models/`.
- **Migration chain verified**: `alembic upgrade head` and `alembic downgrade` (both new revisions) run cleanly against SQLite; resulting schema diffed against the ORM models line-for-line.
- **`configure_mappers()`** run against every model — confirms all 19 tables and every `back_populates` relationship pair are consistent (this is the one check that catches relationship typos SQLAlchemy won't complain about until first query).
- **Live HTTP smoke test**: booted the real FastAPI app (via `TestClient`), seeded a vulnerability/exploit directly, called `POST /orchestration/run` → `GET /orchestration/{job_id}` over genuine HTTP with `MOCK_MODE=true`. Reproduced the full acceptance scenario end-to-end: real trained-model prediction → validated → remediated → revalidation resolved → twin destroyed → report persisted, with 11 audit rows.
- **Celery resilience proven live**: with no Redis running in this sandbox and `TASK_QUEUE_BACKEND=celery` (the default), `POST /orchestration/run` correctly caught the broker connection failure, logged it, fell back to inline execution, and the job still completed — proving the fallback path isn't just theoretical.
- **PDF rendering visually confirmed**: generated a sample closed-loop report PDF, rasterized it with `pdftoppm`, and visually inspected the output — clean, multi-page, correctly laid-out tables for every section.

---

## 4. Known limitations (explicitly, not glossed over)

- **No live Postgres / Metasploit RPC daemon / Twin Generator / Redis were available in the development sandbox.** Everything was validated against SQLite (`DATABASE_URL_OVERRIDE`) and `MOCK_MODE=true`. The code paths for real infrastructure exist and follow the same interfaces already used successfully elsewhere in the original repo (e.g. the pre-existing, working Metasploit RPC login/module-inspection calls), but could not be exercised against genuine external services here.
- **Non-mock remediation "apply"** honestly reports `planned` rather than `applied`, because there is no configuration-management API into the real Twin Generator for AutoSecTwin to call. This is a deliberate honesty choice, not an oversight — see §2.3.
- **Celery/Redis** is the default dispatch path, with automatic fallback to in-process `BackgroundTasks` if unreachable. A real deployment should run a Celery worker (`celery -A services.tasks.celery_app worker`) and a Redis instance for genuine out-of-process execution.

---

## 5. How to apply this overlay

```bash
# From a fresh clone of the original repo:
git clone https://github.com/Adarshsingh36/AutoSecTwin.git
cd AutoSecTwin

# Extract this changed-files package on top of it (overwrites the listed
# files, adds the new ones):
unzip -o /path/to/AutoSecTwin-changed-files.zip -d .

pip install -r requirements.txt
alembic upgrade head

# Local/offline demo (no Postgres/Redis/Metasploit/Twin Generator needed):
MOCK_MODE=true TASK_QUEUE_BACKEND=inline DATABASE_URL_OVERRIDE=sqlite:///./autosectwin.db uvicorn main:app --reload

# Production-shaped run:
redis-server &
celery -A services.tasks.celery_app worker --loglevel=info &
uvicorn main:app
```
