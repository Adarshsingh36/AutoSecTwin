# AutoSecTwin — Full Project Documentation

This package is the **complete AutoSecTwin repository** with all backend
work applied — a working automated cybersecurity validation pipeline built
around an isolated Digital Twin. If you only want to see what changed
relative to the original repo, see the companion
`AutoSecTwin-changed-files.zip` and its `CHANGES_DOCUMENTATION.md`.

Original repository: `https://github.com/Adarshsingh36/AutoSecTwin`

---

## 1. What this system does

AutoSecTwin turns a discovered vulnerability into a validated,
evidence-backed finding — and, where possible, a remediated one — without
ever touching production infrastructure:

```
Vulnerability
   → Exploitability Prediction (trained XGBoost model: CVSS, EPSS, KEV)
   → Exploit Candidate Selection (mapped Metasploit module, ranked by reliability)
   → Digital Twin Provisioning (isolated environment, never production)
   → Twin Readiness Check
   → Metasploit Module Inspection + Readiness Gate
   → Controlled Validation / Exploitation (against the twin only)
   → Evidence Collection + Validation Engine (validated / failed / inconclusive)
   → Remediation Recommendation → Plan → Apply
   → Revalidation (re-run the same validation, compare before/after)
   → Final Report (JSON / HTML / PDF)
   → Learning Feedback (recorded for future model calibration)
   → Twin Cleanup
```

This entire flow is coordinated by `ClosedLoopOrchestrator`
(`services/orchestration/closed_loop_orchestrator.py`) and exposed as a
single non-blocking API call: `POST /orchestration/run`.

---

## 2. Tech stack and why

| Concern | Choice | Why |
|---|---|---|
| API framework | **FastAPI** | Already the project's framework; async-native, good for I/O-bound orchestration (twin provisioning, Metasploit RPC calls). |
| ORM | **SQLAlchemy 2.0** | Already in use; mature, explicit relationship modeling needed for the domain graph (Vulnerability → Exploit → Validation → Remediation → Report). |
| Migrations | **Alembic** | Already in use; linear, reviewable migration chain (see §5). |
| Database | **PostgreSQL** (prod), **SQLite** (dev/test via `DATABASE_URL_OVERRIDE`) | Postgres was the project's existing choice; SQLite override was added purely so the system is testable/runnable without standing up Postgres. |
| ML | **XGBoost + scikit-learn** (pre-trained artifact) | Already in the repo (`ml/models/exploitability_xgb.joblib`); preserved as-is per the explicit "no fake heuristic fallback" requirement. |
| Exploit execution | **Metasploit RPC** (MessagePack over HTTP) | Already in the repo and confirmed working (module inspection against `windows/smb/ms17_010_eternalblue`); extended with mock mode, not replaced. |
| Digital Twin | **Twin Generator** (separate HTTP service, own subproject under `twin_generator/`) | Pre-existing component; integrated via `DigitalTwinClient`, not replaced. |
| Background jobs | **Celery + Redis**, with automatic fallback to FastAPI `BackgroundTasks` | The spec explicitly asked for Celery/Redis where practical, with an allowance to fall back to a simpler mechanism if infrastructure is constrained — implemented both, with the fallback triggering automatically and observably rather than requiring manual toggling. |
| Reporting | JSON (native) + HTML (hand-rolled renderer) + PDF (**reportlab**) | `reportlab` is pure Python — no `weasyprint`/`wkhtmltopdf` system library dependency — so PDF generation works in constrained/offline environments. |
| Testing | **pytest**, **pytest-asyncio**, in-memory SQLite, **pypdf** (for round-trip PDF verification) | Fast, no external services required; `pypdf` specifically so PDF tests assert on *extracted text*, not just "starts with `%PDF`". |

---

## 3. Repository structure

```
AutoSecTwin/
├── main.py                        # FastAPI app entrypoint, router registration
├── requirements.txt
├── .env.example                   # matches core.config.Settings exactly
├── core/
│   ├── config.py                  # Settings (env-driven), incl. MOCK_MODE, Celery, safety flags
│   ├── exceptions.py
│   └── logger.py
├── api/
│   ├── routes/                    # one module per resource
│   │   ├── vulnerabilities.py, exploits.py, validations.py
│   │   ├── twins.py, remediation.py, reports.py
│   │   ├── orchestration.py       # closed-loop entrypoint (NEW)
│   │   ├── approvals.py, confidence.py, trust.py, recommendation.py,
│   │   │   legacy.py, learning.py
│   ├── schemas/autosectwin.py     # Pydantic request/response models
│   └── dependencies.py            # get_db()
├── database/
│   ├── base.py, session.py
│   ├── models/                    # SQLAlchemy ORM models, one per domain object
│   │   └── orchestration_job.py   # job tracking (NEW)
│   └── migrations/versions/       # Alembic chain, 0001 → 0004
├── services/
│   ├── orchestration/             # exploit mapping, module inspection, readiness,
│   │   │                          # execution, and the ValidationOrchestrator
│   │   └── closed_loop_orchestrator.py   # top-level coordinator (NEW)
│   ├── validation/                # ValidationEngine: evidence → validated/failed/inconclusive
│   ├── remediation/                # RemediationEngine: recommend → plan → apply → verify
│   ├── revalidation/               # RevalidationEngine: re-validate, compare before/after
│   ├── reporting/                  # ReportGenerator: JSON / HTML / PDF
│   ├── exploitability/             # trained-model predictor + feature builder
│   ├── legacy/                     # legacy/EOL software profiling
│   ├── trust/                      # AI-prediction-vs-validation agreement/hallucination/drift
│   ├── tasks/                      # Celery app + orchestration task (NEW)
│   └── twin_provisioning_service.py
├── integrations/
│   ├── metasploit/rpc_client.py    # Metasploit RPC client (+ mock mode)
│   ├── digital_twin/twin_client.py # Twin Generator client (+ mock mode)
│   ├── epss/, nvd/, threat_intel/
├── ml/                              # trained model artifact + training pipeline
├── twin_generator/                  # separate subproject: the Digital Twin Generator service
└── tests/
    ├── unit/, e2e/, integration/    # pre-existing
    ├── orchestration/               # closed loop, remediation, revalidation, reports, Celery (NEW)
    ├── api/                         # CRUD coverage for every route (NEW)
    └── conftest.py                  # shared client/db fixtures (NEW)
```

`twin_generator/` is a distinct, separately-runnable service (its own
`main.py`, models, API) that AutoSecTwin's backend talks to over HTTP via
`DigitalTwinClient` — it was **not** modified, per the instruction to
integrate the existing Digital Twin Generator rather than replace it.

---

## 4. Architecture: how a request flows

```
Client
  │  POST /orchestration/run {vulnerability_id}
  ▼
api/routes/orchestration.py
  │  creates OrchestrationJob(status="queued")
  │  dispatches to Celery (default) or BackgroundTasks (fallback)
  │  returns job_id immediately — HTTP never blocks
  ▼
services/tasks/orchestration_tasks.py  (Celery worker process)
  │  opens its own DB session
  ▼
services/orchestration/closed_loop_orchestrator.py
  ├─ services/exploitability/predictor.py         (trained XGBoost model)
  ├─ services/twin_provisioning_service.py          → integrations/digital_twin/twin_client.py
  ├─ services/orchestration/validation_orchestrator.py
  │     ├─ exploit_mapper.py, module_inspector.py, exploit_readiness.py
  │     └─ exploit_executor.py                       → integrations/metasploit/rpc_client.py
  │     └─ services/validation/validation_engine.py   (evidence → status/score)
  ├─ services/remediation/remediation_engine.py
  ├─ services/revalidation/revalidation_engine.py    (re-runs ValidationOrchestrator)
  ├─ services/reporting/report_generator.py          (JSON/HTML/PDF, from persisted rows only)
  └─ database/models/{audit,learning_event}.py       (audit trail, learning feedback)
```

Every stage transition is written to the `OrchestrationJob` row and to the
`Audit` table before moving on — so `GET /orchestration/{job_id}` always
reflects real, current progress, and a failure at any stage leaves a fully
inspectable trail rather than an opaque crash.

---

## 5. Database

19 tables total (see `database/models/__init__.py` for the full export
list). Migration chain: `0001_initial_autosectwin_schema` →
`0002_trust_legacy_extensions` → `tg_20260720_01` (twin generator tables) →
`77af561a9597` (asset twin-provisioning fields) → `9f52b13` (twin metadata)
→ `0003_closed_loop_orchestration` (job tracking + validation phase) →
`0004_orchestration_queue_backend` (Celery/inline dispatch tracking).

Every foreign key, `back_populates` relationship pair, JSON-vs-Text typing,
and nullability constraint was audited against actual read/write usage;
`sqlalchemy.orm.configure_mappers()` passes clean against every model. Full
detail on the two schema bugs found and fixed is in
`CHANGES_DOCUMENTATION.md` (companion package) §2.1.

---

## 6. Safety boundary

Per the project's core safety requirement, exploit execution is only ever
permitted against a host that resolves to a `Twin` row created by
`TwinProvisioningService` — never directly against arbitrary infrastructure.
This is enforced explicitly in `ClosedLoopOrchestrator._enforce_twin_boundary()`
(controlled by `settings.ENFORCE_DIGITAL_TWIN_BOUNDARY`) in addition to the
implicit boundary already provided by every execution path deriving its
target exclusively from `twin.ip_address`/`twin.endpoint`.

---

## 7. Running it

```bash
pip install -r requirements.txt
alembic upgrade head
```

**Local/offline demo** (no Postgres, Redis, Metasploit, or Twin Generator
required — everything simulated deterministically and clearly tagged
`simulated: true`):

```bash
MOCK_MODE=true TASK_QUEUE_BACKEND=inline \
  DATABASE_URL_OVERRIDE=sqlite:///./autosectwin.db \
  uvicorn main:app --reload
```

**Full production-shaped run:**

```bash
redis-server &
celery -A services.tasks.celery_app worker --loglevel=info &
# ... Metasploit RPC daemon and Twin Generator service running separately ...
uvicorn main:app
```

**Demo the full closed loop:**

```bash
curl -X POST localhost:8000/vulnerabilities/ -H 'content-type: application/json' -d '{
  "asset_id": 1, "cve_id": "CVE-2017-0144", "title": "EternalBlue",
  "cvss_score": 9.8, "severity": "CRITICAL", "kev_listed": true
}'
curl -X POST localhost:8000/exploits/ -H 'content-type: application/json' -d '{
  "vulnerability_id": 1, "source": "metasploit",
  "module_name": "windows/smb/ms17_010_eternalblue",
  "title": "MS17-010 EternalBlue", "reliability_score": 0.9
}'
curl -X POST localhost:8000/orchestration/run -H 'content-type: application/json' \
  -d '{"vulnerability_id": 1}'
curl localhost:8000/orchestration/<job_id>        # poll until "completed"
curl localhost:8000/reports/<report_id>/html      # or /pdf
```

---

## 8. Testing

```bash
pytest tests/ -q                 # 77 tests
pytest tests/ --cov=api --cov=services --cov=database/models --cov-report=term-missing
```

Coverage: ~90% across `api/`, `services/`, `database/models/`. See
`CHANGES_DOCUMENTATION.md` §3 for the specific verification steps performed
(migration up/down, live HTTP smoke test, Celery-broker-down resilience
test, visually-inspected PDF output).

---

## 9. What was preserved unchanged

Per the explicit "do not unnecessarily rewrite" instruction, the following
were left as-is because they already worked:

- The Metasploit RPC client's real (non-mock) authentication, module
  inspection, and execution logic.
- The trained XGBoost exploitability model and its feature pipeline.
- The Digital Twin Generator subproject (`twin_generator/`) in its entirety.
- The existing `ValidationOrchestrator`'s mapper → inspector → readiness →
  executor → analyze → persist flow (extended, not replaced).
- All pre-existing, already-passing tests and API routes not listed as
  changed in `CHANGES_DOCUMENTATION.md`.

## 10. What's out of scope / not verified here

- No live Postgres, Metasploit RPC daemon, Twin Generator, or Redis broker
  was available in the development sandbox this was built in. Everything
  was validated against SQLite + `MOCK_MODE=true`, including a genuine
  live-HTTP run of the full acceptance scenario. The real-infrastructure
  code paths reuse the same client interfaces the original repo already had
  working (e.g. real Metasploit module inspection), but weren't exercised
  against live services here.
- Non-mock remediation "apply" honestly reports `planned` rather than
  `applied`, since there's no configuration-management channel into a real
  Twin Generator for AutoSecTwin to call — see
  `services/remediation/remediation_engine.py` docstring.
