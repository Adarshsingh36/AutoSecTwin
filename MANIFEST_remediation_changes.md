# AutoSecTwin Remediation Work — File Bundle

63 files: every file created or modified while fixing the "dry-run"
remediation problem, verified against 136 passing tests (main app) + 87
(twin_generator).

## How to apply

This zip mirrors the repo's directory structure exactly (e.g.
`api/routes/approvals.py` is at that same path inside the zip). Extract it
at your repo root and let it overwrite — nothing outside this file list was
touched.

```bash
cd /path/to/AutoSecTwin
unzip -o autosectwin_remediation_changes.zip
```

## Required steps after extracting

1. **Set the migration's down_revision.** The three new migration files
   chain onto each other correctly, but confirm the first one
   (`a1c9f0e2b7d4_add_orchestration_jobs.py`) has `down_revision = "9f52b13"`
   matching your actual current Alembic head — run `alembic heads` first
   if you've added migrations of your own since this work started.

2. **Apply migrations:**
   ```bash
   alembic upgrade head
   ```

3. **New dependencies** (if not already installed):
   ```bash
   pip install celery redis structlog
   ```

4. **New/changed `.env` settings** — add these (defaults shown; adjust as
   needed):
   ```
   TASK_QUEUE_BACKEND=inline          # or "celery" with Redis running
   CELERY_TASK_ALWAYS_EAGER=true      # for local/dev; false in production
   REMEDIATION_AUTO_APPLY=true        # false to require manual /execute calls
   CODE_REMEDIATION_ALLOWED_ROOT=     # unset = code remediation disabled
   ```

5. **Run the tests:**
   ```bash
   pytest tests/ -q
   pytest twin_generator/tests/ -q --deselect twin_generator/tests/test_legacy_api.py::test_check_returns_legacy_for_seeded_eol_software
   ```
   The one deselected test is a pre-existing, unrelated Legacy Profiler
   schema mismatch (not something this work touched or caused) — see the
   Phase 2 writeup for detail if you want it fixed too.

## New top-level capabilities this bundle adds

- `POST /orchestration/run` + `GET /orchestration/jobs[/{id}]`
- `POST /remediations/{id}/execute` (real Docker twin destroy+redeploy)
- `POST /remediations/{id}/revalidate` (real re-exploit, not a caller-supplied score)
- `POST /approvals/` now requires `target_twin_id` + `fixed_version`; approving auto-dispatches execution if `REMEDIATION_AUTO_APPLY=true`
- `POST /reports/closed-loop/{remediation_id}` (15-section technical report; render via the existing `/reports/{id}/html` and `/reports/{id}/pdf`)
- `POST /code-remediation/propose` + `POST /code-remediation/{approval_id}/apply` (off by default)

See the full conversation for the per-phase reasoning behind each file —
this bundle is the code only.
