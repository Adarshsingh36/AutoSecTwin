# Deployment Instructions

## 1. Host requirements

- **Docker**: a reachable Docker daemon (`DOCKER_HOST` or the default
  socket). The Docker Twin Engine and Network Isolation Manager talk to it
  exclusively via `docker-sdk-python`.
- **VirtualBox**: `VBoxManage` on PATH (or set `VM_TWIN_VBOXMANAGE_PATH`),
  used only when a CVE has no registry-mapped Docker image. Base VMs and
  their clean snapshots (named to match `VM_TWIN_DEFAULT_SNAPSHOT_NAME`,
  default `clean-snapshot`) must already exist on the host — this module
  does not create VMs from scratch, only restores/boots/tears them down.
- **PostgreSQL**: unchanged — this module adds tables to the existing
  database via Alembic, it doesn't provision a new instance.

## 2. Install dependencies

```bash
pip install -r twin_generator/requirements.txt
```

## 3. Apply the database migration

1. Open `database/migrations/versions/20260720_01_twin_generator_tables.py`
2. Set `down_revision` to your current Alembic head (`alembic heads`)
3. Run:
   ```bash
   alembic upgrade head
   ```

This adds `twin_instances`, `twin_registry`, `legacy_profiles`, and
`twin_logs`. No existing tables are modified.

## 4. Configure environment

Append `twin_generator/.env.example` to your `.env` and adjust as needed —
in particular `VM_TWIN_DEFAULT_SNAPSHOT_NAME` and
`VM_TWIN_DEFAULT_ISOLATED_INTNET` should match your actual VirtualBox setup.

## 5. Wire the routers into the FastAPI app

```python
from twin_generator.api import legacy_router, registry_router, twins_router

app.include_router(registry_router)
app.include_router(legacy_router)
app.include_router(twins_router)
```

## 6. Start the background workers

Twin Monitor and Twin Cleanup Manager are asyncio loops, not tied to a
specific task queue. Two ways to run them, pick whichever matches how the
rest of AutoSecTwin already runs background work:

**Option A — FastAPI startup task:**
```python
import asyncio
from twin_generator.monitor.scheduler import run_monitor_loop
from twin_generator.cleanup.scheduler import run_cleanup_loop

@app.on_event("startup")
async def start_twin_generator_workers():
    asyncio.create_task(run_monitor_loop(session_factory, monitor_factory))
    asyncio.create_task(run_cleanup_loop(session_factory, cleanup_factory))
```

**Option B — Celery beat**, scheduling `run_monitor_once()` /
`run_cleanup_once()` (both single-pass, easy to wrap in a Celery task) on
whatever interval you configure in Celery beat instead of
`TWIN_MONITOR_POLL_INTERVAL_SECONDS` / `TWIN_CLEANUP_SWEEP_INTERVAL_SECONDS`.

## 7. Seed the CVE Image Registry

The Docker path only activates for CVEs with a registry entry:

```bash
curl -X POST /registry -d '{"cve": "CVE-2021-44228", "image": "vulhub/log4j:2.15.0"}'
```

CVEs without an entry automatically fall back to the VM Twin Engine.

## 8. Verify

```bash
pytest twin_generator/tests -v   # 81 tests, no Docker/VirtualBox required
```

Then smoke-test against a real Docker daemon:

```bash
curl -X POST /twins/create -d '{"cve": "CVE-2021-44228"}'
curl /twins/1/health
curl -X POST /twins/1/destroy
```
