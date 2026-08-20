# Digital Twin Generator (AutoSecTwin)

Creates isolated, disposable replicas of vulnerable targets — in Docker or
VirtualBox — for the Exploit Engine to test against. This module owns
**only** the Twin Generator stage of the AutoSecTwin pipeline:

```
Scanner -> Classifier -> [ Twin Generator ] -> Exploit Engine -> Validator
                              ^^^^^^^^^^^^
                              this module
```

Its job ends the moment a twin is running, isolated, and healthy. It never
exploits or patches anything — that's the Exploit Engine's and Fix Engine's
job respectively.

## Components

| # | Component | Location |
|---|---|---|
| 1 | Twin Orchestrator | `services/orchestrator.py` |
| 2 | CVE Image Registry | `registry/` |
| 3 | Docker Twin Engine | `docker_engine/` |
| 4 | VM Twin Engine | `vm_engine/` |
| 5 | Legacy Profiler | `legacy/` |
| 6 | Network Isolation | `network/` (Docker) + `vm_engine/manager.py` (VirtualBox `intnet`) |
| 7 | Twin Monitor | `monitor/` |
| 8 | Twin Cleanup Manager | `cleanup/` |

## Workflow

```
Scanner -> Classifier -> Twin Generator receives CVE
  -> search registry -> Docker image available?
       YES -> pull image -> create isolated bridge network -> create
              container -> health check -> register twin -> return Twin ID
       NO  -> restore VirtualBox snapshot -> configure isolated network
              -> boot VM -> check heartbeat -> register twin -> return Twin ID
  -> Legacy Profiler flags EOL software (metadata only, never blocks)
  -> Exploit Engine receives Twin ID
```

## Database

Four new tables, added via `database/migrations/versions/20260720_01_twin_generator_tables.py`:

- `twin_instances` — one row per provisioned twin
- `twin_registry` — CVE -> Docker image mappings
- `legacy_profiles` — local End-of-Life reference data
- `twin_logs` — append-only lifecycle audit trail per twin

No existing tables or columns are touched. **Before running the migration**,
set `down_revision` in that file to your current Alembic head.

## API Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/twins/create` | Provision a new twin for a CVE |
| POST | `/twins/{id}/destroy` | Tear down a twin on demand |
| GET | `/twins` | List all twins |
| GET | `/twins/{id}` | Get one twin |
| GET | `/twins/{id}/health` | Current health status |
| POST | `/registry` | Add a CVE -> image mapping |
| GET | `/registry` | List mappings (optional `?cve=`) |
| PUT | `/registry/{id}` | Update a mapping |
| DELETE | `/registry/{id}` | Remove a mapping |
| POST | `/legacy/check` | Classify software/version as Legacy/Supported/Unknown |

Wire the routers into your existing FastAPI app:

```python
from twin_generator.api import legacy_router, registry_router, twins_router

app.include_router(registry_router)
app.include_router(legacy_router)
app.include_router(twins_router)
```

## Background workers

Twin Monitor and Twin Cleanup Manager are plain asyncio loops
(`monitor/scheduler.py`, `cleanup/scheduler.py`) — deliberately not tied to
Celery or FastAPI BackgroundTasks specifically, so whichever the rest of
AutoSecTwin already uses can schedule them:

```python
# Example: launch both as background tasks at app startup
asyncio.create_task(run_monitor_loop(session_factory, monitor_factory))
asyncio.create_task(run_cleanup_loop(session_factory, cleanup_factory))
```

## Configuration

All settings are `pydantic-settings` classes reading from your existing
`.env` (see `.env.example`). No configuration is hardcoded.

## Design decisions worth knowing about

- **Docker only, no shell**: the Docker Twin Engine and Network Isolation
  Manager use `docker-sdk-python` exclusively (calls wrapped in
  `asyncio.to_thread` since the SDK is synchronous). Never a shell command.
- **VM Twin Engine uses `VBoxManage`/subprocess**: no maintained Python SDK
  for VirtualBox exists (unlike Docker). Every invocation uses
  `asyncio.create_subprocess_exec` with an explicit argument list — never a
  shell string — so there's no shell-injection surface even without an SDK.
- **IP assignment**: Docker auto-assigns the twin's IP within its isolated
  subnet; the engine reads it back after connecting rather than
  pre-computing a static address.
- **VM naming convention**: since the CVE Image Registry only maps CVEs to
  *Docker* images (per spec), VM names/networks are derived deterministically
  from the twin's UUID (`twin-vm-<uuid>`). Confirm this matches how your
  VirtualBox VMs/snapshots are actually named.
- **Container/VM identity**: no `container_id` column was added to
  `twin_instances` — container and network names are derived from the twin's
  UUID using the same convention at both provision and destroy time, so no
  new DB fields were needed for teardown.
- **Snapshot cleanup is disabled by default**: VBoxManage doesn't reliably
  expose snapshot creation timestamps across versions, so true age-based
  deletion isn't possible. The implementation deletes every non-baseline
  snapshot instead — review `CleanupSettings.keep_snapshot_names` before
  enabling `enable_snapshot_cleanup`.
- **Legacy Profiler is metadata-only**: it never blocks or delays twin
  creation, per spec — it only sets `TwinInstance.legacy_flag`.

## Testing

```bash
pip install -r requirements.txt
pytest twin_generator/tests -v
```

81 tests, all passing, covering every component: unit tests with mocked
Docker/VirtualBox (no daemon or hypervisor required to run the suite) plus
integration tests against a real in-memory SQLite DB through the actual
FastAPI routers.

## Not included (out of scope per spec)

- Exploit Engine, Validator, Confidence Engine, Fix Engine, Human Approval,
  Remediation, Revalidation — all assumed to already exist.
- Actually connecting Exploit Engine/Validator containers to a twin's
  isolated network — this module creates and labels the network
  (`twin.allowed_services`); attaching those services' own containers is
  done by whichever module orchestrates them.
