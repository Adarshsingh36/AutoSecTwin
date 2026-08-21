# AutoSecTwin ASDE

AutoSecTwin ASDE is a FastAPI-based security decision engine for vulnerability
analysis, exploitability prediction, digital twin provisioning, exploit
validation, confidence scoring, trust monitoring, remediation recommendation,
and reporting.

The repository contains two closely related parts:

- **ASDE application**: the main API and service layer that manages
  vulnerability workflows, scoring, exploit orchestration, validation,
  recommendations, approvals, trust, learning, and reports.
- **Twin Generator**: the isolated target lifecycle module that creates,
  monitors, and destroys disposable vulnerable replicas through Docker or
  VirtualBox.

No real credentials, usernames, passwords, API keys, or deployment-specific
secrets should be stored in this README. Use placeholders in documentation and
keep real values in a local `.env` file only.

## System Overview

AutoSecTwin is designed around a controlled security validation pipeline:

```text
Vulnerability Intake
  -> Threat Intelligence Enrichment
  -> Exploitability Prediction
  -> Digital Twin Provisioning
  -> Exploit Mapping and Validation
  -> Confidence and Trust Scoring
  -> Recommendation and Remediation
  -> Reporting and Continuous Learning
```

The ASDE layer owns the decision workflow. It stores vulnerabilities and
validation records, computes risk and confidence signals, coordinates
recommendations, and exposes the API surface.

The Twin Generator owns the runtime test target. It creates isolated, disposable
replicas of vulnerable systems so exploit validation can happen away from
production assets.

## ASDE Responsibilities

The root application in [`main.py`](main.py) registers the main FastAPI service.
Its responsibilities include:

- Creating and listing vulnerability records.
- Enriching vulnerabilities with threat intelligence signals.
- Predicting exploitability probability.
- Mapping vulnerabilities to known or candidate exploits.
- Running validation and revalidation workflows.
- Tracking confidence scores, trust metrics, and model drift.
- Managing human approval workflows.
- Generating remediation recommendations and reports.
- Recording learning events for future model and workflow improvement.

The ASDE implementation is organized around route modules in `api/`, persistent
models in `database/`, and domain services in `services/`.

## Twin Generator Responsibilities

The `twin_generator` package owns isolated twin lifecycle management. Its job is
to get a twin running, isolated, registered, monitored, and eventually cleaned
up. It does not exploit or patch targets.

Twin Generator responsibilities include:

- CVE-to-container-image registry management.
- Docker-based twin creation.
- VirtualBox-based VM twin creation when a container image is not available.
- Isolated Docker bridge networks and VirtualBox internal networking.
- Twin registration and lifecycle logging.
- Health monitoring for running twins.
- Cleanup scheduling for expired or destroyed twins.
- Legacy software classification as metadata.

More module-specific detail is available in
[`twin_generator/README.md`](twin_generator/README.md).

## End-To-End Workflow

```text
1. A vulnerability is submitted to ASDE.
2. Threat intelligence services enrich the vulnerability.
3. The exploitability engine estimates probability of exploitation.
4. If validation is needed, ASDE requests a digital twin.
5. The Twin Generator checks the CVE image registry.
6. If a Docker image exists, it provisions an isolated container twin.
7. If no image exists, it can fall back to a VirtualBox VM workflow.
8. The twin is health checked, registered, and returned to ASDE.
9. Exploit validation runs against the isolated twin environment.
10. ASDE compares prediction and validation results.
11. Trust, drift, and confidence records are updated.
12. Recommendation, remediation, report, and learning workflows consume the results.
13. The twin is destroyed manually or by cleanup scheduling.
```

## Project Structure

```text
.
|-- api/                     FastAPI route modules, dependencies, and schemas
|-- core/                    Configuration, logging, security, interfaces, exceptions
|-- database/                SQLAlchemy models, sessions, Alembic migrations
|-- integrations/            External clients for NVD, EPSS, threat intel, Metasploit, twins
|-- ml/                      ML datasets, models, and pipeline package structure
|-- services/                ASDE domain services
|-- tests/                   Root unit, integration, and e2e tests
|-- twin_generator/          Digital twin generator package, docs, and tests
|-- main.py                  Root FastAPI application entry point
|-- requirements.txt         Python dependencies
|-- alembic.ini              Alembic configuration
|-- .env.example             Example environment configuration
```

## Key Packages

| Package | Purpose |
|---|---|
| `api/routes` | HTTP endpoints for ASDE workflows |
| `api/schemas` | Request and response schemas |
| `core` | Shared configuration, interfaces, exceptions, security, and logging |
| `database/models` | SQLAlchemy models for vulnerabilities, assets, approvals, twins, reports, trust, and related records |
| `database/migrations` | Alembic migration history |
| `integrations` | Clients for external intelligence sources and execution systems |
| `services/exploitability` | Feature building, training, inference, and prediction |
| `services/trust` | Prediction comparison, drift monitoring, agreement tracking, and trust metrics |
| `services/recommendation` | Patch, code, configuration, and remediation recommendation engines |
| `services/reporting` | JSON, PDF, technical, and executive report generation support |
| `services/legacy` | Legacy and end-of-life software profiling |
| `services/approval` | Approval queues and human-in-the-loop workflow handling |
| `twin_generator` | Twin provisioning, registry, monitoring, cleanup, Docker, VM, and network isolation |

## Tech Stack

- Python 3.11+
- FastAPI
- SQLAlchemy
- Alembic
- PostgreSQL via `psycopg`
- Pydantic and pydantic-settings
- scikit-learn, XGBoost, Optuna, sentence-transformers
- HTTPX and OpenAI SDK integration points
- Docker SDK for container-based twins
- VirtualBox `VBoxManage` subprocess integration for VM-based twins
- Pytest

## Configuration

Create a local environment file from the example:

```bash
copy .env.example .env
```

Keep real values out of documentation and version control. Use placeholders in
shared docs and replace them only inside your local `.env`:

```env
APP_NAME=AutoSecTwin ASDE
APP_VERSION=0.1.0
ENVIRONMENT=development

DB_HOST=<database-host>
DB_PORT=<database-port>
DB_NAME=<database-name>
DB_USER=<database-user>
DB_PASSWORD=<database-password>

NVD_API_BASE_URL=<nvd-api-base-url>
EPSS_API_BASE_URL=<epss-api-base-url>
METASPLOIT_RPC_URL=<metasploit-rpc-url>
DIGITAL_TWIN_BASE_URL=<digital-twin-service-url>

OPENAI_API_KEY=<openai-api-key>
CLAUDE_API_KEY=<claude-api-key>
GEMINI_API_KEY=<gemini-api-key>
OLLAMA_BASE_URL=<ollama-base-url>
```

Only set integration keys and URLs for services you actually use locally.

## Setup

Create and activate a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Prepare the local environment:

```bash
copy .env.example .env
```

Edit `.env` with local placeholder-specific values. Do not commit the real
`.env` file.

## Database

Start PostgreSQL and create the configured database before running the app.

The application builds its SQLAlchemy connection string from the database
environment variables in `core.config.Settings`:

```text
postgresql+psycopg://<DB_USER>:<DB_PASSWORD>@<DB_HOST>:<DB_PORT>/<DB_NAME>
```

Run migrations:

```bash
alembic upgrade head
```

## Run The ASDE API

Start the root FastAPI service:

```bash
uvicorn main:app --reload
```

Useful local URLs:

- API health: `http://127.0.0.1:8000/health`
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

## ASDE API Areas

The root app registers these route groups:

| Prefix | Purpose |
|---|---|
| `/vulnerabilities` | Create and list vulnerability records with initial scoring |
| `/exploits` | Exploit mapping and execution workflows |
| `/validations` | Validation workflows and results |
| `/confidence` | Confidence scoring and optimization |
| `/approvals` and `/approval` | Human approval workflow endpoints |
| `/trust` | Prediction comparison, trust metrics, and drift history |
| `/legacy` | Legacy and EOL software profiling |
| `/recommendation` | Remediation recommendation generation |
| `/remediations` | Remediation records and workflows |
| `/reports` | Technical and executive report generation |
| `/twins` | Root ASDE twin provisioning, listing, lookup, and teardown |
| `/learning` | Continuous learning event workflows |

## Twin Generator Components

| Component | Location | Purpose |
|---|---|---|
| Twin Orchestrator | `twin_generator/services/orchestrator.py` | Coordinates registry lookup, provisioning, registration, and teardown |
| CVE Image Registry | `twin_generator/registry/` | Stores CVE-to-Docker-image mappings |
| Docker Twin Engine | `twin_generator/docker_engine/` | Creates and destroys container-based twins |
| VM Twin Engine | `twin_generator/vm_engine/` | Creates and destroys VirtualBox-based twins |
| Network Isolation | `twin_generator/network/` and VM manager code | Keeps twins isolated from production networks |
| Twin Monitor | `twin_generator/monitor/` | Checks twin health and lifecycle state |
| Cleanup Manager | `twin_generator/cleanup/` | Removes expired or destroyed twin resources |
| Legacy Profiler | `twin_generator/legacy/` | Classifies software/version pairs as legacy, supported, or unknown |

## Twin Generator Workflow

```text
Scanner or ASDE sends a CVE request
  -> Twin Orchestrator receives the request
  -> Registry lookup checks for a mapped Docker image
      -> If found:
           pull or inspect image
           create isolated Docker network
           create container
           health check
           register twin
      -> If not found:
           restore or prepare VM snapshot
           configure isolated VirtualBox network
           boot VM
           heartbeat or health check
           register twin
  -> Legacy profiler records metadata when applicable
  -> Twin ID and connection metadata are returned
  -> Monitor checks health during the lifecycle
  -> Cleanup destroys resources after teardown or expiry
```

## Twin Generator API Surface

The `twin_generator.api` routers expose a more specific twin lifecycle surface
than the root ASDE `/twins` route group:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/twins/create` | Provision a new twin for a CVE |
| `GET` | `/twins` | List generated twins |
| `GET` | `/twins/{twin_id}` | Fetch one generated twin |
| `GET` | `/twins/{twin_id}/health` | Read current twin health |
| `POST` | `/twins/{twin_id}/destroy` | Destroy a generated twin |
| `POST` | `/registry` | Create a CVE-to-image mapping |
| `GET` | `/registry` | List registry mappings, optionally filtered by CVE |
| `PUT` | `/registry/{entry_id}` | Update a registry mapping |
| `DELETE` | `/registry/{entry_id}` | Delete a registry mapping |
| `POST` | `/legacy/check` | Classify software/version legacy status |

## Root Twins vs Twin Generator Twins

There are two related twin surfaces in this repository:

- `api/routes/twins.py` is part of the root ASDE API and integrates twin
  provisioning into the wider ASDE workflow.
- `twin_generator/api/` is the dedicated twin generator API layer with registry,
  legacy, health, and lifecycle endpoints.

Use the root ASDE routes when working through the full vulnerability decision
pipeline. Use the twin generator routes when testing or integrating the twin
lifecycle module directly.

## External Runtime Dependencies

Different workflows need different external services:

| Dependency | Needed For |
|---|---|
| PostgreSQL | Persistent ASDE and twin records |
| Docker Engine | Container-based twin provisioning |
| VirtualBox and `VBoxManage` | VM-based twin provisioning |
| Metasploit RPC | Exploit orchestration workflows |
| NVD and EPSS APIs | Vulnerability and exploit probability enrichment |
| Threat intelligence sources | Additional vulnerability context |
| LLM providers or Ollama | LLM-backed recommendation or analysis flows |

Mocked tests do not require every external service to be running.

## Testing

Run all tests:

```bash
pytest
```

Run common subsets:

```bash
pytest tests/unit -v
pytest tests/integration -v
pytest tests/e2e -v
pytest twin_generator/tests -v
```

The twin generator tests include mocked Docker and VirtualBox paths, so many
module tests can run without a live daemon or hypervisor.

## Security And Confidentiality Notes

- Do not commit `.env`, API keys, access tokens, passwords, private hostnames,
  internal IPs, or organization-specific usernames.
- Use placeholder values in docs and examples.
- Keep production secrets in a secrets manager or deployment environment.
- Review generated reports before sharing them outside the intended audience.
- Run exploit validation only against isolated twins or explicitly authorized
  targets.

## Development Notes

- Keep route modules thin and put workflow logic in `services/`.
- Run Alembic migrations after changing SQLAlchemy models.
- Keep Twin Generator changes scoped to `twin_generator/` unless the ASDE API
  integration needs to change.
- Prefer structured service clients over shell commands for integrations when a
  maintained SDK exists.
- The VM engine uses explicit subprocess arguments for `VBoxManage`; avoid
  passing user-controlled shell strings.

## License

See [`LICENSE`](LICENSE).
