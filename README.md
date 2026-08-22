# AutoSecTwin ASDE

AutoSecTwin ASDE is a FastAPI-based security decision engine for vulnerability
analysis, exploitability prediction, digital twin provisioning, validation,
confidence scoring, trust monitoring, remediation recommendation, and reporting.

The project combines API workflows, database-backed security models, external
threat intelligence integrations, ML-assisted exploitability services, and a
digital twin generator that can provision isolated test targets through Docker
or VirtualBox.

## What It Does

- Ingests and scores vulnerabilities using threat intelligence and exploitability models.
- Provisions disposable digital twins for controlled validation workflows.
- Maps vulnerabilities to exploits and orchestrates validation flows.
- Tracks prediction confidence, model drift, and agreement between predictions and validation results.
- Generates remediation recommendations, reports, and continuous learning events.
- Provides approval, trust, legacy profiling, and revalidation services for security workflows.

## Project Structure

```text
.
|-- api/                     FastAPI route modules, dependencies, and schemas
|-- core/                    Configuration, logging, security, interfaces, exceptions
|-- database/                SQLAlchemy models, sessions, Alembic migrations
|-- integrations/            External clients for NVD, EPSS, threat intel, Metasploit, twins
|-- ml/                      ML datasets, models, and pipeline package structure
|-- services/                Domain services for ASDE workflows
|-- tests/                   Root unit, integration, and e2e tests
|-- twin_generator/          Digital twin generator package and tests
|-- main.py                  Root FastAPI application entry point
|-- requirements.txt         Python dependencies
|-- alembic.ini              Alembic configuration
|-- .env.example             Example environment configuration
```

For deeper details on the twin generator module, see
[`twin_generator/README.md`](twin_generator/README.md).

## Tech Stack

- Python 3.11+
- FastAPI
- SQLAlchemy
- Alembic
- PostgreSQL via `psycopg`
- Pydantic and pydantic-settings
- scikit-learn, XGBoost, Optuna, sentence-transformers
- Docker SDK and VirtualBox subprocess integration for digital twins
- Pytest

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

Create a local environment file:

```bash
copy .env.example .env
```

Update `.env` for your local database and external integrations. The root
application currently reads database connection settings from these variables:

```env
DB_HOST=localhost
DB_PORT="database port"
DB_NAME="databae name"
DB_USER="user name"
DB_PASSWORD="your password"
```

Optional integrations can be configured with values such as `NVD_API_BASE_URL`,
`EPSS_API_BASE_URL`, `METASPLOIT_RPC_URL`, `DIGITAL_TWIN_BASE_URL`,
`OPENAI_API_KEY`, `CLAUDE_API_KEY`, `GEMINI_API_KEY`, and `OLLAMA_BASE_URL`.

## Database

Start PostgreSQL and create the configured database before running the app.

Run migrations:

```bash
alembic upgrade head
```

The application builds its SQLAlchemy URL from `core.config.Settings`:

```text
postgresql+psycopg://<DB_USER>:<DB_PASSWORD>@<DB_HOST>:<DB_PORT>/<DB_NAME>
```

## Run The API

Start the FastAPI service:

```bash
uvicorn main:app --reload
```

Useful local URLs:

- API health: `http://127.0.0.1:8000/health`
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

## Main API Areas

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
| `/twins` | Digital twin provisioning, listing, lookup, and teardown |
| `/learning` | Continuous learning event workflows |

## Digital Twin Generator

The `twin_generator` package owns isolated twin lifecycle management:

- CVE-to-image registry
- Docker twin provisioning
- VirtualBox VM provisioning
- Isolated Docker and VM networking
- Twin health monitoring
- Cleanup scheduling
- Legacy metadata profiling

Run its focused test suite with:

```bash
pytest twin_generator/tests -v
```

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

## Development Notes

- Keep secrets in `.env`; do not commit real credentials.
- Run Alembic migrations after changing database models.
- Prefer service-layer changes in `services/` and keep route modules thin.
- The twin generator intentionally separates Docker-based and VM-based engines.
- Some integrations require external services to be running, such as PostgreSQL,
  Metasploit RPC, Docker, VirtualBox, Ollama, or hosted LLM APIs.

## License

See [`LICENSE`](LICENSE).
