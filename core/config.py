import http
import re

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Runtime configuration for the ASDE service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )
    APP_NAME: str = "AutoSecTwin ASDE"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "asde_db"
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "root"

    NVD_API_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_BASE_URL: str = "https://api.first.org/data/v1/epss"
    EXPLOITDB_BASE_URL: str = "https://www.exploit-db.com"
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    METASPLOIT_RPC_URL: str = "http://localhost:55552/api/"
    METASPLOIT_RPC_USERNAME: str = "msf"
    METASPLOIT_RPC_PASSWORD: str = "msf"
    DIGITAL_TWIN_BASE_URL: str = "http://localhost:8081"

    OPENAI_API_KEY: str | None = None
    CLAUDE_API_KEY: str | None = None
    GEMINI_API_KEY: str | None = None
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    # ------------------------------------------------------------------
    # AutoSecTwin closed-loop orchestration configuration
    # ------------------------------------------------------------------

    # When true, external infrastructure (Digital Twin Generator,
    # Metasploit RPC) is simulated so the closed loop can be demonstrated
    # and tested without those services running. Must never be left on
    # unintentionally in a production deployment.
    MOCK_MODE: bool = False

    # Digital Twin readiness polling.
    TWIN_HEALTH_POLL_INTERVAL_SECONDS: float = 2.0
    TWIN_HEALTH_TIMEOUT_SECONDS: float = 120.0

    # Whether the closed-loop orchestrator is allowed to apply remediation
    # automatically after a validated finding, or should only recommend it.
    REMEDIATION_AUTO_APPLY: bool = True

    # Whether the closed-loop orchestrator destroys the Digital Twin after
    # the workflow completes (success or failure).
    ORCHESTRATION_DESTROY_TWIN_AFTER_RUN: bool = False

    # Safety boundary: exploit execution is only permitted against hosts
    # that resolve to a Twin provisioned by TwinProvisioningService. This
    # flag exists purely to make the boundary explicit/auditable; it is not
    # meant to be disabled outside of controlled testing.
    ENFORCE_DIGITAL_TWIN_BOUNDARY: bool = True

    # ------------------------------------------------------------------
    # Task queue: how POST /orchestration/run dispatches long-running work
    # ------------------------------------------------------------------

    # "celery" (default): dispatch to a Celery worker over CELERY_BROKER_URL
    #   (Redis), so the HTTP process never runs twin provisioning/Metasploit
    #   execution/remediation/revalidation itself.
    # "inline": use FastAPI's BackgroundTasks in the same process instead.
    #   Useful for local development/demos without Redis running. The API
    #   route also falls back to this automatically if dispatching to
    #   Celery fails (e.g. the broker isn't reachable), so a run is never
    #   silently dropped.
    TASK_QUEUE_BACKEND: str = "celery"

    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # When true, Celery tasks execute synchronously in-process instead of
    # being sent to a broker/worker. Used by the test suite so it never
    # needs a live Redis instance; never enable this in a real deployment.
    CELERY_TASK_ALWAYS_EAGER: bool = False
    
    # Optional full override, e.g. for local/dev/test use with SQLite
    # ("sqlite:///./autosectwin.db") instead of the composed Postgres URL
    # below. Leave unset in normal deployments.
    DATABASE_URL_OVERRIDE: str | None = None

    @property
    def DATABASE_URL(self) -> str:
        if self.DATABASE_URL_OVERRIDE:
            return self.DATABASE_URL_OVERRIDE
        return (
            f"postgresql+psycopg://"
            f"{self.DB_USER}:"
            f"{self.DB_PASSWORD}@"
            f"{self.DB_HOST}:"
            f"{self.DB_PORT}/"
            f"{self.DB_NAME}"
        )
    @field_validator("DB_PORT", mode="before")
    @classmethod
    def parse_db_port(cls, value: object) -> int:
        """Accept the numeric prefix of DB_PORT to survive malformed local env files."""

        if isinstance(value, int):
            return value
        match = re.match(r"\d+", str(value))
        if not match:
            raise ValueError("DB_PORT must start with a number")
        return int(match.group(0))


settings = Settings()
