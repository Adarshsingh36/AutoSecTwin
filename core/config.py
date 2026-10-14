import json
import re

from pydantic import field_validator, model_validator
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
    DB_PASSWORD: str | None = None

    AUTH_ENABLED: bool = True
    AUTH_SECRET_KEY: str | None = None
    AUTH_TOKEN_TTL_SECONDS: int = 3600
    # JSON object: {"username": {"password_hash": "...", "roles": ["admin"]}}
    AUTH_USERS_JSON: str = "{}"
    # JSON object: {"sha256(token)": ["admin"]}; useful for service tokens.
    AUTH_STATIC_TOKEN_HASHES_JSON: str = "{}"
    # Optional plain dev/test token. Refused when ENVIRONMENT=production.
    AUTH_DEV_ADMIN_TOKEN: str | None = None

    NVD_API_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_BASE_URL: str = "https://api.first.org/data/v1/epss"
    EXPLOITDB_BASE_URL: str = "https://www.exploit-db.com"
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    METASPLOIT_RPC_URL: str = "http://localhost:55552/api/"
    METASPLOIT_RPC_USERNAME: str | None = None
    METASPLOIT_RPC_PASSWORD: str | None = None
    DIGITAL_TWIN_BASE_URL: str = "http://localhost:8081"

    # Real (non-mock) exploit execution: driving Metasploit's console to run
    # a module and watching for a resulting session, per the proven pattern
    # in test_console_check.py -- module.execute()'s raw RPC response alone
    # never carries session/proof evidence, only the console transcript does.
    EXPLOIT_CONSOLE_POLL_INTERVAL_SECONDS: float = 2.0
    EXPLOIT_CONSOLE_MAX_WAIT_SECONDS: float = 90.0
    # After a session appears, how long verification commands (sysinfo/
    # getuid/pwd or whoami/hostname/pwd) are allowed to take in total.
    SESSION_VERIFICATION_TIMEOUT_SECONDS: float = 20.0
    SESSION_SHELL_COMMAND_SETTLE_SECONDS: float = 2.0

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
    ORCHESTRATION_DESTROY_TWIN_AFTER_RUN: bool = True

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

    # Code-change remediation (see services/remediation/code_remediation.py).
    # Off by default: CODE_REMEDIATION_ALLOWED_ROOT must be explicitly set
    # to an absolute path before any file may be proposed or modified.
    # Only files inside this directory can ever be touched.
    CODE_REMEDIATION_ALLOWED_ROOT: str | None = None
    CODE_REMEDIATION_TEST_COMMAND: str = "pytest"
    CODE_REMEDIATION_TEST_TIMEOUT_SECONDS: float = 120.0

    @property
    def DATABASE_URL(self) -> str:
        if self.DATABASE_URL_OVERRIDE:
            return self.DATABASE_URL_OVERRIDE
        if not self.DB_PASSWORD:
            raise ValueError("DB_PASSWORD must be set unless DATABASE_URL_OVERRIDE is configured")
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

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        env = self.ENVIRONMENT.lower()
        if env == "production":
            if not self.AUTH_ENABLED:
                raise ValueError("AUTH_ENABLED cannot be false in production")
            if self.AUTH_DEV_ADMIN_TOKEN:
                raise ValueError("AUTH_DEV_ADMIN_TOKEN cannot be set in production")
            if not self.AUTH_SECRET_KEY and not self.AUTH_STATIC_TOKEN_HASHES_JSON.strip("{} \t\r\n"):
                raise ValueError(
                    "Production auth requires AUTH_SECRET_KEY or AUTH_STATIC_TOKEN_HASHES_JSON"
                )
            if not self.DB_PASSWORD:
                raise ValueError("DB_PASSWORD must be set in production")
            if not self.METASPLOIT_RPC_USERNAME or not self.METASPLOIT_RPC_PASSWORD:
                raise ValueError("Metasploit RPC credentials must be set in production")

        for field_name in ("AUTH_USERS_JSON", "AUTH_STATIC_TOKEN_HASHES_JSON"):
            try:
                value = json.loads(getattr(self, field_name))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{field_name} must be valid JSON") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{field_name} must be a JSON object")

        return self


settings = Settings()
