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
    DIGITAL_TWIN_BASE_URL: str = "http://localhost:8080"

    OPENAI_API_KEY: str | None = None
    CLAUDE_API_KEY: str | None = None
    GEMINI_API_KEY: str | None = None
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    
    @property
    def DATABASE_URL(self) -> str:
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
