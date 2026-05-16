"""Configuration loaded from environment variables.

All settings are validated at import time. Bad config fails loudly, not silently.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, PostgresDsn, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Application settings.

    Loaded from .env at the project root, then overlaid with actual environment
    variables. Process environment wins over file.
    """

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Postgres
    postgres_host: str = Field(default="localhost")
    postgres_port: int = Field(default=5432)
    postgres_db: str = Field(default="threat_intel")
    postgres_user: str = Field(default="threat_intel")
    postgres_password: str = Field(default="")

    # Logging
    log_level: str = Field(default="INFO")
    log_dir: Path = Field(default=PROJECT_ROOT / "logs")

    # HTTP
    http_user_agent: str = Field(
        default="threat-intel-attack-trends/0.1 (research)"
    )
    http_timeout_seconds: float = Field(default=30.0)
    http_max_retries: int = Field(default=3)

    # ATT&CK
    attack_version: str = Field(default="v15.1")
    attack_bundle_url: str = Field(
        default=(
            "https://raw.githubusercontent.com/mitre/cti/"
            "ATT%26CK-v15.1/enterprise-attack/enterprise-attack.json"
        )
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def postgres_dsn(self) -> str:
        """SQLAlchemy-compatible DSN."""
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def project_root(self) -> Path:
        return PROJECT_ROOT


# Module-level singleton. Import and use.
settings = Settings()
