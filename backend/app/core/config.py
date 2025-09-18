"""Application configuration.

All configuration is environment driven.  Secrets are never stored in the
repository, never written to logs and never sent to sandbox workers.
"""

from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_DIR = BACKEND_DIR.parent


def _default_secret() -> str:
    return secrets.token_urlsafe(48)


def _env_files() -> list[str]:
    """Return the ordered list of dotenv files that are read."""
    explicit = os.getenv("SAXIS_ENV_FILE")
    candidates = [explicit] if explicit else []
    candidates.extend([str(BACKEND_DIR / ".env"), str(REPO_DIR / ".env")])
    return [path for path in candidates if path]


class Settings(BaseSettings):
    """Runtime settings for the Secure AI Tool Execution & Permission Sandbox."""

    model_config = SettingsConfigDict(
        env_prefix="SAXIS_",
        env_file=_env_files(),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------ app
    app_name: str = "Secure AI Tool Execution & Permission Sandbox"
    app_version: str = "1.0.0"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False
    api_prefix: str = "/api/v1"
    log_level: str = "INFO"
    log_json: bool = True

    # ------------------------------------------------------------- database
    database_url: str = Field(default=f"sqlite:///{BACKEND_DIR / 'data' / 'sandbox.db'}")
    sql_echo: bool = False

    # ---------------------------------------------------------------- auth
    auth_mode: Literal["multiuser", "local"] = "multiuser"
    secret_key: str = Field(default_factory=_default_secret)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 14
    session_cookie_name: str = "sax_session"
    csrf_cookie_name: str = "sax_csrf"
    csrf_header_name: str = "X-CSRF-Token"
    bcrypt_rounds: int = 12
    allow_registration: bool = False
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "admin-change-me"  # noqa: S105 - a documented default, must be changed
    allowed_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ]
    )
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
    rate_limit_login_requests: int = 10
    rate_limit_login_window_seconds: int = 60
    trusted_hosts: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # ----------------------------------------------------------- workspace
    workspace_root: Path = Field(default=REPO_DIR / "sandbox_workspace")
    artifact_root: Path = Field(default=BACKEND_DIR / "data" / "artifacts")
    # A private, per-run job directory; it is never a shared world-writable path.
    job_root: Path = Field(
        default=Path(os.getenv("SAXIS_JOB_ROOT", "/tmp/saxis-jobs"))  # nosec B108
    )
    max_workspace_file_bytes: int = 1_048_576
    max_artifact_bytes: int = 262_144
    max_artifact_count_per_session: int = 200
    max_list_entries: int = 5_000
    max_search_results: int = 500
    #: Limits for the files that are copied into a sandbox job workspace.
    max_staged_bytes: int = 2_097_152
    max_staged_files: int = 200

    # ------------------------------------------------------------- sandbox
    sandbox_backend: Literal["docker", "local-simulated"] = "docker"
    sandbox_image: str = "secure-ai-sandbox-runner:latest"
    sandbox_pull_image: bool = True
    sandbox_user: str = "65534:65534"
    sandbox_uid: int = 65534
    sandbox_gid: int = 65534
    sandbox_workdir: str = "/workspace"
    sandbox_timeout_seconds: int = 30
    sandbox_max_output_bytes: int = 262_144
    sandbox_max_memory_mb: int = 512
    sandbox_max_cpu_cores: float = 1.0
    sandbox_max_pids: int = 64
    sandbox_max_tmpfs_mb: int = 64
    sandbox_deny_network: bool = True
    sandbox_allow_network_exceptions: Annotated[list[str], NoDecode] = Field(default_factory=list)
    sandbox_seccomp_profile: str = "default"
    sandbox_seccomp_profile_path: Path = Field(
        default=REPO_DIR / "docker" / "seccomp" / "sandbox.json", repr=False
    )
    sandbox_apparmor_profile: str = "docker-default"
    sandbox_rootless: bool = True
    sandbox_docker_binary: str = "docker"
    sandbox_container_prefix: str = "saxis"
    sandbox_exec_tool_timeout: int = 300
    sandbox_container_ttl_seconds: int = 900

    # ------------------------------------------------------------- policy
    policy_dir: Path = Field(default=BACKEND_DIR / "policies")
    policy_file: Path = Field(default=BACKEND_DIR / "policies" / "default.yaml")
    policy_allow_admin_edit: bool = True
    policy_grant_ttl_seconds: int = 3600

    # ----------------------------------------------------------- providers
    default_provider: str = "ollama"
    provider_api_key: str = ""
    provider_base_url: str = "http://localhost:11434/v1"
    provider_model: str = "gemma2:2b"
    provider_timeout_seconds: int = 120
    provider_max_retries: int = 2
    provider_max_tokens: int = 4096
    provider_temperature: float = 0.2
    provider_secret_key: str = ""  # Fernet key used to encrypt stored provider keys
    provider_key_env_var: str = "SAXIS_PROVIDER_API_KEY"

    # ------------------------------------------------------------- budgets
    budget_session_usd: float = 1.00
    budget_daily_usd: float = 10.00
    budget_enabled: bool = True
    cost_aware_enabled: bool = True

    # -------------------------------------------------------------- agent
    agent_max_steps: int = 12
    agent_max_tool_calls_per_step: int = 4
    agent_step_timeout_seconds: int = 180
    agent_max_input_chars: int = 100_000

    # -------------------------------------------------------------- audit
    audit_retention_days: int = 90
    audit_hash_algorithm: str = "sha256"
    audit_integrity_enabled: bool = True

    # ---------------------------------------------------------------- misc
    shutdown_grace_seconds: int = 15
    metrics_enabled: bool = True
    cors_allow_credentials: bool = True

    @field_validator("database_url", mode="before")
    @classmethod
    def _expand_database_url(cls, value: object) -> object:
        """Resolve a relative SQLite path against the backend directory."""
        if isinstance(value, str) and value.startswith("sqlite:///") and not value.startswith("sqlite:////"):
            suffix = value[len("sqlite:///") :]
            if suffix and not Path(suffix).is_absolute():
                return f"sqlite:///{(BACKEND_DIR / suffix).resolve()}"
        return value

    @field_validator(
        "workspace_root",
        "artifact_root",
        "job_root",
        "policy_dir",
        "policy_file",
        mode="before",
    )
    @classmethod
    def _expand_path(cls, value: object) -> object:
        """Resolve relative paths against the backend directory."""
        if isinstance(value, str):
            path = Path(value).expanduser()
            if not path.is_absolute():
                path = (BACKEND_DIR / path).resolve()
            return path
        if isinstance(value, Path):
            path = value.expanduser()
            if not path.is_absolute():
                path = (BACKEND_DIR / path).resolve()
            return path
        return value

    @field_validator("allowed_origins", "trusted_hosts", "sandbox_allow_network_exceptions", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def _production_guards(self) -> Settings:
        if self.environment == "production":
            if self.secret_key == _default_secret():  # pragma: no cover - defensive
                raise ValueError("SAXIS_SECRET_KEY must be set explicitly in production")
            if self.auth_mode != "multiuser":
                raise ValueError("Production deployments must use auth_mode=multiuser")
            if self.sandbox_backend != "docker":
                raise ValueError("Production deployments must use the docker sandbox backend")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def ensure_directories(self) -> None:
        for path in (
            self.workspace_root,
            self.artifact_root,
            self.job_root,
            self.policy_dir,
            BACKEND_DIR / "data",
        ):
            path.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    settings = Settings()
    settings.ensure_directories()
    return settings


def reload_settings() -> Settings:
    """Clear the settings cache (used by tests)."""
    get_settings.cache_clear()
    return get_settings()
