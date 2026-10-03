from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    app_env: str = "development"
    database_url: str = "sqlite:///./secureshare.db"
    max_upload_mb: int = Field(default=25, ge=1, le=100)
    session_expiry_minutes: int = Field(default=30, ge=1)
    replay_window_seconds: int = Field(default=300, ge=1)
    rate_limit_login: int = Field(default=12, ge=1)
    rate_limit_upload: int = Field(default=20, ge=1)
    rate_limit_verification: int = Field(default=60, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)
    login_failure_threshold: int = Field(default=5, ge=2)
    login_lock_seconds: int = Field(default=60, ge=1)
    storage_path: Path = Path("storage")
    log_level: str = "INFO"
    enable_attack_demos: bool = True
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    token_expiry_minutes: int = Field(default=120, ge=1)
    challenge_expiry_seconds: int = Field(default=120, ge=1)

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024
