from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ── Required from the start ──────────────────────────────────────────────
    DATABASE_URL: str
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── Required for Milestone 3 (auth) ─────────────────────────────────────
    # Optional until Clerk JWT middleware is wired in.
    SECRET_KEY: Optional[str] = None
    CLERK_SECRET_KEY: Optional[str] = None

    # ── Required for Milestone 7 (credential encryption) ────────────────────
    # base64-encoded 32-byte AES-GCM key.
    ENCRYPTION_KEY: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        # Ignore extra env vars passed by Docker Compose (POSTGRES_*, etc.)
        extra="ignore",
    )


settings = Settings()
