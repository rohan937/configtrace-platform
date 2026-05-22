from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ── Environment ──────────────────────────────────────────────────────────
    # Explicit environment name.  Defaults to "development" so production can
    # never accidentally be reached by omitting the variable.  Set to
    # "production" in production deployments only.
    ENVIRONMENT: str = "development"

    # ── Required from the start ──────────────────────────────────────────────
    DATABASE_URL: str
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── CORS ─────────────────────────────────────────────────────────────────
    # Comma-separated list of allowed frontend origins.
    # Local default covers the Next.js dev server.
    # Set explicitly in production: https://app.configtrace.org,https://configtrace.org
    BACKEND_CORS_ORIGINS: str = "http://localhost:3000,http://localhost:3001"

    # ── Required for Milestone 3 (auth) ─────────────────────────────────────
    # Optional until Clerk JWT middleware is wired in.
    SECRET_KEY: Optional[str] = None
    CLERK_SECRET_KEY: Optional[str] = None

    # ── Required for Milestone 21 (JWT verification) ────────────────────────
    # Clerk's JWKS endpoint, used to verify the RS256 signature on incoming
    # tokens.  Find it in your Clerk dashboard → API Keys → Show JWT public key
    # → "JWKS URL".  Typically:
    #   https://<your-clerk-frontend-api>.clerk.accounts.dev/.well-known/jwks.json
    #
    # When unset in a non-production environment, the backend falls back to
    # dev-mode auth (auto-creates a dev user — no real Clerk required).
    # When unset in production, every protected route returns HTTP 503.
    CLERK_JWKS_URL: Optional[str] = None

    # Optional explicit issuer claim to match against the JWT `iss` claim.
    # If unset, the issuer check is skipped (signature + expiry still enforced).
    CLERK_ISSUER: Optional[str] = None

    # ── Required for Milestone 7 (credential encryption) ────────────────────
    # base64-encoded 32-byte AES-GCM key.
    ENCRYPTION_KEY: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        # Ignore extra env vars passed by Docker Compose (POSTGRES_*, etc.)
        extra="ignore",
    )

    # ── Derived properties ───────────────────────────────────────────────────

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT.lower() in ("development", "dev")

    @property
    def is_clerk_configured(self) -> bool:
        """Return True when a real Clerk JWKS URL is configured.

        Treats placeholder values from the example .env files as "not
        configured" so that copying .env.example does not accidentally flip
        production-mode auth on in local development.
        """
        url = self.CLERK_JWKS_URL
        if not url:
            return False
        placeholders = ("replace-with", "CHANGE_ME", "your-clerk")
        return not any(p in url for p in placeholders)

    @property
    def cors_origins(self) -> list[str]:
        """Return parsed CORS origins as a list, stripping whitespace."""
        return [
            origin.strip()
            for origin in self.BACKEND_CORS_ORIGINS.split(",")
            if origin.strip()
        ]


settings = Settings()
