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

    # ── Required for Milestone 24 (high-risk email alerts) ──────────────────
    # Resend API key.  Used by the worker to send email alerts when a sync
    # detects a high- or critical-risk change.  When unset, alert dispatch
    # logs a clear warning and skips sending — the sync itself still succeeds.
    # Obtain from https://resend.com → API Keys.
    RESEND_API_KEY: Optional[str] = None

    # "From" address on alert emails.  Must be on a verified Resend domain.
    # Example: ConfigTrace Alerts <alerts@configtrace.org>
    # When unset, alert dispatch skips sending.
    ALERTS_FROM_EMAIL: Optional[str] = None

    # Base URL of the ConfigTrace frontend, used to build deep links into
    # the change detail page (e.g. https://app.configtrace.org/changes/<id>).
    # The default is fine for production; override locally for dev/staging.
    APP_BASE_URL: str = "https://app.configtrace.org"

    # "From" address for transactional emails (invites, etc.).
    # Distinct from ALERTS_FROM_EMAIL — invites use a friendlier sender address.
    # Must be on a verified Resend domain.
    # Example: ConfigTrace <invites@configtrace.org>
    # When unset, invite emails are skipped — the copy-link fallback is used.
    EMAIL_FROM: Optional[str] = None

    # ── Required for Milestone 52 (Billing + Usage Limits) ─────────────────
    # Stripe secret key — used to create Checkout/Portal sessions via the API.
    # Find it in the Stripe dashboard → Developers → API keys → Secret key.
    # NEVER expose this to the frontend.  NEVER log it.
    STRIPE_SECRET_KEY: Optional[str] = None

    # Stripe webhook signing secret — used to verify webhook payloads.
    # Find it in the Stripe dashboard → Developers → Webhooks → Signing secret.
    # NEVER expose this to the frontend.
    STRIPE_WEBHOOK_SECRET: Optional[str] = None

    # Stripe Price IDs for each paid plan (monthly billing).
    # Create products + prices in the Stripe dashboard, then paste the IDs here.
    # Example: price_1ABC...
    STRIPE_PRICE_PRO_MONTHLY: Optional[str] = None
    STRIPE_PRICE_TEAM_MONTHLY: Optional[str] = None

    # Public-facing frontend URL — used to build success/cancel URLs for Stripe
    # Checkout.  Defaults to APP_BASE_URL when not set separately.
    # Override in development: FRONTEND_URL=http://localhost:3000
    FRONTEND_URL: Optional[str] = None

    # ── Required for Milestone 31 (GitHub App integration) ──────────────────
    # GitHub App numeric ID — shown on the App settings page.
    GITHUB_APP_ID: Optional[str] = None

    # GitHub App slug — the lowercase URL-safe name used in the install URL:
    #   https://github.com/apps/<GITHUB_APP_SLUG>/installations/new
    # Find it on the GitHub App settings page under "Public link".
    GITHUB_APP_SLUG: Optional[str] = None

    # RSA private key for the GitHub App, used to sign App JWTs (RS256).
    # In Render: base64-encode the PEM file contents into a single env var:
    #   base64 -w 0 private-key.pem
    # Locally: paste the literal PEM (including -----BEGIN RSA PRIVATE KEY-----)
    # NEVER log or expose this value.
    GITHUB_APP_PRIVATE_KEY: Optional[str] = None

    # Random secret used to HMAC-sign state tokens (CSRF protection for the
    # GitHub App install callback).  Generate with:
    #   python -c "import secrets; print(secrets.token_hex(32))"
    # Must be the same value on all API service instances.
    # NEVER log or expose this value.
    GITHUB_APP_OAUTH_STATE_SECRET: Optional[str] = None

    # ── Required for Milestone 58.5 (Slack App installation) ────────────────
    # Slack App OAuth credentials.  Obtain from api.slack.com → Your Apps.
    # NEVER log or expose these values.
    SLACK_CLIENT_ID: Optional[str] = None
    SLACK_CLIENT_SECRET: Optional[str] = None

    # OAuth redirect URI — must match the "Redirect URLs" list in Slack App config.
    # Example: https://api.configtrace.org/slack/oauth/callback
    SLACK_REDIRECT_URI: Optional[str] = None

    # Random secret for HMAC-signing OAuth state tokens (CSRF protection).
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    # NEVER log or expose this value.
    SLACK_APP_STATE_SECRET: Optional[str] = None

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
    def is_stripe_configured(self) -> bool:
        """Return True when Stripe secret key and webhook secret are both set."""
        if not self.STRIPE_SECRET_KEY or not self.STRIPE_WEBHOOK_SECRET:
            return False
        placeholders = ("replace-with", "CHANGE_ME", "sk_test_placeholder")
        return not any(
            p in (self.STRIPE_SECRET_KEY or "")
            for p in placeholders
        )

    @property
    def effective_frontend_url(self) -> str:
        """Return FRONTEND_URL if set, else fall back to APP_BASE_URL."""
        return (self.FRONTEND_URL or self.APP_BASE_URL).rstrip("/")

    @property
    def is_invite_email_configured(self) -> bool:
        """Return True when Resend is set up and EMAIL_FROM is present.

        Invite emails use EMAIL_FROM (e.g. invites@configtrace.org) rather
        than ALERTS_FROM_EMAIL so invite and alert emails have distinct senders.
        If only ALERTS_FROM_EMAIL is set (and not EMAIL_FROM), invite emails are
        skipped — the copy-link fallback is shown instead.
        """
        if not self.RESEND_API_KEY or not self.EMAIL_FROM:
            return False
        placeholders = ("replace-with", "CHANGE_ME", "your-resend")
        return not any(
            p in (self.RESEND_API_KEY or "") or p in (self.EMAIL_FROM or "")
            for p in placeholders
        )

    @property
    def is_email_alerting_configured(self) -> bool:
        """Return True when both Resend API key and From address are set.

        Treats placeholder values from the example .env files as "not
        configured" so copying .env.example never accidentally tries to send
        from an unverified domain.
        """
        if not self.RESEND_API_KEY or not self.ALERTS_FROM_EMAIL:
            return False
        placeholders = ("replace-with", "CHANGE_ME", "your-resend")
        return not any(
            p in (self.RESEND_API_KEY or "") or p in (self.ALERTS_FROM_EMAIL or "")
            for p in placeholders
        )

    @property
    def is_slack_app_configured(self) -> bool:
        """Return True when Slack App OAuth credentials are set.

        Treats placeholder values from the example .env files as "not
        configured" so copying .env.example never accidentally triggers
        Slack OAuth in a dev environment.
        """
        if not self.SLACK_CLIENT_ID or not self.SLACK_CLIENT_SECRET:
            return False
        placeholders = ("replace-with", "CHANGE_ME", "your-slack")
        return not any(
            p in (self.SLACK_CLIENT_ID or "") or p in (self.SLACK_CLIENT_SECRET or "")
            for p in placeholders
        )

    @property
    def cors_origins(self) -> list[str]:
        """Return parsed CORS origins as a list, stripping whitespace."""
        return [
            origin.strip()
            for origin in self.BACKEND_CORS_ORIGINS.split(",")
            if origin.strip()
        ]


settings = Settings()
