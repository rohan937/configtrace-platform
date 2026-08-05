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
    # sk_test_* for test mode, sk_live_* for live mode.
    # NEVER expose this to the frontend.  NEVER log it.
    STRIPE_SECRET_KEY: Optional[str] = None

    # Stripe webhook signing secret — used to verify webhook payloads.
    # Find it in the Stripe dashboard → Developers → Webhooks → Signing secret.
    # NEVER expose this to the frontend.
    # Missing webhook secret disables webhook verification but does NOT block
    # checkout session creation.
    STRIPE_WEBHOOK_SECRET: Optional[str] = None

    # Stripe Price IDs for each paid plan (monthly billing).
    # Create products + prices in the Stripe dashboard, then paste the IDs here.
    # Example: price_1ABC...
    #
    # Three equivalent env var names are supported for each plan so that
    # Render service definitions with different historical naming conventions
    # all resolve correctly.  The first non-empty value wins.
    #
    # Pro plan price ID aliases (use any one):
    STRIPE_PRICE_PRO_MONTHLY: Optional[str] = None       # primary
    STRIPE_PRO_PRICE_ID: Optional[str] = None            # alias
    STRIPE_PRICE_ID_PRO_MONTHLY: Optional[str] = None    # alias
    # Team plan price ID aliases (use any one):
    STRIPE_PRICE_TEAM_MONTHLY: Optional[str] = None      # primary
    STRIPE_TEAM_PRICE_ID: Optional[str] = None           # alias
    STRIPE_PRICE_ID_TEAM_MONTHLY: Optional[str] = None   # alias

    # Public-facing frontend URL — used to build success/cancel URLs for Stripe
    # Checkout.  Defaults to APP_BASE_URL when not set separately.
    # Override in development: FRONTEND_URL=http://localhost:3000
    FRONTEND_URL: Optional[str] = None

    # ── Commercial Infrastructure message 1 — provider-neutral billing ──────
    #
    # BILLING_PROVIDER selects which adapter app.billing.registry returns.
    # "stripe" (default) preserves the existing, already-deployed behavior —
    # message 1 does NOT change any hosted environment's default. Message 2+
    # changes the deployment default to "paddle" once Paddle checkout is
    # actually implemented; setting BILLING_PROVIDER=paddle here with no
    # Paddle price mapping configured fails closed (see
    # app.billing.registry.get_billing_provider) rather than silently using
    # Stripe.
    BILLING_PROVIDER: str = "stripe"

    # Paddle configuration — ALL optional/unset in message 1. No Paddle
    # product/price is created and no Paddle API is called this message;
    # these fields exist only so message 2 can populate them without a
    # settings-schema change.
    #
    # "sandbox" | "production" — never assume sandbox and live values are
    # interchangeable (message-1 spec item 36; message-2 spec item 4).
    PADDLE_ENVIRONMENT: Optional[str] = None
    # Paddle API key — backend only, NEVER exposed to the frontend, NEVER logged.
    PADDLE_API_KEY: Optional[str] = None
    # Paddle webhook/notification signing secret — backend only.
    PADDLE_WEBHOOK_SECRET: Optional[str] = None
    # Paddle recurring price ID for the Team base ($30/month, up to 20 seats) item.
    # PADDLE_TEAM_BASE_PRICE_ID is the message-2 canonical name;
    # PADDLE_BASE_PRICE_ID (message-1 name) is kept as an alias — same
    # multi-alias pattern already used for STRIPE_PRICE_TEAM_MONTHLY.
    PADDLE_TEAM_BASE_PRICE_ID: Optional[str] = None
    PADDLE_BASE_PRICE_ID: Optional[str] = None  # alias (message-1 name)
    # Paddle recurring price ID for the Team additional-seat ($5/month) item.
    PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID: Optional[str] = None
    PADDLE_ADDITIONAL_SEAT_PRICE_ID: Optional[str] = None  # alias (message-1 name)

    # ── Commercial Infrastructure message 2 — Paddle billing integration ────
    #
    # Number of days a past_due subscription retains paid access before
    # entitlements downgrade to free. A single, named setting — never a
    # magic number duplicated across files (message-2 spec item 28).
    BILLING_GRACE_PERIOD_DAYS: int = 7

    # ── Dodo Payments message 1 — Test Mode only ─────────────────────────────
    #
    # ALL optional/unset by default. No Dodo product/customer/subscription/
    # charge is created and no Dodo API is called unless BILLING_PROVIDER is
    # explicitly set to "dodo" AND every field below is populated — this
    # message does not change BILLING_PROVIDER's default ("stripe") in any
    # deployed environment.
    #
    # "test" | "live" — verified base URLs: https://test.dodopayments.com /
    # https://live.dodopayments.com. Never assume test and live credentials
    # or catalog IDs are interchangeable.
    DODO_ENVIRONMENT: Optional[str] = None
    # Dodo API key — backend only, NEVER exposed to the frontend, NEVER logged.
    DODO_API_KEY: Optional[str] = None
    # Dodo webhook signing secret ("whsec_..." — Standard Webhooks format).
    # Backend only, NEVER exposed to the frontend, NEVER logged.
    DODO_WEBHOOK_SECRET: Optional[str] = None
    # Dodo product ID for the Pro plan ($10/month flat recurring price).
    DODO_PRO_PRODUCT_ID: Optional[str] = None
    # Dodo product ID for the Team plan ($30/month base recurring price).
    DODO_TEAM_PRODUCT_ID: Optional[str] = None
    # Dodo add-on ID for the Team additional-seat charge ($5/month per seat
    # above the 20 included in the Team base price).
    DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID: Optional[str] = None

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

    # Slack App signing secret — used to verify incoming Slack interactive action
    # payloads (POST /slack/actions).
    # Find it in api.slack.com → Your App → Basic Information → Signing Secret.
    # NEVER log or expose this value.
    SLACK_SIGNING_SECRET: Optional[str] = None

    # ── Required for Milestone 58.7 (Web Push / PWA notifications) ─────────────
    # VAPID (Voluntary Application Server Identification) keys for Web Push.
    # Generate with: python -c "from py_vapid import Vapid; v=Vapid(); v.generate_keys(); print('PUB:', v.public_key_urlsafe_base64); print('PRIV:', v.private_key_urlsafe_base64)"
    # WEB_PUSH_VAPID_PUBLIC_KEY: base64url-encoded uncompressed EC public key (65 bytes uncompressed)
    # WEB_PUSH_VAPID_PRIVATE_KEY: base64url-encoded EC private key — NEVER expose to frontend.
    WEB_PUSH_VAPID_PUBLIC_KEY: Optional[str] = None
    WEB_PUSH_VAPID_PRIVATE_KEY: Optional[str] = None  # NEVER log or expose
    # mailto: URI or https: URL identifying the push sender.
    WEB_PUSH_SUBJECT: Optional[str] = "mailto:security@configtrace.org"

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
    def effective_stripe_pro_price_id(self) -> Optional[str]:
        """Resolve Pro plan price ID from any supported env var alias.

        Priority: STRIPE_PRICE_PRO_MONTHLY → STRIPE_PRO_PRICE_ID → STRIPE_PRICE_ID_PRO_MONTHLY.
        Returns the first non-empty value, or None if none are set.
        """
        return (
            self.STRIPE_PRICE_PRO_MONTHLY
            or self.STRIPE_PRO_PRICE_ID
            or self.STRIPE_PRICE_ID_PRO_MONTHLY
            or None
        )

    @property
    def effective_stripe_team_price_id(self) -> Optional[str]:
        """Resolve Team plan price ID from any supported env var alias.

        Priority: STRIPE_PRICE_TEAM_MONTHLY → STRIPE_TEAM_PRICE_ID → STRIPE_PRICE_ID_TEAM_MONTHLY.
        Returns the first non-empty value, or None if none are set.
        """
        return (
            self.STRIPE_PRICE_TEAM_MONTHLY
            or self.STRIPE_TEAM_PRICE_ID
            or self.STRIPE_PRICE_ID_TEAM_MONTHLY
            or None
        )

    @property
    def stripe_mode(self) -> str:
        """Detect Stripe key mode from the secret key prefix.

        Returns:
          "test"          — STRIPE_SECRET_KEY starts with sk_test_
          "live"          — STRIPE_SECRET_KEY starts with sk_live_
          "not_configured" — key absent or unrecognised prefix
        """
        key = self.STRIPE_SECRET_KEY or ""
        if key.startswith("sk_test_"):
            return "test"
        if key.startswith("sk_live_"):
            return "live"
        return "not_configured"

    @property
    def is_stripe_configured(self) -> bool:
        """Return True when STRIPE_SECRET_KEY is set and not a placeholder.

        Webhook secret is checked separately via is_webhook_configured.
        A missing webhook secret disables webhook event verification but does
        NOT block checkout session creation — checkout only needs the secret key.
        """
        key = self.STRIPE_SECRET_KEY
        if not key:
            return False
        placeholders = ("replace-with", "CHANGE_ME", "sk_test_placeholder")
        return not any(p in key for p in placeholders)

    @property
    def is_webhook_configured(self) -> bool:
        """Return True when STRIPE_WEBHOOK_SECRET is set and not a placeholder."""
        secret = self.STRIPE_WEBHOOK_SECRET
        if not secret:
            return False
        placeholders = ("replace-with", "CHANGE_ME", "whsec_replace_me")
        return not any(p in secret for p in placeholders)

    @property
    def effective_paddle_team_base_price_id(self) -> Optional[str]:
        """Resolve the Team base price ID from either supported name.

        Priority: PADDLE_TEAM_BASE_PRICE_ID (message-2 canonical) →
        PADDLE_BASE_PRICE_ID (message-1 alias).
        """
        return self.PADDLE_TEAM_BASE_PRICE_ID or self.PADDLE_BASE_PRICE_ID or None

    @property
    def effective_paddle_team_additional_seat_price_id(self) -> Optional[str]:
        """Resolve the Team additional-seat price ID from either supported name."""
        return self.PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID or self.PADDLE_ADDITIONAL_SEAT_PRICE_ID or None

    @property
    def paddle_environment_normalized(self) -> str:
        """Return "sandbox" | "production" | "not_configured".

        Any value not exactly "sandbox" or "production" is treated as
        not_configured — never guessed from a key prefix, since Paddle API
        keys/tokens do not carry an unambiguous, documented sandbox/live
        prefix the way Stripe's sk_test_/sk_live_ do (message-2 spec item 4:
        "sandbox token prefixes are accepted only in sandbox" is enforced at
        the credential-format-validation layer in app.billing.paddle_config,
        not by prefix-sniffing here).
        """
        env = (self.PADDLE_ENVIRONMENT or "").strip().lower()
        if env in ("sandbox", "production"):
            return env
        return "not_configured"

    @property
    def is_paddle_configured(self) -> bool:
        """True when environment, API key, both price IDs, and webhook
        secret are all present. Does NOT validate their format — see
        app.billing.paddle_config.validate_paddle_configuration for the
        fail-closed format/environment-consistency checks."""
        return bool(
            self.paddle_environment_normalized != "not_configured"
            and self.PADDLE_API_KEY
            and self.PADDLE_WEBHOOK_SECRET
            and self.effective_paddle_team_base_price_id
            and self.effective_paddle_team_additional_seat_price_id
        )

    @property
    def dodo_environment_normalized(self) -> str:
        """Return "test" | "live" | "not_configured".

        Accepts BOTH naming conventions and normalizes to the canonical
        internal value used everywhere else in this codebase ("test" /
        "live"):

          * "test" / "live" — this codebase's own short form, used
            internally (base URL selection, catalog mapping, etc.).
          * "test_mode" / "live_mode" — Dodo's own OFFICIAL SDK
            convention, confirmed from the official Python SDK README
            (`environment="test_mode"`, defaults to `"live_mode"`) and
            the official Node.js SDK (`environment: 'test_mode'`) during
            a post-implementation documentation audit. Accepting this
            form avoids an operator who copies Dodo's own documented
            example being rejected by ConfigTrace's config validation.

        Any other value is treated as not_configured — never guessed from
        a key format, since Dodo does not document an unambiguous
        test/live credential-prefix convention (verified: test and live
        are two entirely separate dashboards/API-key spaces, not a shared
        namespace distinguished by prefix)."""
        env = (self.DODO_ENVIRONMENT or "").strip().lower()
        if env in ("test", "test_mode"):
            return "test"
        if env in ("live", "live_mode"):
            return "live"
        return "not_configured"

    @property
    def is_dodo_configured(self) -> bool:
        """True when environment, API key, both product IDs, the addon
        ID, and the webhook secret are all present. Does NOT validate
        their format — see
        app.billing.dodo_config.validate_dodo_configuration for the
        fail-closed format/consistency checks."""
        return bool(
            self.dodo_environment_normalized != "not_configured"
            and self.DODO_API_KEY
            and self.DODO_WEBHOOK_SECRET
            and self.DODO_PRO_PRODUCT_ID
            and self.DODO_TEAM_PRODUCT_ID
            and self.DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID
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
    def is_web_push_configured(self) -> bool:
        """Return True when VAPID keys are set and not placeholders."""
        if not self.WEB_PUSH_VAPID_PUBLIC_KEY or not self.WEB_PUSH_VAPID_PRIVATE_KEY:
            return False
        placeholders = ("replace-with", "CHANGE_ME", "your-vapid")
        return not any(
            p in (self.WEB_PUSH_VAPID_PUBLIC_KEY or "") or p in (self.WEB_PUSH_VAPID_PRIVATE_KEY or "")
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
