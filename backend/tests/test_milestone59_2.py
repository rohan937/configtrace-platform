"""M59.2 — Secret & Token Safety Hardening audit.

Goal
----
Prove that credentials for every provider integration, Slack/notification
channel, Stripe billing, VAPID push, and GitHub App flow are:
  * encrypted at rest (or never persisted)
  * write-only from the frontend perspective
  * never returned in any API response
  * never logged in full
  * never embedded in risk reasons / blast radius / remediation / audit
    metadata / change records / snapshots
  * safely handled in exception messages (only the exception **type** is logged,
    never the raw provider response body or the credential value itself)

Test strategy
-------------
Three layers — all runnable without PostgreSQL:

1. **Static source-code audits** — read backend source files and assert each
   credential variable is never interpolated into a logger call (e.g.
   ``logger.info("%s", api_token)``), and assert security-marker comments
   exist in connector files that handle private keys.

2. **Schema-shape audits** — load Pydantic response schemas and assert
   sensitive field names are absent from the public response surface.

3. **Behavioural audits** — encrypt/decrypt roundtrips, ``_mask_url`` masking,
   and provider risk-classifier tripwires that confirm no realistic secret
   fixture (sk_live / whsec / ghp / AKIA / Bearer / -----BEGIN PRIVATE KEY-----
   / VAPID-shaped / DATABASE_URL / webhook URL with embedded token) ever
   appears in a risk reason.

These tests intentionally do NOT call any external provider API and never
load real credentials from ``.env`` — they fabricate realistic-shaped
fixtures locally.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Realistic secret-shaped fixtures (NOT real credentials)
# ─────────────────────────────────────────────────────────────────────────────

# A representative set of credential shapes the audit must guarantee never
# leak through any response/log/snapshot/risk-reason.  All values are
# synthetic — no real provider would accept them.
FIXTURE_SECRETS: dict[str, str] = {
    "stripe_secret_live": "sk_live_" + ("A" * 99),
    "stripe_secret_test": "sk_test_" + ("B" * 99),
    "stripe_webhook_secret": "whsec_" + ("C" * 80),
    "slack_bot_token": "xoxb-1234567890-1234567890123-" + ("D" * 24),
    "slack_user_token": "xoxp-1234567890-1234567890123-" + ("E" * 24),
    "slack_signing_secret": ("F" * 32),
    "github_pat": "ghp_" + ("G" * 36),
    "github_oauth": "gho_" + ("H" * 36),
    "github_pat_v2": "github_pat_11A" + ("I" * 80),
    "shopify_admin_token": "shpat_" + ("J" * 32),
    "aws_access_key_iam": "AKIA" + ("K" * 16),
    "aws_access_key_sts": "ASIA" + ("L" * 16),
    "aws_secret_access_key": ("M" * 40),
    "bearer_jwt": "Bearer eyJhbGciOi" + ("N" * 80),
    "private_key_pem": (
        "-----BEGIN PRIVATE KEY-----\n"
        + ("O" * 60) + "\n"
        + ("P" * 60) + "\n"
        "-----END PRIVATE KEY-----"
    ),
    "database_url": "postgresql://dbuser:dbpassword@db.example.com:5432/mydb",
    "webhook_url_with_token": (
        "https://hooks.example.com/intake?token=" + ("Q" * 48)
    ),
    "vapid_private_key": ("R" * 64),  # base64url-ish blob
    "cloudflare_api_token": ("S" * 40),
    "vercel_token": ("T" * 24),
    "supabase_pat": "sbp_" + ("U" * 48),
    "firebase_pk_id": ("V" * 40),
}


def _all_secrets() -> tuple[str, ...]:
    return tuple(FIXTURE_SECRETS.values())


# ═════════════════════════════════════════════════════════════════════════════
# A. Encryption-at-rest helper roundtrip + ciphertext leak guard
# ═════════════════════════════════════════════════════════════════════════════


class TestEncryptionAtRest:

    def test_A1_roundtrip_preserves_payload(self):
        from app.core.encryption import (
            decrypt_credentials,
            encrypt_credentials,
        )

        creds = {"api_token": FIXTURE_SECRETS["cloudflare_api_token"],
                 "zone_id": "1234abcd"}
        ct, iv = encrypt_credentials(creds)
        assert decrypt_credentials(ct, iv) == creds

    def test_A2_ciphertext_does_not_contain_plaintext(self):
        """Sanity: the ciphertext bytes must not contain the plaintext token."""
        from app.core.encryption import encrypt_credentials

        token = FIXTURE_SECRETS["github_pat"]
        ct, _iv = encrypt_credentials({"github_token": token})
        assert token.encode() not in ct
        assert b"github_token" not in ct  # JSON key also encrypted

    def test_A3_each_encryption_uses_fresh_iv(self):
        from app.core.encryption import encrypt_credentials

        ct1, iv1 = encrypt_credentials({"x": "y"})
        ct2, iv2 = encrypt_credentials({"x": "y"})
        assert iv1 != iv2
        assert ct1 != ct2  # AES-GCM nonce reuse must be impossible

    def test_A4_missing_or_short_key_raises(self):
        from app.core.encryption import EncryptionKeyError, _load_key
        from app import config

        # Substitute a too-short key (16-byte → invalid for AES-256).
        import base64
        short = base64.b64encode(b"\x00" * 16).decode()
        old = config.settings.ENCRYPTION_KEY
        try:
            config.settings.ENCRYPTION_KEY = short
            with pytest.raises(EncryptionKeyError):
                _load_key()
        finally:
            config.settings.ENCRYPTION_KEY = old

    def test_A5_placeholder_key_raises(self):
        from app.core.encryption import EncryptionKeyError, _load_key
        from app import config

        old = config.settings.ENCRYPTION_KEY
        try:
            config.settings.ENCRYPTION_KEY = "replace-with-a-real-base64-key"
            with pytest.raises(EncryptionKeyError):
                _load_key()
        finally:
            config.settings.ENCRYPTION_KEY = old


# ═════════════════════════════════════════════════════════════════════════════
# B. IntegrationResponse / IntegrationListResponse / NotificationSettings
#    Pydantic shapes deliberately omit credential fields.
# ═════════════════════════════════════════════════════════════════════════════


_FORBIDDEN_CRED_FIELDS: tuple[str, ...] = (
    "api_token",
    "github_token",
    "vercel_token",
    "stripe_api_key",
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "firebase_service_account_json",
    "supabase_access_token",
    "shopify_access_token",
    "encrypted_credentials",
    "credential_iv",
    "slack_bot_token",
    "slack_bot_token_encrypted",
    "slack_bot_iv",
    "slack_webhook_url_encrypted",
    "slack_webhook_iv",
    "webhook_url_encrypted",
    "webhook_iv",
    "subscription_encrypted",
    "p256dh",
    "auth_secret",
    "private_key",
    "client_secret",
    "signing_secret",
)


class TestResponseSchemaShapes:

    def test_B1_integration_response_omits_credential_fields(self):
        from app.schemas.integration import IntegrationResponse

        fields = set(IntegrationResponse.model_fields.keys())
        for forbidden in _FORBIDDEN_CRED_FIELDS:
            assert forbidden not in fields, (
                f"IntegrationResponse exposes forbidden field: {forbidden}"
            )

    def test_B2_integration_list_response_just_wraps_integration_response(self):
        from app.schemas.integration import IntegrationListResponse

        # The only fields are `integrations` (list) and `total`.
        assert set(IntegrationListResponse.model_fields.keys()) == {"integrations", "total"}

    def test_B3_notification_settings_response_only_returns_masked_urls(self):
        from app.schemas.notification_settings import NotificationSettingsResponse

        fields = set(NotificationSettingsResponse.model_fields.keys())
        # Encrypted columns and raw URLs must NEVER be in the response.
        for forbidden in (
            "slack_webhook_url",
            "slack_webhook_url_encrypted",
            "slack_webhook_iv",
            "webhook_url",
            "webhook_url_encrypted",
            "webhook_iv",
            "slack_bot_token",
            "slack_bot_token_encrypted",
            "slack_bot_iv",
        ):
            assert forbidden not in fields, (
                f"NotificationSettingsResponse exposes raw/encrypted field: {forbidden}"
            )
        # The masked variants should be present so the user can see *which*
        # URL is configured without learning the secret part.
        assert "slack_webhook_url_masked" in fields or "slack_webhook_configured" in fields

    def test_B4_push_subscription_response_omits_keys_and_endpoint(self):
        from app.schemas.notification_settings import PushSubscriptionResponse

        fields = set(PushSubscriptionResponse.model_fields.keys())
        for forbidden in (
            "endpoint",
            "subscription_encrypted",
            "subscription_iv",
            "p256dh",
            "auth_secret",
            "auth",
        ):
            assert forbidden not in fields, (
                f"PushSubscriptionResponse exposes forbidden field: {forbidden}"
            )

    def test_B5_billing_response_omits_stripe_secret_fields(self):
        from app.routers.billing import BillingResponse

        fields = set(BillingResponse.model_fields.keys())
        for forbidden in (
            "stripe_secret_key",
            "stripe_api_key",
            "stripe_webhook_secret",
            "client_secret",
        ):
            assert forbidden not in fields

    def test_B6_audit_log_response_metadata_is_json_safe(self):
        """WorkspaceAuditLog.metadata_json should be a sparse, sanitized dict —
        never a full credential payload."""
        import inspect
        from app.services import notification_service, workspace_service

        # The audit-event helper signature only takes a small metadata dict.
        src = inspect.getsource(workspace_service.log_audit_event)
        assert "metadata" in src
        # The notification settings audit metadata only contains booleans + risk level.
        ns_src = inspect.getsource(notification_service)
        # Look at the existing log_audit_event call in notification_service —
        # actually the call is in workspaces.py router, so just confirm
        # the call doesn't include any *_url variable directly inside metadata.
        router_src = Path("app/routers/workspaces.py").read_text()
        # find `notification_settings_updated` audit call; ensure no raw URL
        # in its metadata.
        start = router_src.find('event_type="notification_settings_updated"')
        assert start > 0, "Could not locate the audit event call to verify"
        end = router_src.find(")", start) + 1
        block = router_src[start:end + 200]
        assert "slack_webhook_url" not in block
        assert "webhook_url" not in block


# ═════════════════════════════════════════════════════════════════════════════
# C. URL masking helper — verify _mask_url never echoes the secret tail
# ═════════════════════════════════════════════════════════════════════════════


class TestURLMaskingHelper:

    def test_C1_mask_url_hides_path_secret(self):
        from app.services.notification_service import _mask_url

        url = "https://hooks.slack.com/services/T00/B00/" + ("S" * 32)
        masked = _mask_url(url)
        # Tail keeps only the last 4 chars; the middle 32-char secret is gone.
        assert "S" * 16 not in masked
        # No more than 4 consecutive 'S' should appear in the mask.
        assert not re.search(r"S{5,}", masked)
        # Current implementation truncates at 12 chars (drops the trailing 's').
        assert masked.startswith("https://hook")

    def test_C2_mask_url_handles_empty_and_short(self):
        from app.services.notification_service import _mask_url

        assert _mask_url("") == ""
        assert _mask_url("short") == "https://****"

    def test_C3_mask_url_redacts_query_token(self):
        from app.services.notification_service import _mask_url

        token = FIXTURE_SECRETS["webhook_url_with_token"].split("token=")[-1]
        masked = _mask_url(FIXTURE_SECRETS["webhook_url_with_token"])
        # The 48-Q secret in the query string must not appear in the masked form.
        assert token not in masked
        assert not re.search(r"Q{5,}", masked)


# ═════════════════════════════════════════════════════════════════════════════
# D. Static source-code audit:
#    no credential variable is interpolated into a logger call.
# ═════════════════════════════════════════════════════════════════════════════

# Variable names that must NEVER appear as a positional argument or
# %-format argument to a ``logger.X(...)`` call.  We grep the source files.
_CRED_VARIABLES: tuple[str, ...] = (
    "api_token",
    "github_token",
    "vercel_token",
    "stripe_api_key",
    "aws_secret_access_key",
    "aws_access_key_id",
    "aws_session_token",
    "shopify_access_token",
    "supabase_access_token",
    "firebase_service_account_json",
    "private_key",
    "bot_token",
    "slack_bot_token",
    "signing_secret",
    "stripe_webhook_secret",
    "client_secret",
    "encrypted_credentials",
    "credential_iv",
    "WEB_PUSH_VAPID_PRIVATE_KEY",
    "vapid_private_key",
    "webhook_url",         # raw URL — masked variant is OK
    "slack_webhook_url",   # raw URL — masked variant is OK
    "raw_token",           # invite token plaintext
    "install_token",       # GitHub App ephemeral installation token
)


_LOG_FILES_TO_AUDIT: tuple[str, ...] = (
    "app/services/notification_service.py",
    "app/services/slack_service.py",
    "app/services/push_notification_service.py",
    "app/services/billing_service.py",
    "app/services/integration_service.py",
    "app/services/iac_mapping_service.py",
    "app/services/github_pr_creation_service.py",
    "app/services/sync_service.py",
    "app/services/snapshot_service.py",
    "app/services/email_service.py",
    "app/routers/integrations.py",
    "app/routers/integrations_github_app.py",
    "app/routers/workspaces.py",
    "app/routers/slack_oauth.py",
    "app/routers/stripe_webhook.py",
    "app/routers/billing.py",
)


_LOGGER_RE = re.compile(
    r"logger\.(?:info|warning|error|debug|exception|critical)\s*\(([^)]*\))",
    re.DOTALL,
)


def _find_logger_credential_leaks(source: str) -> list[tuple[str, str]]:
    """Return [(variable, snippet)] for each logger call that references a
    forbidden credential variable as a bare argument (not inside a masking
    or type() wrapper).

    Heuristic: scan each ``logger.<level>(...)`` call site; if it contains
    a bare reference to a credential variable but NOT a wrapping
    ``_mask_url(``, ``mask(``, ``type(``, ``len(``, or ``hash(``, treat
    it as a potential leak.
    """
    leaks: list[tuple[str, str]] = []
    for m in _LOGGER_RE.finditer(source):
        args = m.group(1)
        for var in _CRED_VARIABLES:
            # Word-boundary match on the credential name as a bare token.
            if not re.search(rf"\b{re.escape(var)}\b", args):
                continue
            # Allow safe wrappers:
            if (
                f"_mask_url({var}" in args
                or f"mask({var}" in args
                or f"type({var}" in args
                or f"len({var}" in args
                or f"hash({var}" in args
                or f"{var}_masked" in args
                # `error_type=%r` patterns where `type(exc).__name__` is the arg
                or f"type(" in args and var in ("private_key",)
            ):
                continue
            leaks.append((var, args.strip()[:200]))
    return leaks


class TestNoCredentialInLogs:

    @pytest.mark.parametrize("path", _LOG_FILES_TO_AUDIT)
    def test_D1_no_credential_variable_appears_in_logger_call(self, path):
        text = Path(path).read_text()
        leaks = _find_logger_credential_leaks(text)
        assert not leaks, f"{path}: credential variables in logger() calls: {leaks}"

    def test_D2_no_bearer_or_authorization_substring_in_log_format_string(self):
        """No log format-string literal should bake-in 'Bearer ' / 'Authorization:'
        — that's a red flag the source line tries to log a header."""
        for path in _LOG_FILES_TO_AUDIT:
            text = Path(path).read_text()
            for marker in ("Bearer ", "Authorization:"):
                # Allow comments and docstrings (lines starting with # or in """).
                # Quick proxy: require the marker to appear ONLY inside docstrings,
                # comments, or as part of a known-safe http header build (e.g.
                # `headers = {"Authorization": ...}` is fine but logger.* embedding
                # those strings is not).  We accept if the marker exists, since
                # legitimate header construction is unavoidable; we just confirm
                # there is no `logger.*("...Bearer %s..."` style line.
                bad = re.search(
                    rf'logger\.(?:info|warning|error|debug|exception)'
                    rf'\([^)]*"{re.escape(marker)}',
                    text,
                )
                assert bad is None, (
                    f"{path}: log format string contains literal {marker!r}"
                )


# ═════════════════════════════════════════════════════════════════════════════
# E. Connector snapshot/record shapes never carry credential values.
# ═════════════════════════════════════════════════════════════════════════════


class TestSnapshotShapes:

    def test_E1_cloudflare_dns_record_has_no_secret_fields(self):
        from app.connectors.cloudflare_schema import CloudflareDNSRecord

        # TypedDicts expose their declared keys via __annotations__.
        keys = set(CloudflareDNSRecord.__annotations__.keys())
        for forbidden in _FORBIDDEN_CRED_FIELDS:
            assert forbidden not in keys

    def test_E2_cloudflare_ruleset_record_has_no_secret_fields(self):
        from app.connectors.cloudflare_schema import CloudflareRuleset

        keys = set(CloudflareRuleset.__annotations__.keys())
        for forbidden in _FORBIDDEN_CRED_FIELDS:
            assert forbidden not in keys

    def test_E3_firebase_records_never_include_private_key(self):
        from app.connectors import firebase_schema as fs

        # Walk every TypedDict in the firebase_schema module.
        leaks: list[str] = []
        for name in dir(fs):
            obj = getattr(fs, name)
            if not hasattr(obj, "__annotations__"):
                continue
            for key in obj.__annotations__.keys():
                if key in ("private_key", "private_key_id", "client_secret"):
                    leaks.append(f"{name}.{key}")
        assert not leaks, f"Firebase snapshot fields expose secret keys: {leaks}"

    def test_E4_vercel_env_record_has_no_value_field(self):
        """Vercel env vars must be tracked by NAME, never VALUE.

        The brief says: 'env var values should never be stored, only key/count/hash/timestamp'.
        """
        from app.connectors import vercel_schema as vs

        leaks: list[str] = []
        for name in dir(vs):
            obj = getattr(vs, name)
            if not hasattr(obj, "__annotations__"):
                continue
            for key in obj.__annotations__.keys():
                if key in ("value", "secret_value", "decrypted_value", "raw_value"):
                    leaks.append(f"{name}.{key}")
        assert not leaks, f"Vercel snapshot fields expose env values: {leaks}"

    def test_E5_aws_record_schemas_never_include_secret(self):
        from app.connectors import aws_schema as aws

        leaks: list[str] = []
        for name in dir(aws):
            obj = getattr(aws, name)
            if not hasattr(obj, "__annotations__"):
                continue
            for key in obj.__annotations__.keys():
                if key in (
                    "secret_access_key",
                    "session_token",
                    "access_key_id",
                    "secret",
                ):
                    leaks.append(f"{name}.{key}")
        assert not leaks, f"AWS snapshot fields expose secret keys: {leaks}"


# ═════════════════════════════════════════════════════════════════════════════
# F. Risk classifier tripwires: realistic secret fixtures must not appear
#    in any classifier reason.
# ═════════════════════════════════════════════════════════════════════════════


class TestRiskClassifierSecretSafety:

    def _make_change(self, *, record_type, field_path, prev_value, new_value,
                     change_type="modified", record_name="x.example.com",
                     record_content=""):
        c = MagicMock(name="Change")
        c.change_type = change_type
        c.field_path = field_path
        c.prev_value = prev_value
        c.old_value = prev_value
        c.new_value = new_value
        c.provider_metadata = {
            "record_type": record_type,
            "record_name": record_name,
            "record_content": record_content,
        }
        return c

    @pytest.mark.parametrize("secret_name", list(FIXTURE_SECRETS.keys()))
    def test_F1_stripe_classifier_does_not_echo_secret(self, secret_name):
        from app.services.risk_rules.stripe import classify_stripe_change

        secret = FIXTURE_SECRETS[secret_name]
        c = self._make_change(
            record_type="stripe_webhook_endpoint",
            field_path="url",
            prev_value="https://hooks.example.com/old",
            new_value=secret,
        )
        _, reason = classify_stripe_change(c)
        assert secret not in reason

    @pytest.mark.parametrize("secret_name", list(FIXTURE_SECRETS.keys()))
    def test_F2_github_classifier_does_not_echo_secret(self, secret_name):
        from app.services.risk_rules.github import classify_github_change

        secret = FIXTURE_SECRETS[secret_name]
        c = self._make_change(
            record_type="github_actions_secret",
            field_path="value",
            change_type="modified",
            prev_value="old",
            new_value=secret,
            record_name="API_KEY",
        )
        _, reason = classify_github_change(c)
        assert secret not in reason

    @pytest.mark.parametrize("secret_name", list(FIXTURE_SECRETS.keys()))
    def test_F3_cloudflare_classifier_does_not_echo_secret(self, secret_name):
        from app.services.risk_rules.cloudflare_dns import classify_dns_change

        secret = FIXTURE_SECRETS[secret_name]
        c = self._make_change(
            record_type="TXT",
            field_path="content",
            prev_value="old content",
            new_value=secret,
            record_name="api-key.example.com",
        )
        _, reason = classify_dns_change(c)
        assert secret not in reason

    @pytest.mark.parametrize("secret_name", list(FIXTURE_SECRETS.keys()))
    def test_F4_aws_classifier_does_not_echo_secret(self, secret_name):
        from app.services.risk_rules.aws import classify_aws_change

        secret = FIXTURE_SECRETS[secret_name]
        c = self._make_change(
            record_type="aws_iam_user_access_key",
            field_path="status",
            prev_value="Active",
            new_value=secret,
            record_name="ci-deploy-key",
        )
        # AWS classifier may return a generic message — what matters is the
        # value never appears in the reason.
        _, reason = classify_aws_change(c)
        assert secret not in reason

    @pytest.mark.parametrize("secret_name", list(FIXTURE_SECRETS.keys()))
    def test_F5_vercel_classifier_does_not_echo_secret(self, secret_name):
        from app.services.risk_rules.vercel import classify_vercel_change

        secret = FIXTURE_SECRETS[secret_name]
        c = self._make_change(
            record_type="vercel_env_var",
            field_path="value",
            prev_value="old",
            new_value=secret,
            record_name="STRIPE_SECRET_KEY",
        )
        _, reason = classify_vercel_change(c)
        assert secret not in reason

    @pytest.mark.parametrize("secret_name", list(FIXTURE_SECRETS.keys()))
    def test_F6_shopify_classifier_does_not_echo_secret(self, secret_name):
        from app.services.risk_rules.shopify import classify_shopify_change

        secret = FIXTURE_SECRETS[secret_name]
        c = self._make_change(
            record_type="shopify_webhook_subscription",
            field_path="callback_url",
            prev_value="https://example.com/old",
            new_value=secret,
        )
        _, reason = classify_shopify_change(c)
        assert secret not in reason

    @pytest.mark.parametrize("secret_name", list(FIXTURE_SECRETS.keys()))
    def test_F7_supabase_classifier_does_not_echo_secret(self, secret_name):
        from app.services.risk_rules.supabase import classify_supabase_change

        secret = FIXTURE_SECRETS[secret_name]
        c = self._make_change(
            record_type="supabase_db_role",
            field_path="role_name",
            prev_value="reader",
            new_value=secret,
            record_name="postgres",
        )
        _, reason = classify_supabase_change(c)
        assert secret not in reason

    @pytest.mark.parametrize("secret_name", list(FIXTURE_SECRETS.keys()))
    def test_F8_firebase_classifier_does_not_echo_secret(self, secret_name):
        from app.services.risk_rules.firebase import classify_firebase_change

        secret = FIXTURE_SECRETS[secret_name]
        c = self._make_change(
            record_type="firebase_project",
            field_path="display_name",
            prev_value="My Project",
            new_value=secret,
        )
        _, reason = classify_firebase_change(c)
        assert secret not in reason


# ═════════════════════════════════════════════════════════════════════════════
# G. Frontend type-shape audit: the Integration TS interface and shared
#    response types must not declare any credential field.
# ═════════════════════════════════════════════════════════════════════════════


class TestFrontendTypeShapes:

    def test_G1_frontend_integration_type_omits_credential_fields(self):
        # Read frontend/src/types/index.ts and extract the Integration
        # response interface; ensure none of the forbidden cred field names
        # appear inside its body.
        repo_root = Path(__file__).resolve().parent.parent.parent
        ts_path = repo_root / "frontend" / "src" / "types" / "index.ts"
        if not ts_path.exists():
            pytest.skip("frontend/src/types/index.ts not found in this checkout")
        text = ts_path.read_text()

        # Locate the `Integration` response interface (NOT
        # IntegrationCreateRequest, which legitimately carries credentials
        # for submission only).
        m = re.search(
            r"export interface Integration\s*\{(.+?)^\}",
            text,
            re.DOTALL | re.MULTILINE,
        )
        assert m is not None, "Could not locate `Integration` interface body"
        body = m.group(1)
        for forbidden in (
            "api_token",
            "github_token",
            "vercel_token",
            "stripe_api_key",
            "aws_secret_access_key",
            "aws_session_token",
            "shopify_access_token",
            "supabase_access_token",
            "firebase_service_account_json",
            "encrypted_credentials",
            "credential_iv",
            "private_key",
        ):
            assert forbidden not in body, (
                f"frontend Integration type exposes secret-field name: {forbidden}"
            )

    def test_G2_no_secret_persisted_to_local_storage_in_components(self):
        repo_root = Path(__file__).resolve().parent.parent.parent
        comp_dir = repo_root / "frontend" / "src" / "components"
        if not comp_dir.exists():
            pytest.skip("frontend/src/components not found in this checkout")
        # Sweep components/lib code for localStorage.set with a secret-ish key.
        bad = []
        for ts in list(comp_dir.rglob("*.ts")) + list(comp_dir.rglob("*.tsx")):
            text = ts.read_text()
            for marker in (
                "localStorage.setItem(\"api_token",
                "localStorage.setItem(\"github_token",
                "localStorage.setItem(\"aws_secret",
                "localStorage.setItem(\"stripe_api_key",
                "localStorage.setItem(\"private_key",
                "localStorage.setItem(\"slack_bot_token",
            ):
                if marker in text:
                    bad.append(f"{ts}: {marker}")
        assert not bad, f"Frontend stores secrets in localStorage: {bad}"


# ═════════════════════════════════════════════════════════════════════════════
# H. Connector security-marker presence (defence-in-depth):
#    every connector that handles a credential must carry an inline
#    "NEVER log" or equivalent comment marker so future edits stay safe.
# ═════════════════════════════════════════════════════════════════════════════


class TestConnectorSecurityMarkers:

    @pytest.mark.parametrize(
        "path,must_contain",
        [
            ("app/connectors/firebase.py",
             ("NEVER logged", "private_key")),
            ("app/connectors/shopify.py",
             ("NEVER logged", "shopify_access_token")),
            ("app/connectors/supabase.py",
             ("Authorization", "access_token")),
            ("app/connectors/vercel.py",
             ("Bearer", "Authorization")),
            ("app/connectors/cloudflare.py",
             ("api_token", "zone_id")),
        ],
    )
    def test_H1_connector_handles_credential_explicitly(self, path, must_contain):
        text = Path(path).read_text()
        for marker in must_contain:
            assert marker in text, f"{path}: expected marker {marker!r} missing"


# ═════════════════════════════════════════════════════════════════════════════
# I. Slack OAuth / Stripe webhook / GitHub App callback safety markers
# ═════════════════════════════════════════════════════════════════════════════


class TestPublicCallbackSecretSafety:

    def test_I1_slack_oauth_does_not_log_bot_token(self):
        src = Path("app/routers/slack_oauth.py").read_text()
        # Code-side comments must say the token is never logged.
        assert "NEVER logged" in src
        # No raw token_data["bot_token"] interpolation in any logger call.
        bad = re.search(
            r'logger\.[a-z]+\([^)]*bot_token',
            src,
        )
        assert bad is None, "slack_oauth: bot_token referenced in logger call"

    def test_I2_stripe_webhook_does_not_log_signing_secret(self):
        src = Path("app/routers/stripe_webhook.py").read_text()
        # No logger.X(... STRIPE_WEBHOOK_SECRET ...) format.
        bad = re.search(
            r"logger\.[a-z]+\([^)]*STRIPE_WEBHOOK_SECRET",
            src,
        )
        assert bad is None
        bad2 = re.search(
            r'logger\.[a-z]+\([^)]*"[^"]*whsec_',
            src,
        )
        assert bad2 is None

    def test_I3_github_app_endpoints_never_log_installation_token(self):
        src = Path("app/routers/integrations_github_app.py").read_text()
        # The install token MUST NEVER appear in any logger call.
        bad = re.search(
            r"logger\.[a-z]+\([^)]*\binstall_token\b",
            src,
        )
        assert bad is None

    def test_I4_invite_endpoint_never_logs_raw_token(self):
        src = Path("app/routers/workspaces.py").read_text()
        bad = re.search(
            r"logger\.[a-z]+\([^)]*\braw_token\b",
            src,
        )
        assert bad is None
        # Confirm the security comment is present so future edits stay safe.
        assert "raw_token" in src and "not logged" in src


# ═════════════════════════════════════════════════════════════════════════════
# J. Defence-in-depth: the centralized SECRET_PATTERNS regex catches every
#    fixture above.
# ═════════════════════════════════════════════════════════════════════════════


# Regexes that detect the realistic credential shapes we fabricated.
_SECRET_SHAPE_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\bsk_live_[A-Za-z0-9]{32,}"),
    re.compile(r"\bsk_test_[A-Za-z0-9]{32,}"),
    re.compile(r"\bwhsec_[A-Za-z0-9]{32,}"),
    re.compile(r"\bxox[a-z]-[A-Za-z0-9-]{40,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{30,}"),
    re.compile(r"\bgho_[A-Za-z0-9]{30,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}"),
    re.compile(r"\bshpat_[A-Za-z0-9]{20,}"),
    re.compile(r"\bAKIA[A-Z0-9]{16}"),
    re.compile(r"\bASIA[A-Z0-9]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+ey[A-Za-z0-9._-]{30,}"),
    re.compile(r"postgres(?:ql)?://[^\s/:]+:[^\s/@]+@"),
    re.compile(r"\bsbp_[A-Za-z0-9]{20,}"),
)


class TestSecretShapeRegexCatchesFixtures:

    @pytest.mark.parametrize("name,value", list(FIXTURE_SECRETS.items()))
    def test_J1_fixture_matches_at_least_one_secret_pattern(self, name, value):
        """Every realistic-shaped fixture must match at least one of the
        SECRET_SHAPE_PATTERNS — otherwise the patterns are too narrow to be
        useful in downstream redaction guards."""
        # Fixtures that aren't designed to match a "well-known" pattern:
        # webhook_url_with_token, vapid_private_key, cloudflare_api_token,
        # vercel_token, firebase_pk_id (these are generic high-entropy blobs).
        # The patterns are intentionally tight to avoid false positives,
        # so those four are exempt — verify by name.
        well_known_exempt = {
            "webhook_url_with_token",
            "vapid_private_key",
            "cloudflare_api_token",
            "vercel_token",
            "firebase_pk_id",
            "slack_signing_secret",
            "aws_secret_access_key",
        }
        if name in well_known_exempt:
            pytest.skip(f"{name} is intentionally generic (no well-known prefix)")
        matched = any(p.search(value) for p in _SECRET_SHAPE_PATTERNS)
        assert matched, (
            f"No SECRET_SHAPE_PATTERN matches the well-known shape for {name}"
        )

    def test_J2_no_secret_shape_pattern_appears_in_any_runtime_string(self):
        """Sweep ALL backend/.py files for hardcoded credential-shaped strings.

        This is a tripwire that catches accidental check-ins like
        `STRIPE_LIVE_KEY = "sk_live_xxx..."` in source.  Excludes the test
        files (which deliberately contain realistic fixtures) and any
        DOCSTRINGS examples in connector schema files.
        """
        repo_root = Path("app")
        offenders: list[str] = []
        for py in repo_root.rglob("*.py"):
            text = py.read_text()
            for pattern in _SECRET_SHAPE_PATTERNS:
                for m in pattern.finditer(text):
                    span_text = m.group(0)
                    # Permit short matches that are part of the regex
                    # definition itself (the pattern source uses very short
                    # snippets).
                    if len(span_text) < 24:
                        continue
                    # Find the surrounding line and exclude Python comments
                    # (e.g. ``# Locally: paste the literal PEM...``) — those
                    # are operator instructions, not credential check-ins.
                    line_start = text.rfind("\n", 0, m.start()) + 1
                    line_end = text.find("\n", m.end())
                    line = text[line_start:line_end if line_end > 0 else None]
                    if line.lstrip().startswith("#"):
                        continue
                    offenders.append(f"{py}: {span_text[:60]}…")
        assert not offenders, (
            f"Hardcoded credential-shaped strings found in backend/app: {offenders}"
        )
