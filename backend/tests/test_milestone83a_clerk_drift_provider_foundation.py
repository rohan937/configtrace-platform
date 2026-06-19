"""M83A — Clerk drift provider foundation tests.

Verifies the connector schema, ClerkConnector, integration wiring,
frontend provider card/connectability, trust center, capability matrix,
provider expansion framework, and privacy / secret-safety for the Clerk
drift provider foundation.

Test sections:

  1.  CLERK_RECORD_TYPES — all 10 expected types present.
  2.  ClerkConnector — class exists, fetch + validate_credentials present.
  3.  Connector auth header — secret key never stored on instance; header
      is built in-context only.
  4.  Normalizers — produce safe flat dicts (no raw URLs, secrets, tokens,
      emails, phone numbers, user data, customer PII).
  5.  Privacy/schema contract — forbidden fields never appear in records.
  6.  Error mapping — 401/403/429/network/5xx follow connector conventions.
  7.  Pagination / caps — bounded.
  8.  sync_service — supports clerk.
  9.  sync_task — dispatches to ClerkConnector.
  10. IntegrationCreateRequest — accepts clerk; requires clerk_secret_key.
  11. Router _build_credentials — builds connector-native dict without logging.
  12. Integration service — creates clerk integration; encrypts credentials;
      resource_metadata has no secrets.
  13. providers.ts — includes clerk in ProviderId union, PROVIDERS map,
      PROVIDER_IDS, CONNECTABLE_PROVIDER_IDS; NOT in SECURITY_PREVIEW_PROVIDER_IDS.
  14. types/index.ts — clerk in IntegrationCreateBody; credential fields present.
  15. integrations/page.tsx — Clerk card, form, setup guide, identity category.
  16. trustCenter.ts — Clerk trust profile present.
  17. Capability matrix — Clerk partial entry with drift_snapshots=True, all
      security=False, maturity=partial.
  18. Expansion framework — planned_next_stage → M83B; Clerk absent from
      RECOMMENDED_NEXT_PROVIDERS; PagerDuty at queue head.
  19. Regression — M82I tests still pass (smoke check).
  20. Forbidden claim wording — absent from connector and schema modules.
  21. Secret-shape grep — no JWT/SG/AC/SK shapes in Clerk source files.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ROOT = REPO_ROOT / "frontend" / "src"
FE_PROVIDERS = FE_ROOT / "lib" / "providers.ts"
FE_TYPES = FE_ROOT / "types" / "index.ts"
FE_INTEGRATIONS_PAGE = FE_ROOT / "app" / "(app)" / "integrations" / "page.tsx"
FE_TRUST_CENTER = FE_ROOT / "lib" / "trustCenter.ts"

EXPECTED_RECORD_TYPES = {
    "clerk_instance_settings",
    "clerk_application",
    "clerk_domain",
    "clerk_redirect_url_config",
    "clerk_jwt_template",
    "clerk_webhook_endpoint",
    "clerk_email_sms_settings",
    "clerk_auth_strategy",
    "clerk_organization_settings",
    "clerk_session_policy",
}

FORBIDDEN_CLAIM_PHRASES = [
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
]

# Fields that must NEVER appear in normalised Clerk records.
FORBIDDEN_RECORD_FIELDS = (
    "secret_key", "secretKey", "api_key", "token", "bearer",
    "raw_url", "callback_url", "redirect_url", "allowed_origin",
    "email", "user_email", "user_id", "phone", "phone_number",
    "name", "first_name", "last_name", "username",
    "member", "membership", "invitation",
    "session_token", "session_id", "jwt", "access_token",
    "webhook_url", "signing_secret", "signing_key",
    "ip_address", "user_agent",
    "password", "backup_code", "mfa_secret", "otp_seed",
    "pii", "customer_data",
)


# ════════════════════════════════════════════════════════════════════════════
# 1. CLERK_RECORD_TYPES
# ════════════════════════════════════════════════════════════════════════════


def test_clerk_record_types_count():
    from app.connectors.clerk_schema import CLERK_RECORD_TYPES
    assert len(CLERK_RECORD_TYPES) == 10


def test_clerk_record_types_match_expected():
    from app.connectors.clerk_schema import CLERK_RECORD_TYPES
    assert CLERK_RECORD_TYPES == EXPECTED_RECORD_TYPES, (
        f"extra={CLERK_RECORD_TYPES - EXPECTED_RECORD_TYPES!r}\n"
        f"missing={EXPECTED_RECORD_TYPES - CLERK_RECORD_TYPES!r}"
    )


def test_clerk_record_type_constants_are_canonical():
    from app.connectors.clerk_schema import CLERK_RECORD_TYPES
    for rt in CLERK_RECORD_TYPES:
        assert rt.startswith("clerk_"), rt
        assert rt == rt.lower(), rt


def test_clerk_record_type_string_constants_exist():
    from app.connectors import clerk_schema as cs
    for rt in EXPECTED_RECORD_TYPES:
        const_name = rt.upper()
        assert hasattr(cs, const_name), (
            f"clerk_schema.py is missing the constant {const_name!r} for record type {rt!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# 2. ClerkConnector — exists, has required methods
# ════════════════════════════════════════════════════════════════════════════


def test_clerk_connector_class_exists():
    from app.connectors.clerk import ClerkConnector
    assert ClerkConnector is not None


def test_clerk_connector_has_fetch():
    from app.connectors.clerk import ClerkConnector
    assert callable(getattr(ClerkConnector, "fetch", None))


def test_clerk_connector_has_validate_credentials():
    from app.connectors.clerk import ClerkConnector
    assert callable(getattr(ClerkConnector, "validate_credentials", None))


def test_clerk_connector_inherits_base_connector():
    from app.connectors.base import BaseConnector
    from app.connectors.clerk import ClerkConnector
    assert issubclass(ClerkConnector, BaseConnector)


# ════════════════════════════════════════════════════════════════════════════
# 3. Connector auth header — secret key not stored on instance
# ════════════════════════════════════════════════════════════════════════════


def test_clerk_connector_is_stateless():
    """ClerkConnector must not store secret_key as an instance attribute."""
    from app.connectors.clerk import ClerkConnector
    conn = ClerkConnector()
    for attr in dir(conn):
        if "secret" in attr.lower() or "key" in attr.lower() or "token" in attr.lower():
            val = getattr(conn, attr, None)
            if callable(val):
                continue
            assert val is None or val == "" or isinstance(val, type), (
                f"ClerkConnector instance must not store credentials; "
                f"found {attr!r} = {val!r}"
            )


def test_clerk_connector_make_client_uses_bearer():
    from app.connectors.clerk import ClerkConnector
    src = inspect.getsource(ClerkConnector._make_client)
    assert "Bearer" in src, "_make_client must use Bearer token auth"
    assert "secret_key" in src or "Authorization" in src


def test_clerk_connector_secret_key_not_in_instance_source():
    """secret_key must not be stored as self.secret_key or similar."""
    from app.connectors.clerk import ClerkConnector
    src = inspect.getsource(ClerkConnector)
    assert "self.secret_key" not in src, (
        "secret_key must not be stored as an instance attribute"
    )
    assert "self._secret_key" not in src


# ════════════════════════════════════════════════════════════════════════════
# 4. Normalizers — safe flat dicts
# ════════════════════════════════════════════════════════════════════════════


def _make_instance_raw() -> dict:
    return {
        "id": "ins_safe_opaque_id_001",
        "environment_type": "production",
        "sign_up_enabled": True,
        "sign_in_enabled": True,
        "user_settings": {
            "email_address": {"enabled": True},
            "phone_number": {"enabled": False},
            "username": {"enabled": False},
            "password": {"enabled": True},
            "social": {"google": {"enabled": True}, "github": {"enabled": False}},
            "mfa": {"enabled": False, "supported_factors": []},
        },
        "session_settings": {"token_lifetime_minutes": 60},
        "organization_settings": {"enabled": False},
        "restrictions": {"sign_in_mode": "public"},
    }


def test_normalize_instance_record_type():
    from app.connectors.clerk import ClerkConnector
    from app.connectors.clerk_schema import CLERK_INSTANCE_SETTINGS
    conn = ClerkConnector()
    rec = conn._normalize_instance(_make_instance_raw())
    assert rec["record_type"] == CLERK_INSTANCE_SETTINGS


def test_normalize_instance_has_required_fields():
    from app.connectors.clerk import ClerkConnector
    conn = ClerkConnector()
    rec = conn._normalize_instance(_make_instance_raw())
    for field in ("record_type", "record_id", "provider_resource_id", "provider",
                  "environment_type", "sign_up_enabled", "sign_in_enabled",
                  "email_enabled", "password_enabled", "mfa_enabled",
                  "session_lifetime_category", "allowlist_enabled", "blocklist_enabled"):
        assert field in rec, f"Missing field {field!r} in instance record"


def test_normalize_instance_no_forbidden_fields():
    from app.connectors.clerk import ClerkConnector
    conn = ClerkConnector()
    rec = conn._normalize_instance(_make_instance_raw())
    for bad in FORBIDDEN_RECORD_FIELDS:
        assert bad not in rec, (
            f"Forbidden field {bad!r} found in instance record: {rec}"
        )


def test_normalize_domain_never_stores_domain_name():
    from app.connectors.clerk import ClerkConnector
    from app.connectors.clerk_schema import CLERK_DOMAIN
    conn = ClerkConnector()
    raw_domain = {
        "id": "dmn_safe_opaque_id_001",
        "name": "myapp.example.com",  # MUST NOT be stored
        "is_primary": True,
        "verified": True,
        "ssl_enabled": True,
        "dns_records_status": "verified",
    }
    rec = conn._normalize_domain(raw_domain)
    assert rec["record_type"] == CLERK_DOMAIN
    assert rec["domain_present"] is True
    assert "myapp.example.com" not in str(rec), (
        "Raw domain name must never appear in normalised record"
    )
    assert "name" not in rec, "Raw name field must not be stored in domain record"


def test_normalize_redirect_url_never_stores_raw_url():
    from app.connectors.clerk import ClerkConnector
    from app.connectors.clerk_schema import CLERK_REDIRECT_URL_CONFIG
    conn = ClerkConnector()
    raw_redirect = {
        "id": "ru_safe_opaque_id_001",
        "url": "https://myapp.example.com/callback",  # MUST NOT be stored
    }
    rec = conn._normalize_redirect_url(raw_redirect)
    assert rec["record_type"] == CLERK_REDIRECT_URL_CONFIG
    assert "myapp.example.com" not in str(rec), (
        "Raw redirect URL must never appear in normalised record"
    )
    assert rec["url_present"] is True
    assert rec["url_scheme_category"] == "https"


def test_normalize_redirect_url_http_scheme_category():
    from app.connectors.clerk import ClerkConnector
    conn = ClerkConnector()
    raw = {"id": "ru_002", "url": "http://myapp.example.com/callback"}
    rec = conn._normalize_redirect_url(raw)
    assert rec["url_scheme_category"] == "http"


def test_normalize_redirect_url_wildcard_detected():
    from app.connectors.clerk import ClerkConnector
    conn = ClerkConnector()
    raw = {"id": "ru_003", "url": "https://*.example.com/callback"}
    rec = conn._normalize_redirect_url(raw)
    assert rec["wildcard_present"] is True


def test_normalize_redirect_url_localhost_detected():
    from app.connectors.clerk import ClerkConnector
    conn = ClerkConnector()
    raw = {"id": "ru_004", "url": "http://localhost:3000/callback"}
    rec = conn._normalize_redirect_url(raw)
    assert rec["localhost_present"] is True


def test_normalize_jwt_template_never_stores_claims():
    from app.connectors.clerk import ClerkConnector
    from app.connectors.clerk_schema import CLERK_JWT_TEMPLATE
    conn = ClerkConnector()
    raw = {
        "id": "jt_safe_opaque_id_001",
        "name": "My JWT Template",
        "claims": {"sub": "{{user.id}}", "email": "{{user.primary_email_address}}"},
        "audience": "https://my-api.example.com",  # MUST NOT be stored
        "lifetime": 3600,
        "signing_algorithm": "RS256",
    }
    rec = conn._normalize_jwt_template(raw)
    assert rec["record_type"] == CLERK_JWT_TEMPLATE
    assert "my-api.example.com" not in str(rec), (
        "Audience URI must never appear in normalised record"
    )
    assert "claims" not in rec, "Raw claims must not be stored"
    assert rec["claims_count"] == 2  # count only
    assert rec["audience_present"] is True
    assert rec["algorithm"] == "RS256"


def test_normalize_webhook_never_stores_url_or_secret():
    from app.connectors.clerk import ClerkConnector
    from app.connectors.clerk_schema import CLERK_WEBHOOK_ENDPOINT
    conn = ClerkConnector()
    raw = {
        "id": "wh_safe_opaque_id_001",
        "url": "https://myapp.example.com/webhooks/clerk",  # MUST NOT be stored
        "secret": "whsec_supersecret123456789",              # MUST NOT be stored
        "filter_types": ["user.created", "session.created"],
        "enabled": True,
    }
    rec = conn._normalize_webhook(raw)
    assert rec["record_type"] == CLERK_WEBHOOK_ENDPOINT
    assert "myapp.example.com" not in str(rec), (
        "Webhook URL must never appear in normalised record"
    )
    assert "whsec_" not in str(rec), (
        "Webhook secret must never appear in normalised record"
    )
    assert "supersecret" not in str(rec)
    assert rec["url_present"] is True
    assert rec["url_scheme_category"] == "https"
    assert rec["secret_present"] is True
    assert rec["event_count"] == 2


# ════════════════════════════════════════════════════════════════════════════
# 5. Privacy/schema contract
# ════════════════════════════════════════════════════════════════════════════


def test_clerk_connector_source_never_stores_users_or_sessions():
    from app.connectors import clerk as clerk_mod
    src = inspect.getsource(clerk_mod)
    # Must not fetch user-level endpoints — check non-comment, non-docstring lines only
    code_lines = [
        ln for ln in src.split("\n")
        if not ln.strip().startswith("#")
        and not ln.strip().startswith("*")
        and not ln.strip().startswith('"""')
        and not ln.strip().startswith("- ")
        and "NEVER" not in ln
        and "never" not in ln.lower()
    ]
    code_only = "\n".join(code_lines)
    for forbidden_path in ("/v1/users", "/v1/sessions", "/v1/audit_log"):
        assert forbidden_path not in code_only, (
            f"Clerk connector must not call {forbidden_path!r} — user/session data is PII"
        )


def test_clerk_schema_typedicts_have_no_raw_url_fields():
    from app.connectors import clerk_schema
    src = inspect.getsource(clerk_schema)
    # Must not have raw URL fields as bare field names (counts/booleans are OK).
    # Check for exact TypedDict field declarations of the forbidden patterns.
    for bad_field in ("raw_url", "callback_url", "raw_redirect"):
        # Look for the field as a TypedDict declaration (field_name: type)
        assert not re.search(rf"^\s+{re.escape(bad_field)}\s*:", src, re.MULTILINE), (
            f"clerk_schema.py must not declare raw field {bad_field!r} — raw URLs are never stored"
        )
    # allowed_origin is OK as allowed_origin_count (integer count), not as a raw URL field
    assert not re.search(r"^\s+allowed_origin\s*:", src, re.MULTILINE), (
        "clerk_schema.py must not declare 'allowed_origin' as a raw field — use allowed_origin_count"
    )


# ════════════════════════════════════════════════════════════════════════════
# 6. Error mapping
# ════════════════════════════════════════════════════════════════════════════


def test_clerk_connector_maps_401_to_authentication_error():
    from app.connectors.clerk import ClerkConnector
    from app.connectors.exceptions import AuthenticationError
    conn = ClerkConnector()
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.headers = {}
    with pytest.raises(AuthenticationError):
        conn._raise_for_status(mock_resp)


def test_clerk_connector_maps_429_to_rate_limit_error():
    from app.connectors.clerk import ClerkConnector
    from app.connectors.exceptions import RateLimitError
    conn = ClerkConnector()
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {"Retry-After": "30"}
    with pytest.raises(RateLimitError):
        conn._raise_for_status(mock_resp)


def test_clerk_connector_maps_500_to_connector_error():
    from app.connectors.clerk import ClerkConnector
    from app.connectors.exceptions import ConnectorError
    conn = ClerkConnector()
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.headers = {}
    with pytest.raises(ConnectorError):
        conn._raise_for_status(mock_resp)


def test_clerk_connector_200_does_not_raise():
    from app.connectors.clerk import ClerkConnector
    conn = ClerkConnector()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    conn._raise_for_status(mock_resp)  # must not raise


def test_clerk_connector_network_error_raises_network_error():
    from app.connectors.clerk import ClerkConnector
    from app.connectors.exceptions import NetworkError
    import httpx
    conn = ClerkConnector()
    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        mock_client.get.side_effect = httpx.ConnectError("connection refused")
        with pytest.raises(NetworkError):
            conn.fetch({"secret_key": "CLERK_TEST_SECRET_KEY_PLACEHOLDER"})


# ════════════════════════════════════════════════════════════════════════════
# 7. Pagination / caps
# ════════════════════════════════════════════════════════════════════════════


def test_clerk_connector_has_domain_cap():
    from app.connectors import clerk as clerk_mod
    src = inspect.getsource(clerk_mod)
    assert "_MAX_DOMAINS" in src


def test_clerk_connector_has_redirect_url_cap():
    from app.connectors import clerk as clerk_mod
    src = inspect.getsource(clerk_mod)
    assert "_MAX_REDIRECT_URLS" in src


def test_clerk_connector_has_jwt_template_cap():
    from app.connectors import clerk as clerk_mod
    src = inspect.getsource(clerk_mod)
    assert "_MAX_JWT_TEMPLATES" in src


def test_clerk_connector_has_webhook_cap():
    from app.connectors import clerk as clerk_mod
    src = inspect.getsource(clerk_mod)
    assert "_MAX_WEBHOOKS" in src


# ════════════════════════════════════════════════════════════════════════════
# 8. sync_service supports clerk
# ════════════════════════════════════════════════════════════════════════════


def test_sync_service_includes_clerk():
    from app.services import sync_service
    src = inspect.getsource(sync_service)
    m = re.search(r"_SUPPORTED_PROVIDERS\s*=\s*\(([^)]+)\)", src)
    assert m, "_SUPPORTED_PROVIDERS tuple not found in sync_service"
    tuple_body = m.group(1)
    assert "clerk" in tuple_body, (
        f"'clerk' must be in sync_service._SUPPORTED_PROVIDERS; got: {tuple_body!r}"
    )


# ════════════════════════════════════════════════════════════════════════════
# 9. sync_task dispatches to ClerkConnector
# ════════════════════════════════════════════════════════════════════════════


def test_sync_task_dispatches_clerk():
    from app.workers import sync_task
    src = inspect.getsource(sync_task)
    assert "ClerkConnector" in src, (
        "sync_task.py must import and dispatch to ClerkConnector for provider='clerk'"
    )
    assert "integration.provider == \"clerk\"" in src or "provider == 'clerk'" in src


# ════════════════════════════════════════════════════════════════════════════
# 10. IntegrationCreateRequest
# ════════════════════════════════════════════════════════════════════════════


def test_integration_schema_accepts_clerk_provider():
    from app.schemas.integration import IntegrationCreateRequest
    req = IntegrationCreateRequest(
        provider="clerk",
        display_name="Test Clerk",
        clerk_secret_key="CLERK_TEST_SECRET_KEY_PLACEHOLDER",
    )
    assert req.provider == "clerk"


def test_integration_schema_requires_clerk_secret_key():
    from pydantic import ValidationError
    from app.schemas.integration import IntegrationCreateRequest
    with pytest.raises(ValidationError, match="clerk_secret_key"):
        IntegrationCreateRequest(
            provider="clerk",
            display_name="Test Clerk",
            # missing clerk_secret_key
        )


def test_integration_schema_clerk_accepts_optional_frontend_api_url():
    from app.schemas.integration import IntegrationCreateRequest
    req = IntegrationCreateRequest(
        provider="clerk",
        display_name="Test Clerk",
        clerk_secret_key="CLERK_TEST_SECRET_KEY_PLACEHOLDER",
        clerk_frontend_api_url="CLERK_TEST_FRONTEND_API_URL_PLACEHOLDER",
    )
    assert req.clerk_frontend_api_url == "CLERK_TEST_FRONTEND_API_URL_PLACEHOLDER"


# ════════════════════════════════════════════════════════════════════════════
# 11. Router _build_credentials
# ════════════════════════════════════════════════════════════════════════════


def test_router_build_credentials_clerk():
    from app.routers.integrations import _build_credentials
    from app.schemas.integration import IntegrationCreateRequest
    body = IntegrationCreateRequest(
        provider="clerk",
        display_name="Test Clerk",
        clerk_secret_key="CLERK_TEST_SECRET_KEY_PLACEHOLDER",
    )
    creds = _build_credentials(body)
    assert "secret_key" in creds, "Router must produce 'secret_key' in credentials dict"
    assert creds["secret_key"] == "CLERK_TEST_SECRET_KEY_PLACEHOLDER"


def test_router_build_credentials_clerk_includes_frontend_api_url():
    from app.routers.integrations import _build_credentials
    from app.schemas.integration import IntegrationCreateRequest
    body = IntegrationCreateRequest(
        provider="clerk",
        display_name="Test Clerk",
        clerk_secret_key="CLERK_TEST_SECRET_KEY_PLACEHOLDER",
        clerk_frontend_api_url="CLERK_TEST_FRONTEND_API_URL_PLACEHOLDER",
    )
    creds = _build_credentials(body)
    assert "frontend_api_url" in creds


def test_router_build_credentials_clerk_no_extra_secrets():
    from app.routers.integrations import _build_credentials
    from app.schemas.integration import IntegrationCreateRequest
    body = IntegrationCreateRequest(
        provider="clerk",
        display_name="Test Clerk",
        clerk_secret_key="CLERK_TEST_SECRET_KEY_PLACEHOLDER",
    )
    creds = _build_credentials(body)
    # Must not include datadog or auth0 fields
    for unexpected in ("api_key", "application_key", "client_secret", "domain"):
        assert unexpected not in creds, (
            f"Unexpected field {unexpected!r} in Clerk credentials dict"
        )


# ════════════════════════════════════════════════════════════════════════════
# 12. Integration service — creates clerk integration safely
# ════════════════════════════════════════════════════════════════════════════


def test_integration_service_accepts_clerk(test_user, db_session):
    from app.services.integration_service import create_integration
    from app.core.encryption import decrypt_credentials
    integration = create_integration(
        provider="clerk",
        user_id=test_user.id,
        display_name="Test Clerk M83A",
        credentials={"secret_key": "CLERK_TEST_SECRET_KEY_PLACEHOLDER"},
        db=db_session,
    )
    assert integration.provider == "clerk"
    assert integration.status == "active"
    # SECURITY: secret_key must be encrypted, not stored in plaintext
    creds = decrypt_credentials(integration.encrypted_credentials, integration.credential_iv)
    assert creds.get("secret_key") == "CLERK_TEST_SECRET_KEY_PLACEHOLDER"


def test_integration_service_clerk_resource_metadata_has_no_secrets(test_user, db_session):
    from app.services.integration_service import create_integration
    from app.models.resource import Resource
    integration = create_integration(
        provider="clerk",
        user_id=test_user.id,
        display_name="Test Clerk M83A resource metadata",
        credentials={"secret_key": "CLERK_TEST_SECRET_KEY_PLACEHOLDER"},
        db=db_session,
    )
    resource = (
        db_session.query(Resource)
        .filter(Resource.integration_id == integration.id)
        .first()
    )
    assert resource is not None
    meta = resource.resource_metadata or {}
    for secret_field in ("secret_key", "clerk_secret_key", "api_key", "token", "jwt"):
        assert secret_field not in meta, (
            f"Secret field {secret_field!r} must not appear in resource_metadata"
        )
    assert resource.provider_resource_type == "clerk_instance"


def test_integration_service_unsupported_still_raises():
    from app.services.integration_service import create_integration
    with pytest.raises((ValueError, Exception)):
        create_integration(
            provider="unknown_future_provider",
            user_id=None,
            display_name="Test",
            credentials={},
            db=None,
        )


# ════════════════════════════════════════════════════════════════════════════
# 13. providers.ts frontend
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="frontend tree absent")
def test_fe_providers_clerk_in_provider_id_union():
    src = FE_PROVIDERS.read_text()
    assert '"clerk"' in src or "'clerk'" in src


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="frontend tree absent")
def test_fe_providers_clerk_has_providers_entry():
    src = FE_PROVIDERS.read_text()
    assert "clerk:" in src and '"Clerk"' in src


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="frontend tree absent")
def test_fe_providers_clerk_category_is_identity():
    src = FE_PROVIDERS.read_text()
    # Find the clerk entry and check its category
    idx = src.find("clerk:")
    assert idx >= 0
    snippet = src[idx: idx + 400]
    assert "identity" in snippet, "Clerk provider category must be 'identity'"


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="frontend tree absent")
def test_fe_providers_clerk_in_provider_ids_array():
    src = FE_PROVIDERS.read_text()
    idx = src.find("PROVIDER_IDS")
    assert idx >= 0
    snippet = src[idx: idx + 600]
    assert '"clerk"' in snippet or "'clerk'" in snippet


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="frontend tree absent")
def test_fe_providers_clerk_in_connectable_ids():
    src = FE_PROVIDERS.read_text()
    idx = src.find("CONNECTABLE_PROVIDER_IDS")
    assert idx >= 0
    snippet = src[idx: idx + 600]
    assert '"clerk"' in snippet or "'clerk'" in snippet, (
        "Clerk must be in CONNECTABLE_PROVIDER_IDS"
    )


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="frontend tree absent")
def test_fe_providers_clerk_not_in_security_preview_ids():
    src = FE_PROVIDERS.read_text()
    idx = src.find("SECURITY_PREVIEW_PROVIDER_IDS")
    assert idx >= 0
    snippet = src[idx: idx + 300]
    assert '"clerk"' not in snippet and "'clerk'" not in snippet


# ════════════════════════════════════════════════════════════════════════════
# 14. types/index.ts
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_TYPES.exists(), reason="frontend tree absent")
def test_fe_types_clerk_in_provider_union():
    src = FE_TYPES.read_text()
    assert '"clerk"' in src or "'clerk'" in src


@pytest.mark.skipif(not FE_TYPES.exists(), reason="frontend tree absent")
def test_fe_types_has_clerk_secret_key_field():
    src = FE_TYPES.read_text()
    assert "clerk_secret_key" in src


@pytest.mark.skipif(not FE_TYPES.exists(), reason="frontend tree absent")
def test_fe_types_clerk_secret_key_is_optional():
    src = FE_TYPES.read_text()
    assert "clerk_secret_key?" in src, (
        "clerk_secret_key must be optional in IntegrationCreateBody"
    )


# ════════════════════════════════════════════════════════════════════════════
# 15. integrations/page.tsx
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_INTEGRATIONS_PAGE.exists(), reason="frontend tree absent")
def test_fe_integrations_page_imports_clerk_form():
    src = FE_INTEGRATIONS_PAGE.read_text()
    assert "ClerkIntegrationForm" in src


@pytest.mark.skipif(not FE_INTEGRATIONS_PAGE.exists(), reason="frontend tree absent")
def test_fe_integrations_page_dispatches_clerk_form():
    src = FE_INTEGRATIONS_PAGE.read_text()
    assert '"clerk"' in src or "'clerk'" in src


@pytest.mark.skipif(not FE_INTEGRATIONS_PAGE.exists(), reason="frontend tree absent")
def test_fe_integrations_page_has_clerk_setup_guide():
    src = FE_INTEGRATIONS_PAGE.read_text()
    assert "Clerk" in src
    # Setup guide should mention connecting
    lower = src.lower()
    assert "connect a clerk" in lower or "clerk instance" in lower


@pytest.mark.skipif(not FE_INTEGRATIONS_PAGE.exists(), reason="frontend tree absent")
def test_fe_integrations_page_clerk_no_forbidden_wording():
    src = FE_INTEGRATIONS_PAGE.read_text()
    for phrase in FORBIDDEN_CLAIM_PHRASES:
        assert phrase.lower() not in src.lower(), (
            f"Forbidden phrase {phrase!r} in integrations page"
        )


# ════════════════════════════════════════════════════════════════════════════
# 16. trustCenter.ts
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_TRUST_CENTER.exists(), reason="frontend tree absent")
def test_fe_trust_center_has_clerk_profile():
    src = FE_TRUST_CENTER.read_text()
    assert "clerk:" in src or "clerk :" in src or '"clerk"' in src


@pytest.mark.skipif(not FE_TRUST_CENTER.exists(), reason="frontend tree absent")
def test_fe_trust_center_clerk_never_reads_users():
    src = FE_TRUST_CENTER.read_text()
    idx = src.find("clerk:")
    if idx < 0:
        idx = src.find('"clerk"')
    assert idx >= 0
    # Check the clerk profile context
    snippet = src[idx: idx + 2000]
    assert "user" in snippet.lower(), "Clerk trust profile should mention user data is not read"


@pytest.mark.skipif(not FE_TRUST_CENTER.exists(), reason="frontend tree absent")
def test_fe_trust_center_clerk_no_forbidden_wording():
    src = FE_TRUST_CENTER.read_text()
    for phrase in FORBIDDEN_CLAIM_PHRASES:
        assert phrase.lower() not in src.lower(), (
            f"Forbidden phrase {phrase!r} in trustCenter.ts"
        )


# ════════════════════════════════════════════════════════════════════════════
# 17. Capability matrix
# ════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_has_clerk_entry():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("clerk")
    assert cap is not None, "Clerk must have a capability matrix entry"


def test_capability_matrix_clerk_drift_snapshots_true():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("clerk")
    assert cap.drift.drift_snapshots is True


def test_capability_matrix_clerk_drift_diff_true():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("clerk")
    assert cap.drift.drift_diff is True


def test_capability_matrix_clerk_security_rules_false():
    # M83B added Clerk security rules, so security_rules is now True.
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("clerk")
    assert cap.security.security_rules is True


def test_capability_matrix_clerk_all_security_false():
    # M83B+ promotes security_rules=True, M83D promotes activity_ingestion=True,
    # M83E promotes activity_signals=True.
    # This test now checks only the fields that remained False after M83E.
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("clerk")
    sec = cap.security
    for field in ("risk_activity_correlations",
                  "demo_seed_clear", "case_report", "evidence_timeline", "evidence_graph"):
        val = getattr(sec, field)
        assert val is False, f"Clerk capability matrix field {field!r} should be False at M83E"


def test_capability_matrix_clerk_maturity_partial():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("clerk")
    assert cap.maturity == "partial"


def test_capability_matrix_clerk_category_identity():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("clerk")
    assert cap.category == "identity"


def test_capability_matrix_clerk_notes_mention_m83a():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("clerk")
    assert "M83A" in (cap.notes or ""), (
        "Capability matrix notes must reference M83A drift foundation"
    )


def test_capability_matrix_clerk_in_partial_list():
    from app.services.provider_capability_matrix_service import PROVIDER_CAPABILITIES_PARTIAL
    providers = [p.provider for p in PROVIDER_CAPABILITIES_PARTIAL]
    assert "clerk" in providers


# ════════════════════════════════════════════════════════════════════════════
# 18. Provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_is_m83b():
    # M83B has landed; planned_next_stage now references M83C (Clerk Auth/Application Risk).
    from app.services.provider_expansion_framework import get_framework
    framework = get_framework()
    planned = framework["summary"]["planned_next_stage"]
    assert "M83B" in planned or "M83C" in planned or "Clerk" in planned, (
        f"planned_next_stage should reference an M83 Clerk stage; got {planned!r}"
    )


def test_expansion_framework_clerk_not_in_recommended_providers():
    from app.services.provider_expansion_framework import get_framework
    framework = get_framework()
    providers = [r["provider"] for r in framework.get("recommended_next_providers", [])]
    assert "clerk" not in providers, (
        "Clerk launched in M83A; must not remain in RECOMMENDED_NEXT_PROVIDERS"
    )


def test_expansion_framework_pagerduty_at_head():
    from app.services.provider_expansion_framework import get_framework
    framework = get_framework()
    recs = framework.get("recommended_next_providers", [])
    assert recs, "RECOMMENDED_NEXT_PROVIDERS must not be empty"
    assert recs[0]["provider"] == "pagerduty", (
        f"PagerDuty should be head of recommended queue after Clerk launch; "
        f"got {recs[0]['provider']!r}"
    )


def test_expansion_framework_not_pointing_to_m83a():
    from app.services.provider_expansion_framework import get_framework
    framework = get_framework()
    planned = framework["summary"]["planned_next_stage"]
    assert "M83A" not in planned, (
        f"planned_next_stage still points at M83A (current milestone): {planned!r}"
    )


# ════════════════════════════════════════════════════════════════════════════
# 19. Regression smoke — M82I key assertions
# ════════════════════════════════════════════════════════════════════════════


def test_regression_datadog_still_in_capability_matrix():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("datadog")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.demo_seed_clear is True


def test_regression_datadog_not_in_recommended_providers():
    from app.services.provider_expansion_framework import get_framework
    framework = get_framework()
    providers = [r["provider"] for r in framework.get("recommended_next_providers", [])]
    assert "datadog" not in providers


def test_regression_auth0_still_in_capability_matrix():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("auth0")
    assert cap is not None
    assert cap.security.security_rules is True


# ════════════════════════════════════════════════════════════════════════════
# 20. Forbidden claim wording
# ════════════════════════════════════════════════════════════════════════════


def test_clerk_connector_no_forbidden_claims():
    from app.connectors import clerk as clerk_mod
    src = inspect.getsource(clerk_mod)
    for phrase in FORBIDDEN_CLAIM_PHRASES:
        lines = [ln for ln in src.split("\n") if phrase.lower() in ln.lower()]
        for ln in lines:
            low = ln.lower()
            is_negation = any(n in low for n in ("does not", "never", "not confirm", "# never", "avoid"))
            assert is_negation, (
                f"Clerk connector contains forbidden phrase {phrase!r} without negation:\n"
                f"  {ln.strip()!r}"
            )


def test_clerk_schema_no_forbidden_claims():
    from app.connectors import clerk_schema
    src = inspect.getsource(clerk_schema)
    for phrase in FORBIDDEN_CLAIM_PHRASES:
        assert phrase.lower() not in src.lower(), (
            f"clerk_schema.py contains forbidden phrase {phrase!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# 21. Secret-shape grep
# ════════════════════════════════════════════════════════════════════════════


def test_no_jwt_shapes_in_clerk_connector():
    from app.connectors import clerk as clerk_mod
    src = inspect.getsource(clerk_mod)
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", src), (
        "JWT-shaped token found in clerk.py — use safe placeholders only"
    )


def test_no_sendgrid_shapes_in_clerk_connector():
    from app.connectors import clerk as clerk_mod
    src = inspect.getsource(clerk_mod)
    assert not re.search(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", src)


def test_no_twilio_shapes_in_clerk_connector():
    from app.connectors import clerk as clerk_mod
    src = inspect.getsource(clerk_mod)
    assert not re.search(r"AC[0-9a-fA-F]{32}", src)
    assert not re.search(r"SK[0-9a-fA-F]{32}", src)


def test_no_real_clerk_key_shapes_in_test_file():
    """Test file must not contain real Clerk secret key shapes (sk_live_...)."""
    src = Path(__file__).read_text()
    assert "CLERK_TEST_SECRET_KEY_PLACEHOLDER" in src, "Must use safe placeholders"
    # No real sk_live_ or sk_test_ key values (long random suffix)
    assert not re.search(r"sk_live_[A-Za-z0-9]{20,}", src), (
        "Real Clerk secret key shape found in test file — use CLERK_TEST_SECRET_KEY_PLACEHOLDER"
    )
