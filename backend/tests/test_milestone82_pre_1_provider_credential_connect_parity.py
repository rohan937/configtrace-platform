"""M82-pre.1 — Provider credential connect parity guardrails.

Azure, Google Cloud, Twilio, SendGrid, and Auth0 are now fully connectable
through POST /integrations using the existing encrypted-credential pattern.
This file pins:

  A. Backend POST /integrations allowlist accepts all 13 providers
     (the canonical 8 + the 5 M82-pre.1 providers).
  B. IntegrationCreateRequest declares the new credential fields with the
     right names and presence-validation rules.
  C. integration_service.create_integration dispatches each new provider to
     a helper that calls encrypt_credentials and creates an Integration row
     with the credentials encrypted at rest (NEVER returned in the response).
  D. The helpers never leak secret values into the response body or the
     Integration ORM object's resource_metadata.
  E. sync_service / sync_task already dispatch the new provider keys.
  F. Frontend providers.ts no longer marks the 5 providers as security
     preview — they are in CONNECTABLE_PROVIDER_IDS and the preview subset
     is empty.
  G. The integrations page imports each new credential form component.
  H. Frontend types/index.ts and api.ts surface the new credential fields.
  I. Trust center exposes either a profile or a safe fallback for all 13
     providers (Partial<Record> consumer handles missing safely).
  J. Provider expansion framework points to M82A: Datadog.
  K. Capability matrix Auth0 notes mention M82-pre.1.
  L. No forbidden claim phrases or secret-shape strings.

This file adds NO product code — it only asserts existing behavior.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import pytest

from app.services import provider_capability_matrix_service as cap_svc
from app.services import provider_expansion_framework as exp_svc

# ── Forbidden claim phrases (M75A) ────────────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# ── Provider sets ─────────────────────────────────────────────────────────────
CANONICAL_CONNECTABLE_PROVIDERS = (
    "cloudflare", "github", "vercel", "stripe",
    "aws", "firebase", "supabase", "shopify",
)
M82_PRE_1_PROVIDERS = ("azure", "google_cloud", "twilio", "sendgrid", "auth0")
# M82A added Datadog; M83A added Clerk — now 15 providers total.
M82A_PROVIDERS = ("datadog",)
M83A_PROVIDERS = ("clerk",)
ALL_THIRTEEN = CANONICAL_CONNECTABLE_PROVIDERS + M82_PRE_1_PROVIDERS + M82A_PROVIDERS + M83A_PROVIDERS

# ── Safe placeholder credential values for tests ──────────────────────────────
# NEVER use real-looking JWTs / Twilio SIDs / SendGrid keys / Azure secrets.
AZURE_TEST_TENANT_ID = "AZURE_TEST_TENANT_ID"
AZURE_TEST_CLIENT_ID = "AZURE_TEST_CLIENT_ID"
AZURE_TEST_CLIENT_SECRET = "AZURE_TEST_CLIENT_SECRET_PLACEHOLDER"
AZURE_TEST_SUBSCRIPTION_ID = "AZURE_TEST_SUBSCRIPTION_ID"

GCP_TEST_PROJECT_ID = "GCP_TEST_PROJECT_ID"
# A minimal JSON shape — no private_key, no PEM material. The schema accepts
# any non-empty string; live validation happens at sync time.
GCP_TEST_SERVICE_ACCOUNT_JSON = (
    '{"type":"service_account","project_id":"GCP_TEST_PROJECT_ID",'
    '"client_email":"sa@example.invalid",'
    '"placeholder":"GCP_TEST_SERVICE_ACCOUNT_JSON_PLACEHOLDER"}'
)

TWILIO_TEST_ACCOUNT_ID = "TWILIO_TEST_ACCOUNT_ID"
TWILIO_TEST_AUTH_TOKEN = "TWILIO_TEST_AUTH_TOKEN_PLACEHOLDER"

SENDGRID_TEST_API_KEY = "SENDGRID_TEST_API_KEY_PLACEHOLDER"

AUTH0_TEST_DOMAIN = "AUTH0_TEST_DOMAIN"
AUTH0_TEST_CLIENT_ID = "AUTH0_TEST_CLIENT_ID"
AUTH0_TEST_CLIENT_SECRET = "AUTH0_TEST_CLIENT_SECRET_PLACEHOLDER"
AUTH0_TEST_MANAGEMENT_TOKEN = "AUTH0_TEST_MANAGEMENT_TOKEN_PLACEHOLDER"


# ════════════════════════════════════════════════════════════════════════════
# Section A — Backend POST /integrations allowlist accepts all 13 providers
# ════════════════════════════════════════════════════════════════════════════


def test_schema_provider_literal_includes_all_thirteen():
    """IntegrationCreateRequest.provider Literal type covers all 15 providers (M83A)."""
    from app.schemas.integration import IntegrationCreateRequest
    import typing
    annotation = IntegrationCreateRequest.model_fields["provider"].annotation
    allowed = set(typing.get_args(annotation))
    assert allowed == set(ALL_THIRTEEN), (
        f"provider Literal drift: expected {set(ALL_THIRTEEN)}, got {allowed}"
    )


def test_schema_rejects_unknown_provider():
    """An unknown provider raises a Pydantic validation error."""
    from app.schemas.integration import IntegrationCreateRequest
    # datadog is now a valid provider (M82A) — test a different unknown provider.
    with pytest.raises(Exception):
        IntegrationCreateRequest(provider="totally-fake-provider", display_name="x")
    with pytest.raises(Exception):
        IntegrationCreateRequest(provider="clerk", display_name="x")


# ════════════════════════════════════════════════════════════════════════════
# Section B — Schema credential field presence / shape validation
# ════════════════════════════════════════════════════════════════════════════


def test_schema_azure_requires_all_four_fields():
    """Azure requires tenant_id, client_id, client_secret, subscription_id."""
    from app.schemas.integration import IntegrationCreateRequest

    # Missing each field → rejected.
    base = dict(
        provider="azure", display_name="x",
        azure_tenant_id=AZURE_TEST_TENANT_ID,
        azure_client_id=AZURE_TEST_CLIENT_ID,
        azure_client_secret=AZURE_TEST_CLIENT_SECRET,
        azure_subscription_id=AZURE_TEST_SUBSCRIPTION_ID,
    )
    # Accepts the full set.
    IntegrationCreateRequest(**base)

    for missing in (
        "azure_tenant_id",
        "azure_client_id",
        "azure_client_secret",
        "azure_subscription_id",
    ):
        payload = dict(base)
        payload.pop(missing)
        with pytest.raises(Exception):
            IntegrationCreateRequest(**payload)


def test_schema_google_cloud_requires_service_account_json():
    """Google Cloud requires the service_account_json (project_id is optional)."""
    from app.schemas.integration import IntegrationCreateRequest

    # SA JSON only — accepted (project_id is derived).
    IntegrationCreateRequest(
        provider="google_cloud", display_name="x",
        google_cloud_service_account_json=GCP_TEST_SERVICE_ACCOUNT_JSON,
    )
    # Missing SA JSON — rejected.
    with pytest.raises(Exception):
        IntegrationCreateRequest(
            provider="google_cloud", display_name="x",
            google_cloud_project_id=GCP_TEST_PROJECT_ID,
        )


def test_schema_twilio_requires_account_sid_and_auth_token():
    """Twilio requires both account_sid and auth_token."""
    from app.schemas.integration import IntegrationCreateRequest

    IntegrationCreateRequest(
        provider="twilio", display_name="x",
        twilio_account_sid=TWILIO_TEST_ACCOUNT_ID,
        twilio_auth_token=TWILIO_TEST_AUTH_TOKEN,
    )
    for missing in ("twilio_account_sid", "twilio_auth_token"):
        payload = dict(
            provider="twilio", display_name="x",
            twilio_account_sid=TWILIO_TEST_ACCOUNT_ID,
            twilio_auth_token=TWILIO_TEST_AUTH_TOKEN,
        )
        payload.pop(missing)
        with pytest.raises(Exception):
            IntegrationCreateRequest(**payload)


def test_schema_sendgrid_requires_api_key():
    """SendGrid requires api_key."""
    from app.schemas.integration import IntegrationCreateRequest

    IntegrationCreateRequest(
        provider="sendgrid", display_name="x",
        sendgrid_api_key=SENDGRID_TEST_API_KEY,
    )
    with pytest.raises(Exception):
        IntegrationCreateRequest(provider="sendgrid", display_name="x")


def test_schema_auth0_client_credentials_mode_accepted():
    """Auth0 client_credentials mode (domain + client_id + client_secret) is accepted."""
    from app.schemas.integration import IntegrationCreateRequest

    IntegrationCreateRequest(
        provider="auth0", display_name="x",
        auth0_domain=AUTH0_TEST_DOMAIN,
        auth0_client_id=AUTH0_TEST_CLIENT_ID,
        auth0_client_secret=AUTH0_TEST_CLIENT_SECRET,
    )


def test_schema_auth0_management_token_mode_accepted():
    """Auth0 direct-token mode (domain + management_api_token) is accepted."""
    from app.schemas.integration import IntegrationCreateRequest

    IntegrationCreateRequest(
        provider="auth0", display_name="x",
        auth0_domain=AUTH0_TEST_DOMAIN,
        auth0_management_api_token=AUTH0_TEST_MANAGEMENT_TOKEN,
    )


def test_schema_auth0_requires_domain():
    """Auth0 always requires a domain regardless of auth mode."""
    from app.schemas.integration import IntegrationCreateRequest

    # Domain missing — rejected.
    with pytest.raises(Exception):
        IntegrationCreateRequest(
            provider="auth0", display_name="x",
            auth0_management_api_token=AUTH0_TEST_MANAGEMENT_TOKEN,
        )


def test_schema_auth0_requires_either_client_creds_or_mgmt_token():
    """Auth0 needs either client_id+client_secret OR a management_api_token."""
    from app.schemas.integration import IntegrationCreateRequest

    # Domain alone — rejected.
    with pytest.raises(Exception):
        IntegrationCreateRequest(
            provider="auth0", display_name="x",
            auth0_domain=AUTH0_TEST_DOMAIN,
        )
    # Domain + client_id (no secret) — rejected.
    with pytest.raises(Exception):
        IntegrationCreateRequest(
            provider="auth0", display_name="x",
            auth0_domain=AUTH0_TEST_DOMAIN,
            auth0_client_id=AUTH0_TEST_CLIENT_ID,
        )


# ════════════════════════════════════════════════════════════════════════════
# Section C — Router credential extraction sanitisation
# ════════════════════════════════════════════════════════════════════════════


def test_router_build_credentials_extracts_each_new_provider():
    """_build_credentials returns the connector-shape credentials dict."""
    from app.routers.integrations import _build_credentials
    from app.schemas.integration import IntegrationCreateRequest

    azure_req = IntegrationCreateRequest(
        provider="azure", display_name="x",
        azure_tenant_id=AZURE_TEST_TENANT_ID,
        azure_client_id=AZURE_TEST_CLIENT_ID,
        azure_client_secret=AZURE_TEST_CLIENT_SECRET,
        azure_subscription_id=AZURE_TEST_SUBSCRIPTION_ID,
    )
    creds = _build_credentials(azure_req)
    assert creds == {
        "tenant_id": AZURE_TEST_TENANT_ID,
        "client_id": AZURE_TEST_CLIENT_ID,
        "client_secret": AZURE_TEST_CLIENT_SECRET,
        "subscription_id": AZURE_TEST_SUBSCRIPTION_ID,
    }

    gcp_req = IntegrationCreateRequest(
        provider="google_cloud", display_name="x",
        google_cloud_project_id=GCP_TEST_PROJECT_ID,
        google_cloud_service_account_json=GCP_TEST_SERVICE_ACCOUNT_JSON,
    )
    creds = _build_credentials(gcp_req)
    assert creds == {
        "project_id": GCP_TEST_PROJECT_ID,
        "service_account_json": GCP_TEST_SERVICE_ACCOUNT_JSON,
    }

    twilio_req = IntegrationCreateRequest(
        provider="twilio", display_name="x",
        twilio_account_sid=TWILIO_TEST_ACCOUNT_ID,
        twilio_auth_token=TWILIO_TEST_AUTH_TOKEN,
    )
    creds = _build_credentials(twilio_req)
    assert creds == {
        "account_sid": TWILIO_TEST_ACCOUNT_ID,
        "auth_token": TWILIO_TEST_AUTH_TOKEN,
    }

    sendgrid_req = IntegrationCreateRequest(
        provider="sendgrid", display_name="x",
        sendgrid_api_key=SENDGRID_TEST_API_KEY,
    )
    creds = _build_credentials(sendgrid_req)
    assert creds == {"api_key": SENDGRID_TEST_API_KEY}

    auth0_req_cc = IntegrationCreateRequest(
        provider="auth0", display_name="x",
        auth0_domain=AUTH0_TEST_DOMAIN,
        auth0_client_id=AUTH0_TEST_CLIENT_ID,
        auth0_client_secret=AUTH0_TEST_CLIENT_SECRET,
    )
    creds = _build_credentials(auth0_req_cc)
    assert creds == {
        "domain": AUTH0_TEST_DOMAIN,
        "client_id": AUTH0_TEST_CLIENT_ID,
        "client_secret": AUTH0_TEST_CLIENT_SECRET,
    }

    auth0_req_mt = IntegrationCreateRequest(
        provider="auth0", display_name="x",
        auth0_domain=AUTH0_TEST_DOMAIN,
        auth0_management_api_token=AUTH0_TEST_MANAGEMENT_TOKEN,
    )
    creds = _build_credentials(auth0_req_mt)
    assert creds == {
        "domain": AUTH0_TEST_DOMAIN,
        "management_api_token": AUTH0_TEST_MANAGEMENT_TOKEN,
    }


# ════════════════════════════════════════════════════════════════════════════
# Section D — integration_service dispatch for each new provider
# ════════════════════════════════════════════════════════════════════════════


def test_integration_service_dispatch_branches_exist():
    """integration_service.create_integration has explicit branches for each new provider."""
    from app.services import integration_service
    import inspect
    src = inspect.getsource(integration_service.create_integration)
    for p in M82_PRE_1_PROVIDERS:
        assert f'provider == "{p}"' in src, (
            f"create_integration missing dispatch branch for {p!r}"
        )


def test_integration_service_helpers_exist():
    """Each M82-pre.1 provider has a dedicated _create_*_integration helper."""
    from app.services import integration_service
    assert hasattr(integration_service, "_create_azure_integration")
    assert hasattr(integration_service, "_create_google_cloud_integration")
    assert hasattr(integration_service, "_create_twilio_integration")
    assert hasattr(integration_service, "_create_sendgrid_integration")
    assert hasattr(integration_service, "_create_auth0_integration")


def test_integration_service_unsupported_provider_error_message_updated():
    """The ValueError 'Unsupported provider' message lists every supported provider."""
    from app.services import integration_service
    import inspect
    src = inspect.getsource(integration_service.create_integration)
    # The else-branch message must mention every M82-pre.1 provider so a future
    # author cannot regress to the 7-provider list.
    for p in M82_PRE_1_PROVIDERS:
        assert f"'{p}'" in src or f'"{p}"' in src, (
            f"Unsupported-provider message must mention {p!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section E — Sync layer dispatches every new provider
# ════════════════════════════════════════════════════════════════════════════


def test_sync_service_supported_providers_contains_new_providers():
    """sync_service._SUPPORTED_PROVIDERS lists every M82-pre.1 provider."""
    from app.services import sync_service
    import inspect
    src = inspect.getsource(sync_service)
    m = re.search(r"_SUPPORTED_PROVIDERS\s*=\s*\((.*?)\)", src, flags=re.DOTALL)
    assert m is not None
    listed = set(re.findall(r'"([a-z0-9_]+)"', m.group(1)))
    for p in M82_PRE_1_PROVIDERS:
        assert p in listed, (
            f"sync_service._SUPPORTED_PROVIDERS missing {p!r}"
        )


def test_sync_task_dispatch_handles_new_providers():
    """sync_task source contains explicit dispatch for each M82-pre.1 provider."""
    from app.workers import sync_task
    import inspect
    src = inspect.getsource(sync_task)
    for p in M82_PRE_1_PROVIDERS:
        assert f'integration.provider == "{p}"' in src, (
            f"sync_task missing dispatch branch for {p!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section F — Frontend providers.ts surface
# ════════════════════════════════════════════════════════════════════════════

_FE_ROOT = Path(__file__).resolve().parents[2] / "frontend" / "src"


def _read_fe(rel: str) -> str:
    if not _FE_ROOT.is_dir():
        pytest.skip("frontend/src not mounted")
    path = _FE_ROOT / rel
    if not path.is_file():
        pytest.skip(f"frontend file not found: {rel}")
    return path.read_text(encoding="utf-8")


def test_fe_providers_ts_no_security_preview_flag_on_m82_pre_1_providers():
    """providers.ts entries for the 5 providers no longer carry securityPreview: true."""
    text = _read_fe("lib/providers.ts")
    for p in M82_PRE_1_PROVIDERS:
        m = re.search(rf'{p}:\s*\{{(.*?)\n  \}},', text, flags=re.DOTALL)
        assert m is not None, f"providers.ts entry for {p!r} not found"
        block = m.group(1)
        assert "securityPreview: true" not in block, (
            f"providers.ts entry for {p!r} must NOT carry securityPreview: true"
        )


def test_fe_providers_ts_all_thirteen_in_connectable_subset():
    """CONNECTABLE_PROVIDER_IDS includes every M82-pre.1 provider."""
    text = _read_fe("lib/providers.ts")
    m = re.search(
        r"export const CONNECTABLE_PROVIDER_IDS\s*:\s*ProviderId\[\]\s*=\s*\[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None
    ids = set(re.findall(r'"([a-z0-9_]+)"', m.group(1)))
    for p in M82_PRE_1_PROVIDERS:
        assert p in ids, (
            f"CONNECTABLE_PROVIDER_IDS missing {p!r} after M82-pre.1"
        )


def test_fe_providers_ts_security_preview_subset_is_empty():
    """SECURITY_PREVIEW_PROVIDER_IDS is empty after M82-pre.1."""
    text = _read_fe("lib/providers.ts")
    m = re.search(
        r"export const SECURITY_PREVIEW_PROVIDER_IDS\s*:\s*ProviderId\[\]\s*=\s*\[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None
    ids = re.findall(r'"([a-z0-9_]+)"', m.group(1))
    assert ids == [], (
        f"SECURITY_PREVIEW_PROVIDER_IDS must be empty post-M82-pre.1; got {ids}"
    )


def test_fe_providers_ts_trust_notes_safe_copy():
    """Each M82-pre.1 provider's trustNote says what is NEVER stored."""
    text = _read_fe("lib/providers.ts")
    privacy_required = {
        "azure": ("client secrets", "access tokens"),
        # GCP says "Service account JSON key material" — covers both 'service
        # account' and 'key material' privacy guarantees.
        "google_cloud": ("service account", "key material"),
        "twilio": ("auth tokens", "phone"),
        "sendgrid": ("api key values", "email"),
        "auth0": ("client secrets", "user emails"),
    }
    for p, keywords in privacy_required.items():
        m = re.search(rf'{p}:\s*\{{(.*?)\n  \}},', text, flags=re.DOTALL)
        assert m is not None
        block_lower = m.group(1).lower()
        for kw in keywords:
            assert kw in block_lower, (
                f"providers.ts {p!r} trustNote should mention {kw!r}"
            )
        assert "never" in block_lower


# ════════════════════════════════════════════════════════════════════════════
# Section G — Integrations page wires each new credential form
# ════════════════════════════════════════════════════════════════════════════


def test_fe_integrations_page_imports_each_new_form():
    """The integrations page imports each M82-pre.1 credential form component."""
    text = _read_fe("app/(app)/integrations/page.tsx")
    for component in (
        "AzureIntegrationForm",
        "GoogleCloudIntegrationForm",
        "TwilioIntegrationForm",
        "SendGridIntegrationForm",
        "Auth0IntegrationForm",
    ):
        assert component in text, (
            f"integrations/page.tsx missing import for {component!r}"
        )


def test_fe_integrations_page_renders_each_new_form():
    """renderProviderForm has a branch for each M82-pre.1 provider."""
    text = _read_fe("app/(app)/integrations/page.tsx")
    for p in M82_PRE_1_PROVIDERS:
        assert f'selectedProvider === "{p}"' in text, (
            f"renderProviderForm missing branch for {p!r}"
        )


def test_fe_each_credential_form_file_exists():
    """Each M82-pre.1 form file exists in components/integrations/."""
    base = _FE_ROOT / "components" / "integrations"
    if not base.is_dir():
        pytest.skip("frontend components/integrations not mounted")
    for filename in (
        "AzureIntegrationForm.tsx",
        "GoogleCloudIntegrationForm.tsx",
        "TwilioIntegrationForm.tsx",
        "SendGridIntegrationForm.tsx",
        "Auth0IntegrationForm.tsx",
    ):
        assert (base / filename).is_file(), (
            f"missing form file: {filename}"
        )


def test_fe_credential_forms_clear_secret_state_on_success():
    """Every form clears its secret-bearing useState after a successful submit."""
    forms_to_secrets = {
        "AzureIntegrationForm.tsx": "setClientSecret",
        "GoogleCloudIntegrationForm.tsx": "setServiceAccountJson",
        "TwilioIntegrationForm.tsx": "setAuthToken",
        "SendGridIntegrationForm.tsx": "setApiKey",
        "Auth0IntegrationForm.tsx": "setClientSecret",
    }
    for fname, setter in forms_to_secrets.items():
        text = _read_fe(f"components/integrations/{fname}")
        # The secret-clearing setter must be called with an empty string.
        assert re.search(rf'{setter}\(\s*""\s*\)', text), (
            f"{fname} must clear secret state via {setter}(\"\") after submit"
        )


def test_fe_credential_forms_use_password_input_for_secrets():
    """Secret inputs use type=password to avoid shoulder-surfing."""
    for fname in (
        "AzureIntegrationForm.tsx",
        "TwilioIntegrationForm.tsx",
        "SendGridIntegrationForm.tsx",
        "Auth0IntegrationForm.tsx",
    ):
        text = _read_fe(f"components/integrations/{fname}")
        assert 'type="password"' in text, (
            f"{fname} must use type=password for secret fields"
        )


def test_fe_credential_forms_have_safe_trust_copy():
    """Each form includes a 'ConfigTrace stores ... encrypted' privacy note.

    The trust-copy strings can wrap across JSX line breaks, so we collapse
    runs of whitespace before checking for each keyword.
    """
    forms_to_keywords = {
        "AzureIntegrationForm.tsx": ("encrypted", "client secrets"),
        "GoogleCloudIntegrationForm.tsx": ("encrypted", "private keys"),
        "TwilioIntegrationForm.tsx": ("encrypted", "auth tokens"),
        "SendGridIntegrationForm.tsx": ("encrypted", "API key values"),
        "Auth0IntegrationForm.tsx": ("encrypted", "client secrets"),
    }
    for fname, keywords in forms_to_keywords.items():
        raw = _read_fe(f"components/integrations/{fname}")
        # Collapse JSX whitespace runs (newline + indent) into single space
        # so multi-line phrases like "client\n            secrets" match.
        collapsed = re.sub(r"\s+", " ", raw)
        for kw in keywords:
            assert kw in collapsed, (
                f"{fname} must include trust-copy keyword {kw!r}"
            )


def test_fe_credential_forms_no_forbidden_wording():
    """Forms contain no forbidden claim phrases."""
    for fname in (
        "AzureIntegrationForm.tsx",
        "GoogleCloudIntegrationForm.tsx",
        "TwilioIntegrationForm.tsx",
        "SendGridIntegrationForm.tsx",
        "Auth0IntegrationForm.tsx",
    ):
        text = _read_fe(f"components/integrations/{fname}").lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"{fname} contains forbidden phrase {phrase!r}"
            )


def test_fe_credential_forms_no_secret_shape_strings():
    """Forms do not embed JWT/Twilio/SendGrid secret-shape strings."""
    forbidden = [
        r"eyJ[A-Za-z0-9_-]{10,}",
        r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"AC[0-9a-fA-F]{32}",
        r"SK[0-9a-fA-F]{32}",
    ]
    for fname in (
        "AzureIntegrationForm.tsx",
        "GoogleCloudIntegrationForm.tsx",
        "TwilioIntegrationForm.tsx",
        "SendGridIntegrationForm.tsx",
        "Auth0IntegrationForm.tsx",
    ):
        text = _read_fe(f"components/integrations/{fname}")
        for pattern in forbidden:
            assert not re.search(pattern, text), (
                f"{fname} contains secret-shape pattern {pattern}"
            )


# ════════════════════════════════════════════════════════════════════════════
# Section H — Frontend types/index.ts and api.ts
# ════════════════════════════════════════════════════════════════════════════


def test_fe_types_provider_union_includes_all_thirteen():
    """IntegrationCreateRequest.provider union covers all 13 providers."""
    text = _read_fe("types/index.ts")
    # The union is split across multiple lines after M82-pre.1.
    m = re.search(
        r"export interface IntegrationCreateRequest\s*\{(.*?)\}",
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "IntegrationCreateRequest interface not found"
    interface_block = m.group(1)
    for p in ALL_THIRTEEN:
        assert f'"{p}"' in interface_block, (
            f"IntegrationCreateRequest provider union missing {p!r}"
        )


def test_fe_types_credential_fields_present():
    """IntegrationCreateRequest declares every new credential field."""
    text = _read_fe("types/index.ts")
    for field in (
        "azure_tenant_id",
        "azure_client_id",
        "azure_client_secret",
        "azure_subscription_id",
        "google_cloud_project_id",
        "google_cloud_service_account_json",
        "twilio_account_sid",
        "twilio_auth_token",
        "sendgrid_api_key",
        "auth0_domain",
        "auth0_client_id",
        "auth0_client_secret",
        "auth0_management_api_token",
    ):
        assert f"{field}?:" in text, (
            f"types/index.ts IntegrationCreateRequest missing field {field!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section I — Capability matrix and provider expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_auth0_notes_mention_m82_pre_1():
    """Auth0 capability notes mention the M82-pre.1 credential-connect parity."""
    cap = cap_svc.get_provider_capability("auth0")
    assert cap is not None
    notes = cap.notes or ""
    assert "M82-pre.1" in notes, (
        "Auth0 capability notes must mention M82-pre.1 after credential-connect "
        "parity lands"
    )


def test_expansion_framework_planned_next_stage_is_m82a_datadog():
    """planned_next_stage points to M82A: Datadog (unchanged from M82-pre)."""
    fw = exp_svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M82A" in stage or "Datadog" in stage or "M83" in stage or "Clerk" in stage, (
        f"planned_next_stage should point to M82A/Datadog or later; got: {stage!r}"
    )
    # The intermediate M82-pre / M82-pre.1 stages are done.
    assert "M82-pre" not in stage


# ════════════════════════════════════════════════════════════════════════════
# Section J — Secret-safety / no-leak guarantees (live in-memory pipeline)
# ════════════════════════════════════════════════════════════════════════════


def test_create_integration_does_not_leak_credentials_in_response(
    test_user, db_session,
):
    """Creating an Azure integration returns IntegrationResponse without secrets."""
    from app.services import integration_service
    from app.schemas.integration import IntegrationResponse

    credentials = {
        "tenant_id": AZURE_TEST_TENANT_ID,
        "client_id": AZURE_TEST_CLIENT_ID,
        "client_secret": AZURE_TEST_CLIENT_SECRET,
        "subscription_id": AZURE_TEST_SUBSCRIPTION_ID,
    }
    integration = integration_service.create_integration(
        user_id=test_user.id,
        provider="azure",
        display_name="m82pre1-azure",
        credentials=credentials,
        db=db_session,
    )

    try:
        # The Integration row stores encrypted credentials only.
        assert integration.encrypted_credentials is not None
        assert integration.credential_iv is not None
        # IntegrationResponse omits credentials entirely.
        response = IntegrationResponse.model_validate(integration)
        response_dump = response.model_dump_json()
        for secret in (
            AZURE_TEST_CLIENT_SECRET,
            credentials["tenant_id"],
            credentials["client_id"],
        ):
            # tenant_id and client_id are not strictly secret but they should
            # not be returned by IntegrationResponse either — only safe summary
            # fields (id, provider, display_name, status, etc.) are surfaced.
            assert secret not in response_dump, (
                f"IntegrationResponse leaked credential value {secret!r}"
            )
    finally:
        # Cleanup
        from app.models.resource import Resource
        db_session.query(Resource).filter(
            Resource.integration_id == integration.id
        ).delete(synchronize_session=False)
        db_session.delete(integration)
        db_session.commit()


def test_create_integration_resource_metadata_omits_secrets(
    test_user, db_session,
):
    """The seeded Resource row's resource_metadata contains no secret values."""
    from app.services import integration_service
    from app.models.resource import Resource

    creds_per_provider = {
        "azure": {
            "tenant_id": AZURE_TEST_TENANT_ID,
            "client_id": AZURE_TEST_CLIENT_ID,
            "client_secret": AZURE_TEST_CLIENT_SECRET,
            "subscription_id": AZURE_TEST_SUBSCRIPTION_ID,
        },
        "google_cloud": {
            "project_id": GCP_TEST_PROJECT_ID,
            "service_account_json": GCP_TEST_SERVICE_ACCOUNT_JSON,
        },
        "twilio": {
            "account_sid": TWILIO_TEST_ACCOUNT_ID,
            "auth_token": TWILIO_TEST_AUTH_TOKEN,
        },
        "sendgrid": {
            "api_key": SENDGRID_TEST_API_KEY,
        },
        "auth0": {
            "domain": AUTH0_TEST_DOMAIN,
            "client_id": AUTH0_TEST_CLIENT_ID,
            "client_secret": AUTH0_TEST_CLIENT_SECRET,
        },
    }
    secret_values = {
        AZURE_TEST_CLIENT_SECRET,
        TWILIO_TEST_AUTH_TOKEN,
        SENDGRID_TEST_API_KEY,
        AUTH0_TEST_CLIENT_SECRET,
        AUTH0_TEST_MANAGEMENT_TOKEN,
        GCP_TEST_SERVICE_ACCOUNT_JSON,
    }

    created_ids: list[uuid.UUID] = []
    try:
        for provider, creds in creds_per_provider.items():
            integration = integration_service.create_integration(
                user_id=test_user.id,
                provider=provider,
                display_name=f"m82pre1-{provider}",
                credentials=creds,
                db=db_session,
            )
            created_ids.append(integration.id)

            # Inspect the seeded Resource row's metadata.
            resource = (
                db_session.query(Resource)
                .filter(Resource.integration_id == integration.id)
                .first()
            )
            assert resource is not None, (
                f"create_integration for {provider!r} did not seed a Resource"
            )
            md = resource.resource_metadata or {}
            import json as _json
            md_blob = _json.dumps(md, default=str)
            for secret in secret_values:
                assert secret not in md_blob, (
                    f"{provider!r} resource_metadata leaked secret value "
                    f"{secret[:12]!r}…"
                )
    finally:
        for iid in created_ids:
            db_session.query(Resource).filter(
                Resource.integration_id == iid
            ).delete(synchronize_session=False)
        from app.models.integration import Integration
        db_session.query(Integration).filter(
            Integration.id.in_(created_ids)
        ).delete(synchronize_session=False)
        db_session.commit()


# ════════════════════════════════════════════════════════════════════════════
# Section K — Forbidden wording / secret-shape sweep
# ════════════════════════════════════════════════════════════════════════════


def test_no_forbidden_wording_in_new_backend_modules():
    """No forbidden claim phrases in the credential-connect backend touchpoints."""
    from app.schemas import integration as int_schema
    from app.routers import integrations as int_router
    from app.services import integration_service
    import inspect

    for mod in (int_schema, int_router, integration_service):
        src = inspect.getsource(mod)
        # Strip negation-context lines.
        lines = []
        for line in src.splitlines():
            low = line.lower()
            if any(tok in low for tok in (
                "does not confirm", "never assert", "never claim",
                "do not claim", "forbidden", "not confirm",
                "claim discipline", "review-safe", "without claiming",
            )):
                continue
            lines.append(line)
        stripped = "\n".join(lines).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in stripped, (
                f"{mod.__name__} contains forbidden phrase {phrase!r}"
            )


def test_no_secret_shapes_in_new_backend_modules():
    """No JWT/Twilio/SendGrid secret-shape literals in new backend touchpoints."""
    from app.schemas import integration as int_schema
    from app.routers import integrations as int_router
    from app.services import integration_service
    import inspect

    patterns = [
        r"eyJ[A-Za-z0-9_-]{10,}",
        r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"AC[0-9a-fA-F]{32}",
        r"SK[0-9a-fA-F]{32}",
    ]
    for mod in (int_schema, int_router, integration_service):
        src = inspect.getsource(mod)
        for pattern in patterns:
            assert not re.search(pattern, src), (
                f"{mod.__name__} contains secret-shape pattern {pattern}"
            )
