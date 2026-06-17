"""M82-pre — Provider integration card parity guardrails.

Pins the M82-pre product change: Azure, Google Cloud, Twilio, SendGrid, and
Auth0 are surfaced on the integrations page as security-preview cards that
route to /security/cases (where each provider's demo lives) instead of
opening a credential connect form.

CRITICAL PRINCIPLE: the integrations card grid is allowed to advertise a
provider only when one of the following is true:

  * Backend POST /integrations validates the provider AND the connector
    has a tested credential-driven sync path (the 8 canonical providers).
  * The provider has a complete security arc (drift rules, activity
    ingestion, signals, correlations, demo + case evidence) but no
    credential connect form yet — surfaced as a "Security preview" card
    that links to /security/cases (the demo home).

This file adds NO product code — it pins:

  A. Backend integrations allowlist still excludes security-preview providers
  B. Sync layer / sync_task already supports all 13 provider keys
  C. Each security-preview provider has a real connector class
  D. Frontend provider registry (providers.ts) surfaces all 13 providers
  E. Integrations page renders security-preview CTA for the 5 new providers
  F. Provider expansion framework advances past M82-pre
  G. Capability matrix Auth0 notes mention M82-pre
  H. No forbidden claim phrases, no JWT/secret-shape strings on the
     integrations surface
"""

from __future__ import annotations

import re
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

# ── The 5 M82-pre security-preview providers ─────────────────────────────────
SECURITY_PREVIEW_PROVIDERS = ("azure", "google_cloud", "twilio", "sendgrid", "auth0")

# ── The 8 canonical connectable providers (POST /integrations allowlist) ─────
CONNECTABLE_PROVIDERS = (
    "cloudflare", "github", "vercel", "stripe",
    "aws", "firebase", "supabase", "shopify",
)


# ════════════════════════════════════════════════════════════════════════════
# Section A — Backend integrations allowlist
# ════════════════════════════════════════════════════════════════════════════
#
# The POST /integrations schema must keep the existing 8-provider allowlist.
# The 5 security-preview providers (azure, google_cloud, twilio, sendgrid,
# auth0) have connectors and sync support but no validated credential UI,
# so they MUST NOT be in the integration-creation allowlist yet.


def test_backend_post_integrations_allowlist_is_eight_connectable_providers():
    """POST /integrations Literal type contains exactly the 8 canonical providers."""
    from app.schemas.integration import IntegrationCreateRequest
    # Pydantic v2: the provider field's allowed literal values.
    field = IntegrationCreateRequest.model_fields["provider"]
    annotation = field.annotation
    # annotation is Literal["cloudflare", "github", ...] — extract its args.
    import typing
    allowed = set(typing.get_args(annotation))
    assert allowed == set(CONNECTABLE_PROVIDERS), (
        f"POST /integrations allowlist drift: expected {set(CONNECTABLE_PROVIDERS)}, "
        f"got {allowed}"
    )


def test_backend_post_integrations_allowlist_excludes_security_preview_providers():
    """The 5 security-preview providers must NOT yet be accepted by POST /integrations."""
    from app.schemas.integration import IntegrationCreateRequest
    import typing
    annotation = IntegrationCreateRequest.model_fields["provider"].annotation
    allowed = set(typing.get_args(annotation))
    for p in SECURITY_PREVIEW_PROVIDERS:
        assert p not in allowed, (
            f"Security-preview provider {p!r} must NOT be in the integration-creation "
            f"allowlist until its credential UI is wired."
        )


# ════════════════════════════════════════════════════════════════════════════
# Section B — Sync layer support
# ════════════════════════════════════════════════════════════════════════════


def test_sync_service_supports_all_thirteen_provider_keys():
    """sync_service._SUPPORTED_PROVIDERS covers all 13 provider keys."""
    # _SUPPORTED_PROVIDERS is a function-local constant in sync_service; the
    # easiest durable check is a source scan for every expected provider key.
    from app.services import sync_service
    import inspect
    src = inspect.getsource(sync_service)
    # Locate the _SUPPORTED_PROVIDERS literal block.
    m = re.search(r"_SUPPORTED_PROVIDERS\s*=\s*\((.*?)\)", src, flags=re.DOTALL)
    assert m is not None, "_SUPPORTED_PROVIDERS literal not found in sync_service"
    block = m.group(1)
    keys = set(re.findall(r'"([a-z0-9_]+)"', block))
    expected = set(CONNECTABLE_PROVIDERS) | set(SECURITY_PREVIEW_PROVIDERS)
    missing = expected - keys
    assert missing == set(), (
        f"sync_service._SUPPORTED_PROVIDERS missing providers: {missing}"
    )


def test_sync_task_dispatch_handles_security_preview_providers():
    """sync_task source contains dispatch branches for every security-preview provider."""
    from app.workers import sync_task
    import inspect
    src = inspect.getsource(sync_task)
    for p in SECURITY_PREVIEW_PROVIDERS:
        assert f'"{p}"' in src or f"'{p}'" in src, (
            f"sync_task source missing dispatch literal for provider {p!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section C — Connector classes exist for every security-preview provider
# ════════════════════════════════════════════════════════════════════════════


def test_azure_connector_class_exists():
    from app.connectors.azure import AzureConnector
    assert AzureConnector is not None


def test_google_cloud_connector_class_exists():
    from app.connectors.google_cloud import GoogleCloudConnector
    assert GoogleCloudConnector is not None


def test_twilio_connector_class_exists():
    from app.connectors.twilio import TwilioConnector
    assert TwilioConnector is not None


def test_sendgrid_connector_class_exists():
    from app.connectors.sendgrid import SendGridConnector
    assert SendGridConnector is not None


def test_auth0_connector_class_exists():
    from app.connectors.auth0 import Auth0Connector
    assert Auth0Connector is not None


# ════════════════════════════════════════════════════════════════════════════
# Section D — Frontend provider registry (providers.ts)
# ════════════════════════════════════════════════════════════════════════════

_FE_ROOT = Path(__file__).resolve().parents[2] / "frontend" / "src"


def _read_fe(rel: str) -> str:
    if not _FE_ROOT.is_dir():
        pytest.skip("frontend/src not mounted")
    path = _FE_ROOT / rel
    if not path.is_file():
        pytest.skip(f"frontend file not found: {rel}")
    return path.read_text(encoding="utf-8")


def test_fe_providers_ts_provider_id_union_includes_all_thirteen():
    """providers.ts ProviderId union includes all 13 provider keys."""
    text = _read_fe("lib/providers.ts")
    # Extract the ProviderId union block.
    m = re.search(r"export type ProviderId\s*=\s*([^;]+);", text, flags=re.DOTALL)
    assert m is not None, "ProviderId union not found in providers.ts"
    union_block = m.group(1)
    for p in CONNECTABLE_PROVIDERS + SECURITY_PREVIEW_PROVIDERS:
        assert f'"{p}"' in union_block, (
            f"ProviderId union missing {p!r}"
        )


def test_fe_providers_ts_provider_ids_array_includes_all_thirteen():
    """providers.ts PROVIDER_IDS array includes all 13 provider keys."""
    text = _read_fe("lib/providers.ts")
    m = re.search(
        r"export const PROVIDER_IDS\s*:\s*ProviderId\[\]\s*=\s*\[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None, "PROVIDER_IDS array not found in providers.ts"
    arr_block = m.group(1)
    ids = re.findall(r'"([a-z0-9_]+)"', arr_block)
    assert set(ids) == set(CONNECTABLE_PROVIDERS) | set(SECURITY_PREVIEW_PROVIDERS), (
        f"PROVIDER_IDS drift: got {ids}"
    )


def test_fe_providers_ts_security_preview_subset_exists():
    """providers.ts exposes SECURITY_PREVIEW_PROVIDER_IDS with exactly the 5 providers."""
    text = _read_fe("lib/providers.ts")
    m = re.search(
        r"export const SECURITY_PREVIEW_PROVIDER_IDS\s*:\s*ProviderId\[\]\s*=\s*\[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None, (
        "SECURITY_PREVIEW_PROVIDER_IDS array not found in providers.ts"
    )
    ids = re.findall(r'"([a-z0-9_]+)"', m.group(1))
    assert set(ids) == set(SECURITY_PREVIEW_PROVIDERS), (
        f"SECURITY_PREVIEW_PROVIDER_IDS drift: got {ids}"
    )


def test_fe_providers_ts_connectable_subset_exists():
    """providers.ts exposes CONNECTABLE_PROVIDER_IDS with exactly the 8 connectable providers."""
    text = _read_fe("lib/providers.ts")
    m = re.search(
        r"export const CONNECTABLE_PROVIDER_IDS\s*:\s*ProviderId\[\]\s*=\s*\[(.*?)\];",
        text,
        flags=re.DOTALL,
    )
    assert m is not None, (
        "CONNECTABLE_PROVIDER_IDS array not found in providers.ts"
    )
    ids = re.findall(r'"([a-z0-9_]+)"', m.group(1))
    assert set(ids) == set(CONNECTABLE_PROVIDERS), (
        f"CONNECTABLE_PROVIDER_IDS drift: got {ids}"
    )


def test_fe_providers_ts_each_security_preview_has_security_preview_flag():
    """Every security-preview provider entry has securityPreview: true."""
    text = _read_fe("lib/providers.ts")
    for p in SECURITY_PREVIEW_PROVIDERS:
        # Locate the entry block for this provider id.
        m = re.search(
            rf'{p}:\s*\{{(.*?)\n  \}},',
            text,
            flags=re.DOTALL,
        )
        assert m is not None, f"providers.ts entry for {p!r} not found"
        block = m.group(1)
        assert "securityPreview: true" in block, (
            f"providers.ts entry for {p!r} missing securityPreview: true flag"
        )


def test_fe_providers_ts_each_provider_has_required_metadata_fields():
    """Each of the 5 new providers has label, description, monitoredSurfaces, trustNote."""
    text = _read_fe("lib/providers.ts")
    for p in SECURITY_PREVIEW_PROVIDERS:
        m = re.search(rf'{p}:\s*\{{(.*?)\n  \}},', text, flags=re.DOTALL)
        assert m is not None
        block = m.group(1)
        for field in ("label:", "shortLabel:", "category:", "description:",
                      "monitoredSurfaces:", "trustNote:", "color:",
                      "bgColor:", "borderColor:"):
            assert field in block, (
                f"providers.ts entry for {p!r} missing field {field!r}"
            )


def test_fe_providers_ts_safe_trust_notes_for_security_preview_providers():
    """Each security-preview provider's trustNote explicitly says what is NOT stored."""
    text = _read_fe("lib/providers.ts")
    privacy_keywords = {
        "azure": ("client secrets", "access tokens"),
        "google_cloud": ("service account", "tokens"),
        "twilio": ("auth tokens", "phone"),
        "sendgrid": ("api key values", "email"),
        "auth0": ("client secrets", "user emails"),
    }
    for p, must_include in privacy_keywords.items():
        m = re.search(rf'{p}:\s*\{{(.*?)\n  \}},', text, flags=re.DOTALL)
        assert m is not None
        block_lower = m.group(1).lower()
        for kw in must_include:
            assert kw in block_lower, (
                f"providers.ts trustNote for {p!r} should mention {kw!r}"
            )
        # Must NEVER claim ConfigTrace stores secrets/tokens/PII.
        # The trustNote is allowed to say "never accessed or stored".
        assert "never" in block_lower, (
            f"providers.ts trustNote for {p!r} must say what is never accessed/stored"
        )


def test_fe_providers_ts_no_forbidden_wording():
    text = _read_fe("lib/providers.ts").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text, (
            f"providers.ts contains forbidden phrase {phrase!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section E — Integrations page renders security-preview CTA correctly
# ════════════════════════════════════════════════════════════════════════════


def test_fe_integrations_page_imports_security_preview_constant():
    """integrations/page.tsx imports SECURITY_PREVIEW_PROVIDER_IDS."""
    text = _read_fe("app/(app)/integrations/page.tsx")
    assert "SECURITY_PREVIEW_PROVIDER_IDS" in text


def test_fe_integrations_page_has_security_preview_branch():
    """integrations/page.tsx has a Security preview CTA branch."""
    text = _read_fe("app/(app)/integrations/page.tsx")
    assert "Security preview" in text
    assert "View security demo" in text


def test_fe_integrations_page_handle_connect_routes_security_preview_to_cases():
    """handleConnect routes security-preview providers to /security/cases."""
    text = _read_fe("app/(app)/integrations/page.tsx")
    # Locate handleConnect function and confirm it pushes to /security/cases
    # for the security-preview set.
    m = re.search(r"function handleConnect\([^)]*\)\s*\{(.*?)\n  \}", text, flags=re.DOTALL)
    assert m is not None, "handleConnect not found in integrations/page.tsx"
    fn_body = m.group(1)
    assert "/security/cases" in fn_body, (
        "handleConnect must route security-preview providers to /security/cases"
    )
    assert "SECURITY_PREVIEW_SET" in fn_body or "SECURITY_PREVIEW_PROVIDER_IDS" in fn_body, (
        "handleConnect must check the security-preview set before opening the form"
    )


def test_fe_integrations_page_has_new_category_labels():
    """CATEGORY_LABELS map covers the new communications and identity categories."""
    text = _read_fe("app/(app)/integrations/page.tsx")
    assert "communications:" in text
    assert "identity:" in text
    assert "Communications" in text
    assert "Identity" in text


def test_fe_integrations_page_has_no_forbidden_wording():
    text = _read_fe("app/(app)/integrations/page.tsx").lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text, (
            f"integrations/page.tsx contains forbidden phrase {phrase!r}"
        )


def test_fe_integrations_page_has_no_secret_shaped_strings():
    """integrations/page.tsx does not embed any JWT/Twilio/SendGrid secret-shape strings."""
    text = _read_fe("app/(app)/integrations/page.tsx")
    forbidden = [
        r"eyJ[A-Za-z0-9_-]{10,}",
        r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"AC[0-9a-fA-F]{32}",
        r"SK[0-9a-fA-F]{32}",
    ]
    for pattern in forbidden:
        assert not re.search(pattern, text), (
            f"integrations/page.tsx contains secret-shape pattern {pattern}"
        )


def test_fe_providers_ts_has_no_secret_shaped_strings():
    """providers.ts (the registry users see) has no JWT/Twilio/SendGrid secret-shape strings."""
    text = _read_fe("lib/providers.ts")
    forbidden = [
        r"eyJ[A-Za-z0-9_-]{10,}",
        r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"AC[0-9a-fA-F]{32}",
        r"SK[0-9a-fA-F]{32}",
    ]
    for pattern in forbidden:
        assert not re.search(pattern, text), (
            f"providers.ts contains secret-shape pattern {pattern}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section F — Provider expansion framework advances past M82-pre
# ════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_is_m82a_datadog():
    """After M82-pre, planned_next_stage points to M82A: Datadog Drift Provider Foundation."""
    fw = exp_svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M82-pre" not in stage, (
        f"planned_next_stage still points to M82-pre after arc closed: {stage!r}"
    )
    assert "M82A" in stage or "Datadog" in stage, (
        f"planned_next_stage should point to M82A/Datadog; got: {stage!r}"
    )


def test_expansion_framework_auth0_arc_complete_not_in_recommendations():
    """Auth0 arc complete M81A–M81I — not in recommended queue."""
    fw = exp_svc.get_framework()
    providers = [r["provider"] for r in fw["recommended_next_providers"]]
    assert "auth0" not in providers


def test_expansion_framework_datadog_is_next():
    """Datadog is the top recommendation after the Auth0 arc closed."""
    fw = exp_svc.get_framework()
    recs = fw["recommended_next_providers"]
    assert len(recs) > 0
    assert recs[0]["provider"] == "datadog"


# ════════════════════════════════════════════════════════════════════════════
# Section G — Capability matrix Auth0 notes mention M82-pre
# ════════════════════════════════════════════════════════════════════════════


def test_capability_matrix_auth0_notes_mention_m82_pre():
    """Auth0 capability notes mention M82-pre integration-card surfacing."""
    cap = cap_svc.get_provider_capability("auth0")
    assert cap is not None
    notes = cap.notes or ""
    assert "M82-pre" in notes, (
        "Auth0 capability notes should mention M82-pre after the integrations "
        "card lands"
    )


def test_capability_matrix_provider_keys_intact():
    """The 5 security-preview providers are still registered in the capability matrix."""
    for p in SECURITY_PREVIEW_PROVIDERS:
        cap = cap_svc.get_provider_capability(p)
        assert cap is not None, (
            f"capability matrix missing entry for security-preview provider {p!r}"
        )
        assert cap.provider == p


# ════════════════════════════════════════════════════════════════════════════
# Section H — Privacy / secret-shape / forbidden wording across the surface
# ════════════════════════════════════════════════════════════════════════════


def test_no_forbidden_phrases_in_backend_capability_matrix():
    """provider_capability_matrix_service has no forbidden claim phrases in user-facing notes."""
    import inspect
    src = inspect.getsource(cap_svc).lower()
    # Strip negation contexts.
    lines = []
    for line in src.splitlines():
        if any(tok in line for tok in (
            "does not confirm", "never assert", "never claim",
            "do not claim", "forbidden", "not confirm",
            "claim discipline", "review-safe", "without claiming",
        )):
            continue
        lines.append(line)
    stripped = "\n".join(lines)
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"provider_capability_matrix_service contains forbidden phrase "
            f"{phrase!r} outside a negation context"
        )
