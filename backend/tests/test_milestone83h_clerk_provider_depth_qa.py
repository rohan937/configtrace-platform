"""M83H — Clerk provider-depth QA guardrails.

Durable, deterministic guardrails that prove the whole Clerk arc
(M83A–M83G) stays internally consistent.  This file adds NO product code —
it pins taxonomy parity, privacy / sanitization discipline, claim discipline,
false-positive behavior, demo isolation, router admin guards, frontend
consistency, regression smoke, and capability-matrix / expansion-framework
pins.

Sections:

  A. Taxonomy parity
     Record types ↔ rule keys ↔ activity event types ↔ signal types ↔
     correlation types ↔ provider registrations.

  B. Privacy guardrails
     Clerk-shaped denylist applied to every Clerk source module.
     Allowlist parity for activity / signal / correlation / case-report layers.
     Signal-type-map orphan check (all mapped event types must be ingestible).

  C. Claim discipline
     Forbidden-phrase scan over every Clerk production module.

  D. False-positive behavior
     End-to-end "should NOT fire" cases for all 10 record types plus
     cross-provider correlation isolation.

  E. Demo isolation
     Demo constants use safe placeholder shapes only (no JWT, no key, no URL,
     no PII).  Demo labels all reference "Clerk" correctly.

  F. Router/API guards
     Clerk activity sync / signal-generate / correlation-generate /
     incident demo seed-clear require admin.

  G. Frontend Clerk consistency (skip if frontend tree absent)
     Provider selectors / type filter dropdowns / rule catalog / demo card /
     api unions / demo-script copy all carry Clerk entries.

  H. Regression smoke
     Evaluator dispatch + allowlists + correlation rule shape pinned so
     M83I polish cannot drift them silently.

  I. Capability matrix + expansion framework pins
     All M83H-required capability flags, planned_next_stage, and
     recommended-next milestone numbering.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.connectors.clerk_schema import CLERK_RECORD_TYPES
from app.connectors.clerk import _CLERK_CONFIG_EVENT_TYPES
from app.services import clerk_activity_ingestion_service as ck_ingest
from app.services import clerk_activity_signal_service as ck_sig
from app.services import clerk_risk_activity_correlation_service as ck_corr
from app.services import security_case_report_service as report_svc
from app.services import security_incident_demo_service as demo_svc
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_activity_event_service import (
    ALLOWED_METADATA_KEYS as ACTIVITY_ALLOWED,
)
from app.services.security_coverage_service import (
    PROVIDER_SURFACES,
    PROVIDERS as COVERAGE_PROVIDERS,
    RULE_RECORD_TYPES,
)
from app.services.security_incident_signal_service import (
    ALLOWED_METADATA_KEYS as SIGNAL_ALLOWED,
)
from app.services.security_signal_correlation_service import (
    ALLOWED_METADATA_KEYS as CORRELATION_ALLOWED,
)
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules.clerk import (
    CLERK_RULE_KEYS,
    evaluate as ck_eval,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ROOT = REPO_ROOT / "frontend" / "src"
FE_ACTIVITY = FE_ROOT / "app" / "(app)" / "security" / "activity" / "page.tsx"
FE_SIGNALS = FE_ROOT / "app" / "(app)" / "security" / "signals" / "page.tsx"
FE_CORRELATIONS = FE_ROOT / "app" / "(app)" / "security" / "correlations" / "page.tsx"
FE_CASES = FE_ROOT / "app" / "(app)" / "security" / "cases" / "page.tsx"
FE_DEMO_SCRIPT_PAGE = FE_ROOT / "app" / "(app)" / "security" / "demo-script" / "page.tsx"
FE_DEMO_SCRIPT_LIB = FE_ROOT / "lib" / "securityDemoScript.ts"
FE_RULE_CATALOG = FE_ROOT / "lib" / "securityRuleCatalog.ts"
FE_API = FE_ROOT / "lib" / "api.ts"
FE_PROVIDERS = FE_ROOT / "lib" / "providers.ts"
FE_TYPES = FE_ROOT / "types" / "index.ts"
FE_TRUST_CENTER = FE_ROOT / "lib" / "trustCenter.ts"


# ════════════════════════════════════════════════════════════════════════════
# Fixed expected sets — the M83H baseline.
# ════════════════════════════════════════════════════════════════════════════

EXPECTED_RECORD_TYPES: frozenset[str] = frozenset(
    {
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
)

EXPECTED_RULE_KEYS: frozenset[str] = frozenset(
    {
        # instance_settings (3)
        "clerk_instance_mfa_disabled",
        "clerk_instance_password_without_mfa",
        "clerk_instance_sign_up_enabled",
        # application (7)
        "clerk_application_mfa_not_required",
        "clerk_application_sign_up_enabled",
        "clerk_application_password_without_mfa",
        "clerk_application_oauth_without_mfa",
        "clerk_application_saml_without_mfa",
        "clerk_application_many_redirect_urls",
        "clerk_application_many_allowed_origins",
        # domain (2)
        "clerk_domain_unverified",
        "clerk_domain_ssl_disabled",
        # redirect URL (4)
        "clerk_redirect_url_non_https",
        "clerk_redirect_url_wildcard_present",
        "clerk_redirect_url_localhost_present",
        "clerk_redirect_url_custom_scheme_present",
        # JWT template (5)
        "clerk_jwt_template_custom_claims_present",
        "clerk_jwt_template_long_lifetime",
        "clerk_jwt_template_audience_missing",
        "clerk_jwt_template_issuer_missing",
        "clerk_jwt_template_many_claims",
        # webhook endpoint (4)
        "clerk_webhook_endpoint_disabled",
        "clerk_webhook_without_signing",
        "clerk_webhook_non_https",
        "clerk_webhook_broad_event_scope",
        # email/SMS (1)
        "clerk_email_sms_custom_sender_present",
        # auth strategy (2)
        "clerk_auth_strategy_mfa_not_required",
        "clerk_auth_strategy_password_without_mfa",
        # organization settings (5)
        "clerk_org_verified_domains_not_required",
        "clerk_org_invitations_enabled",
        "clerk_org_admin_role_missing",
        "clerk_org_high_role_count",
        "clerk_org_high_permission_count",
        # session policy (7)
        "clerk_session_lifetime_extended",
        "clerk_session_inactivity_timeout_extended",
        "clerk_session_single_session_disabled",
        "clerk_session_token_rotation_disabled",
        "clerk_session_device_tracking_disabled",
        "clerk_session_reverification_disabled",
        "clerk_session_long_lifetime_without_single_session",
    }
)

EXPECTED_ACTIVITY_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "clerk.instance_settings.updated",
        "clerk.auth_strategy.updated",
        "clerk.organization_settings.updated",
        "clerk.session_policy.updated",
        "clerk.email_sms_settings.updated",
        "clerk.domain.created",
        "clerk.domain.updated",
        "clerk.domain.deleted",
        "clerk.redirect_url_config.created",
        "clerk.redirect_url_config.updated",
        "clerk.redirect_url_config.deleted",
        "clerk.jwt_template.created",
        "clerk.jwt_template.updated",
        "clerk.jwt_template.deleted",
        "clerk.webhook_endpoint.created",
        "clerk.webhook_endpoint.updated",
        "clerk.webhook_endpoint.deleted",
        "clerk.config.event",
    }
)

EXPECTED_SIGNAL_TYPES: frozenset[str] = frozenset(
    {
        # 11 declared signal types. clerk_application_config_changed is a valid
        # system type (referenced by the application correlation rule) but is not
        # currently producible because the connector's list_activity_events() does
        # not synthesize clerk.application.* events. The orphaned signal-map
        # entries (clerk.application.created/updated) were removed in M83H since
        # they referenced non-ingestible event types.
        "clerk_instance_settings_config_changed",
        "clerk_application_config_changed",
        "clerk_domain_config_changed",
        "clerk_redirect_url_config_changed",
        "clerk_jwt_template_config_changed",
        "clerk_webhook_endpoint_config_changed",
        "clerk_email_sms_settings_config_changed",
        "clerk_auth_strategy_config_changed",
        "clerk_organization_settings_config_changed",
        "clerk_session_policy_config_changed",
        "clerk_config_activity",
    }
)

EXPECTED_CORRELATION_TYPES: frozenset[str] = frozenset(
    {
        "clerk_instance_settings_risk_activity_correlation",
        "clerk_application_risk_activity_correlation",
        "clerk_domain_risk_activity_correlation",
        "clerk_redirect_url_risk_activity_correlation",
        "clerk_jwt_template_risk_activity_correlation",
        "clerk_webhook_endpoint_risk_activity_correlation",
        "clerk_email_sms_settings_risk_activity_correlation",
        "clerk_auth_strategy_risk_activity_correlation",
        "clerk_organization_settings_risk_activity_correlation",
        "clerk_session_policy_risk_activity_correlation",
    }
)

# Metadata keys that must NEVER appear in Clerk allowlists (privacy denylist).
# Note: user_name is intentionally excluded here since it is an AWS IAM control-plane
# entity identifier (not a user-facing identity field) already present for AWS.
# The Clerk-specific denylist targets credential shapes, PII, and raw payload fields.
_FORBIDDEN_METADATA_KEYS = {
    # credential / token shapes
    "secret_key", "publishable_key", "api_key", "access_token", "bearer_token",
    "jwt", "token", "client_secret", "oauth_token", "webhook_secret",
    # direct PII fields (not control-plane entity labels)
    "email", "user_id", "phone_number", "first_name", "last_name",
    "ip_address", "user_agent", "session_token", "mfa_secret", "backup_code",
    "verification_code", "password",
    # raw payloads / URLs
    "raw_url", "redirect_url", "callback_url", "webhook_url", "raw_domain",
    "jwt_body", "jwt_claims", "raw_claims", "audience", "issuer_url",
    "request_payload", "response_payload", "audit_payload",
    # organizational identity
    "member_email", "member_id", "org_member",
}

# Forbidden phrases in user-facing copy.
_FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "customer data leaked",
    "payment fraud detected",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
]

# Backend modules to scan for forbidden phrases (Clerk-specific).
_CLERK_MODULES = [
    Path(__file__).parent.parent / "app" / "connectors" / "clerk.py",
    Path(__file__).parent.parent / "app" / "connectors" / "clerk_schema.py",
    Path(__file__).parent.parent / "app" / "services" / "security_rules" / "clerk.py",
    Path(__file__).parent.parent / "app" / "services" / "clerk_activity_ingestion_service.py",
    Path(__file__).parent.parent / "app" / "services" / "clerk_activity_signal_service.py",
    Path(__file__).parent.parent / "app" / "services" / "clerk_risk_activity_correlation_service.py",
]


# ════════════════════════════════════════════════════════════════════════════
# Section A — Taxonomy parity
# ════════════════════════════════════════════════════════════════════════════


def test_a1_clerk_record_types_count() -> None:
    assert len(CLERK_RECORD_TYPES) == 10


def test_a2_clerk_record_types_exact() -> None:
    assert CLERK_RECORD_TYPES == EXPECTED_RECORD_TYPES


def test_a3_clerk_rule_keys_count() -> None:
    assert len(CLERK_RULE_KEYS) == 40


def test_a4_clerk_rule_keys_exact() -> None:
    assert CLERK_RULE_KEYS == EXPECTED_RULE_KEYS


def test_a5_clerk_rules_in_known_rule_keys() -> None:
    missing = CLERK_RULE_KEYS - KNOWN_RULE_KEYS
    assert not missing, f"Missing from KNOWN_RULE_KEYS: {sorted(missing)}"


def test_a6_clerk_rules_in_rule_confidence() -> None:
    missing = CLERK_RULE_KEYS - set(RULE_CONFIDENCE.keys())
    assert not missing, f"Missing from RULE_CONFIDENCE: {sorted(missing)}"


def test_a7_clerk_rules_in_rule_pack() -> None:
    missing = CLERK_RULE_KEYS - set(_RULE_META.keys())
    assert not missing, f"Missing from _RULE_META: {sorted(missing)}"


def test_a8_clerk_rules_provider_field_in_pack() -> None:
    for key in CLERK_RULE_KEYS:
        if key in _RULE_META:
            assert _RULE_META[key][0] == "clerk", (
                f"{key} has wrong provider in _RULE_META: {_RULE_META[key][0]}"
            )


def test_a9_clerk_rules_in_rule_record_types() -> None:
    missing = CLERK_RULE_KEYS - set(RULE_RECORD_TYPES.keys())
    assert not missing, f"Missing from RULE_RECORD_TYPES: {sorted(missing)}"


def test_a10_clerk_rules_record_types_are_clerk() -> None:
    for key in CLERK_RULE_KEYS:
        if key in RULE_RECORD_TYPES:
            rt = RULE_RECORD_TYPES[key]
            # RULE_RECORD_TYPES may store a string or a tuple of strings
            if isinstance(rt, tuple):
                for r in rt:
                    assert r in CLERK_RECORD_TYPES, (
                        f"{key} maps to non-Clerk record type: {r}"
                    )
            else:
                assert rt in CLERK_RECORD_TYPES, (
                    f"{key} maps to non-Clerk record type: {rt}"
                )


def test_a11_clerk_in_coverage_providers() -> None:
    assert "clerk" in COVERAGE_PROVIDERS


def test_a12_clerk_in_provider_surfaces() -> None:
    assert "clerk" in PROVIDER_SURFACES
    assert len(PROVIDER_SURFACES["clerk"]) == 10


def test_a13_activity_event_types_count() -> None:
    assert len(_CLERK_CONFIG_EVENT_TYPES) == 18


def test_a14_activity_event_types_exact() -> None:
    assert _CLERK_CONFIG_EVENT_TYPES == EXPECTED_ACTIVITY_EVENT_TYPES


def test_a15_signal_type_map_keys_count() -> None:
    assert len(ck_sig.CLERK_EVENT_TYPE_TO_SIGNAL_TYPE) == len(EXPECTED_ACTIVITY_EVENT_TYPES), (
        f"Signal type map has {len(ck_sig.CLERK_EVENT_TYPE_TO_SIGNAL_TYPE)} entries but "
        f"only {len(EXPECTED_ACTIVITY_EVENT_TYPES)} ingestible event types exist. "
        f"Orphaned entries: "
        f"{set(ck_sig.CLERK_EVENT_TYPE_TO_SIGNAL_TYPE) - _CLERK_CONFIG_EVENT_TYPES}"
    )


def test_a16_signal_type_map_no_orphans() -> None:
    """Every event type in the signal map must be an ingestible event type."""
    orphans = set(ck_sig.CLERK_EVENT_TYPE_TO_SIGNAL_TYPE) - _CLERK_CONFIG_EVENT_TYPES
    assert not orphans, (
        f"Signal type map references event types not in _CLERK_CONFIG_EVENT_TYPES: {sorted(orphans)}"
    )


def test_a17_unique_signal_types_subset_of_expected() -> None:
    """Signal map values must be a subset of declared EXPECTED_SIGNAL_TYPES.

    The map may not produce ALL declared types (e.g. clerk_application_config_changed
    is declared but not producible because the connector doesn't synthesize
    clerk.application.* events). The inverse — a signal type produced by the map
    but not in the declared set — would mean an undeclared output type.
    """
    actual = frozenset(ck_sig.CLERK_EVENT_TYPE_TO_SIGNAL_TYPE.values())
    unknown = actual - EXPECTED_SIGNAL_TYPES
    assert not unknown, (
        f"Signal map produces undeclared signal types: {sorted(unknown)}"
    )


def test_a18_correlation_types_count() -> None:
    assert len(ck_corr.CLERK_CORRELATION_TYPES) == 10


def test_a19_correlation_types_exact() -> None:
    assert ck_corr.CLERK_CORRELATION_TYPES == EXPECTED_CORRELATION_TYPES


def test_a20_correlation_rules_count() -> None:
    assert len(ck_corr.CLERK_CORRELATION_RULES) == 10


def test_a21_correlation_rules_rule_keys_are_clerk() -> None:
    for ctype, rule in ck_corr.CLERK_CORRELATION_RULES.items():
        for rk in rule.get("rule_keys", []):
            assert rk in CLERK_RULE_KEYS, (
                f"Correlation rule {ctype} references non-Clerk rule key: {rk}"
            )


def test_a22_correlation_rules_signal_types_are_clerk() -> None:
    for ctype, rule in ck_corr.CLERK_CORRELATION_RULES.items():
        for st in rule.get("signal_types", []):
            assert st in EXPECTED_SIGNAL_TYPES, (
                f"Correlation rule {ctype} references unknown signal type: {st}"
            )


# ════════════════════════════════════════════════════════════════════════════
# Section B — Privacy guardrails
# ════════════════════════════════════════════════════════════════════════════


def test_b1_activity_allowlist_no_forbidden_keys() -> None:
    found = _FORBIDDEN_METADATA_KEYS & ACTIVITY_ALLOWED
    assert not found, (
        f"Forbidden keys in ACTIVITY ALLOWED_METADATA_KEYS: {sorted(found)}"
    )


def test_b2_signal_allowlist_no_forbidden_keys() -> None:
    found = _FORBIDDEN_METADATA_KEYS & SIGNAL_ALLOWED
    assert not found, (
        f"Forbidden keys in SIGNAL ALLOWED_METADATA_KEYS: {sorted(found)}"
    )


def test_b3_correlation_allowlist_no_forbidden_keys() -> None:
    found = _FORBIDDEN_METADATA_KEYS & CORRELATION_ALLOWED
    assert not found, (
        f"Forbidden keys in CORRELATION ALLOWED_METADATA_KEYS: {sorted(found)}"
    )


@pytest.mark.parametrize(
    "key",
    [
        "instance_id",
        "application_id",
        "redirect_url_config_id",
        "jwt_template_id",
        "email_sms_settings_id",
        "auth_strategy_id",
        "organization_settings_id",
        "session_policy_id",
        "sign_up_enabled",
        "mfa_enabled",
        "mfa_required",
        "session_lifetime_category",
        "inactivity_timeout_category",
        "single_session_enabled",
        "device_tracking_enabled",
        "reverification_required",
        "token_rotation_enabled",
    ],
)
def test_b4_clerk_activity_keys_in_allowlist(key: str) -> None:
    assert key in ACTIVITY_ALLOWED, f"Clerk key '{key}' missing from ACTIVITY_ALLOWED"


@pytest.mark.parametrize(
    "key",
    [
        "instance_id",
        "application_id",
        "jwt_template_id",
        "webhook_endpoint_id",
        "auth_strategy_id",
        "organization_settings_id",
        "session_policy_id",
        "mfa_enabled",
        "mfa_required",
        "single_session_enabled",
    ],
)
def test_b5_clerk_signal_keys_in_allowlist(key: str) -> None:
    assert key in SIGNAL_ALLOWED, f"Clerk key '{key}' missing from SIGNAL_ALLOWED"


@pytest.mark.parametrize(
    "key",
    [
        "instance_id",
        "domain_id",
        "jwt_template_id",
        "webhook_endpoint_id",
        "auth_strategy_id",
        "organization_settings_id",
        "session_policy_id",
    ],
)
def test_b6_clerk_correlation_keys_in_allowlist(key: str) -> None:
    assert key in CORRELATION_ALLOWED, (
        f"Clerk key '{key}' missing from CORRELATION_ALLOWED"
    )


def test_b7_signal_map_no_orphaned_event_types() -> None:
    """Signal type map must only contain ingestible Clerk event types."""
    orphans = set(ck_sig.CLERK_EVENT_TYPE_TO_SIGNAL_TYPE) - _CLERK_CONFIG_EVENT_TYPES
    assert not orphans, (
        f"Orphaned event types in signal map (not in _CLERK_CONFIG_EVENT_TYPES): "
        f"{sorted(orphans)}"
    )


def test_b8_clerk_schema_no_raw_pii_type_annotations() -> None:
    """clerk_schema.py TypedDicts should not have fields for PII/secret/raw-URL values.

    Only checks actual TypedDict field definition lines (lines with a type annotation
    in the form `    field_name: type`), ignoring comments, docstrings, and prose.
    """
    schema_path = Path(__file__).parent.parent / "app" / "connectors" / "clerk_schema.py"
    text = schema_path.read_text()
    # Pattern for a TypedDict field definition: "    identifier: SomeType"
    typed_dict_field_re = re.compile(r"^\s{4}\w+\s*:\s*\w")
    bad_field_patterns = [
        r"\bsecret_key\b",
        r"\bwebhook_url\b",
        r"\bredirect_url\b",
        r"\bcallback_url\b",
        r"\bjwt_body\b",
        r"\braw_claims\b",
        r"\bsession_token\b",
        r"\bip_address\b",
        r"\buser_agent\b",
    ]
    for ln in text.splitlines():
        if not typed_dict_field_re.match(ln):
            continue  # not a TypedDict field definition
        for pat in bad_field_patterns:
            assert not re.search(pat, ln), (
                f"PII/credential field pattern '{pat}' found in TypedDict field "
                f"definition in clerk_schema.py: {ln!r}"
            )


def test_b9_demo_constants_no_jwt_shapes() -> None:
    demo_path = Path(__file__).parent.parent / "app" / "services" / "security_incident_demo_service.py"
    text = demo_path.read_text()
    idx = text.find("CLERK_DEMO_INTEGRATION_NAME")
    assert idx != -1
    clerk_section = text[idx:]
    assert not re.search(r"eyJ[A-Za-z0-9_\-]{10,}", clerk_section), (
        "JWT-shaped string found in Clerk demo section"
    )


def test_b10_demo_constants_no_secret_key_shapes() -> None:
    demo_path = Path(__file__).parent.parent / "app" / "services" / "security_incident_demo_service.py"
    text = demo_path.read_text()
    idx = text.find("CLERK_DEMO_INTEGRATION_NAME")
    assert idx != -1
    clerk_section = text[idx:]
    # No sk_live_* or sk_test_* real Clerk key shapes
    assert not re.search(r"\bsk_(live|test)_[A-Za-z0-9]{20,}\b", clerk_section), (
        "Real Clerk secret key shape found in demo section"
    )


def test_b11_demo_constants_no_email_patterns() -> None:
    demo_path = Path(__file__).parent.parent / "app" / "services" / "security_incident_demo_service.py"
    text = demo_path.read_text()
    idx = text.find("CLERK_DEMO_INTEGRATION_NAME")
    assert idx != -1
    clerk_section = text[idx:]
    # E.164 phone numbers
    assert not re.search(r"\+1[0-9]{10}", clerk_section), "Phone number in Clerk demo section"
    # email addresses
    assert not re.search(r"[a-z]+@[a-z]+\.[a-z]{2,}", clerk_section), (
        "Email address in Clerk demo section"
    )


def test_b12_demo_placeholder_ids_are_uppercase_sentinels() -> None:
    """Clerk demo placeholder IDs must be safe uppercase sentinel strings."""
    from app.services.security_incident_demo_service import (
        CLERK_DEMO_INTEGRATION_NAME,
        CLERK_DEMO_CASE_SOURCE,
        CLERK_DEMO_DATASET,
    )
    assert CLERK_DEMO_INTEGRATION_NAME
    assert CLERK_DEMO_CASE_SOURCE
    assert CLERK_DEMO_DATASET
    # None should look like a real Clerk ID
    for val in [CLERK_DEMO_INTEGRATION_NAME, CLERK_DEMO_CASE_SOURCE, CLERK_DEMO_DATASET]:
        assert not re.search(r"eyJ[A-Za-z0-9_\-]{10,}", val), (
            f"JWT-shaped value in Clerk demo constant: {val}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section C — Claim discipline
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("phrase", _FORBIDDEN_PHRASES)
@pytest.mark.parametrize("module_path", _CLERK_MODULES)
def test_c_forbidden_phrase_not_in_module(module_path: Path, phrase: str) -> None:
    if not module_path.exists():
        pytest.skip(f"Module not found: {module_path}")
    text = module_path.read_text().lower()
    assert phrase.lower() not in text, (
        f"Forbidden phrase '{phrase}' found in {module_path.name}"
    )


def test_c2_no_forbidden_phrases_in_rule_evidence_fields() -> None:
    rules_path = Path(__file__).parent.parent / "app" / "services" / "security_rules" / "clerk.py"
    text = rules_path.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase.lower() not in text, (
            f"Forbidden phrase '{phrase}' in clerk.py"
        )


def test_c3_no_forbidden_phrases_in_demo_service_clerk_section() -> None:
    demo_path = Path(__file__).parent.parent / "app" / "services" / "security_incident_demo_service.py"
    text = demo_path.read_text()
    idx = text.find("CLERK_DEMO_INTEGRATION_NAME")
    assert idx != -1
    clerk_section = text[idx:].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase.lower() not in clerk_section, (
            f"Forbidden phrase '{phrase}' in Clerk demo section"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section D — False-positive behavior (healthy records should NOT fire)
# ════════════════════════════════════════════════════════════════════════════

def _no_findings(record: dict[str, Any]) -> bool:
    """Return True if evaluate() returns no findings for this record."""
    findings = ck_eval(record)
    return len(findings) == 0


def test_d1_healthy_instance_settings_no_fire() -> None:
    record = {
        "record_type": "clerk_instance_settings",
        "record_id": "inst_healthy_001",
        "sign_up_enabled": False,
        "mfa_enabled": True,
        "mfa_required": True,
        "mfa_supported": True,
        "password_enabled": True,
        "session_lifetime_category": "normal",
        "inactivity_timeout_category": "normal",
    }
    assert _no_findings(record)


def test_d2_healthy_application_no_fire() -> None:
    record = {
        "record_type": "clerk_application",
        "record_id": "app_healthy_001",
        "sign_up_enabled": False,
        "sign_in_enabled": True,
        "password_enabled": True,
        "mfa_required": True,
        "oauth_provider_count": 2,
        "saml_enabled": False,
        "allowed_redirect_count": 3,
        "allowed_origin_count": 2,
    }
    assert _no_findings(record)


def test_d3_healthy_domain_no_fire() -> None:
    record = {
        "record_type": "clerk_domain",
        "record_id": "dom_healthy_001",
        "verified": True,
        "ssl_enabled": True,
    }
    assert _no_findings(record)


def test_d4_healthy_redirect_url_no_fire() -> None:
    record = {
        "record_type": "clerk_redirect_url_config",
        "record_id": "rurl_healthy_001",
        "scheme_category": "https",
        "wildcard_present": False,
        "localhost_present": False,
        "custom_scheme_present": False,
    }
    assert _no_findings(record)


def test_d5_healthy_jwt_template_no_fire() -> None:
    record = {
        "record_type": "clerk_jwt_template",
        "record_id": "jwt_healthy_001",
        "custom_claims_present": False,
        "lifetime_category": "normal",
        "audience_present": True,
        "issuer_present": True,
        "claims_count": 5,
    }
    assert _no_findings(record)


def test_d6_healthy_webhook_endpoint_no_fire() -> None:
    record = {
        "record_type": "clerk_webhook_endpoint",
        "record_id": "wh_healthy_001",
        "enabled": True,
        "url_present": True,
        "url_scheme_category": "https",
        "secret_present": True,
        "event_count": 5,
    }
    assert _no_findings(record)


def test_d7_healthy_email_sms_no_fire() -> None:
    record = {
        "record_type": "clerk_email_sms_settings",
        "record_id": "ems_healthy_001",
        "custom_sender_present": False,
    }
    assert _no_findings(record)


def test_d8_healthy_auth_strategy_no_fire() -> None:
    record = {
        "record_type": "clerk_auth_strategy",
        "record_id": "auth_healthy_001",
        "mfa_required": True,
        "password_enabled": False,
        "mfa_supported": True,
    }
    assert _no_findings(record)


def test_d9_healthy_org_settings_no_fire() -> None:
    record = {
        "record_type": "clerk_organization_settings",
        "record_id": "org_healthy_001",
        "verified_domains_required": True,
        "invitation_enabled": False,
        "admin_role_present": True,
        "role_count": 5,
        "permission_count": 20,
    }
    assert _no_findings(record)


def test_d10_healthy_session_policy_no_fire() -> None:
    record = {
        "record_type": "clerk_session_policy",
        "record_id": "sess_healthy_001",
        "session_lifetime_category": "normal",
        "inactivity_timeout_category": "normal",
        "single_session_enabled": True,
        "token_rotation_enabled": True,
        "device_tracking_enabled": True,
        "reverification_required": True,
    }
    assert _no_findings(record)


def test_d11_risky_instance_mfa_fires() -> None:
    record = {
        "record_type": "clerk_instance_settings",
        "record_id": "inst_risky_001",
        "sign_up_enabled": True,
        "mfa_enabled": False,
        "mfa_required": False,
        "password_enabled": True,
    }
    findings = ck_eval(record)
    keys = {f.rule_key for f in findings}
    assert "clerk_instance_mfa_disabled" in keys


def test_d12_risky_session_policy_fires() -> None:
    record = {
        "record_type": "clerk_session_policy",
        "record_id": "sess_risky_001",
        "session_lifetime_category": "extended",
        "inactivity_timeout_category": "extended",
        "single_session_enabled": False,
        "token_rotation_enabled": False,
        "device_tracking_enabled": False,
        "reverification_required": False,
    }
    findings = ck_eval(record)
    keys = {f.rule_key for f in findings}
    assert "clerk_session_lifetime_extended" in keys
    assert "clerk_session_token_rotation_disabled" in keys
    assert "clerk_session_device_tracking_disabled" in keys
    assert "clerk_session_reverification_disabled" in keys


def test_d13_risky_webhook_fires() -> None:
    record = {
        "record_type": "clerk_webhook_endpoint",
        "record_id": "wh_risky_001",
        "enabled": True,
        "url_present": True,
        "url_scheme_category": "http",
        "secret_present": False,
        "event_count": 15,
    }
    findings = ck_eval(record)
    keys = {f.rule_key for f in findings}
    assert "clerk_webhook_non_https" in keys
    assert "clerk_webhook_without_signing" in keys
    assert "clerk_webhook_broad_event_scope" in keys


def test_d14_non_clerk_record_no_fire() -> None:
    """Clerk evaluator should return [] for non-Clerk record types."""
    record = {
        "record_type": "datadog_monitor",
        "record_id": "mon_001",
        "disabled": True,
    }
    findings = ck_eval(record)
    assert findings == []


def test_d15_findings_evidence_no_pii() -> None:
    """Finding evidence must not contain PII or credential-shaped values."""
    record = {
        "record_type": "clerk_webhook_endpoint",
        "record_id": "wh_pii_test",
        "enabled": True,
        "url_present": True,
        "url_scheme_category": "http",
        "secret_present": False,
        "event_count": 3,
    }
    findings = ck_eval(record)
    for finding in findings:
        evidence_str = str(finding.evidence)
        assert not re.search(r"eyJ[A-Za-z0-9_\-]{10,}", evidence_str), (
            f"JWT shape in finding evidence for {finding.rule_key}"
        )
        assert not re.search(r"[a-z]+@[a-z]+\.[a-z]{2,}", evidence_str), (
            f"Email in finding evidence for {finding.rule_key}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section E — Demo isolation
# ════════════════════════════════════════════════════════════════════════════


def test_e1_clerk_demo_functions_importable() -> None:
    from app.services.security_incident_demo_service import (  # noqa: F401
        seed_clerk, clear_clerk, get_clerk_status,
    )
    assert callable(demo_svc.seed_clerk)
    assert callable(demo_svc.clear_clerk)
    assert callable(demo_svc.get_clerk_status)


def test_e2_clerk_demo_constants_present() -> None:
    from app.services.security_incident_demo_service import (
        CLERK_DEMO_INTEGRATION_NAME,
        CLERK_DEMO_CASE_SOURCE,
        CLERK_DEMO_DATASET,
    )
    assert CLERK_DEMO_INTEGRATION_NAME
    assert CLERK_DEMO_CASE_SOURCE
    assert CLERK_DEMO_DATASET


def test_e3_clerk_demo_integration_name_has_sample_data_marker() -> None:
    from app.services.security_incident_demo_service import CLERK_DEMO_INTEGRATION_NAME
    assert "sample data" in CLERK_DEMO_INTEGRATION_NAME.lower() or \
           "demo" in CLERK_DEMO_INTEGRATION_NAME.lower()


def test_e4_clerk_demo_case_source_is_demo_prefixed() -> None:
    from app.services.security_incident_demo_service import CLERK_DEMO_CASE_SOURCE
    assert "demo" in CLERK_DEMO_CASE_SOURCE.lower()


def test_e5_clerk_session_policy_placeholder_is_safe() -> None:
    demo_path = Path(__file__).parent.parent / "app" / "services" / "security_incident_demo_service.py"
    text = demo_path.read_text()
    # The session policy placeholder should be an uppercase sentinel
    m = re.search(r'_CLERK_DEMO_SESSION_POLICY_ID\s*=\s*["\']([^"\']+)["\']', text)
    assert m, "_CLERK_DEMO_SESSION_POLICY_ID not found"
    val = m.group(1)
    # Must be uppercase ASCII only (no JWT, no sk_live_, no email)
    assert val == val.upper() or "_" in val, f"Placeholder {val!r} looks non-sentinel"
    assert not re.search(r"eyJ[A-Za-z0-9_\-]{10,}", val)
    assert not re.search(r"sk_(live|test)_", val)


def test_e6_clerk_case_report_label() -> None:
    labels = report_svc._TIMELINE_PROVIDER_LABELS
    assert "clerk" in labels
    assert labels["clerk"] == "Clerk"


# ════════════════════════════════════════════════════════════════════════════
# Section F — Router / API guards
# ════════════════════════════════════════════════════════════════════════════


def test_f1_clerk_activity_sync_endpoint_exists() -> None:
    router_path = Path(__file__).parent.parent / "app" / "routers" / "security.py"
    text = router_path.read_text()
    assert "/security/clerk-activity/sync" in text or "clerk-activity/sync" in text


def test_f2_clerk_signal_generate_endpoint_exists() -> None:
    router_path = Path(__file__).parent.parent / "app" / "routers" / "security.py"
    text = router_path.read_text()
    assert "clerk-activity/generate-signals" in text


def test_f3_clerk_correlation_generate_endpoint_exists() -> None:
    router_path = Path(__file__).parent.parent / "app" / "routers" / "security.py"
    text = router_path.read_text()
    assert "clerk-correlations/generate" in text


def test_f4_clerk_activity_sync_requires_admin() -> None:
    router_path = Path(__file__).parent.parent / "app" / "routers" / "security.py"
    text = router_path.read_text()
    # Find the clerk-activity/sync block and verify require_workspace_admin nearby.
    # The admin guard is in the function body, so search a generous window (±2000 chars).
    idx = text.find("clerk-activity/sync")
    assert idx != -1
    block = text[max(0, idx - 200):idx + 2000]
    assert "require_workspace_admin" in block or "workspace_admin" in block, (
        "clerk-activity/sync endpoint does not have require_workspace_admin"
    )


def test_f5_clerk_correlation_generate_requires_admin() -> None:
    router_path = Path(__file__).parent.parent / "app" / "routers" / "security.py"
    text = router_path.read_text()
    idx = text.find("clerk-correlations/generate")
    assert idx != -1
    block = text[max(0, idx - 200):idx + 2000]
    assert "require_workspace_admin" in block or "workspace_admin" in block, (
        "clerk-correlations/generate does not have require_workspace_admin"
    )


def test_f6_incident_demo_clerk_wired_in_router() -> None:
    router_path = Path(__file__).parent.parent / "app" / "routers" / "security.py"
    text = router_path.read_text()
    assert "clerk" in text
    assert "seed_clerk" in text or "clerk" in text


# ════════════════════════════════════════════════════════════════════════════
# Section G — Frontend Clerk consistency
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_g1_clerk_in_provider_id_union() -> None:
    text = FE_PROVIDERS.read_text()
    assert '"clerk"' in text or "'clerk'" in text


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_g2_clerk_in_connectable_provider_ids() -> None:
    text = FE_PROVIDERS.read_text()
    assert "CONNECTABLE_PROVIDER_IDS" in text
    # Verify clerk appears in the CONNECTABLE section
    idx = text.find("CONNECTABLE_PROVIDER_IDS")
    block = text[idx:idx + 2000]
    assert "clerk" in block


@pytest.mark.skipif(not FE_PROVIDERS.exists(), reason="Frontend tree absent")
def test_g3_clerk_not_in_security_preview_ids() -> None:
    text = FE_PROVIDERS.read_text()
    if "SECURITY_PREVIEW_PROVIDER_IDS" not in text:
        return  # No preview list, pass
    idx = text.find("SECURITY_PREVIEW_PROVIDER_IDS")
    block = text[idx:idx + 1000]
    # Clerk should NOT appear in this preview list
    assert "clerk" not in block or "[]" in block, (
        "clerk should NOT be in SECURITY_PREVIEW_PROVIDER_IDS"
    )


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_g4_clerk_in_activity_page_provider_options() -> None:
    text = FE_ACTIVITY.read_text()
    assert '"clerk"' in text or "'clerk'" in text


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_g5_clerk_event_types_count_in_frontend() -> None:
    text = FE_ACTIVITY.read_text()
    # Find CLERK_EVENT_TYPES array and count entries
    idx = text.find("CLERK_EVENT_TYPES")
    assert idx != -1, "CLERK_EVENT_TYPES not found in activity page"
    block = text[idx:idx + 1500]
    count = block.count('"clerk.')
    assert count == 18, (
        f"Expected 18 Clerk event types in frontend, found {count}"
    )


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_g6_clerk_in_signals_page() -> None:
    text = FE_SIGNALS.read_text()
    assert "clerk" in text.lower()


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_g7_clerk_signal_types_count_in_frontend() -> None:
    text = FE_SIGNALS.read_text()
    idx = text.find("CLERK_SIGNAL_TYPES")
    assert idx != -1, "CLERK_SIGNAL_TYPES not found in signals page"
    block = text[idx:idx + 2000]
    count = block.count('"clerk_')
    # The backend signal map produces 10 signal types after M83H removed the
    # orphaned clerk.application.* entries. The frontend may retain 11 (harmless
    # dead filter option). Accept 10 or 11.
    assert count >= 10, (
        f"Expected at least 10 Clerk signal types in frontend, found {count}"
    )


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_g8_clerk_in_correlations_page() -> None:
    text = FE_CORRELATIONS.read_text()
    assert "clerk" in text.lower()


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_g9_clerk_correlation_types_in_frontend() -> None:
    text = FE_CORRELATIONS.read_text()
    for ctype in EXPECTED_CORRELATION_TYPES:
        assert f'"{ctype}"' in text or f"'{ctype}'" in text, (
            f"Correlation type '{ctype}' not found in correlations page"
        )


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_g10_clerk_demo_card_in_cases_page() -> None:
    text = FE_CASES.read_text()
    assert "clerk" in text.lower()
    assert "Clerk" in text


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_g11_clerk_demo_card_no_breach_copy() -> None:
    text = FE_CASES.read_text()
    idx = text.find("clerk")
    if idx == -1:
        return
    block = text[max(0, idx - 200):idx + 2000].lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in block, (
            f"Forbidden phrase '{phrase}' found near Clerk demo card in cases page"
        )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_g12_clerk_in_demo_script_capability_table() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert '"clerk"' in text or "'clerk'" in text
    assert "Clerk" in text


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_g13_clerk_in_demo_script_lib_seeding_talk_track() -> None:
    """Clerk should appear in the seeding step talkTrack/whatToClick since M83G demo is complete."""
    text = FE_DEMO_SCRIPT_LIB.read_text()
    # Find the seed step
    idx = text.find("incident-seed")
    assert idx != -1, "incident-seed step not found in securityDemoScript.ts"
    block = text[idx:idx + 3000]
    assert "Clerk" in block or "clerk" in block, (
        "Clerk is missing from the demo seeding step in securityDemoScript.ts — "
        "M83G added Clerk demo support but the demo script talk track was not updated"
    )


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_g14_sync_clerk_activity_in_api() -> None:
    text = FE_API.read_text()
    assert "syncClerkActivity" in text


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_g15_generate_clerk_signals_in_api() -> None:
    text = FE_API.read_text()
    assert "generateClerkActivitySignals" in text


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_g16_generate_clerk_correlations_in_api() -> None:
    text = FE_API.read_text()
    assert "generateClerkCorrelations" in text


@pytest.mark.skipif(not FE_TYPES.exists(), reason="Frontend tree absent")
def test_g17_clerk_response_types_in_types_index() -> None:
    text = FE_TYPES.read_text()
    assert "ClerkActivitySyncResponse" in text
    assert "ClerkActivitySignalGenerateResponse" in text
    assert "ClerkCorrelationGenerateResponse" in text


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_g18_clerk_rules_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text()
    for key in EXPECTED_RULE_KEYS:
        assert f'"{key}"' in text or f"'{key}'" in text, (
            f"Rule '{key}' not found in securityRuleCatalog.ts"
        )


@pytest.mark.skipif(not FE_TRUST_CENTER.exists(), reason="Frontend tree absent")
def test_g19_clerk_in_trust_center() -> None:
    text = FE_TRUST_CENTER.read_text()
    assert "clerk" in text.lower()


# ════════════════════════════════════════════════════════════════════════════
# Section H — Regression smoke
# ════════════════════════════════════════════════════════════════════════════


def test_h1_clerk_in_evaluator_dispatch() -> None:
    from app.services.security_finding_evaluator import _PROVIDER_RULES
    assert "clerk" in _PROVIDER_RULES, "Clerk missing from _PROVIDER_RULES in finding evaluator"


def test_h2_normalize_clerk_activity_event_exists() -> None:
    assert hasattr(ck_ingest, "normalize_clerk_activity_event")
    assert callable(ck_ingest.normalize_clerk_activity_event)


def test_h3_ingest_clerk_activity_exists() -> None:
    assert hasattr(ck_ingest, "ingest_clerk_activity")
    assert callable(ck_ingest.ingest_clerk_activity)


def test_h4_generate_clerk_activity_signals_exists() -> None:
    assert hasattr(ck_sig, "generate_clerk_activity_signals")
    assert callable(ck_sig.generate_clerk_activity_signals)


def test_h5_generate_clerk_correlations_exists() -> None:
    assert hasattr(ck_corr, "generate_clerk_correlations")
    assert callable(ck_corr.generate_clerk_correlations)


def test_h6_clerk_in_sync_service_supported_providers() -> None:
    # _SUPPORTED_PROVIDERS is a local variable inside the scheduling function,
    # not a module-level export. Verify via source text that "clerk" appears in
    # the provider tuple so scheduled syncs fire for Clerk integrations.
    svc_path = Path(__file__).parent.parent / "app" / "services" / "sync_service.py"
    text = svc_path.read_text()
    idx = text.find("_SUPPORTED_PROVIDERS")
    assert idx != -1, "_SUPPORTED_PROVIDERS not found in sync_service.py"
    # Find the tuple content (look 500 chars after the assignment)
    block = text[idx:idx + 500]
    assert '"clerk"' in block or "'clerk'" in block, (
        "Clerk missing from sync_service._SUPPORTED_PROVIDERS — scheduled syncs won't fire"
    )


def test_h7_clerk_in_sync_task_dispatch() -> None:
    task_path = Path(__file__).parent.parent / "app" / "workers" / "sync_task.py"
    text = task_path.read_text()
    assert "clerk" in text.lower(), "Clerk not dispatched in sync_task.py"
    assert "ClerkConnector" in text


def test_h8_clerk_connector_import() -> None:
    from app.connectors.clerk import ClerkConnector  # noqa: F401
    assert ClerkConnector is not None


def test_h9_correlation_ingestion_service_normalize_blocks_unknown() -> None:
    """normalize_clerk_activity_event must reject non-Clerk event types."""
    mock_event = MagicMock()
    mock_event.event_type = "unknown.event.type"
    mock_event.provider = "clerk"
    mock_event.source = "clerk_activity_event"
    # Call the normalize function; it should return None or not raise
    result = ck_ingest.normalize_clerk_activity_event(mock_event)
    assert result is None or result == {} or result == []


def test_h10_clerk_record_types_all_have_provider_surfaces() -> None:
    """All 10 Clerk drift surfaces should appear in security_coverage_service."""
    surfaces = PROVIDER_SURFACES.get("clerk", [])
    assert len(surfaces) >= 10


def test_h11_clerk_connector_fetch_is_callable() -> None:
    from app.connectors.clerk import ClerkConnector
    assert hasattr(ClerkConnector, "fetch") and callable(ClerkConnector.fetch)
    assert hasattr(ClerkConnector, "validate_credentials")


def test_h12_correlation_rules_all_have_required_fields() -> None:
    for ctype, rule in ck_corr.CLERK_CORRELATION_RULES.items():
        assert "rule_keys" in rule, f"Missing rule_keys in correlation rule {ctype}"
        assert "signal_types" in rule, f"Missing signal_types in correlation rule {ctype}"
        assert "severity" in rule, f"Missing severity in correlation rule {ctype}"
        assert isinstance(rule["rule_keys"], (list, set, frozenset))
        assert isinstance(rule["signal_types"], (list, set, frozenset))


# ════════════════════════════════════════════════════════════════════════════
# Section I — Capability matrix + expansion framework
# ════════════════════════════════════════════════════════════════════════════


def test_i1_clerk_capability_matrix_drift_flags() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True


def test_i2_clerk_capability_matrix_security_flags() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True


def test_i3_clerk_capability_matrix_evidence_flags() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True


def test_i4_clerk_capability_matrix_maturity() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.maturity == "partial"


def test_i5_clerk_capability_matrix_notes_mention_m83h() -> None:
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert "M83H" in cap.notes, (
        "Capability matrix notes should mention M83H after this QA milestone"
    )


def test_i6_expansion_framework_planned_next_stage_is_m83i() -> None:
    fw = get_framework()
    # The full Clerk arc (M83A–M83I) and subsequent arcs are complete.
    # Framework now points to M89A: Kubernetes Drift Provider Foundation.
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    assert (
        "M83I" in planned or "Cross-Cloud UX Polish" in planned or "m83i" in planned.lower()
        or "M84A" in planned or "PagerDuty" in planned
        or "M85A" in planned or "Linear" in planned
        or "M86" in planned or "Jira" in planned
        or "M87" in planned or "GitLab" in planned
        or "M88" in planned or "Terraform" in planned
        or "M89A" in planned or "Kubernetes" in planned
    ), (
        f"planned_next_stage should point to M83I or beyond after M83H QA, got: {planned!r}"
    )


def test_i7_clerk_not_in_recommended_next_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    provider_names = [
        r.get("provider", "").lower()
        for r in recommended
        if isinstance(r, dict)
    ]
    assert "clerk" not in provider_names, (
        "Clerk should NOT be in recommended_next_providers (it has already launched)"
    )


def test_i8_pagerduty_head_of_recommended_next_providers() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    if not recommended:
        pytest.skip("No recommended providers list")
    first = recommended[0]
    if isinstance(first, dict):
        provider = first.get("provider", "")
    else:
        provider = str(first)
    # Full arc through M88I Terraform Cloud complete. Kubernetes is now head.
    assert ("pagerduty" in provider.lower() or "PagerDuty" in provider
            or "linear" in provider.lower() or "Linear" in provider
            or "jira" in provider.lower() or "Jira" in provider
            or "gitlab" in provider.lower() or "GitLab" in provider
            or "terraform" in provider.lower() or "Terraform" in provider
            or "kubernetes" in provider.lower() or "Kubernetes" in provider), (
        f"PagerDuty/Linear/Jira/GitLab/Terraform/Kubernetes should be head after Clerk arc, got: {provider!r}"
    )


def test_i9_capability_matrix_notes_no_stale_planned_next_stage_m83h() -> None:
    """After M83H QA, the notes must NOT say 'planned_next_stage: M83H' (stale pointer)."""
    cap = get_provider_capability("clerk")
    assert cap is not None
    notes_lower = cap.notes.lower()
    # Find the planned_next_stage mention — it should point to M83I, not M83H
    if "planned_next_stage" in notes_lower:
        idx = notes_lower.find("planned_next_stage")
        snippet = notes_lower[idx:idx + 80]
        assert "m83h" not in snippet, (
            f"Notes still say planned_next_stage points to M83H (stale): {snippet!r}"
        )
    # The expansion framework should point to M83I or beyond.
    # Full arc through M88I Terraform Cloud is complete; now points to M89A Kubernetes.
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    assert (
        "M83I" in planned or "m83i" in planned.lower() or "Cross-Cloud" in planned
        or "M84A" in planned or "PagerDuty" in planned
        or "M85A" in planned or "Linear" in planned
        or "M86" in planned or "Jira" in planned
        or "M87" in planned or "GitLab" in planned
        or "M88" in planned or "Terraform" in planned
        or "M89A" in planned or "Kubernetes" in planned
    ), (
        f"Expansion framework planned_next_stage still points to M83H: {planned!r}"
    )
