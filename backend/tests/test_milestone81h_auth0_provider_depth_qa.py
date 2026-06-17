"""M81H — Auth0 provider-depth QA guardrails.

Durable, deterministic guardrails that prove the whole Auth0 arc
(M81A–M81G) stays internally consistent.  This file adds NO product code —
it pins taxonomy parity, privacy / sanitization discipline, false-positive
behavior, demo isolation, and router admin / member guards.

Sections:

  A. Taxonomy parity
     Record types ↔ rule keys ↔ activity event types ↔ signal types ↔
     correlation rule keys ↔ correlation activity types.

  B. Privacy guardrails
     Auth0-shaped denylist applied to every Auth0 source file we own
     (connector, ingestion, signal, correlation, demo); also asserted on a
     live in-memory pipeline (_build_signal → _build_correlation →
     seed/clear case-report blobs).

  C. Claim discipline
     Forbidden-phrase scan over every Auth0 production module and the demo
     fixtures.

  D. False-positive behavior
     End-to-end "should NOT fire" cases: tenant safe settings, application
     safe OAuth posture, connection good password policy, resource server
     with RBAC enabled and offline-access disabled, enabled rule with short
     script, deployed action with no secrets, enabled MFA factor, custom
     domain ready with recommended TLS — and their positive-fire counterparts.
     Cross-resource correlation mismatches; tenant-level always matches.

  E. Demo isolation
     Seed-twice / clear-twice idempotency; clear_auth0 leaves every other
     provider demo intact and never touches a real Auth0 integration.

  F. Router/API guards
     Auth0 activity sync / signal-generate / correlation-generate /
     incident demo seed-clear require admin; read-only endpoints stay
     member-accessible.

  G. Frontend Auth0 consistency (skip if frontend tree absent)
     Provider selectors / type filter dropdowns / rule catalog / demo card
     / api unions / demo-script copy all carry Auth0 entries.

  H. Regression smoke
     Evaluator dispatch + allowlists + correlation rule shape pinned so the
     future M81I polish cannot drift them silently.
"""

from __future__ import annotations

import inspect
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.connectors import auth0 as auth0_conn
from app.connectors.auth0_schema import (
    AUTH0_ACTION,
    AUTH0_APPLICATION,
    AUTH0_CONNECTION,
    AUTH0_CUSTOM_DOMAIN,
    AUTH0_MFA_FACTOR,
    AUTH0_RECORD_TYPES,
    AUTH0_RESOURCE_SERVER,
    AUTH0_RULE,
    AUTH0_TENANT_SETTINGS,
)
from app.services import auth0_activity_ingestion_service as auth0_ingest
from app.services import auth0_activity_signal_service as auth0_sig
from app.services import auth0_risk_activity_correlation_service as auth0_corr
from app.services import security_case_report_service as report_svc
from app.services import security_incident_demo_service as demo_svc
from app.services import security_signal_correlation_service as corr_svc
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
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules.auth0 import (
    AUTH0_RULE_KEYS,
    evaluate as auth0_eval,
)


# ════════════════════════════════════════════════════════════════════════════
# Fixed expected sets — the M81H baseline.
# Drift here triggers an intentional update of this file (with a note in
# the commit message explaining the change).
# ════════════════════════════════════════════════════════════════════════════

EXPECTED_RECORD_TYPES = {
    "auth0_tenant_settings",
    "auth0_application",
    "auth0_connection",
    "auth0_resource_server",
    "auth0_rule",
    "auth0_action",
    "auth0_mfa_factor",
    "auth0_custom_domain",
}

EXPECTED_RULE_KEYS = {
    # ── M81B: Tenant settings (3) ─────────────────────────────────────────
    "auth0_tenant_session_lifetime_extended",
    "auth0_tenant_idle_session_lifetime_extended",
    "auth0_tenant_dynamic_client_registration_enabled",
    # ── M81B: Application core (7) ───────────────────────────────────────
    "auth0_application_no_callbacks",
    "auth0_application_many_callbacks",
    "auth0_application_many_allowed_origins",
    "auth0_application_oidc_non_conformant",
    "auth0_application_weak_jwt_algorithm",
    "auth0_refresh_token_rotation_disabled",
    "auth0_refresh_token_lifetime_extended",
    # ── M81B: Connection (2) ──────────────────────────────────────────────
    "auth0_connection_no_enabled_clients",
    "auth0_connection_weak_password_policy",
    # ── M81B: Resource server (3) ─────────────────────────────────────────
    "auth0_resource_server_offline_access_enabled",
    "auth0_resource_server_token_lifetime_extended",
    "auth0_resource_server_rbac_disabled",
    # ── M81B: Rule (2) ───────────────────────────────────────────────────
    "auth0_rule_disabled",
    "auth0_rule_large_script",
    # ── M81B: Action (2) ─────────────────────────────────────────────────
    "auth0_action_not_deployed",
    "auth0_action_secrets_present",
    # ── M81B: MFA factor (1) ─────────────────────────────────────────────
    "auth0_mfa_factor_disabled",
    # ── M81B: Custom domain (2) ──────────────────────────────────────────
    "auth0_custom_domain_not_ready",
    "auth0_custom_domain_weak_tls_policy",
    # ── M81C: Grant type posture (6) ─────────────────────────────────────
    "auth0_application_password_grant_enabled",
    "auth0_application_implicit_grant_enabled",
    "auth0_application_public_client_credentials_enabled",
    "auth0_application_refresh_grant_without_rotation",
    "auth0_application_many_grant_types",
    "auth0_application_device_code_grant_enabled",
    # ── M81C: Wildcard posture (3) ────────────────────────────────────────
    "auth0_application_wildcard_callback",
    "auth0_application_wildcard_allowed_origin",
    "auth0_application_wildcard_logout_url",
    # ── M81C: Localhost posture (2) ───────────────────────────────────────
    "auth0_application_localhost_callback",
    "auth0_application_localhost_origin",
    # ── M81C: HTTPS posture (2) ───────────────────────────────────────────
    "auth0_application_callback_missing_https",
    "auth0_application_origin_missing_https",
    # ── M81C: Public client / token endpoint (2) ─────────────────────────
    "auth0_public_client_refresh_tokens_enabled",
    "auth0_application_token_endpoint_auth_none",
}

# Canonical activity event types produced by the ingestion pipeline (23 total,
# including the synthetic auth0.config.event fallback).
EXPECTED_ACTIVITY_EVENT_TYPES = {
    "auth0.tenant.updated",
    "auth0.application.created",
    "auth0.application.updated",
    "auth0.application.deleted",
    "auth0.connection.created",
    "auth0.connection.updated",
    "auth0.connection.deleted",
    "auth0.resource_server.created",
    "auth0.resource_server.updated",
    "auth0.resource_server.deleted",
    "auth0.rule.created",
    "auth0.rule.updated",
    "auth0.rule.deleted",
    "auth0.action.created",
    "auth0.action.updated",
    "auth0.action.deployed",
    "auth0.action.deleted",
    "auth0.mfa_factor.updated",
    "auth0.custom_domain.created",
    "auth0.custom_domain.updated",
    "auth0.custom_domain.verified",
    "auth0.custom_domain.deleted",
    "auth0.config.event",
}

EXPECTED_SIGNAL_TYPES = {
    "auth0_tenant_config_changed",
    "auth0_application_config_changed",
    "auth0_connection_config_changed",
    "auth0_resource_server_config_changed",
    "auth0_rule_config_changed",
    "auth0_action_config_changed",
    "auth0_mfa_factor_config_changed",
    "auth0_custom_domain_config_changed",
    "auth0_config_activity",
}

EXPECTED_CORRELATION_TYPES = {
    "auth0_tenant_risk_activity_correlation",
    "auth0_application_risk_activity_correlation",
    "auth0_connection_risk_activity_correlation",
    "auth0_resource_server_risk_activity_correlation",
    "auth0_rule_risk_activity_correlation",
    "auth0_action_risk_activity_correlation",
    "auth0_mfa_factor_risk_activity_correlation",
    "auth0_custom_domain_risk_activity_correlation",
}

# ── Forbidden claim wording (M75A pin) ───────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# ── Auth0-shaped privacy denylist (M81H) ─────────────────────────────────────
# Substrings that MUST NOT appear (case-insensitive) as quoted JSON keys in
# any Auth0 production blob we generate.  Written as `"key":` so we catch
# dict serialisation but not narrative text.
AUTH0_FORBIDDEN_METADATA_KEYS = (
    # Credentials / tokens / secrets
    "client_secret", "management_api_token", "management_token",
    "access_token", "refresh_token", "id_token",
    "authorization", "bearer", "auth_header",
    "signing_key", "private_key", "signing_secret",
    # Raw URLs (stored as counts/booleans only)
    "callback_url", "logout_url", "allowed_origin",
    "web_origin", "audience", "identifier_uri",
    # User data / PII
    "user_email", "user_id", "email",
    "user_name", "username", "identities",
    "login_history", "ip_address", "device_fingerprint",
    "session_token", "session_id",
    # MFA / enrollment data
    "mfa_recovery_code", "otp_seed", "push_device_token",
    # Domain name (customer-identifying)
    "domain_name", "custom_domain_name",
    # Rule/action code content
    "script_content", "action_code",
    # Connection credentials
    "db_password", "ldap_password", "saml_certificate",
    # Raw API responses / log entries
    "raw_payload", "raw_response", "raw_log", "raw_log_description",
    # Customer data
    "customer_data", "user_data", "pii",
)

# Shape-only substrings that must never appear as raw values.
AUTH0_FORBIDDEN_VALUE_PATTERNS = (
    "begin private key",   # PEM header
    "begin rsa private",
    "begin certificate",
)


# ════════════════════════════════════════════════════════════════════════════
# Section A — Taxonomy parity
# ════════════════════════════════════════════════════════════════════════════


def test_record_types_match_expected():
    assert set(AUTH0_RECORD_TYPES) == EXPECTED_RECORD_TYPES


def test_record_type_constants_are_canonical_lowercase():
    """Each schema constant must equal its lowercase name; evaluator dispatches on this."""
    pairs = (
        ("AUTH0_TENANT_SETTINGS", AUTH0_TENANT_SETTINGS),
        ("AUTH0_APPLICATION", AUTH0_APPLICATION),
        ("AUTH0_CONNECTION", AUTH0_CONNECTION),
        ("AUTH0_RESOURCE_SERVER", AUTH0_RESOURCE_SERVER),
        ("AUTH0_RULE", AUTH0_RULE),
        ("AUTH0_ACTION", AUTH0_ACTION),
        ("AUTH0_MFA_FACTOR", AUTH0_MFA_FACTOR),
        ("AUTH0_CUSTOM_DOMAIN", AUTH0_CUSTOM_DOMAIN),
    )
    for name, val in pairs:
        assert val == name.lower(), (
            f"{name} value ({val!r}) must be its lowercased name "
            f"({name.lower()!r}); evaluator dispatch keys on this."
        )


def test_rule_keys_match_expected():
    assert set(AUTH0_RULE_KEYS) == EXPECTED_RULE_KEYS


def test_rule_registry_parity_for_auth0_keys():
    in_registry = {k for k in KNOWN_RULE_KEYS if k.startswith("auth0_")}
    assert in_registry == EXPECTED_RULE_KEYS

    in_confidence = {k for k in RULE_CONFIDENCE if k.startswith("auth0_")}
    assert in_confidence == EXPECTED_RULE_KEYS

    in_pack = {k for k, v in _RULE_META.items() if v[0] == "auth0"}
    assert in_pack == EXPECTED_RULE_KEYS

    in_coverage = {k for k in RULE_RECORD_TYPES if k.startswith("auth0_")}
    assert in_coverage == EXPECTED_RULE_KEYS


def test_auth0_in_coverage_providers_and_surfaces():
    assert "auth0" in COVERAGE_PROVIDERS
    surfaces = PROVIDER_SURFACES["auth0"]
    assert len(surfaces) >= 8, f"expected >= 8 Auth0 surfaces; got {len(surfaces)}"
    for s in surfaces:
        assert isinstance(s, str) and s.strip()


def test_activity_event_type_map_matches_expected():
    """AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE covers every expected activity event type."""
    types = set(auth0_sig.AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE)
    assert types == EXPECTED_ACTIVITY_EVENT_TYPES


def test_signal_types_match_expected():
    types = set(auth0_sig.AUTH0_SIGNAL_TYPES)
    assert types == EXPECTED_SIGNAL_TYPES


def test_signal_types_derived_from_event_type_map():
    """AUTH0_SIGNAL_TYPES is exactly the values of AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE."""
    from_map = set(auth0_sig.AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE.values())
    assert from_map == set(auth0_sig.AUTH0_SIGNAL_TYPES)


def test_correlation_types_match_expected():
    types = set(auth0_corr.AUTH0_CORRELATION_TYPES)
    assert types == EXPECTED_CORRELATION_TYPES


def test_correlation_rules_cover_all_37_auth0_rule_keys():
    """Every Auth0 rule key must appear in at least one AUTH0_CORRELATION_RULES entry."""
    all_rule_keys: set[str] = set()
    for rule in auth0_corr.AUTH0_CORRELATION_RULES.values():
        all_rule_keys.update(rule["rule_keys"])
    assert all_rule_keys == EXPECTED_RULE_KEYS, (
        f"Rule key parity error. Missing: {EXPECTED_RULE_KEYS - all_rule_keys}; "
        f"Extra: {all_rule_keys - EXPECTED_RULE_KEYS}"
    )


def test_correlation_activity_types_are_subset_of_signal_types():
    """Correlation signal_types must only reference types the signal service handles."""
    referenced: set[str] = set()
    for rule in auth0_corr.AUTH0_CORRELATION_RULES.values():
        referenced.update(rule["signal_types"])
    not_in_signal = referenced - EXPECTED_SIGNAL_TYPES
    assert not_in_signal == set(), (
        f"correlation references signal types not in EXPECTED_SIGNAL_TYPES: "
        f"{sorted(not_in_signal)}"
    )


def test_ingestion_provider_and_source_constants():
    """Ingestion service must tag events provider=auth0, source=auth0_activity_event."""
    assert auth0_ingest.PROVIDER == "auth0"
    assert auth0_ingest.SOURCE == "auth0_activity_event"
    assert auth0_ingest.EVENT_SOURCE == "auth0_activity_event"


def test_capability_matrix_pins_auth0_partial_demo_ready():
    cap = get_provider_capability("auth0")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    # evidence_timeline and evidence_graph enabled for Auth0 (M81G).
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True
    assert cap.maturity == "partial"
    # M81H must be reflected in the capability notes after this milestone.
    notes = (cap.notes or "")
    assert "M81H" in notes, (
        f"Capability notes must mention M81H after provider-depth QA; got: {notes[:200]}"
    )


def test_expansion_framework_points_to_m81i():
    """M81H complete — planned_next_stage must advance past M81H (to M81I or beyond)."""
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert "M81H" not in planned, (
        f"M81H is done; pointer must advance past it (got: {planned!r})"
    )
    # After M81I or beyond is acceptable.
    assert any(tag in planned for tag in (
        "M81I", "M82A", "M82",
    )), (
        f"planned_next_stage must point past M81H; got: {planned!r}"
    )


def test_auth0_not_in_canonical_eight_provider_matrix():
    """Auth0 stays in PROVIDER_CAPABILITIES_PARTIAL — never in the canonical 8."""
    from app.services.provider_capability_matrix_service import (
        PROVIDER_CAPABILITIES,
        PROVIDER_CAPABILITIES_PARTIAL,
    )
    canonical = {p.provider for p in PROVIDER_CAPABILITIES}
    partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
    assert "auth0" not in canonical
    assert "auth0" in partial


# ════════════════════════════════════════════════════════════════════════════
# Section B — Privacy guardrails (allowlist + denylist)
# ════════════════════════════════════════════════════════════════════════════


# Representative subset of safe keys the M81D ingester writes.
_AUTH0_ACTIVITY_SAFE_KEYS = {
    "client_id",              # opaque Auth0 client ID — never client_secret
    "connection_id",          # opaque Auth0 connection ID
    "resource_server_id",     # opaque Auth0 resource server ID
    "rule_id",                # opaque Auth0 rule ID — never script content
    "action_id",              # opaque Auth0 action ID — never code or secrets
    "factor_name",            # MFA factor name (e.g. "otp")
    "custom_domain_id",       # opaque Auth0 custom domain ID — never domain string
    "resource_type",          # config surface type label
    "operation_family",       # operation namespace label
    "event_source",           # source tag
}

# Representative subset of safe keys the M81E signal builder emits.
_AUTH0_SIGNAL_SAFE_KEYS = {
    "source",
    "event_types",
    "event_count",
    "resource_type",
    "client_id",
    "connection_id",
    "resource_server_id",
    "action_id",
    "factor_name",
    "custom_domain_id",
    "window_start",
    "window_end",
    "password_policy_category",
    "rbac_enabled",
    "allow_offline_access",
    "token_endpoint_auth_method",
    "script_present",
    "secrets_count",
    "enabled",
    "status_category",
}

# Representative subset of safe keys the M81F correlation builder emits.
_AUTH0_CORRELATION_SAFE_KEYS = {
    "client_id",
    "connection_id",
    "resource_server_id",
    "action_id",
    "factor_name",
    "custom_domain_id",
    "match_reason",
    "match_strength",
    "rule_key",
    "signal_type",
}


def test_activity_allowlist_contains_all_auth0_safe_keys():
    """Every key the M81D ingester writes must be in the activity allowlist."""
    missing = _AUTH0_ACTIVITY_SAFE_KEYS - ACTIVITY_ALLOWED
    assert missing == set(), (
        f"M81D safe keys missing from activity allowlist: {missing}"
    )


def test_signal_allowlist_contains_all_auth0_safe_keys():
    """Every Auth0-safe key the M81E signal builder emits must be allowlisted."""
    missing = _AUTH0_SIGNAL_SAFE_KEYS - SIGNAL_ALLOWED
    assert missing == set(), (
        f"M81E safe keys missing from signal allowlist: {missing}"
    )


def test_correlation_allowlist_contains_all_auth0_safe_keys():
    missing = _AUTH0_CORRELATION_SAFE_KEYS - corr_svc.ALLOWED_METADATA_KEYS
    assert missing == set(), (
        f"M81F safe keys missing from correlation allowlist: {missing}"
    )


def test_case_report_preview_allowlist_includes_auth0_safe_keys():
    """M81G expansion of the case-report preview allowlist covers Auth0 keys."""
    expected = {
        "client_id", "connection_id", "resource_server_id",
        "action_id", "custom_domain_id", "factor_name",
        "session_lifetime_category", "token_endpoint_auth_method",
        "password_policy_category", "allow_offline_access",
        "rbac_enabled", "script_present", "code_present", "secrets_count",
        "status_category",
    }
    missing = expected - report_svc._PREVIEW_ALLOWLIST
    assert missing == set(), (
        f"case-report preview allowlist missing Auth0-safe keys: {missing}"
    )


# ── Denylist helpers ──────────────────────────────────────────────────────────


def _denylist_assert(blob: str, *, where: str) -> None:
    lower = blob.lower()
    for bad in AUTH0_FORBIDDEN_METADATA_KEYS:
        assert f'"{bad}":' not in lower, (
            f"{where}: forbidden quoted key {bad!r} present"
        )
    for bad in AUTH0_FORBIDDEN_VALUE_PATTERNS:
        assert bad not in lower, (
            f"{where}: forbidden substring {bad!r} present"
        )


def _build_polluted_auth0_signal() -> dict:
    """Build a signal from an event polluted with Auth0-private fields.

    sanitize_signal_metadata() must drop every forbidden key before persisting.
    """
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "auth0.application.updated"
    ev.provider = "auth0"
    ev.source = "auth0_activity_event"
    ev.resource_id = "AUTH0_TEST_CLIENT_ID"
    ev.resource_type = "application"
    ev.provider_event_id = "demo-auth0-evt-1"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {
        # Safe keys (must survive):
        "client_id": "AUTH0_TEST_CLIENT_ID",
        "resource_type": "application",
        "token_endpoint_auth_method": "none",
        # Forbidden pollution that MUST be dropped:
        "client_secret": "FAKE_CLIENT_SECRET_VALUE",
        "management_api_token": "FAKE_MANAGEMENT_TOKEN",
        "access_token": "FAKE_ACCESS_TOKEN",
        "authorization": "Bearer FAKE_BEARER",
        "user_email": "user@example.com",
        "user_id": "auth0|fake_user_id_here",
        "ip_address": "1.2.3.4",
        "login_history": "last_login_fake_data",
        "client_secret_value": "FAKE_SECRET_XYZ",
        "callback_url": "https://app.example.com/callback",
        "raw_payload": '{"client_secret": "FAKE"}',
        "customer_data": "pii here",
        "domain_name": "login.example.com",
        "script_content": "var rule = function(user) { ... }",
    }
    sig = auth0_sig._build_signal([ev])
    assert sig is not None
    return sig


def test_signal_metadata_drops_every_polluted_key():
    sig = _build_polluted_auth0_signal()
    meta = sig["metadata"]
    # Safe metadata survives.
    assert meta.get("client_id") == "AUTH0_TEST_CLIENT_ID"
    assert meta.get("resource_type") == "application"
    assert meta.get("token_endpoint_auth_method") == "none"
    # Forbidden keys dropped.
    for bad in (
        "client_secret", "management_api_token", "access_token",
        "authorization", "user_email", "user_id",
        "ip_address", "login_history", "callback_url",
        "raw_payload", "customer_data", "domain_name", "script_content",
    ):
        assert bad not in meta, (
            f"forbidden key {bad!r} survived in signal metadata"
        )
    # Private values never appear in any serialisable surface.
    blob = json.dumps({
        "metadata": meta, "title": sig["title"], "summary": sig["summary"],
    })
    for value in (
        "FAKE_CLIENT_SECRET_VALUE", "FAKE_MANAGEMENT_TOKEN",
        "FAKE_ACCESS_TOKEN", "FAKE_BEARER",
        "user@example.com", "auth0|fake_user_id_here",
        "1.2.3.4", "pii here", "login.example.com",
    ):
        assert value not in blob, f"private value {value!r} in signal blob"


def _make_finding_mock(rule_key: str, **evidence: Any) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.finding_key = f"{rule_key}:AUTH0_TEST_CLIENT_ID"
    f.severity = "high"
    f.title = "Demo Auth0 finding"
    f.evidence = evidence
    f.first_detected_at = datetime.now(timezone.utc) - timedelta(hours=1)
    f.last_seen_at = datetime.now(timezone.utc)
    f.linked_change_id = None
    f.integration_id = uuid.uuid4()
    return f


def _make_signal_mock(signal_type: str, metadata: dict) -> MagicMock:
    sig = MagicMock()
    sig.id = uuid.uuid4()
    sig.signal_type = signal_type
    sig.provider = "auth0"
    sig.source = "auth0_activity_event"
    sig.signal_metadata = metadata
    sig.severity = "medium"
    sig.first_seen_at = datetime.now(timezone.utc)
    sig.last_seen_at = datetime.now(timezone.utc)
    sig.linked_activity_event_id = uuid.uuid4()
    return sig


def test_correlation_metadata_drops_every_polluted_key():
    """_build_correlation sanitizes forbidden keys from both finding and signal."""
    finding = _make_finding_mock(
        "auth0_application_token_endpoint_auth_none",
        client_id="AUTH0_TEST_CLIENT_ID",
        token_endpoint_auth_method="none",
        # Forbidden pollution on the finding side:
        client_secret="FAKE_CLIENT_SECRET",
        access_token="FAKE_ACCESS_TOKEN",
        user_email="user@example.com",
        callback_url="https://example.com/callback",
        customer_data="pii here",
    )
    signal = _make_signal_mock(
        "auth0_application_config_changed",
        {
            "client_id": "AUTH0_TEST_CLIENT_ID",
            "resource_type": "application",
            "event_types": "auth0.application.updated",
            # Forbidden pollution on the signal side:
            "management_api_token": "FAKE_MGMT_TOKEN",
            "user_id": "auth0|fake_user_id",
            "ip_address": "9.9.9.9",
            "script_content": "rule code here",
            "raw_payload": '{"client_secret": "FAKE"}',
        },
    )
    rule = auth0_corr.AUTH0_CORRELATION_RULES[
        "auth0_application_risk_activity_correlation"
    ]
    c = auth0_corr._build_correlation(
        finding=finding, signal=signal,
        correlation_type="auth0_application_risk_activity_correlation",
        rule=rule,
        match_reason="client_id_match",
    )
    blob = json.dumps({
        "metadata": c["metadata"], "title": c["title"], "summary": c["summary"],
    })
    _denylist_assert(blob, where="correlation built from polluted finding+signal")
    assert "FAKE_CLIENT_SECRET" not in blob
    assert "FAKE_MGMT_TOKEN" not in blob
    assert "user@example.com" not in blob


def test_auth0_demo_case_artifacts_pass_denylist(test_user, db_session):
    """The Auth0 demo seed/report stay denylist-clean."""
    from app.services import workspace_service
    ws = workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M81H demo", db=db_session,
    )
    try:
        seed = demo_svc.seed_auth0(
            workspace_id=ws.id, actor_user_id=test_user.id, db=db_session,
        )
        case_id = uuid.UUID(seed["case_id"])
        from app.models.security_case import SecurityCase
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(report, default=str)
        _denylist_assert(blob, where="auth0 demo report")
        # No JWT-shaped strings.
        assert not re.search(
            r'eyJ[A-Za-z0-9_-]{10,}', blob
        ), "JWT-shaped string found in demo case blobs"
        # No real-looking email addresses.
        assert not re.search(r'[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}', blob), (
            "email address found in demo case blobs"
        )
    finally:
        demo_svc.clear_auth0(workspace_id=ws.id, db=db_session)


# ════════════════════════════════════════════════════════════════════════════
# Section C — Claim discipline (forbidden phrases on Auth0 modules)
# ════════════════════════════════════════════════════════════════════════════


_AUTH0_MODULES = [
    auth0_conn, auth0_ingest, auth0_sig, demo_svc,
]


def _strip_known_negation_contexts(src: str) -> str:
    """Remove lines that explicitly NEGATE a forbidden claim."""
    out = []
    for line in src.splitlines():
        low = line.lower()
        if any(
            tok in low
            for tok in (
                "does not confirm", "never assert", "never claim",
                "do not claim", "is not a claim", "without claiming",
                "claim discipline", "claim-discipline",
                "review-safe wording", "review safe wording",
                "without overclaim", "review-safe", "doesn't confirm",
                "forbidden", "not confirm",
            )
        ):
            continue
        out.append(line)
    return "\n".join(out)


@pytest.mark.parametrize("module", _AUTH0_MODULES)
def test_auth0_modules_have_no_forbidden_claims(module):
    src = inspect.getsource(module)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in {module.__name__} "
            f"outside a negation context"
        )


def test_auth0_security_rules_module_has_no_forbidden_claims():
    """The security_rules.auth0 module ships claim-discipline copy."""
    from app.services.security_rules import auth0 as auth0_rules
    src = inspect.getsource(auth0_rules)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in security_rules.auth0"
        )


def test_auth0_correlation_module_has_no_forbidden_claims():
    """The Auth0 risk×activity correlation module is claim-discipline clean."""
    src = inspect.getsource(auth0_corr)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in auth0_risk_activity_correlation_service"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section D — False-positive behavior pins
# ════════════════════════════════════════════════════════════════════════════


# ── Record builder helpers ────────────────────────────────────────────────────

def _tenant_record(**kwargs) -> dict:
    base = {
        "record_type": AUTH0_TENANT_SETTINGS,
        "record_id": "auth0_tenant_settings_main",
        "provider_resource_id": "tenants/settings",
        "session_lifetime_category": "standard",
        "idle_session_lifetime_category": "standard",
        "flag_enable_dynamic_client_registration": False,
        "friendly_name_present": True,
        "support_email_domain": "example",
        "default_directory_present": False,
        "enabled_locales_count": 1,
        "flag_change_pwd_on_first_login": False,
        "flag_enable_client_connections": True,
        "flag_enable_apis_section": True,
        "flag_enable_pipeline2": False,
        "flag_enable_custom_domain_in_emails": False,
        "flag_universal_login": True,
        "flag_enable_legacy_logs_search_v2": False,
        "flag_no_disclose_enterprise_connections": False,
        "flag_disable_management_api_sms_obfuscation": False,
        "flag_enable_adfs_waad_email_verification": False,
        "flag_revoke_refresh_token_grant": False,
    }
    base.update(kwargs)
    return base


def _application_record(**kwargs) -> dict:
    base = {
        "record_type": AUTH0_APPLICATION,
        "record_id": "AUTH0_TEST_CLIENT_ID",
        "provider_resource_id": "clients/AUTH0_TEST_CLIENT_ID",
        "client_id": "AUTH0_TEST_CLIENT_ID",
        "name": "Demo Application",
        "app_type": "regular_web",
        "is_first_party": True,
        "callbacks_count": 2,
        "allowed_logout_urls_count": 1,
        "allowed_origins_count": 2,
        "web_origins_count": 1,
        "jwt_alg": "RS256",
        "oidc_conformant": True,
        "token_endpoint_auth_method": "client_secret_post",
        "refresh_token_rotation_enabled": True,
        "refresh_token_lifetime_category": "standard",
        "grant_types_summary": "authorization_code, refresh_token",
        "grant_types_count": 2,
        "grant_password_enabled": False,
        "grant_implicit_enabled": False,
        "grant_client_credentials_enabled": False,
        "grant_authorization_code_enabled": True,
        "grant_refresh_token_enabled": True,
        "grant_device_code_enabled": False,
        "grant_mfa_enabled": False,
        "wildcard_callback_present": False,
        "wildcard_logout_url_present": False,
        "wildcard_allowed_origin_present": False,
        "localhost_callback_present": False,
        "localhost_origin_present": False,
        "callbacks_missing_https": False,
        "allowed_origins_missing_https": False,
    }
    base.update(kwargs)
    return base


def _connection_record(**kwargs) -> dict:
    base = {
        "record_type": AUTH0_CONNECTION,
        "record_id": "AUTH0_TEST_CONNECTION_ID",
        "provider_resource_id": "connections/AUTH0_TEST_CONNECTION_ID",
        "connection_id": "AUTH0_TEST_CONNECTION_ID",
        "name": "Demo Database Connection",
        "strategy": "auth0",
        "enabled_clients_count": 3,
        "is_domain_connection": False,
        "password_policy_category": "good",
        "mfa_enabled": True,
    }
    base.update(kwargs)
    return base


def _resource_server_record(**kwargs) -> dict:
    base = {
        "record_type": AUTH0_RESOURCE_SERVER,
        "record_id": "AUTH0_TEST_RESOURCE_SERVER_ID",
        "provider_resource_id": "resource-servers/AUTH0_TEST_RESOURCE_SERVER_ID",
        "resource_server_id": "AUTH0_TEST_RESOURCE_SERVER_ID",
        "name": "Demo API",
        "identifier_present": True,
        "signing_alg": "RS256",
        "token_lifetime_category": "standard",
        "allow_offline_access": False,
        "skip_consent_for_verifiable_first_party_clients": False,
        "rbac_enabled": True,
        "scopes_count": 5,
    }
    base.update(kwargs)
    return base


def _rule_record(**kwargs) -> dict:
    base = {
        "record_type": AUTH0_RULE,
        "record_id": "AUTH0_TEST_RULE_ID",
        "provider_resource_id": "rules/AUTH0_TEST_RULE_ID",
        "rule_id": "AUTH0_TEST_RULE_ID",
        "name": "Demo Rule",
        "enabled": True,
        "order": 1,
        "script_present": True,
        "script_length_category": "short",
        "stage": "login_success",
    }
    base.update(kwargs)
    return base


def _action_record(**kwargs) -> dict:
    base = {
        "record_type": AUTH0_ACTION,
        "record_id": "AUTH0_TEST_ACTION_ID",
        "provider_resource_id": "actions/actions/AUTH0_TEST_ACTION_ID",
        "action_id": "AUTH0_TEST_ACTION_ID",
        "name": "Demo Action",
        "status": "built",
        "runtime": "node18-actions",
        "trigger_id": "post-login",
        "code_present": True,
        "code_length_category": "short",
        "deployed_version_present": True,
        "dependencies_count": 1,
        "secrets_count": 0,
    }
    base.update(kwargs)
    return base


def _mfa_factor_record(**kwargs) -> dict:
    base = {
        "record_type": AUTH0_MFA_FACTOR,
        "record_id": "auth0_mfa_factor_otp",
        "provider_resource_id": "guardian/factors/otp",
        "factor_name": "otp",
        "enabled": True,
        "trial_expired": None,
        "provider_category": "totp",
    }
    base.update(kwargs)
    return base


def _custom_domain_record(**kwargs) -> dict:
    base = {
        "record_type": AUTH0_CUSTOM_DOMAIN,
        "record_id": "AUTH0_TEST_CUSTOM_DOMAIN_ID",
        "provider_resource_id": "custom-domains/AUTH0_TEST_CUSTOM_DOMAIN_ID",
        "custom_domain_id": "AUTH0_TEST_CUSTOM_DOMAIN_ID",
        "domain_present": True,
        "status": "ready",
        "type": "auth0_managed_certs",
        "primary": True,
        "verification_method_category": "cname",
        "tls_policy_category": "recommended",
    }
    base.update(kwargs)
    return base


# ── False-positive: should NOT fire ──────────────────────────────────────────

def test_tenant_standard_sessions_do_not_fire():
    """standard session / idle lifetimes → no session-lifetime findings."""
    rec = _tenant_record(
        session_lifetime_category="standard",
        idle_session_lifetime_category="standard",
        flag_enable_dynamic_client_registration=False,
    )
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_tenant_session_lifetime_extended" not in keys
    assert "auth0_tenant_idle_session_lifetime_extended" not in keys
    assert "auth0_tenant_dynamic_client_registration_enabled" not in keys


def test_application_safe_posture_does_not_fire():
    """Safe application with RS256, client_secret_post, OIDC conformant → no findings."""
    rec = _application_record(
        jwt_alg="RS256",
        oidc_conformant=True,
        token_endpoint_auth_method="client_secret_post",
        grant_password_enabled=False,
        grant_implicit_enabled=False,
        grant_device_code_enabled=False,
        wildcard_callback_present=False,
        localhost_callback_present=False,
        callbacks_missing_https=False,
        allowed_origins_missing_https=False,
        refresh_token_rotation_enabled=True,
        callbacks_count=2,
    )
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_application_weak_jwt_algorithm" not in keys
    assert "auth0_application_token_endpoint_auth_none" not in keys
    assert "auth0_application_password_grant_enabled" not in keys
    assert "auth0_application_implicit_grant_enabled" not in keys
    assert "auth0_application_device_code_grant_enabled" not in keys
    assert "auth0_application_wildcard_callback" not in keys
    assert "auth0_application_localhost_callback" not in keys
    assert "auth0_application_callback_missing_https" not in keys
    assert "auth0_application_origin_missing_https" not in keys


def test_connection_good_password_policy_does_not_fire():
    """enabled_clients > 0 and good password policy → no connection findings."""
    rec = _connection_record(
        enabled_clients_count=2,
        password_policy_category="good",
    )
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_connection_no_enabled_clients" not in keys
    assert "auth0_connection_weak_password_policy" not in keys


def test_resource_server_safe_posture_does_not_fire():
    """rbac_enabled=True, offline_access=False, standard lifetime → no RS findings."""
    rec = _resource_server_record(
        allow_offline_access=False,
        rbac_enabled=True,
        token_lifetime_category="standard",
    )
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_resource_server_offline_access_enabled" not in keys
    assert "auth0_resource_server_rbac_disabled" not in keys
    assert "auth0_resource_server_token_lifetime_extended" not in keys


def test_rule_enabled_short_script_does_not_fire():
    """enabled=True and short script → no rule findings."""
    rec = _rule_record(enabled=True, script_length_category="short")
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_rule_disabled" not in keys
    assert "auth0_rule_large_script" not in keys


def test_action_built_no_secrets_does_not_fire():
    """status=built, secrets_count=0 → no action findings."""
    rec = _action_record(status="built", secrets_count=0, deployed_version_present=True)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_action_not_deployed" not in keys
    assert "auth0_action_secrets_present" not in keys


def test_mfa_factor_enabled_does_not_fire():
    """otp enabled=True → no mfa_factor_disabled finding."""
    rec = _mfa_factor_record(factor_name="otp", enabled=True)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_mfa_factor_disabled" not in keys


def test_custom_domain_ready_recommended_tls_does_not_fire():
    """status=ready and tls_policy_category=recommended → no custom domain findings."""
    rec = _custom_domain_record(status="ready", tls_policy_category="recommended")
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_custom_domain_not_ready" not in keys
    assert "auth0_custom_domain_weak_tls_policy" not in keys


def test_unknown_record_type_returns_no_findings():
    """The Auth0 evaluator dispatch is closed — unknown types yield []."""
    assert auth0_eval({"record_type": "auth0_unknown_thing"}) == []
    assert auth0_eval({"record_type": ""}) == []
    assert auth0_eval({}) == []


# ── Positive: SHOULD fire ─────────────────────────────────────────────────────

def test_tenant_extended_session_lifetime_fires():
    """session_lifetime_category=extended MUST trigger tenant_session_lifetime_extended."""
    rec = _tenant_record(session_lifetime_category="extended")
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_tenant_session_lifetime_extended" in keys, (
        "Expected auth0_tenant_session_lifetime_extended to fire for extended session"
    )


def test_tenant_dynamic_client_registration_fires():
    """flag_enable_dynamic_client_registration=True MUST trigger DCR rule."""
    rec = _tenant_record(flag_enable_dynamic_client_registration=True)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_tenant_dynamic_client_registration_enabled" in keys


def test_application_token_endpoint_auth_none_fires():
    """token_endpoint_auth_method=none MUST trigger application_token_endpoint_auth_none."""
    rec = _application_record(token_endpoint_auth_method="none")
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_application_token_endpoint_auth_none" in keys


def test_application_weak_jwt_algorithm_fires():
    """jwt_alg=HS256 MUST trigger application_weak_jwt_algorithm."""
    rec = _application_record(jwt_alg="HS256")
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_application_weak_jwt_algorithm" in keys


def test_application_password_grant_enabled_fires():
    """grant_password_enabled=True MUST trigger application_password_grant_enabled."""
    rec = _application_record(grant_password_enabled=True)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_application_password_grant_enabled" in keys


def test_application_wildcard_callback_fires():
    """wildcard_callback_present=True MUST trigger application_wildcard_callback."""
    rec = _application_record(wildcard_callback_present=True)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_application_wildcard_callback" in keys


def test_application_callback_missing_https_fires():
    """callbacks_missing_https=True MUST trigger application_callback_missing_https."""
    rec = _application_record(callbacks_missing_https=True)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_application_callback_missing_https" in keys


def test_connection_weak_password_policy_fires():
    """password_policy_category=low MUST trigger connection_weak_password_policy."""
    rec = _connection_record(password_policy_category="low")
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_connection_weak_password_policy" in keys


def test_connection_no_enabled_clients_fires():
    """enabled_clients_count=0 MUST trigger connection_no_enabled_clients."""
    rec = _connection_record(enabled_clients_count=0)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_connection_no_enabled_clients" in keys


def test_resource_server_offline_access_fires():
    """allow_offline_access=True MUST trigger resource_server_offline_access_enabled."""
    rec = _resource_server_record(allow_offline_access=True)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_resource_server_offline_access_enabled" in keys


def test_resource_server_rbac_disabled_fires():
    """rbac_enabled=False MUST trigger resource_server_rbac_disabled."""
    rec = _resource_server_record(rbac_enabled=False)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_resource_server_rbac_disabled" in keys


def test_rule_disabled_fires():
    """enabled=False MUST trigger rule_disabled."""
    rec = _rule_record(enabled=False)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_rule_disabled" in keys


def test_action_not_deployed_fires():
    """deployed_version_present=False MUST trigger action_not_deployed."""
    rec = _action_record(deployed_version_present=False)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_action_not_deployed" in keys


def test_action_secrets_present_fires():
    """secrets_count=2 MUST trigger action_secrets_present."""
    rec = _action_record(secrets_count=2)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_action_secrets_present" in keys


def test_mfa_factor_disabled_fires():
    """otp enabled=False MUST trigger mfa_factor_disabled."""
    rec = _mfa_factor_record(factor_name="otp", enabled=False)
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_mfa_factor_disabled" in keys


def test_custom_domain_not_ready_fires():
    """status=pending_verification MUST trigger custom_domain_not_ready."""
    rec = _custom_domain_record(status="pending_verification")
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_custom_domain_not_ready" in keys


def test_custom_domain_weak_tls_fires():
    """tls_policy_category=compatible MUST trigger custom_domain_weak_tls_policy."""
    rec = _custom_domain_record(status="ready", tls_policy_category="compatible")
    keys = {f.rule_key for f in auth0_eval(rec)}
    assert "auth0_custom_domain_weak_tls_policy" in keys


# ── Correlation false-positive / positive ────────────────────────────────────

def test_tenant_level_always_matches():
    """Tenant correlation always produces match regardless of finding/signal metadata."""
    finding = _make_finding_mock("auth0_tenant_session_lifetime_extended")
    signal = _make_signal_mock("auth0_tenant_config_changed", {})
    result = auth0_corr._match_pair(finding, signal, "tenant")
    assert result == "tenant_level", (
        "Tenant-level correlation must always return 'tenant_level'"
    )


def test_different_client_ids_do_not_correlate():
    """Mismatched client_id on both sides → no application correlation."""
    finding = _make_finding_mock(
        "auth0_application_token_endpoint_auth_none",
        client_id="AUTH0_CLIENT_ID_A",
    )
    signal = _make_signal_mock(
        "auth0_application_config_changed",
        {"client_id": "AUTH0_CLIENT_ID_B"},
    )
    result = auth0_corr._match_pair(finding, signal, "application")
    assert result is None, (
        "Different client_id values must not produce an application correlation"
    )


def test_same_client_id_produces_exact_match():
    """Matching client_id on both sides → client_id_match."""
    finding = _make_finding_mock(
        "auth0_application_token_endpoint_auth_none",
        client_id="AUTH0_DEMO_CLIENT_ID",
    )
    signal = _make_signal_mock(
        "auth0_application_config_changed",
        {"client_id": "AUTH0_DEMO_CLIENT_ID"},
    )
    result = auth0_corr._match_pair(finding, signal, "application")
    assert result == "client_id_match"


def test_missing_client_id_produces_application_family():
    """When neither side has client_id, family-level match is returned."""
    finding = _make_finding_mock("auth0_application_token_endpoint_auth_none")
    signal = _make_signal_mock("auth0_application_config_changed", {})
    result = auth0_corr._match_pair(finding, signal, "application")
    assert result == "application_family"


def test_different_connection_ids_do_not_correlate():
    """Mismatched connection_id → no connection correlation."""
    finding = _make_finding_mock(
        "auth0_connection_weak_password_policy",
        connection_id="AUTH0_CONN_ID_A",
    )
    signal = _make_signal_mock(
        "auth0_connection_config_changed",
        {"connection_id": "AUTH0_CONN_ID_B"},
    )
    result = auth0_corr._match_pair(finding, signal, "connection")
    assert result is None


def test_same_connection_id_produces_exact_match():
    """Matching connection_id on both sides → connection_id_match."""
    finding = _make_finding_mock(
        "auth0_connection_weak_password_policy",
        connection_id="AUTH0_DEMO_CONNECTION_ID",
    )
    signal = _make_signal_mock(
        "auth0_connection_config_changed",
        {"connection_id": "AUTH0_DEMO_CONNECTION_ID"},
    )
    result = auth0_corr._match_pair(finding, signal, "connection")
    assert result == "connection_id_match"


def test_same_resource_server_id_produces_exact_match():
    """Matching resource_server_id on both sides → resource_server_id_match."""
    finding = _make_finding_mock(
        "auth0_resource_server_rbac_disabled",
        resource_server_id="AUTH0_DEMO_RS_ID",
    )
    signal = _make_signal_mock(
        "auth0_resource_server_config_changed",
        {"resource_server_id": "AUTH0_DEMO_RS_ID"},
    )
    result = auth0_corr._match_pair(finding, signal, "resource_server")
    assert result == "resource_server_id_match"


def test_same_rule_id_produces_exact_match():
    """Matching rule_id on both sides → rule_id_match."""
    finding = _make_finding_mock(
        "auth0_rule_disabled",
        rule_id="AUTH0_DEMO_RULE_ID",
    )
    signal = _make_signal_mock(
        "auth0_rule_config_changed",
        {"rule_id": "AUTH0_DEMO_RULE_ID"},
    )
    result = auth0_corr._match_pair(finding, signal, "rule")
    assert result == "rule_id_match"


def test_same_action_id_produces_exact_match():
    """Matching action_id on both sides → action_id_match."""
    finding = _make_finding_mock(
        "auth0_action_secrets_present",
        action_id="AUTH0_DEMO_ACTION_ID",
    )
    signal = _make_signal_mock(
        "auth0_action_config_changed",
        {"action_id": "AUTH0_DEMO_ACTION_ID"},
    )
    result = auth0_corr._match_pair(finding, signal, "action")
    assert result == "action_id_match"


def test_same_factor_name_produces_exact_match():
    """Matching factor_name on both sides → factor_name_match."""
    finding = _make_finding_mock(
        "auth0_mfa_factor_disabled",
        factor_name="otp",
    )
    signal = _make_signal_mock(
        "auth0_mfa_factor_config_changed",
        {"factor_name": "otp"},
    )
    result = auth0_corr._match_pair(finding, signal, "mfa_factor")
    assert result == "factor_name_match"


def test_same_custom_domain_id_produces_exact_match():
    """Matching custom_domain_id on both sides → custom_domain_id_match."""
    finding = _make_finding_mock(
        "auth0_custom_domain_not_ready",
        custom_domain_id="AUTH0_DEMO_CUSTOM_DOMAIN_ID",
    )
    signal = _make_signal_mock(
        "auth0_custom_domain_config_changed",
        {"custom_domain_id": "AUTH0_DEMO_CUSTOM_DOMAIN_ID"},
    )
    result = auth0_corr._match_pair(finding, signal, "custom_domain")
    assert result == "custom_domain_id_match"


def test_generic_config_event_maps_to_config_activity_low_severity():
    """auth0.config.event maps to auth0_config_activity — low severity."""
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "auth0.config.event"
    ev.provider = "auth0"
    ev.source = "auth0_activity_event"
    ev.resource_type = "configuration"
    ev.resource_id = None
    ev.provider_event_id = "demo-cfg-1"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {"resource_type": "configuration"}
    sig = auth0_sig._build_signal([ev])
    assert sig is not None
    assert sig["signal_type"] == "auth0_config_activity"
    assert sig["severity"] == "low"


def test_unknown_signal_event_type_returns_no_signal():
    """The signal dispatcher silently drops unmapped event types."""
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "auth0.totally.unknown"
    ev.provider = "auth0"
    ev.source = "auth0_activity_event"
    ev.resource_type = "configuration"
    ev.resource_id = None
    ev.provider_event_id = "demo-unk-1"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {}
    sig = auth0_sig._build_signal([ev])
    assert sig is None


# ════════════════════════════════════════════════════════════════════════════
# Section E — Demo isolation
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def _ws(test_user, db_session):
    from app.services import workspace_service
    return workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M81H ws", db=db_session,
    )


def test_seed_auth0_demo_is_idempotent(test_user, db_session, _ws):
    try:
        r1 = demo_svc.seed_auth0(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        r2 = demo_svc.seed_auth0(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
    finally:
        demo_svc.clear_auth0(workspace_id=_ws.id, db=db_session)


def test_clear_auth0_demo_is_idempotent(test_user, db_session, _ws):
    demo_svc.seed_auth0(
        workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
    )
    demo_svc.clear_auth0(workspace_id=_ws.id, db=db_session)
    out = demo_svc.clear_auth0(workspace_id=_ws.id, db=db_session)
    assert out == {"cleared": True}
    assert demo_svc.get_auth0_status(_ws.id, db_session)["seeded"] is False


def test_clear_auth0_demo_leaves_real_auth0_integration_alone(
    test_user, db_session, _ws,
):
    """Real (non-demo) Auth0 rows survive clear_auth0."""
    from app.core.encryption import encrypt_credentials
    from app.models.integration import Integration
    from app.models.security_finding import SecurityFinding
    ct, iv = encrypt_credentials({"tenant_id": "AUTH0_TEST_TENANT_ID"})
    real = Integration(
        user_id=test_user.id, workspace_id=_ws.id, provider="auth0",
        display_name="real-auth0-tenant", encrypted_credentials=ct,
        credential_iv=iv, status="active",
    )
    db_session.add(real)
    db_session.commit()
    db_session.refresh(real)
    keep = SecurityFinding(
        workspace_id=_ws.id, integration_id=real.id, provider="auth0",
        finding_key="auth0_tenant_session_lifetime_extended:AUTH0_TEST_TENANT_ID#real",
        severity="medium", title="Real Auth0 tenant session risk (keep)",
        status="active",
        evidence={
            "rule": "auth0_tenant_session_lifetime_extended",
            "session_lifetime_category": "extended",
        },
        remediation={"summary": "Review session lifetime."},
    )
    db_session.add(keep)
    db_session.commit()
    db_session.refresh(keep)
    keep_id = keep.id
    try:
        demo_svc.seed_auth0(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        demo_svc.clear_auth0(workspace_id=_ws.id, db=db_session)
        # Demo integration is gone.
        assert demo_svc.get_auth0_demo_integration(_ws.id, db_session) is None
        # Real integration and finding survive.
        survivor = db_session.query(SecurityFinding).filter(
            SecurityFinding.id == keep_id).first()
        assert survivor is not None, (
            "clear_auth0 removed a non-demo Auth0 finding"
        )
        assert db_session.query(Integration).filter(
            Integration.id == real.id).first() is not None
    finally:
        db_session.query(SecurityFinding).filter(
            SecurityFinding.id == keep_id).delete(synchronize_session=False)
        db_session.query(Integration).filter(
            Integration.id == real.id).delete(synchronize_session=False)
        db_session.commit()
        demo_svc.clear_auth0(workspace_id=_ws.id, db=db_session)


def test_clear_auth0_demo_does_not_touch_other_provider_demos(
    test_user, db_session, _ws,
):
    """A multi-provider workspace: clearing Auth0 leaves every other demo alone."""
    other_providers = (
        ("sendgrid", demo_svc.seed_sendgrid, demo_svc.clear_sendgrid, demo_svc.get_sendgrid_status),
        ("twilio",   demo_svc.seed_twilio,   demo_svc.clear_twilio,   demo_svc.get_twilio_status),
        ("azure",    demo_svc.seed_azure,    demo_svc.clear_azure,    demo_svc.get_azure_status),
    )
    try:
        for _p, seed_fn, _c, _s in other_providers:
            seed_fn(workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session)
        demo_svc.seed_auth0(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        for _p, _, _c, status_fn in other_providers:
            assert status_fn(_ws.id, db_session)["seeded"] is True
        assert demo_svc.get_auth0_status(_ws.id, db_session)["seeded"] is True

        demo_svc.clear_auth0(workspace_id=_ws.id, db=db_session)

        assert demo_svc.get_auth0_status(_ws.id, db_session)["seeded"] is False
        for p, _, _c, status_fn in other_providers:
            assert status_fn(_ws.id, db_session)["seeded"] is True, (
                f"clear_auth0 incorrectly removed the {p} demo"
            )
    finally:
        for _p, _s, clear_fn, _status in other_providers:
            try:
                clear_fn(workspace_id=_ws.id, db=db_session)
            except Exception:
                db_session.rollback()
        try:
            demo_svc.clear_auth0(workspace_id=_ws.id, db=db_session)
        except Exception:
            db_session.rollback()


def test_auth0_demo_integration_is_hidden_and_safe(test_user, db_session, _ws):
    """The demo integration must use DEMO_PROVIDER_TAG and 'deleted' status."""
    try:
        demo_svc.seed_auth0(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        integ = demo_svc.get_auth0_demo_integration(_ws.id, db_session)
        assert integ is not None
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG
        assert integ.status == "deleted"
        assert integ.scheduled_sync_enabled is False
        assert "Auth0" in integ.display_name
        assert "demo" in integ.display_name.lower()
    finally:
        demo_svc.clear_auth0(workspace_id=_ws.id, db=db_session)


def test_auth0_demo_uses_safe_placeholder_constants(test_user, db_session, _ws):
    """Seeded demo findings must not contain JWT-shaped strings or emails."""
    from app.models.security_finding import SecurityFinding
    try:
        demo_svc.seed_auth0(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        integ = demo_svc.get_auth0_demo_integration(_ws.id, db_session)
        assert integ is not None
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        for f in findings:
            blob = json.dumps(f.evidence or {}, default=str)
            # No JWT-shaped strings (eyJ...)
            assert not re.search(
                r'eyJ[A-Za-z0-9_-]{10,}', blob
            ), f"JWT-shaped string in finding {f.finding_key}"
            # No email addresses
            assert not re.search(
                r'[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}', blob
            ), f"email address in finding {f.finding_key}: {blob[:200]}"
            # The finding_key must use safe sentinel placeholders.
            # (Tenant-only findings may have no placeholder ID in evidence;
            # resource-specific findings carry their ID in the finding_key.)
            assert not re.search(r'[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}', f.finding_key), (
                f"email address in finding_key {f.finding_key}"
            )
    finally:
        demo_svc.clear_auth0(workspace_id=_ws.id, db=db_session)


# ════════════════════════════════════════════════════════════════════════════
# Section F — Router/API guards (admin-only mutations; member reads)
# ════════════════════════════════════════════════════════════════════════════


def _scan_router_source() -> str:
    from app.routers import security as sec_router
    return inspect.getsource(sec_router)


def test_router_auth0_activity_sync_endpoint_exists():
    src = _scan_router_source()
    assert '"/auth0-activity/sync"' in src, (
        "auth0-activity/sync endpoint missing from router"
    )


def test_router_auth0_activity_sync_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/auth0-activity/sync"')
    assert idx != -1
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block, (
        "/auth0-activity/sync handler missing admin guard"
    )


def test_router_auth0_signal_generate_endpoint_exists():
    src = _scan_router_source()
    assert '"/auth0-activity/generate-signals"' in src, (
        "auth0-activity/generate-signals endpoint missing"
    )


def test_router_auth0_signal_generate_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/auth0-activity/generate-signals"')
    assert idx != -1
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block, (
        "/auth0-activity/generate-signals handler missing admin guard"
    )


def test_router_auth0_correlations_generate_endpoint_exists():
    src = _scan_router_source()
    assert '"/auth0-correlations/generate"' in src, (
        "auth0-correlations/generate endpoint missing from router"
    )


def test_router_auth0_correlations_generate_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/auth0-correlations/generate"')
    assert idx != -1
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block, (
        "/auth0-correlations/generate handler missing admin guard"
    )


def test_router_auth0_correlations_dispatches_to_generate_auth0_correlations():
    src = _scan_router_source()
    assert "generate_auth0_correlations" in src, (
        "router does not call generate_auth0_correlations"
    )


def test_router_incident_demo_seed_clear_require_admin():
    """seed/clear are admin-only; status is member-readable."""
    src = _scan_router_source()
    for ep in ('"/incident-demo/seed"', '"/incident-demo/clear"'):
        idx = src.find(ep)
        assert idx != -1, f"{ep} endpoint missing"
        fn_block = src[idx: idx + 4000]
        assert "require_workspace_admin" in fn_block, (
            f"{ep} handler missing admin guard"
        )


def test_router_incident_demo_status_is_member_readable():
    """The status endpoint must NOT require admin."""
    src = _scan_router_source()
    idx = src.find('@router.get("/incident-demo/status"')
    assert idx != -1, "/incident-demo/status endpoint missing or not GET"
    next_router = src.find("\n@router", idx + 1)
    fn_block = src[idx: next_router if next_router > 0 else idx + 4000]
    assert "require_workspace_admin" not in fn_block, (
        "/incident-demo/status must not require admin"
    )


def test_router_dispatches_auth0_for_all_demo_endpoints():
    """All three incident-demo endpoints route provider='auth0'."""
    src = _scan_router_source()
    for substring in (
        "get_auth0_status", "seed_auth0", "clear_auth0",
    ):
        assert substring in src, f"router missing dispatch to {substring}"


# ════════════════════════════════════════════════════════════════════════════
# Section G — Frontend Auth0 consistency (skip if frontend tree absent)
# ════════════════════════════════════════════════════════════════════════════


_FE_ROOT_CANDIDATES = (
    Path(__file__).resolve().parents[2] / "frontend" / "src",
)


def _fe_src() -> Path | None:
    for c in _FE_ROOT_CANDIDATES:
        if c.is_dir():
            return c
    return None


def _read_fe(rel: str) -> str:
    root = _fe_src()
    if root is None:
        pytest.skip("frontend/src not mounted")
    return (root / rel).read_text(encoding="utf-8")


def test_fe_activity_page_includes_auth0_provider_and_event_types():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert '"auth0"' in text
    assert "Auth0" in text
    for ev in (
        "auth0.tenant.updated",
        "auth0.application.created",
        "auth0.application.updated",
        "auth0.connection.updated",
        "auth0.resource_server.updated",
        "auth0.rule.updated",
        "auth0.action.deployed",
        "auth0.mfa_factor.updated",
        "auth0.custom_domain.updated",
        "auth0.config.event",
    ):
        assert ev in text, (
            f"activity page filter missing auth0 event type {ev!r}"
        )


def test_fe_signals_page_includes_auth0_provider_and_signal_types():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert '"auth0"' in text
    for s in EXPECTED_SIGNAL_TYPES:
        assert s in text, f"signals page filter missing {s!r}"


def test_fe_correlations_page_includes_auth0_provider_and_correlation_types():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    assert '"auth0"' in text
    for ctype in EXPECTED_CORRELATION_TYPES:
        assert ctype in text, f"correlations page missing {ctype!r}"


def test_fe_cases_page_has_auth0_demo_card():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert 'provider: "auth0"' in text
    assert "Auth0" in text
    assert "Load Auth0 security demo" in text


def test_fe_demo_script_page_marks_auth0_demo_ready():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(r'\{\s*provider:\s*"auth0",[^}]*demo:\s*true', text)
    assert m is not None, "demo-script Auth0 row missing demo: true"


def test_fe_demo_script_page_marks_auth0_signals_and_correlations_ready():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    # signals: true
    m_sig = re.search(r'\{\s*provider:\s*"auth0"[^}]*signals:\s*(true|false)', text)
    assert m_sig is not None, "Auth0 row not found in demo capability table"
    assert m_sig.group(1) == "true", "Auth0 signals should be true (M81E)"
    # correlations: true
    m_corr = re.search(r'\{\s*provider:\s*"auth0"[^}]*correlations:\s*(true|false)', text)
    assert m_corr is not None, "Auth0 row not found in demo capability table"
    assert m_corr.group(1) == "true", "Auth0 correlations should be true (M81F)"


def test_fe_rule_catalog_includes_every_auth0_rule_key():
    text = _read_fe("lib/securityRuleCatalog.ts")
    for key in EXPECTED_RULE_KEYS:
        assert f'key: "{key}"' in text, (
            f"frontend securityRuleCatalog missing rule key {key}"
        )


def test_fe_api_demo_provider_unions_include_auth0():
    """getIncidentDemoStatus / seedIncidentDemo / clearIncidentDemo unions all
    include auth0."""
    text = _read_fe("lib/api.ts")
    # Count occurrences of the auth0 union member
    assert text.count('"auth0"') >= 3, (
        f"expected >= 3 demo helper unions to include auth0; check api.ts"
    )


def test_fe_demo_script_mentions_auth0():
    """securityDemoScript talk-track includes Auth0."""
    text = _read_fe("lib/securityDemoScript.ts")
    assert "Auth0" in text


def test_fe_activity_page_sync_action_has_safe_copy():
    """Activity sync bar must not contain forbidden phrases."""
    text = _read_fe("app/(app)/security/activity/page.tsx")
    lower = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in lower, (
            f"activity page contains forbidden phrase {phrase!r}"
        )


def test_fe_signals_page_has_safe_copy():
    """Signals page must not contain forbidden phrases."""
    text = _read_fe("app/(app)/security/signals/page.tsx")
    lower = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in lower, (
            f"signals page contains forbidden phrase {phrase!r}"
        )


def test_fe_correlations_page_has_safe_copy():
    """Correlations page must not contain forbidden phrases."""
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    lower = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in lower, (
            f"correlations page contains forbidden phrase {phrase!r}"
        )


def test_fe_cases_page_auth0_card_has_safe_copy():
    """The Auth0 demo card copy must not contain forbidden phrases."""
    text = _read_fe("app/(app)/security/cases/page.tsx")
    lower = text.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in lower, (
            f"cases page contains forbidden phrase {phrase!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section H — Regression smoke (M81A–M81G still wire together)
# ════════════════════════════════════════════════════════════════════════════


def test_evaluator_dispatcher_handles_every_record_type_safely():
    """Every Auth0 record type round-trips through evaluate() without raising."""
    for rt in EXPECTED_RECORD_TYPES:
        rec = {"record_type": rt, "record_id": f"demo_{rt}"}
        out = auth0_eval(rec)
        assert isinstance(out, list)


def test_signal_service_handles_every_activity_event_type():
    """Every activity event type is handled by _build_signal (returns signal or None)."""
    for event_type in EXPECTED_ACTIVITY_EVENT_TYPES:
        ev = MagicMock()
        ev.id = uuid.uuid4()
        ev.event_type = event_type
        ev.provider = "auth0"
        ev.source = "auth0_activity_event"
        ev.resource_type = "configuration"
        ev.resource_id = "AUTH0_DEMO_RESOURCE"
        ev.provider_event_id = f"demo-{event_type}"
        ev.integration_id = uuid.uuid4()
        ev.occurred_at = datetime.now(timezone.utc)
        ev.ingested_at = ev.occurred_at
        ev.created_at = ev.occurred_at
        ev.event_metadata = {"resource_type": "configuration"}
        result = auth0_sig._build_signal([ev])
        # A valid event type must produce a signal.
        if event_type in auth0_sig.AUTH0_EVENT_TYPE_TO_SIGNAL_TYPE:
            assert result is not None, (
                f"_build_signal returned None for valid event type {event_type!r}"
            )


def test_correlation_rules_have_required_shape_fields():
    """Every AUTH0_CORRELATION_RULES entry carries required structure fields."""
    required = {"rule_keys", "signal_types", "match_key", "severity",
                "title_phrase", "subject_phrase"}
    for ctype, rule in auth0_corr.AUTH0_CORRELATION_RULES.items():
        missing = required - set(rule.keys())
        assert missing == set(), (
            f"AUTH0_CORRELATION_RULES[{ctype!r}] missing fields: {missing}"
        )
        assert isinstance(rule["rule_keys"], (set, frozenset)), (
            f"{ctype}: rule_keys must be a set"
        )
        assert isinstance(rule["signal_types"], (set, frozenset)), (
            f"{ctype}: signal_types must be a set"
        )


def test_correlation_eight_families_cover_all_match_keys():
    """AUTH0_CORRELATION_RULES must cover exactly the 8 expected match_key families."""
    match_keys = {v["match_key"] for v in auth0_corr.AUTH0_CORRELATION_RULES.values()}
    expected = {
        "tenant", "application", "connection", "resource_server",
        "rule", "action", "mfa_factor", "custom_domain",
    }
    assert match_keys == expected


def test_auth0_ingestion_never_raises_on_bad_event():
    """normalize_auth0_activity_event must return None for malformed entries."""
    assert auth0_ingest.normalize_auth0_activity_event(None) is None
    assert auth0_ingest.normalize_auth0_activity_event({}) is None
    assert auth0_ingest.normalize_auth0_activity_event(
        {"event_type": ""}
    ) is None
    assert auth0_ingest.normalize_auth0_activity_event(
        {"provider_event_id": "x"}
    ) is None


def test_ingestion_blocks_login_and_user_events():
    """Login, auth, session, token, and user-profile event types NEVER pass the gate.

    Auth0 Management API logs include user_id, email, IP, and device data.
    ConfigTrace only ingests config-state events synthesized from safe drift
    surfaces; login/auth/session/token/user-profile/org-member events are
    permanently excluded.
    """
    blocked_event_types = (
        # Login / authentication / MFA
        "login.success", "s", "f", "fepft",
        "mfa.enrollment_start", "mfa.success",
        "gd_start_enroll", "gd_auth_success",
        # Session / token exchange
        "sercft", "token.exchange",
        "user.create", "user.update", "user.delete",
        # Password management
        "user.password_reset", "pwd_reset",
        # Organization member
        "org.member.added", "org.member_invitation.create",
        # Raw Auth0 log event codes (user-centric)
        "cls", "csa",  # change_email / change_phone (login type)
        # Any non-config, non-auth0.x event type
        "sendgrid.api_key.updated",   # wrong provider
        "aws.s3.data.get_object",
    )
    for ev_type in blocked_event_types:
        result = auth0_ingest.normalize_auth0_activity_event(
            {"event_type": ev_type}
        )
        assert result is None, (
            f"login/user event {ev_type!r} must not pass the ingestion gate"
        )


def test_match_strength_returns_high_for_exact_match():
    """_match_strength must return 'high' for exact-ID match reasons."""
    assert auth0_corr._match_strength("client_id_match") == "high"
    assert auth0_corr._match_strength("connection_id_match") == "high"
    assert auth0_corr._match_strength("resource_server_id_match") == "high"
    assert auth0_corr._match_strength("rule_id_match") == "high"
    assert auth0_corr._match_strength("action_id_match") == "high"
    assert auth0_corr._match_strength("factor_name_match") == "high"
    assert auth0_corr._match_strength("custom_domain_id_match") == "high"


def test_match_strength_returns_medium_for_family_aggregate():
    """_match_strength must return 'medium' for family-aggregate match reasons."""
    assert auth0_corr._match_strength("tenant_level") == "medium"
    assert auth0_corr._match_strength("application_family") == "medium"
    assert auth0_corr._match_strength("connection_family") == "medium"
    assert auth0_corr._match_strength("resource_server_family") == "medium"
    assert auth0_corr._match_strength("rule_family") == "medium"
    assert auth0_corr._match_strength("action_family") == "medium"
    assert auth0_corr._match_strength("mfa_factor_family") == "medium"
    assert auth0_corr._match_strength("custom_domain_family") == "medium"


def test_expansion_framework_auth0_arc_not_abandoned():
    """After M81H, the planned stage must still be within the Auth0 arc or beyond."""
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    # M81I or M82x are both acceptable — Auth0 arc should not be skipped.
    assert (
        "M81I" in planned
        or "M82" in planned
        or "Auth0" in planned
    ), (
        f"After M81H, planned_next_stage should be M81I or M82/beyond; got: {planned!r}"
    )
