"""M80H — SendGrid provider-depth QA guardrails.

Durable, deterministic guardrails that prove the whole SendGrid arc
(M80A–M80G) stays internally consistent.  This file adds NO product code —
it pins taxonomy parity, privacy / sanitization discipline, false-positive
behavior, demo isolation, and router admin / member guards.

Sections:

  A. Taxonomy parity
     Record types ↔ rule keys ↔ activity event types ↔ signal types ↔
     correlation rule keys ↔ correlation activity types.

  B. Privacy guardrails
     SendGrid-shaped denylist applied to every SendGrid source file we own
     (connector, ingestion, signal, correlation, demo); also asserted on a
     live in-memory pipeline (_build_signal → _build_correlation →
     seed/clear case-report blobs).

  C. Claim discipline
     Forbidden-phrase scan over every SendGrid production module and the demo
     fixtures.

  D. False-positive behavior
     End-to-end "should NOT fire" cases: API key with narrow scopes, sender
     identity verified, domain auth valid + automatic security enabled,
     all mail/tracking/webhook settings safe, suppression non-empty,
     cross-family correlation mismatch, generic config event, unknown record.

  E. Demo isolation
     Seed-twice / clear-twice idempotency; clear_sendgrid leaves every other
     provider demo intact and never touches a real SendGrid integration.

  F. Router/API guards
     SendGrid activity sync / signal-generate / correlation-generate /
     incident demo seed-clear require admin; read-only endpoints stay
     member-accessible.

  G. Frontend SendGrid consistency (skip if frontend tree absent)
     Provider selectors / type filter dropdowns / rule catalog / demo card
     / api unions / demo-script copy all carry SendGrid entries.

  H. Regression smoke
     Evaluator dispatch + allowlists + correlation rule shape pinned so the
     future M80I polish cannot drift them silently.
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

from app.connectors import sendgrid as sendgrid_conn
from app.connectors.sendgrid_schema import (
    SENDGRID_ACCOUNT,
    SENDGRID_API_KEY,
    SENDGRID_DOMAIN_AUTHENTICATION,
    SENDGRID_MAIL_SETTINGS,
    SENDGRID_RECORD_TYPES,
    SENDGRID_SENDER_IDENTITY,
    SENDGRID_SUPPRESSION_SETTINGS,
    SENDGRID_TRACKING_SETTINGS,
    SENDGRID_WEBHOOK_SETTINGS,
)
from app.services import sendgrid_activity_ingestion_service as sendgrid_ingest
from app.services import sendgrid_activity_signal_service as sendgrid_sig
from app.services import sendgrid_risk_activity_correlation_service as sendgrid_corr
from app.services import security_case_report_service as report_svc
from app.services import security_incident_demo_service as demo_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services.provider_capability_matrix_service import (
    get_provider_capability,
)
from app.services.provider_expansion_framework import get_framework
from app.services.security_activity_event_service import (
    ALLOWED_METADATA_KEYS as ACTIVITY_ALLOWED,
)
from app.services.security_coverage_service import (
    PROVIDER_SURFACES, PROVIDERS as COVERAGE_PROVIDERS, RULE_RECORD_TYPES,
)
from app.services.security_incident_signal_service import (
    ALLOWED_METADATA_KEYS as SIGNAL_ALLOWED,
)
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules.sendgrid import (
    SENDGRID_RULE_KEYS, evaluate as sendgrid_eval,
)


# ════════════════════════════════════════════════════════════════════════════
# Fixed expected sets — the M80H baseline.
# Drift here triggers an intentional update of this file (with a note in the
# commit message explaining the change).
# ════════════════════════════════════════════════════════════════════════════

EXPECTED_RECORD_TYPES = {
    "sendgrid_account",
    "sendgrid_api_key",
    "sendgrid_sender_identity",
    "sendgrid_domain_authentication",
    "sendgrid_mail_settings",
    "sendgrid_tracking_settings",
    "sendgrid_webhook_settings",
    "sendgrid_suppression_settings",
}

EXPECTED_RULE_KEYS = {
    # M80B core rules (15)
    "sendgrid_api_key_broad_scopes",
    "sendgrid_sender_identity_unverified",
    "sendgrid_sender_identity_locked",
    "sendgrid_domain_authentication_invalid",
    "sendgrid_domain_automatic_security_disabled",
    "sendgrid_domain_authentication_legacy",
    "sendgrid_spam_check_disabled",
    "sendgrid_sandbox_mode_enabled",
    "sendgrid_bcc_enabled",
    "sendgrid_click_tracking_enabled",
    "sendgrid_open_tracking_enabled",
    "sendgrid_subscription_tracking_disabled",
    "sendgrid_event_webhook_disabled",
    "sendgrid_event_webhook_url_missing",
    "sendgrid_suppression_settings_empty",
    # M80C expansion rules (11)
    "sendgrid_sender_identity_reply_domain_mismatch",
    "sendgrid_domain_dns_records_missing",
    "sendgrid_default_domain_authentication_invalid",
    "sendgrid_footer_disabled",
    "sendgrid_bounce_purge_disabled",
    "sendgrid_template_engine_enabled",
    "sendgrid_google_analytics_tracking_enabled",
    "sendgrid_event_webhook_broad_event_stream",
    "sendgrid_inbound_parse_enabled",
    "sendgrid_inbound_parse_raw_email_enabled",
    "sendgrid_inbound_parse_spam_check_disabled",
}

# Canonical activity event types produced by the ingestion pipeline (17 total,
# including the synthetic sendgrid.config.event fallback).
EXPECTED_ACTIVITY_EVENT_TYPES = {
    "sendgrid.account.updated",
    "sendgrid.api_key.created",
    "sendgrid.api_key.updated",
    "sendgrid.api_key.deleted",
    "sendgrid.sender_identity.created",
    "sendgrid.sender_identity.updated",
    "sendgrid.sender_identity.verified",
    "sendgrid.sender_identity.deleted",
    "sendgrid.domain_authentication.created",
    "sendgrid.domain_authentication.updated",
    "sendgrid.domain_authentication.deleted",
    "sendgrid.mail_settings.updated",
    "sendgrid.tracking_settings.updated",
    "sendgrid.event_webhook.updated",
    "sendgrid.inbound_parse.updated",
    "sendgrid.suppression_settings.updated",
    "sendgrid.config.event",
}

EXPECTED_SIGNAL_TYPES = {
    "sendgrid_account_config_changed",
    "sendgrid_api_key_config_changed",
    "sendgrid_sender_identity_config_changed",
    "sendgrid_domain_authentication_config_changed",
    "sendgrid_mail_settings_config_changed",
    "sendgrid_tracking_settings_config_changed",
    "sendgrid_event_webhook_config_changed",
    "sendgrid_inbound_parse_config_changed",
    "sendgrid_suppression_settings_config_changed",
    "sendgrid_config_activity",
}

EXPECTED_CORRELATION_TYPES = {
    "sendgrid_api_key_risk_activity_correlation",
    "sendgrid_sender_identity_risk_activity_correlation",
    "sendgrid_domain_authentication_risk_activity_correlation",
    "sendgrid_mail_settings_risk_activity_correlation",
    "sendgrid_tracking_settings_risk_activity_correlation",
    "sendgrid_webhook_risk_activity_correlation",
    "sendgrid_suppression_settings_risk_activity_correlation",
}

# ── Forbidden claim wording (M75A pin) ───────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# ── SendGrid-shaped privacy denylist (M80H) ───────────────────────────────────
# Substrings that MUST NOT appear (case-insensitive) as quoted JSON keys in
# any SendGrid production blob we generate.  Written as `"key":` so we catch
# dict serialisation but not narrative text.
SENDGRID_FORBIDDEN_METADATA_KEYS = (
    # Credentials / tokens
    "api_key_value", "api_key_secret", "key_value", "key_secret",
    "authorization", "bearer", "access_token", "auth_header",
    # Email content
    "email_body", "email_subject", "subject", "body", "message_body",
    "email_content",
    # Email addresses
    "to_email", "from_email", "recipient_email", "sender_email",
    "reply_to", "bcc_email", "suppression_email", "from_address",
    # Template content
    "template_html", "template_body", "template_plaintext", "template_content",
    # Raw URLs (webhook / inbound parse stored as booleans only)
    "webhook_url", "inbound_parse_url", "inbound_parse_hostname",
    "unsubscribe_url", "click_url",
    # Raw DNS record values (only count is stored)
    "dns_record_value", "dkim_value", "cname_value", "spf_value",
    # Raw payloads
    "raw_payload", "request_body", "response_body", "raw_request",
    "raw_response", "raw_event",
    # Customer data / PII
    "customer_data", "user_data", "contact_data", "marketing_data",
    # Other sensitive
    "message_id", "smtp_id", "ip_address", "user_agent",
)

# Shape-only substrings that must never appear as raw values.
SENDGRID_FORBIDDEN_VALUE_PATTERNS = (
    "SG.",               # SendGrid API key prefix
    "begin private key",  # PEM header
    "begin rsa private",
)


# ════════════════════════════════════════════════════════════════════════════
# Section A — Taxonomy parity
# ════════════════════════════════════════════════════════════════════════════


def test_record_types_match_expected():
    assert set(SENDGRID_RECORD_TYPES) == EXPECTED_RECORD_TYPES


def test_record_type_constants_are_canonical_lowercase():
    """Each schema constant uses the canonical lowercase value."""
    pairs = (
        ("SENDGRID_ACCOUNT", SENDGRID_ACCOUNT),
        ("SENDGRID_API_KEY", SENDGRID_API_KEY),
        ("SENDGRID_SENDER_IDENTITY", SENDGRID_SENDER_IDENTITY),
        ("SENDGRID_DOMAIN_AUTHENTICATION", SENDGRID_DOMAIN_AUTHENTICATION),
        ("SENDGRID_MAIL_SETTINGS", SENDGRID_MAIL_SETTINGS),
        ("SENDGRID_TRACKING_SETTINGS", SENDGRID_TRACKING_SETTINGS),
        ("SENDGRID_WEBHOOK_SETTINGS", SENDGRID_WEBHOOK_SETTINGS),
        ("SENDGRID_SUPPRESSION_SETTINGS", SENDGRID_SUPPRESSION_SETTINGS),
    )
    for name, val in pairs:
        assert val == name.lower(), (
            f"{name} value ({val!r}) must be its lowercased name "
            f"({name.lower()!r}); evaluator dispatch keys on this."
        )


def test_rule_keys_match_expected():
    assert set(SENDGRID_RULE_KEYS) == EXPECTED_RULE_KEYS


def test_rule_registry_parity_for_sendgrid_keys():
    in_registry = {k for k in KNOWN_RULE_KEYS if k.startswith("sendgrid_")}
    assert in_registry == EXPECTED_RULE_KEYS

    in_confidence = {k for k in RULE_CONFIDENCE if k.startswith("sendgrid_")}
    assert in_confidence == EXPECTED_RULE_KEYS

    in_pack = {k for k, v in _RULE_META.items() if v[0] == "sendgrid"}
    assert in_pack == EXPECTED_RULE_KEYS

    in_coverage = {k for k in RULE_RECORD_TYPES if k.startswith("sendgrid_")}
    assert in_coverage == EXPECTED_RULE_KEYS


def test_sendgrid_in_coverage_providers_and_surfaces():
    assert "sendgrid" in COVERAGE_PROVIDERS
    surfaces = PROVIDER_SURFACES["sendgrid"]
    for s in surfaces:
        assert isinstance(s, str) and s.strip()


def test_activity_event_type_map_matches_expected():
    """SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE covers every expected activity event type."""
    types = set(sendgrid_sig.SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE)
    assert types == EXPECTED_ACTIVITY_EVENT_TYPES


def test_signal_types_match_expected():
    types = set(sendgrid_sig.SENDGRID_SIGNAL_TYPES)
    assert types == EXPECTED_SIGNAL_TYPES


def test_signal_types_derived_from_event_type_map():
    """SENDGRID_SIGNAL_TYPES is exactly the values of SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE."""
    from_map = set(sendgrid_sig.SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE.values())
    assert from_map == set(sendgrid_sig.SENDGRID_SIGNAL_TYPES)


def test_correlation_types_match_expected():
    types = set(sendgrid_corr.SENDGRID_CORRELATION_TYPES)
    assert types == EXPECTED_CORRELATION_TYPES


def test_correlation_rules_cover_all_26_sendgrid_rule_keys():
    """Every SendGrid rule key must appear in at least one SENDGRID_CORRELATION_RULES entry."""
    all_rule_keys: set[str] = set()
    for rule in sendgrid_corr.SENDGRID_CORRELATION_RULES.values():
        all_rule_keys.update(rule["rule_keys"])
    assert all_rule_keys == EXPECTED_RULE_KEYS, (
        f"Rule key parity error. Missing: {EXPECTED_RULE_KEYS - all_rule_keys}; "
        f"Extra: {all_rule_keys - EXPECTED_RULE_KEYS}"
    )


def test_correlation_activity_types_are_subset_of_signal_types():
    """Correlation signal_types must only reference types the signal service handles."""
    referenced: set[str] = set()
    for rule in sendgrid_corr.SENDGRID_CORRELATION_RULES.values():
        referenced.update(rule["signal_types"])
    not_in_signal = referenced - EXPECTED_SIGNAL_TYPES
    assert not_in_signal == set(), (
        f"correlation references signal types not in EXPECTED_SIGNAL_TYPES: "
        f"{sorted(not_in_signal)}"
    )


def test_ingestion_provider_and_source_constants():
    """Ingestion service must tag events provider=sendgrid, source=sendgrid_activity_event."""
    assert sendgrid_ingest.PROVIDER == "sendgrid"
    assert sendgrid_ingest.SOURCE == "sendgrid_activity_event"
    assert sendgrid_ingest.EVENT_SOURCE == "sendgrid_activity_event"


def test_capability_matrix_pins_sendgrid_partial_demo_ready():
    cap = get_provider_capability("sendgrid")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    # evidence_timeline and evidence_graph intentionally deferred for SendGrid.
    assert cap.security.evidence_timeline is False
    assert cap.security.evidence_graph is False
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True
    assert cap.maturity == "partial"
    # M80H must be reflected in the capability notes after this milestone.
    notes = (cap.notes or "")
    assert "M80H" in notes, (
        f"Capability notes must mention M80H after provider-depth QA; got: {notes[:200]}"
    )


def test_expansion_framework_points_to_m80i():
    """M80H complete — planned_next_stage must advance past M80H (to M80I or beyond)."""
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert "M80H" not in planned, (
        f"M80H is done; pointer must advance past it (got: {planned!r})"
    )
    # After M80I completes, the pointer advances to M81A — either is acceptable here.
    assert (
        "M80I" in planned or "M81A" in planned or "M81B" in planned
    ), (
        f"planned_next_stage must point past M80H; got: {planned!r}"
    )


def test_sendgrid_not_in_canonical_eight_provider_matrix():
    """SendGrid stays in PROVIDER_CAPABILITIES_PARTIAL — never in the canonical 8."""
    from app.services.provider_capability_matrix_service import (
        PROVIDER_CAPABILITIES, PROVIDER_CAPABILITIES_PARTIAL,
    )
    canonical = {p.provider for p in PROVIDER_CAPABILITIES}
    partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
    assert "sendgrid" not in canonical
    assert "sendgrid" in partial


# ════════════════════════════════════════════════════════════════════════════
# Section B — Privacy guardrails (allowlist + denylist)
# ════════════════════════════════════════════════════════════════════════════


# M80D activity-event metadata keys (representative subset the ingester writes).
_SENDGRID_ACTIVITY_SAFE_KEYS = {
    "sendgrid_event_id",          # stable synthetic event identifier
    "resource_id",                # resource identifier
    "resource_type",              # config surface type
    "api_key_id",                 # API key opaque ID (never key value)
    "sender_id",                  # sender identity opaque ID (never email)
    "domain_id",                  # domain auth opaque ID (never DNS values)
    "event_webhook_enabled",      # bool — webhook delivery active
    "inbound_parse_enabled",      # bool — inbound parse enabled
    "suppression_group_count",    # int — ASM group count (never recipient emails)
    "event_source",               # source tag
}

# M80E signal-metadata subset.
_SENDGRID_SIGNAL_SAFE_KEYS = {
    "source",
    "event_types",
    "event_count",
    "resource_type",
    "api_key_id",
    "sender_id",
    "event_webhook_enabled",
    "event_webhook_has_url",
    "inbound_parse_enabled",
    "suppression_group_count",
    "window_start",
    "window_end",
}

# M80F correlation-metadata subset.
_SENDGRID_CORRELATION_SAFE_KEYS = {
    "api_key_id",
    "sender_id",
    "match_reason",
    "match_strength",
    "rule_key",
    "signal_type",
}


def test_activity_allowlist_contains_all_sendgrid_safe_keys():
    """Every key the M80D ingester writes must be in the activity allowlist."""
    missing = _SENDGRID_ACTIVITY_SAFE_KEYS - ACTIVITY_ALLOWED
    assert missing == set(), (
        f"M80D safe keys missing from activity allowlist: {missing}"
    )


def test_signal_allowlist_contains_all_sendgrid_safe_keys():
    """Every SendGrid-safe key the M80E signal builder emits must be allowlisted."""
    missing = _SENDGRID_SIGNAL_SAFE_KEYS - SIGNAL_ALLOWED
    assert missing == set(), (
        f"M80E safe keys missing from signal allowlist: {missing}"
    )


def test_correlation_allowlist_contains_all_sendgrid_safe_keys():
    core_keys = {
        "api_key_id", "sender_id", "domain_id",
        "match_reason", "match_strength",
        "rule_key", "signal_type",
    }
    missing = core_keys - corr_svc.ALLOWED_METADATA_KEYS
    assert missing == set(), (
        f"M80F safe keys missing from correlation allowlist: {missing}"
    )


def test_case_report_preview_allowlist_includes_sendgrid_safe_keys():
    """M80H expansion of the case-report preview allowlist covers SendGrid keys."""
    expected = {
        "api_key_id", "sender_id", "domain_id", "suppression_group_count",
    }
    missing = expected - report_svc._PREVIEW_ALLOWLIST
    assert missing == set(), (
        f"case-report preview allowlist missing SendGrid-safe keys: {missing}"
    )


# ── Denylist helpers ──────────────────────────────────────────────────────────


def _denylist_assert(blob: str, *, where: str) -> None:
    lower = blob.lower()
    for bad in SENDGRID_FORBIDDEN_METADATA_KEYS:
        assert f'"{bad}":' not in lower, (
            f"{where}: forbidden quoted key {bad!r} present"
        )
    for bad in SENDGRID_FORBIDDEN_VALUE_PATTERNS:
        assert bad not in lower, (
            f"{where}: forbidden substring {bad!r} present"
        )


def _build_polluted_signal() -> dict:
    """Build a signal from an event polluted with SendGrid-private fields.

    sanitize_signal_metadata() must drop every forbidden key before persisting.
    """
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "sendgrid.api_key.updated"
    ev.provider = "sendgrid"
    ev.source = "sendgrid_activity_event"
    ev.resource_id = "SENDGRID_DEMO_API_KEY_ID"
    ev.resource_type = "api_key"
    ev.provider_event_id = "demo-sendgrid-evt-1"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {
        # Safe keys (must survive):
        "api_key_id": "SENDGRID_DEMO_API_KEY_ID",
        "resource_type": "api_key",
        # Forbidden pollution that MUST be dropped:
        "api_key_value": "FAKE_API_KEY_VALUE",
        "api_key_secret": "FAKE_API_KEY_SECRET",
        "authorization": "Bearer FAKE_TOKEN",
        "bearer": "FAKE_BEARER",
        "email_body": "Hello from customer",
        "email_subject": "Fake subject line",
        "to_email": "customer@example.com",
        "from_email": "sender@example.com",
        "template_html": "<html>fake template</html>",
        "webhook_url": "https://example.com/webhook",
        "inbound_parse_hostname": "parse.example.com",
        "raw_payload": '{"api_key": "FAKE_KEY"}',
        "customer_data": "pii here",
        "ip_address": "1.2.3.4",
        "user_agent": "SendGrid-Test/1.0",
    }
    sig = sendgrid_sig._build_signal([ev])
    assert sig is not None
    return sig


def test_signal_metadata_drops_every_polluted_key():
    sig = _build_polluted_signal()
    meta = sig["metadata"]
    # Safe metadata survives.
    assert meta.get("api_key_id") == "SENDGRID_DEMO_API_KEY_ID"
    assert meta.get("resource_type") == "api_key"
    # Forbidden keys dropped.
    for bad in (
        "api_key_value", "api_key_secret", "authorization", "bearer",
        "email_body", "email_subject", "to_email", "from_email",
        "template_html", "webhook_url", "inbound_parse_hostname",
        "raw_payload", "customer_data", "ip_address", "user_agent",
    ):
        assert bad not in meta, (
            f"forbidden key {bad!r} survived in signal metadata"
        )
    # Private values never appear in any serialisable surface of the signal.
    blob = json.dumps({
        "metadata": meta, "title": sig["title"], "summary": sig["summary"],
    })
    for value in (
        "FAKE_API_KEY_VALUE", "FAKE_API_KEY_SECRET", "FAKE_BEARER",
        "FAKE_TOKEN", "Hello from customer", "Fake subject line",
        "customer@example.com", "<html>fake template</html>",
        "parse.example.com", "pii here",
    ):
        assert value not in blob, f"private value {value!r} in signal blob"


def _make_finding_mock(rule_key: str, **evidence) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.finding_key = f"{rule_key}:SENDGRID_DEMO_API_KEY_ID"
    f.severity = "high"
    f.title = "Demo SendGrid finding"
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
    sig.provider = "sendgrid"
    sig.source = "sendgrid_activity_event"
    sig.signal_metadata = metadata
    sig.severity = "medium"
    sig.first_seen_at = datetime.now(timezone.utc)
    sig.last_seen_at = datetime.now(timezone.utc)
    sig.linked_activity_event_id = uuid.uuid4()
    return sig


def test_correlation_metadata_drops_every_polluted_key():
    """_build_correlation sanitizes forbidden keys from both finding and signal."""
    finding = _make_finding_mock(
        "sendgrid_api_key_broad_scopes",
        api_key_id="SENDGRID_DEMO_API_KEY_ID",
        # Forbidden pollution on the finding side:
        api_key_value="FAKE_API_KEY_VALUE",
        authorization="Bearer FAKE_TOKEN",
        email_body="Hello customer",
        webhook_url="https://example.com/webhook",
        customer_data="pii here",
    )
    signal = _make_signal_mock(
        "sendgrid_api_key_config_changed",
        {
            "api_key_id": "SENDGRID_DEMO_API_KEY_ID",
            "resource_type": "api_key",
            "event_types": "sendgrid.api_key.updated",
            # Forbidden pollution on the signal side:
            "api_key_secret": "FAKE_API_KEY_SECRET",
            "email_body": "Hello from demo",
            "to_email": "customer@example.com",
            "template_html": "<html>fake</html>",
            "inbound_parse_hostname": "parse.example.com",
            "raw_payload": '{"api_key": "SG.FAKE"}',
            "ip_address": "9.9.9.9",
        },
    )
    rule = sendgrid_corr.SENDGRID_CORRELATION_RULES[
        "sendgrid_api_key_risk_activity_correlation"
    ]
    c = sendgrid_corr._build_correlation(
        finding=finding, signal=signal,
        correlation_type="sendgrid_api_key_risk_activity_correlation",
        rule=rule,
        match_reason="api_key_id_match",
    )
    blob = json.dumps({
        "metadata": c["metadata"], "title": c["title"], "summary": c["summary"],
    })
    _denylist_assert(blob, where="correlation built from polluted finding+signal")
    # Safe key survives or is absent — never the raw API key value.
    assert "FAKE_API_KEY_VALUE" not in blob
    assert "FAKE_API_KEY_SECRET" not in blob
    assert "SG.FAKE" not in blob


def test_sendgrid_demo_case_artifacts_pass_denylist(test_user, db_session):
    """The SendGrid demo seed/report stay denylist-clean."""
    from app.services import workspace_service
    ws = workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M80H demo", db=db_session,
    )
    try:
        seed = demo_svc.seed_sendgrid(
            workspace_id=ws.id, actor_user_id=test_user.id, db=db_session,
        )
        case_id = uuid.UUID(seed["case_id"])
        from app.models.security_case import SecurityCase
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(report, default=str)
        _denylist_assert(blob, where="sendgrid demo report")
        # No SendGrid API-key-shaped strings.
        assert not re.search(
            r'SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', blob
        ), "SG.xxx-shaped API key found in demo case blobs"
        # No real-looking email addresses in any field.
        assert not re.search(r'[a-z]+@[a-z]+\.[a-z]{2,}', blob), (
            "email address found in demo case blobs"
        )
    finally:
        demo_svc.clear_sendgrid(workspace_id=ws.id, db=db_session)


# ════════════════════════════════════════════════════════════════════════════
# Section C — Claim discipline (forbidden phrases on SendGrid modules)
# ════════════════════════════════════════════════════════════════════════════


_SENDGRID_MODULES = [
    sendgrid_conn, sendgrid_ingest, sendgrid_sig, demo_svc,
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


@pytest.mark.parametrize("module", _SENDGRID_MODULES)
def test_sendgrid_modules_have_no_forbidden_claims(module):
    src = inspect.getsource(module)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in {module.__name__} "
            f"outside a negation context"
        )


def test_sendgrid_security_rules_module_has_no_forbidden_claims():
    """The security_rules.sendgrid module ships claim-discipline copy."""
    from app.services.security_rules import sendgrid as sendgrid_rules
    src = inspect.getsource(sendgrid_rules)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in security_rules.sendgrid"
        )


def test_sendgrid_correlation_module_has_no_forbidden_claims():
    """The SendGrid risk×activity correlation module is claim-discipline clean."""
    src = inspect.getsource(sendgrid_corr)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in sendgrid_risk_activity_correlation_service"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section D — False-positive behavior pins
# ════════════════════════════════════════════════════════════════════════════


def _api_key_record(**kwargs) -> dict:
    base = {
        "record_type": SENDGRID_API_KEY,
        "record_id": "SENDGRID_DEMO_API_KEY_ID",
        "provider_resource_id": "api_keys/SENDGRID_DEMO_API_KEY_ID",
        "api_key_id": "SENDGRID_DEMO_API_KEY_ID",
        "name": "Demo Key",
        "scopes_count": 2,
        "has_mail_send": True,
        "has_full_access": False,
    }
    base.update(kwargs)
    return base


def _sender_record(**kwargs) -> dict:
    base = {
        "record_type": SENDGRID_SENDER_IDENTITY,
        "record_id": "SENDGRID_DEMO_SENDER_ID",
        "provider_resource_id": "verified_senders/SENDGRID_DEMO_SENDER_ID",
        "sender_id": "SENDGRID_DEMO_SENDER_ID",
        "nickname": "Demo Sender",
        "from_email_domain": "example.com",
        "reply_to_domain": "example.com",
        "verified": True,
        "locked": False,
    }
    base.update(kwargs)
    return base


def _domain_record(**kwargs) -> dict:
    base = {
        "record_type": SENDGRID_DOMAIN_AUTHENTICATION,
        "record_id": "SENDGRID_DEMO_DOMAIN_ID",
        "provider_resource_id": "whitelabel/domains/SENDGRID_DEMO_DOMAIN_ID",
        "domain_id": "SENDGRID_DEMO_DOMAIN_ID",
        "domain": "example.com",
        "valid": True,
        "automatic_security": True,
        "default": True,
        "legacy": False,
        "dns_record_count": 3,
    }
    base.update(kwargs)
    return base


def _mail_settings_record(**kwargs) -> dict:
    base = {
        "record_type": SENDGRID_MAIL_SETTINGS,
        "record_id": "sendgrid_mail_settings_main",
        "provider_resource_id": "mail_settings/main",
        "bcc_enabled": False,
        "bounce_purge_enabled": True,
        "footer_enabled": True,
        "forward_bounce_enabled": False,
        "forward_spam_enabled": False,
        "sandbox_mode_enabled": False,
        "spam_check_enabled": True,
        "template_enabled": False,
    }
    base.update(kwargs)
    return base


def _tracking_settings_record(**kwargs) -> dict:
    base = {
        "record_type": SENDGRID_TRACKING_SETTINGS,
        "record_id": "sendgrid_tracking_settings_main",
        "provider_resource_id": "tracking_settings/main",
        "click_tracking_enabled": False,
        "open_tracking_enabled": False,
        "subscription_tracking_enabled": True,
        "ganalytics_enabled": False,
    }
    base.update(kwargs)
    return base


def _webhook_settings_record(**kwargs) -> dict:
    base = {
        "record_type": SENDGRID_WEBHOOK_SETTINGS,
        "record_id": "sendgrid_webhook_settings_main",
        "provider_resource_id": "webhooks/event/settings/main",
        "event_webhook_enabled": True,
        "event_webhook_has_url": True,
        "event_webhook_signed": True,
        "event_count": 5,
        "inbound_parse_enabled": False,
        "inbound_parse_spam_check_enabled": True,
        "inbound_parse_send_raw_enabled": False,
    }
    base.update(kwargs)
    return base


def _suppression_record(**kwargs) -> dict:
    base = {
        "record_type": SENDGRID_SUPPRESSION_SETTINGS,
        "record_id": "sendgrid_suppression_settings_main",
        "provider_resource_id": "suppression_settings/main",
        "suppression_group_count": 3,
    }
    base.update(kwargs)
    return base


# ── False-positive: should NOT fire ──────────────────────────────────────────

def test_api_key_narrow_scopes_does_not_fire():
    """API key without full_access and low scope count → no broad_scopes finding."""
    rec = _api_key_record(has_full_access=False, has_mail_send=True, scopes_count=2)
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_api_key_broad_scopes" not in keys


def test_sender_identity_verified_not_locked_does_not_fire():
    """verified=True and locked=False → no unverified or locked findings."""
    rec = _sender_record(verified=True, locked=False)
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_sender_identity_unverified" not in keys
    assert "sendgrid_sender_identity_locked" not in keys


def test_domain_auth_valid_automatic_security_enabled_does_not_fire():
    """valid=True and automatic_security=True → no invalid or disabled findings."""
    rec = _domain_record(valid=True, automatic_security=True)
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_domain_authentication_invalid" not in keys
    assert "sendgrid_domain_automatic_security_disabled" not in keys


def test_mail_settings_spam_check_enabled_no_bcc_does_not_fire():
    """spam_check_enabled=True and bcc_enabled=False → no spam/bcc findings."""
    rec = _mail_settings_record(spam_check_enabled=True, bcc_enabled=False)
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_spam_check_disabled" not in keys
    assert "sendgrid_bcc_enabled" not in keys


def test_event_webhook_enabled_with_url_does_not_fire():
    """event_webhook_enabled=True and event_webhook_has_url=True → no webhook findings."""
    rec = _webhook_settings_record(
        event_webhook_enabled=True, event_webhook_has_url=True,
    )
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_event_webhook_disabled" not in keys
    assert "sendgrid_event_webhook_url_missing" not in keys


def test_suppression_group_nonzero_does_not_fire():
    """suppression_group_count > 0 → no suppression_settings_empty finding."""
    rec = _suppression_record(suppression_group_count=5)
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_suppression_settings_empty" not in keys


def test_unknown_record_type_returns_no_findings():
    """The SendGrid evaluator dispatch is closed — unknown types yield []."""
    assert sendgrid_eval({"record_type": "sendgrid_unknown_thing"}) == []
    assert sendgrid_eval({"record_type": ""}) == []
    assert sendgrid_eval({}) == []


# ── Positive: SHOULD fire ─────────────────────────────────────────────────────

def test_api_key_full_access_fires_broad_scopes():
    """has_full_access=True MUST trigger sendgrid_api_key_broad_scopes."""
    rec = _api_key_record(has_full_access=True, scopes_count=20)
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_api_key_broad_scopes" in keys, (
        "Expected sendgrid_api_key_broad_scopes to fire for a full-access API key"
    )


def test_sender_identity_unverified_fires():
    """verified=False MUST trigger sendgrid_sender_identity_unverified."""
    rec = _sender_record(verified=False)
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_sender_identity_unverified" in keys


def test_domain_auth_invalid_fires():
    """valid=False MUST trigger sendgrid_domain_authentication_invalid."""
    rec = _domain_record(valid=False)
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_domain_authentication_invalid" in keys


def test_mail_settings_spam_check_disabled_fires():
    """spam_check_enabled=False MUST trigger sendgrid_spam_check_disabled."""
    rec = _mail_settings_record(spam_check_enabled=False)
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_spam_check_disabled" in keys


def test_event_webhook_disabled_fires():
    """event_webhook_enabled=False MUST trigger sendgrid_event_webhook_disabled."""
    rec = _webhook_settings_record(event_webhook_enabled=False)
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_event_webhook_disabled" in keys


def test_suppression_settings_empty_fires():
    """suppression_group_count=0 MUST trigger sendgrid_suppression_settings_empty."""
    rec = _suppression_record(suppression_group_count=0)
    keys = {f.rule_key for f in sendgrid_eval(rec)}
    assert "sendgrid_suppression_settings_empty" in keys


# ── Correlation false-positive / positive ────────────────────────────────────

def test_different_api_key_ids_do_not_correlate():
    """Mismatched api_key_id on both sides → no correlation match."""
    finding = _make_finding_mock(
        "sendgrid_api_key_broad_scopes",
        api_key_id="SENDGRID_KEY_ID_A",
    )
    signal = _make_signal_mock(
        "sendgrid_api_key_config_changed",
        {"api_key_id": "SENDGRID_KEY_ID_B"},
    )
    result = sendgrid_corr._match_pair(finding, signal, "api_key")
    assert result is None, (
        "Different api_key_id must not produce a correlation"
    )


def test_same_api_key_id_produces_exact_match():
    """Matching api_key_id on both sides → api_key_id_match reason."""
    finding = _make_finding_mock(
        "sendgrid_api_key_broad_scopes",
        api_key_id="SENDGRID_DEMO_API_KEY_ID",
    )
    signal = _make_signal_mock(
        "sendgrid_api_key_config_changed",
        {"api_key_id": "SENDGRID_DEMO_API_KEY_ID"},
    )
    result = sendgrid_corr._match_pair(finding, signal, "api_key")
    assert result == "api_key_id_match"


def test_missing_api_key_id_produces_family_level_match():
    """When neither side has api_key_id, family-level match is returned."""
    finding = _make_finding_mock("sendgrid_api_key_broad_scopes")
    signal = _make_signal_mock("sendgrid_api_key_config_changed", {})
    result = sendgrid_corr._match_pair(finding, signal, "api_key")
    assert result == "api_key_family"


def test_different_sender_ids_do_not_correlate():
    """Mismatched sender_id → no correlation match."""
    finding = _make_finding_mock(
        "sendgrid_sender_identity_unverified",
        sender_id="SENDGRID_SENDER_A",
    )
    signal = _make_signal_mock(
        "sendgrid_sender_identity_config_changed",
        {"sender_id": "SENDGRID_SENDER_B"},
    )
    result = sendgrid_corr._match_pair(finding, signal, "sender_identity")
    assert result is None, (
        "Different sender_id must not produce a correlation"
    )


def test_same_sender_id_produces_exact_match():
    """Matching sender_id on both sides → sender_id_match reason."""
    finding = _make_finding_mock(
        "sendgrid_sender_identity_unverified",
        sender_id="SENDGRID_DEMO_SENDER_ID",
    )
    signal = _make_signal_mock(
        "sendgrid_sender_identity_config_changed",
        {"sender_id": "SENDGRID_DEMO_SENDER_ID"},
    )
    result = sendgrid_corr._match_pair(finding, signal, "sender_identity")
    assert result == "sender_id_match"


def test_different_domain_ids_do_not_correlate():
    """Mismatched domain_id → no correlation match."""
    finding = _make_finding_mock(
        "sendgrid_domain_authentication_invalid",
        domain_id="SENDGRID_DOMAIN_A",
    )
    signal = _make_signal_mock(
        "sendgrid_domain_authentication_config_changed",
        {"domain_id": "SENDGRID_DOMAIN_B"},
    )
    result = sendgrid_corr._match_pair(finding, signal, "domain_authentication")
    assert result is None


def test_same_domain_id_produces_exact_match():
    """Matching domain_id on both sides → domain_id_match reason."""
    finding = _make_finding_mock(
        "sendgrid_domain_authentication_invalid",
        domain_id="SENDGRID_DEMO_DOMAIN_ID",
    )
    signal = _make_signal_mock(
        "sendgrid_domain_authentication_config_changed",
        {"domain_id": "SENDGRID_DEMO_DOMAIN_ID"},
    )
    result = sendgrid_corr._match_pair(finding, signal, "domain_authentication")
    assert result == "domain_id_match"


def test_account_level_families_always_match():
    """mail_settings / tracking_settings / webhook / suppression_settings always
    produce a family-level match regardless of metadata content."""
    finding = _make_finding_mock("sendgrid_spam_check_disabled")
    signal = _make_signal_mock("sendgrid_mail_settings_config_changed", {})
    for family in ("mail_settings", "tracking_settings", "webhook", "suppression_settings"):
        result = sendgrid_corr._match_pair(finding, signal, family)
        assert result is not None, (
            f"account-level family {family!r} must always produce a match"
        )
        assert result.endswith("_family"), (
            f"account-level family match reason must end in '_family'; got {result!r}"
        )


def test_generic_config_event_maps_to_config_activity_low_severity():
    """sendgrid.config.event maps to sendgrid_config_activity — low severity."""
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "sendgrid.config.event"
    ev.provider = "sendgrid"
    ev.source = "sendgrid_activity_event"
    ev.resource_type = "configuration"
    ev.resource_id = None
    ev.provider_event_id = "demo-cfg-1"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {"resource_type": "configuration"}
    sig = sendgrid_sig._build_signal([ev])
    assert sig is not None
    assert sig["signal_type"] == "sendgrid_config_activity"
    assert sig["severity"] == "low"


def test_unknown_signal_event_type_returns_no_signal():
    """The signal dispatcher silently drops unmapped event types."""
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "sendgrid.totally.unknown"
    ev.provider = "sendgrid"
    ev.source = "sendgrid_activity_event"
    ev.resource_type = "configuration"
    ev.resource_id = None
    ev.provider_event_id = "demo-unk-1"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {}
    sig = sendgrid_sig._build_signal([ev])
    assert sig is None


# ════════════════════════════════════════════════════════════════════════════
# Section E — Demo isolation
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def _ws(test_user, db_session):
    from app.services import workspace_service
    return workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M80H ws", db=db_session,
    )


def test_seed_sendgrid_demo_is_idempotent(test_user, db_session, _ws):
    try:
        r1 = demo_svc.seed_sendgrid(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        r2 = demo_svc.seed_sendgrid(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
    finally:
        demo_svc.clear_sendgrid(workspace_id=_ws.id, db=db_session)


def test_clear_sendgrid_demo_is_idempotent(test_user, db_session, _ws):
    demo_svc.seed_sendgrid(
        workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
    )
    demo_svc.clear_sendgrid(workspace_id=_ws.id, db=db_session)
    out = demo_svc.clear_sendgrid(workspace_id=_ws.id, db=db_session)
    assert out == {"cleared": True}
    assert demo_svc.get_sendgrid_status(
        _ws.id, db_session
    )["seeded"] is False


def test_clear_sendgrid_demo_leaves_real_sendgrid_integration_alone(
    test_user, db_session, _ws,
):
    """Real-but-non-demo SendGrid rows survive clear_sendgrid."""
    from app.core.encryption import encrypt_credentials
    from app.models.integration import Integration
    from app.models.security_finding import SecurityFinding
    ct, iv = encrypt_credentials({"api_key": "SENDGRID_TEST_API_KEY_PLACEHOLDER"})
    real = Integration(
        user_id=test_user.id, workspace_id=_ws.id, provider="sendgrid",
        display_name="real-sendgrid", encrypted_credentials=ct,
        credential_iv=iv, status="active",
    )
    db_session.add(real); db_session.commit(); db_session.refresh(real)
    keep = SecurityFinding(
        workspace_id=_ws.id, integration_id=real.id, provider="sendgrid",
        finding_key="sendgrid_api_key_broad_scopes:real#keep",
        severity="high", title="Real SendGrid risk (keep)",
        status="active",
        evidence={
            "rule": "sendgrid_api_key_broad_scopes",
            "api_key_id": "SENDGRID_REAL_KEY_ID",
        },
        remediation={"summary": "x"},
    )
    db_session.add(keep); db_session.commit(); db_session.refresh(keep)
    keep_id = keep.id
    try:
        demo_svc.seed_sendgrid(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        demo_svc.clear_sendgrid(workspace_id=_ws.id, db=db_session)
        assert demo_svc.get_sendgrid_demo_integration(_ws.id, db_session) is None
        survivor = db_session.query(SecurityFinding).filter(
            SecurityFinding.id == keep_id).first()
        assert survivor is not None, (
            "clear_sendgrid removed a non-demo SendGrid finding"
        )
        assert db_session.query(Integration).filter(
            Integration.id == real.id).first() is not None
    finally:
        db_session.query(SecurityFinding).filter(
            SecurityFinding.id == keep_id).delete(synchronize_session=False)
        db_session.query(Integration).filter(
            Integration.id == real.id).delete(synchronize_session=False)
        db_session.commit()
        demo_svc.clear_sendgrid(workspace_id=_ws.id, db=db_session)


def test_clear_sendgrid_demo_does_not_touch_other_provider_demos(
    test_user, db_session, _ws,
):
    """A multi-provider workspace: clearing SendGrid leaves every other demo alone."""
    other_providers = (
        ("twilio",      demo_svc.seed_twilio,       demo_svc.clear_twilio,       demo_svc.get_twilio_status),
        ("stripe",      demo_svc.seed_stripe,       demo_svc.clear_stripe,       demo_svc.get_stripe_status),
        ("shopify",     demo_svc.seed_shopify,      demo_svc.clear_shopify,      demo_svc.get_shopify_status),
        ("azure",       demo_svc.seed_azure,        demo_svc.clear_azure,        demo_svc.get_azure_status),
    )
    try:
        for _p, seed_fn, _c, _s in other_providers:
            seed_fn(workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session)
        demo_svc.seed_sendgrid(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        for _p, _, _c, status_fn in other_providers:
            assert status_fn(_ws.id, db_session)["seeded"] is True
        assert demo_svc.get_sendgrid_status(_ws.id, db_session)["seeded"] is True

        demo_svc.clear_sendgrid(workspace_id=_ws.id, db=db_session)

        assert demo_svc.get_sendgrid_status(_ws.id, db_session)["seeded"] is False
        for p, _, _c, status_fn in other_providers:
            assert status_fn(_ws.id, db_session)["seeded"] is True, (
                f"clear_sendgrid incorrectly removed the {p} demo"
            )
    finally:
        for _p, _s, clear_fn, _status in other_providers:
            try:
                clear_fn(workspace_id=_ws.id, db=db_session)
            except Exception:
                db_session.rollback()
        try:
            demo_svc.clear_sendgrid(workspace_id=_ws.id, db=db_session)
        except Exception:
            db_session.rollback()


def test_sendgrid_demo_integration_is_hidden_and_safe(
    test_user, db_session, _ws,
):
    """The demo integration must use DEMO_PROVIDER_TAG and 'deleted' status."""
    try:
        demo_svc.seed_sendgrid(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        integ = demo_svc.get_sendgrid_demo_integration(_ws.id, db_session)
        assert integ is not None
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG
        assert integ.status == "deleted"
        assert integ.scheduled_sync_enabled is False
        assert "SendGrid" in integ.display_name
        assert "demo" in integ.display_name.lower()
    finally:
        demo_svc.clear_sendgrid(workspace_id=_ws.id, db=db_session)


def test_sendgrid_demo_uses_safe_placeholder_constants(test_user, db_session, _ws):
    """Seeded demo findings must not contain SendGrid API-key-shaped strings."""
    from app.models.security_finding import SecurityFinding
    try:
        demo_svc.seed_sendgrid(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        integ = demo_svc.get_sendgrid_demo_integration(_ws.id, db_session)
        assert integ is not None
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        for f in findings:
            blob = json.dumps(f.evidence or {}, default=str)
            # No SendGrid API key shape
            assert not re.search(
                r'SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', blob
            ), f"SG.xxx-shaped API key in finding {f.finding_key}"
            # No email addresses
            assert not re.search(r'[a-z]+@[a-z]+\.[a-z]{2,}', blob), (
                f"email address in finding {f.finding_key}: {blob[:200]}"
            )
    finally:
        demo_svc.clear_sendgrid(workspace_id=_ws.id, db=db_session)


# ════════════════════════════════════════════════════════════════════════════
# Section F — Router/API guards (admin-only mutations; member reads)
# ════════════════════════════════════════════════════════════════════════════


def _scan_router_source() -> str:
    from app.routers import security as sec_router
    return inspect.getsource(sec_router)


def test_router_sendgrid_activity_sync_endpoint_exists():
    src = _scan_router_source()
    assert '"/sendgrid-activity/sync"' in src, (
        "sendgrid-activity/sync endpoint missing from router"
    )


def test_router_sendgrid_activity_sync_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/sendgrid-activity/sync"')
    assert idx != -1
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block, (
        "/sendgrid-activity/sync handler missing admin guard"
    )


def test_router_sendgrid_signal_generate_endpoint_exists():
    src = _scan_router_source()
    assert '"/sendgrid-activity/generate-signals"' in src, (
        "sendgrid-activity/generate-signals endpoint missing"
    )


def test_router_sendgrid_signal_generate_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/sendgrid-activity/generate-signals"')
    assert idx != -1
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block, (
        "/sendgrid-activity/generate-signals handler missing admin guard"
    )


def test_router_sendgrid_correlations_generate_endpoint_exists():
    src = _scan_router_source()
    assert '"/sendgrid-correlations/generate"' in src, (
        "sendgrid-correlations/generate endpoint missing from router"
    )


def test_router_sendgrid_correlations_generate_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/sendgrid-correlations/generate"')
    assert idx != -1
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block, (
        "/sendgrid-correlations/generate handler missing admin guard"
    )


def test_router_sendgrid_correlations_dispatches_to_generate_sendgrid_correlations():
    src = _scan_router_source()
    assert "generate_sendgrid_correlations" in src, (
        "router does not call generate_sendgrid_correlations"
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


def test_router_dispatches_sendgrid_for_all_demo_endpoints():
    """All three incident-demo endpoints route provider='sendgrid'."""
    src = _scan_router_source()
    for substring in (
        "get_sendgrid_status", "seed_sendgrid", "clear_sendgrid",
    ):
        assert substring in src, f"router missing dispatch to {substring}"


# ════════════════════════════════════════════════════════════════════════════
# Section G — Frontend SendGrid consistency (skip if frontend absent)
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


def test_fe_activity_page_includes_sendgrid_provider_and_event_types():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert '"sendgrid"' in text
    assert "SendGrid" in text
    for ev in (
        "sendgrid.api_key.created",
        "sendgrid.api_key.updated",
        "sendgrid.sender_identity.updated",
        "sendgrid.domain_authentication.updated",
        "sendgrid.mail_settings.updated",
        "sendgrid.event_webhook.updated",
    ):
        assert ev in text, (
            f"activity page filter missing sendgrid event type {ev!r}"
        )


def test_fe_signals_page_includes_sendgrid_provider_and_signal_types():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert '"sendgrid"' in text
    for s in EXPECTED_SIGNAL_TYPES:
        assert s in text, f"signals page filter missing {s!r}"


def test_fe_correlations_page_includes_sendgrid_provider_and_correlation_types():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    assert '"sendgrid"' in text
    for ctype in EXPECTED_CORRELATION_TYPES:
        assert ctype in text, f"correlations page missing {ctype!r}"


def test_fe_cases_page_has_sendgrid_demo_card():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert 'provider: "sendgrid"' in text
    assert "SendGrid" in text


def test_fe_demo_script_page_marks_sendgrid_demo_ready():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    m = re.search(r'\{\s*provider:\s*"sendgrid",[^}]*demo:\s*true', text)
    assert m is not None, "demo-script SendGrid row missing demo: true"


def test_fe_rule_catalog_includes_every_sendgrid_rule_key():
    text = _read_fe("lib/securityRuleCatalog.ts")
    for key in EXPECTED_RULE_KEYS:
        assert f'key: "{key}"' in text, (
            f"frontend securityRuleCatalog missing rule key {key}"
        )


def test_fe_api_demo_provider_unions_include_sendgrid():
    """getIncidentDemoStatus / seedIncidentDemo / clearIncidentDemo unions all
    include sendgrid (M80G + M80H fix for getIncidentDemoStatus)."""
    text = _read_fe("lib/api.ts")
    full_union = (
        '"github" | "aws" | "cloudflare" | "vercel" | "supabase" | '
        '"firebase" | "stripe" | "shopify" | "azure" | "google_cloud" | "twilio" | "sendgrid"'
    )
    count = text.count(full_union)
    assert count >= 3, (
        f"expected >= 3 demo helper unions to include sendgrid; found {count}"
    )


def test_fe_demo_script_mentions_sendgrid():
    """securityDemoScript talk-track includes SendGrid."""
    text = _read_fe("lib/securityDemoScript.ts")
    assert "SendGrid" in text


def test_fe_activity_page_sync_action_has_safe_copy():
    """Activity sync bar must not contain forbidden phrases for SendGrid."""
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


# ════════════════════════════════════════════════════════════════════════════
# Section H — Regression smoke (M80A–M80G still wire together)
# ════════════════════════════════════════════════════════════════════════════


def test_evaluator_dispatcher_handles_every_record_type_safely():
    """Every SendGrid record type round-trips through evaluate() without raising."""
    for rt in EXPECTED_RECORD_TYPES:
        rec = {"record_type": rt, "record_id": f"demo_{rt}"}
        out = sendgrid_eval(rec)
        assert isinstance(out, list)


def test_signal_service_handles_every_activity_event_type():
    """Every activity event type is handled by _build_signal (returns signal or None)."""
    for event_type in EXPECTED_ACTIVITY_EVENT_TYPES:
        ev = MagicMock()
        ev.id = uuid.uuid4()
        ev.event_type = event_type
        ev.provider = "sendgrid"
        ev.source = "sendgrid_activity_event"
        ev.resource_type = "configuration"
        ev.resource_id = "SENDGRID_DEMO_RESOURCE"
        ev.provider_event_id = f"demo-{event_type}"
        ev.integration_id = uuid.uuid4()
        ev.occurred_at = datetime.now(timezone.utc)
        ev.ingested_at = ev.occurred_at
        ev.created_at = ev.occurred_at
        ev.event_metadata = {"resource_type": "configuration"}
        result = sendgrid_sig._build_signal([ev])
        # A valid event type should produce a signal.
        if event_type in sendgrid_sig.SENDGRID_EVENT_TYPE_TO_SIGNAL_TYPE:
            assert result is not None, (
                f"_build_signal returned None for valid event type {event_type!r}"
            )


def test_correlation_rules_have_required_shape_fields():
    """Every SENDGRID_CORRELATION_RULES entry carries required structure fields."""
    required = {"rule_keys", "signal_types", "match_key", "severity",
                "title_phrase", "subject_phrase"}
    for ctype, rule in sendgrid_corr.SENDGRID_CORRELATION_RULES.items():
        missing = required - set(rule.keys())
        assert missing == set(), (
            f"SENDGRID_CORRELATION_RULES[{ctype!r}] missing fields: {missing}"
        )
        assert isinstance(rule["rule_keys"], (set, frozenset)), (
            f"{ctype}: rule_keys must be a set"
        )
        assert isinstance(rule["signal_types"], (set, frozenset)), (
            f"{ctype}: signal_types must be a set"
        )


def test_correlation_seven_families_cover_all_match_keys():
    """SENDGRID_CORRELATION_RULES must cover exactly the 7 expected match_key families."""
    match_keys = {v["match_key"] for v in sendgrid_corr.SENDGRID_CORRELATION_RULES.values()}
    expected = {
        "api_key", "sender_identity", "domain_authentication",
        "mail_settings", "tracking_settings", "webhook", "suppression_settings",
    }
    assert match_keys == expected


def test_sendgrid_ingestion_never_raises_on_bad_event():
    """normalize_sendgrid_activity_event must return None for malformed entries."""
    assert sendgrid_ingest.normalize_sendgrid_activity_event(None) is None
    assert sendgrid_ingest.normalize_sendgrid_activity_event({}) is None
    assert sendgrid_ingest.normalize_sendgrid_activity_event(
        {"event_type": ""}
    ) is None
    assert sendgrid_ingest.normalize_sendgrid_activity_event(
        {"provider_event_id": "x"}
    ) is None


def test_ingestion_blocks_mail_delivery_events():
    """Mail-delivery event types (bounce, click, open, etc.) must NEVER pass the gate."""
    mail_delivery_events = (
        "sendgrid.delivered", "sendgrid.bounced", "sendgrid.bounce",
        "sendgrid.click", "sendgrid.open", "sendgrid.dropped",
        "sendgrid.deferred", "sendgrid.spamreport", "sendgrid.unsubscribe",
        "sendgrid.group_unsubscribe", "sendgrid.processed",
        # Even if caller passes a hybrid label
        "mail.send", "email.delivered",
    )
    for ev_type in mail_delivery_events:
        result = sendgrid_ingest.normalize_sendgrid_activity_event(
            {"event_type": ev_type}
        )
        assert result is None, (
            f"mail-delivery event {ev_type!r} must not pass the ingestion gate"
        )


def test_match_strength_returns_high_for_exact_match():
    """_match_strength must return 'high' for exact-ID match reasons."""
    assert sendgrid_corr._match_strength("api_key_id_match") == "high"
    assert sendgrid_corr._match_strength("sender_id_match") == "high"
    assert sendgrid_corr._match_strength("domain_id_match") == "high"


def test_match_strength_returns_medium_for_family_aggregate():
    """_match_strength must return 'medium' for family-aggregate match reasons."""
    assert sendgrid_corr._match_strength("api_key_family") == "medium"
    assert sendgrid_corr._match_strength("sender_identity_family") == "medium"
    assert sendgrid_corr._match_strength("mail_settings_family") == "medium"
    assert sendgrid_corr._match_strength("webhook_family") == "medium"
    assert sendgrid_corr._match_strength("suppression_settings_family") == "medium"


def test_expansion_framework_sendgrid_arc_not_abandoned():
    """After M80H, the planned stage must still be within the SendGrid arc or Auth0 next."""
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    # M80I or M81A (Auth0) are both acceptable — SendGrid arc should not be skipped.
    assert (
        "M80I" in planned
        or "M81A" in planned
        or "Auth0" in planned
    ), (
        f"After M80H, planned_next_stage should be M80I or M81A/Auth0; got: {planned!r}"
    )
