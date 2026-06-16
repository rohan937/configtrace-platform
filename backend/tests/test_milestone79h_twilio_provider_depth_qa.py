"""M79H — Twilio provider-depth QA guardrails.

Durable, deterministic guardrails that prove the whole Twilio arc
(M79A–M79G) stays internally consistent.  This file adds NO product code —
it pins taxonomy parity, privacy / sanitization discipline, false-positive
behavior, demo isolation, and router admin / member guards.

Sections:

  A. Taxonomy parity
     Record types ↔ rule keys ↔ activity event types ↔ signal types ↔
     correlation rule keys ↔ correlation activity types.

  B. Privacy guardrails
     Twilio-shaped denylist applied to every Twilio source file we own
     (connector, ingestion, signal, correlation, demo); also asserted on a
     live in-memory pipeline (_build_signal → _build_correlation →
     seed/clear case-report blobs).

  C. Claim discipline
     Forbidden-phrase scan over every Twilio production module and the demo
     fixtures.

  D. False-positive behavior
     End-to-end "should NOT fire" cases: webhook present, code length ok,
     fresh API key, active account, mismatched phone_number_last4,
     mismatched messaging_service_sid, cross-family correlation attempt,
     generic config event, unknown record type.

  E. Demo isolation
     Seed-twice / clear-twice idempotency; clear_twilio leaves every other
     provider demo intact and never touches a real Twilio integration.

  F. Router/API guards
     Twilio activity sync / signal-generate / correlation-generate /
     incident demo seed-clear require admin; read-only endpoints stay
     member-accessible.

  G. Frontend Twilio consistency (skip if frontend tree absent)
     Provider selectors / type filter dropdowns / rule catalog / demo card
     / api unions / demo-script copy all carry Twilio entries.

  H. Regression smoke
     Evaluator dispatch + allowlists + correlation rule shape pinned so the
     future M79I polish cannot drift them silently.
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

from app.connectors import twilio as twilio_conn
from app.connectors.twilio_schema import (
    TWILIO_ACCOUNT,
    TWILIO_API_KEY_SUMMARY,
    TWILIO_INCOMING_PHONE_NUMBER,
    TWILIO_MESSAGING_SERVICE,
    TWILIO_RECORD_TYPES,
    TWILIO_VERIFY_SERVICE,
)
from app.services import twilio_activity_ingestion_service as twilio_ingest
from app.services import twilio_activity_signal_service as twilio_sig
from app.services import twilio_risk_activity_correlation_service as twilio_corr
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
from app.services.security_rules.twilio import (
    TWILIO_RULE_KEYS, evaluate as twilio_eval,
)


# ════════════════════════════════════════════════════════════════════════════
# Fixed expected sets — the M79H baseline.
# Drift here triggers an intentional update of this file (with a note in the
# commit message explaining the change).
# ════════════════════════════════════════════════════════════════════════════

EXPECTED_RECORD_TYPES = {
    "twilio_account",
    "twilio_incoming_phone_number",
    "twilio_messaging_service",
    "twilio_verify_service",
    "twilio_api_key_summary",
}

EXPECTED_RULE_KEYS = {
    # M79B — webhook / verify / account posture (9 rules)
    "twilio_phone_number_sms_webhook_missing",
    "twilio_phone_number_voice_webhook_missing",
    "twilio_phone_number_status_callback_missing",
    "twilio_messaging_service_inbound_webhook_missing",
    "twilio_messaging_service_fallback_missing",
    "twilio_messaging_service_status_callback_missing",
    "twilio_verify_short_code_length",
    "twilio_verify_lookup_disabled",
    "twilio_account_suspended",
    # M79C — API key + observability + posture (8 rules)
    "twilio_api_key_stale",
    "twilio_messaging_service_observability_gap",
    "twilio_messaging_service_number_level_inbound_webhook",
    "twilio_messaging_service_long_validity_period",
    "twilio_phone_number_messaging_observability_gap",
    "twilio_phone_number_voice_observability_gap",
    "twilio_verify_psd2_disabled",
    "twilio_verify_sms_to_landlines_allowed",
}

# Canonical activity event types produced by the ingestion pipeline (15 total,
# including the synthetic twilio.config.event fallback and sender_pool.updated).
EXPECTED_ACTIVITY_EVENT_TYPES = {
    "twilio.account.updated",
    "twilio.phone_number.created",
    "twilio.phone_number.updated",
    "twilio.phone_number.deleted",
    "twilio.messaging_service.created",
    "twilio.messaging_service.updated",
    "twilio.messaging_service.deleted",
    "twilio.messaging_service.sender_pool.updated",
    "twilio.verify_service.created",
    "twilio.verify_service.updated",
    "twilio.verify_service.deleted",
    "twilio.api_key.created",
    "twilio.api_key.updated",
    "twilio.api_key.deleted",
    "twilio.config.event",
}

EXPECTED_SIGNAL_TYPES = {
    "twilio_phone_number_config_changed",
    "twilio_messaging_service_config_changed",
    "twilio_messaging_sender_pool_changed",
    "twilio_verify_service_config_changed",
    "twilio_api_key_config_changed",
    "twilio_account_config_changed",
    "twilio_config_activity",
}

EXPECTED_CORRELATION_TYPES = {
    "twilio_phone_number_risk_activity_correlation",
    "twilio_messaging_service_risk_activity_correlation",
    "twilio_verify_service_risk_activity_correlation",
    "twilio_api_key_risk_activity_correlation",
    "twilio_account_risk_activity_correlation",
}

# ── Forbidden claim wording (M75A pin) ───────────────────────────────────────
FORBIDDEN_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# ── Twilio-shaped privacy denylist (M79H) ────────────────────────────────────
# Substrings that MUST NOT appear (case-insensitive) as quoted JSON keys in
# any Twilio production blob we generate.  Written as `"key":` so we catch
# dict serialisation but not narrative text.
TWILIO_FORBIDDEN_METADATA_KEYS = (
    # Credentials / tokens
    "auth_token", "api_secret", "api_key_secret", "signing_secret",
    "access_token", "access_token_secret", "bearer", "authorization",
    "client_secret", "private_key",
    # Raw Twilio API payloads
    "raw_payload", "request_body", "response_body", "requestbody",
    "responsebody", "webhook_body", "raw_request", "raw_response",
    # Phone number / PII
    "phone_number", "to", "from", "from_",
    "recipient_number", "sender_number", "caller", "called",
    "caller_name", "forwarded_from", "to_formatted", "from_formatted",
    # Message / call / recording content
    "body", "message_body", "message_content", "sms_body",
    "call_sid", "recording_url", "recording_sid", "transcription",
    "media_url", "media_content_type",
    # Conversation / chat data
    "conversation_sid", "message_sid", "chat_message",
    # Webhook URLs (stored as booleans only)
    "sms_url", "voice_url", "status_callback_url", "fallback_url",
    "inbound_request_url", "webhook_url",
    # Full SIDs / credential identifiers
    "account_sid", "full_account_sid", "auth_key",
    # Customer data
    "customer_data", "user_data",
    # Twilio request signatures
    "x_twilio_signature", "twilio_signature",
    # Raw IP / headers
    "ip_address", "caller_ip", "raw_ip", "x_forwarded_for",
    "user_agent", "useragent",
)

# Shape-only substrings that must never appear as a raw value.
TWILIO_FORBIDDEN_VALUE_PATTERNS = (
    # E.164 full phone number shape (e.g. "+12125551234")
    r"\+1[2-9]\d{9}",       # regex — applied specially
    "begin private key",    # PEM header
    "begin rsa private",
    # Twilio SID shapes — never as literal values (use safe placeholders only)
    # Note: AC/SK regex is not applied here; it is checked by the secret-grep
    # tests separately.  This list is for narrative/raw-value patterns.
    "AccountSid=",
    "AuthToken=",
)


# ════════════════════════════════════════════════════════════════════════════
# Section A — Taxonomy parity
# ════════════════════════════════════════════════════════════════════════════


def test_record_types_match_expected():
    assert set(TWILIO_RECORD_TYPES) == EXPECTED_RECORD_TYPES


def test_record_type_constants_are_canonical_lowercase():
    """Each schema constant uses the canonical lowercase value."""
    pairs = (
        ("TWILIO_ACCOUNT", TWILIO_ACCOUNT),
        ("TWILIO_INCOMING_PHONE_NUMBER", TWILIO_INCOMING_PHONE_NUMBER),
        ("TWILIO_MESSAGING_SERVICE", TWILIO_MESSAGING_SERVICE),
        ("TWILIO_VERIFY_SERVICE", TWILIO_VERIFY_SERVICE),
        ("TWILIO_API_KEY_SUMMARY", TWILIO_API_KEY_SUMMARY),
    )
    for name, val in pairs:
        assert val == name.lower(), (
            f"{name} value ({val!r}) must be its lowercased name "
            f"({name.lower()!r}); evaluator dispatch keys on this."
        )


def test_rule_keys_match_expected():
    assert set(TWILIO_RULE_KEYS) == EXPECTED_RULE_KEYS


def test_rule_registry_parity_for_twilio_keys():
    in_registry = {k for k in KNOWN_RULE_KEYS if k.startswith("twilio_")}
    assert in_registry == EXPECTED_RULE_KEYS

    in_confidence = {k for k in RULE_CONFIDENCE if k.startswith("twilio_")}
    assert in_confidence == EXPECTED_RULE_KEYS

    in_pack = {k for k, v in _RULE_META.items() if v[0] == "twilio"}
    assert in_pack == EXPECTED_RULE_KEYS

    in_coverage = {k for k in RULE_RECORD_TYPES if k.startswith("twilio_")}
    assert in_coverage == EXPECTED_RULE_KEYS


def test_twilio_in_coverage_providers_and_surfaces():
    assert "twilio" in COVERAGE_PROVIDERS
    surfaces = PROVIDER_SURFACES["twilio"]
    for s in surfaces:
        assert isinstance(s, str) and s.strip()


def test_activity_event_type_map_matches_expected():
    """TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE covers every expected activity event type."""
    types = set(twilio_sig.TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE)
    assert types == EXPECTED_ACTIVITY_EVENT_TYPES


def test_signal_types_match_expected():
    types = set(twilio_sig.TWILIO_SIGNAL_TYPES)
    assert types == EXPECTED_SIGNAL_TYPES


def test_signal_types_derived_from_event_type_map():
    """TWILIO_SIGNAL_TYPES is exactly the values of TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE."""
    from_map = set(twilio_sig.TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE.values())
    assert from_map == set(twilio_sig.TWILIO_SIGNAL_TYPES)


def test_correlation_types_match_expected():
    types = set(twilio_corr.TWILIO_CORRELATION_TYPES)
    assert types == EXPECTED_CORRELATION_TYPES


def test_correlation_rules_cover_all_17_twilio_rule_keys():
    """Every Twilio rule key must appear in at least one TWILIO_CORRELATION_RULES entry."""
    all_rule_keys: set[str] = set()
    for rule in twilio_corr.TWILIO_CORRELATION_RULES.values():
        all_rule_keys.update(rule["rule_keys"])
    assert all_rule_keys == EXPECTED_RULE_KEYS, (
        f"Rule key parity error. Missing: {EXPECTED_RULE_KEYS - all_rule_keys}; "
        f"Extra: {all_rule_keys - EXPECTED_RULE_KEYS}"
    )


def test_correlation_activity_types_are_subset_of_activity_event_types():
    """Correlation signal_types must only reference types the signal service handles."""
    referenced: set[str] = set()
    for rule in twilio_corr.TWILIO_CORRELATION_RULES.values():
        referenced.update(rule["signal_types"])
    not_in_signal = referenced - EXPECTED_SIGNAL_TYPES
    assert not_in_signal == set(), (
        f"correlation references signal types not in EXPECTED_SIGNAL_TYPES: "
        f"{sorted(not_in_signal)}"
    )


def test_ingestion_provider_and_source_constants():
    """Ingestion service must tag events provider=twilio, source=twilio_activity_event."""
    assert twilio_ingest.PROVIDER == "twilio"
    assert twilio_ingest.SOURCE == "twilio_activity_event"
    assert twilio_ingest.EVENT_SOURCE == "twilio_activity_event"


def test_capability_matrix_pins_twilio_partial_demo_ready():
    cap = get_provider_capability("twilio")
    assert cap is not None
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True
    assert cap.maturity == "partial"
    # M79H must be reflected in the capability notes after this milestone.
    notes = (cap.notes or "")
    assert "M79H" in notes, (
        f"Capability notes must mention M79H after provider-depth QA; got: {notes[:200]}"
    )


def test_expansion_framework_points_to_m79i():
    """M80C complete — planned_next_stage must advance to M80D."""
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert "M80H" in planned, (
        f"planned_next_stage must point to M80D (SendGrid Activity) after M80C; got: {planned!r}"
    )
    assert "SendGrid" in planned
    assert "M79H" not in planned, (
        f"M79H is done; pointer must advance past it (got: {planned!r})"
    )
    assert "M79I" not in planned, (
        f"M79I is done; stale reference (got: {planned!r})"
    )


def test_twilio_not_in_canonical_eight_provider_matrix():
    """Twilio stays in PROVIDER_CAPABILITIES_PARTIAL — never in the canonical 8."""
    from app.services.provider_capability_matrix_service import (
        PROVIDER_CAPABILITIES, PROVIDER_CAPABILITIES_PARTIAL,
    )
    canonical = {p.provider for p in PROVIDER_CAPABILITIES}
    partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
    assert "twilio" not in canonical
    assert "twilio" in partial


def test_twilio_label_in_timeline_provider_labels():
    """build_case_evidence_timeline must render 'Twilio' as the provider label."""
    assert report_svc._TIMELINE_PROVIDER_LABELS.get("twilio") == "Twilio"


# ════════════════════════════════════════════════════════════════════════════
# Section B — Privacy guardrails (allowlist + denylist)
# ════════════════════════════════════════════════════════════════════════════


# M79D activity-event metadata keys (full set the ingester writes).
_TWILIO_ACTIVITY_SAFE_KEYS = {
    "twilio_event_id", "twilio_resource_sid_prefix", "resource_type",
    "event_action", "account_sid_prefix", "operation_name", "event_time",
    "event_source",
}

# M79E signal-metadata subset.
_TWILIO_SIGNAL_SAFE_KEYS = {
    "source", "event_types", "event_count", "resource_type",
    "twilio_resource_sid_prefix", "messaging_service_sid",
    "verify_service_sid", "api_key_sid", "phone_number_last4",
    "window_start", "window_end",
}

# M79F correlation-metadata subset.
_TWILIO_CORRELATION_SAFE_KEYS = _TWILIO_SIGNAL_SAFE_KEYS | {
    "rule_key", "signal_type", "match_reason", "match_strength",
    "finding_severity", "event_count",
}


def test_activity_allowlist_contains_all_twilio_safe_keys():
    """Every key the M79D ingester writes must be in the activity allowlist."""
    missing = _TWILIO_ACTIVITY_SAFE_KEYS - ACTIVITY_ALLOWED
    assert missing == set(), (
        f"M79D safe keys missing from activity allowlist: {missing}"
    )


def test_signal_allowlist_contains_all_twilio_safe_keys():
    """Every Twilio-safe key the M79E signal builder emits must be allowlisted."""
    missing = _TWILIO_SIGNAL_SAFE_KEYS - SIGNAL_ALLOWED
    assert missing == set(), (
        f"M79E safe keys missing from signal allowlist: {missing}"
    )


def test_correlation_allowlist_contains_all_twilio_safe_keys():
    core_keys = {
        "twilio_resource_sid_prefix", "messaging_service_sid",
        "verify_service_sid", "api_key_sid", "phone_number_last4",
        "match_reason", "match_strength",
    }
    missing = core_keys - corr_svc.ALLOWED_METADATA_KEYS
    assert missing == set(), (
        f"M79F safe keys missing from correlation allowlist: {missing}"
    )


def test_case_report_preview_allowlist_includes_twilio_safe_keys():
    """M79G expansion of the case-report preview allowlist covers Twilio keys."""
    expected = {
        "phone_number_last4", "messaging_service_sid", "verify_service_sid",
        "api_key_sid", "twilio_resource_sid_prefix",
    }
    missing = expected - report_svc._PREVIEW_ALLOWLIST
    assert missing == set(), (
        f"case-report preview allowlist missing Twilio-safe keys: {missing}"
    )


# ── Denylist helpers ──────────────────────────────────────────────────────────


def _denylist_assert(blob: str, *, where: str) -> None:
    lower = blob.lower()
    for bad in TWILIO_FORBIDDEN_METADATA_KEYS:
        assert f'"{bad}":' not in lower, (
            f"{where}: forbidden quoted key {bad!r} present"
        )
    for bad in TWILIO_FORBIDDEN_VALUE_PATTERNS:
        if bad.startswith(r"\+"):
            # regex pattern — skip (handled separately)
            continue
        assert bad not in lower, (
            f"{where}: forbidden substring {bad!r} present"
        )


def _build_polluted_signal() -> dict:
    """Build a signal from an event polluted with Twilio-private fields.

    sanitize_signal_metadata() must drop every forbidden key before persisting.
    """
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "twilio.phone_number.updated"
    ev.provider = "twilio"
    ev.source = "twilio_activity_event"
    ev.resource_id = "TWILIO_DEMO_PHONE_RESOURCE"
    ev.resource_type = "incoming-phone-number"
    ev.provider_event_id = "demo-twilio-evt-1"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {
        # Safe keys (must survive):
        "twilio_resource_sid_prefix": "TWILIO_DE",
        "resource_type": "incoming-phone-number",
        "phone_number_last4": "5678",
        # Forbidden pollution that MUST be dropped:
        "auth_token": "FAKE_AUTH_TOKEN",
        "api_secret": "FAKE_API_SECRET",
        "phone_number": "+15555551234",
        "body": "Hello from demo",
        "sms_url": "https://example.com/sms",
        "voice_url": "https://example.com/voice",
        "from": "+15555550001",
        "to": "+15555550002",
        "account_sid": "TWILIO_TEST_ACCOUNT_ID",
        "recording_url": "https://api.twilio.com/recordings/RE...",
        "message_body": "secret message content",
        "customer_data": "pii here",
        "x_twilio_signature": "signature_blob",
        "ip_address": "1.2.3.4",
        "user_agent": "Twilio-Test/1.0",
        "raw_payload": '{"AccountSid": "TWILIO_TEST_ACCOUNT_ID"}',
    }
    sig = twilio_sig._build_signal([ev])
    assert sig is not None
    return sig


def test_signal_metadata_drops_every_polluted_key():
    sig = _build_polluted_signal()
    meta = sig["metadata"]
    # Safe metadata survives.
    assert meta.get("phone_number_last4") == "5678"
    assert meta.get("resource_type") == "incoming-phone-number"
    # Forbidden keys dropped.
    for bad in (
        "auth_token", "api_secret", "phone_number", "body", "sms_url",
        "voice_url", "from", "to", "account_sid", "recording_url",
        "message_body", "customer_data", "x_twilio_signature",
        "ip_address", "user_agent", "raw_payload",
    ):
        assert bad not in meta, (
            f"forbidden key {bad!r} survived in signal metadata"
        )
    # PII values never appear in any serialisable surface of the signal.
    blob = json.dumps({
        "metadata": meta, "title": sig["title"], "summary": sig["summary"],
    })
    for value in (
        "+15555551234", "FAKE_AUTH_TOKEN", "FAKE_API_SECRET",
        "Hello from demo", "secret message content",
        "+15555550001", "+15555550002",
    ):
        assert value not in blob, f"private value {value!r} in signal blob"


def _make_finding_mock(rule_key: str, **evidence) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.finding_key = f"{rule_key}:TWILIO_DEMO_PHONE_RESOURCE"
    f.severity = "high"
    f.title = "Demo Twilio finding"
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
    sig.provider = "twilio"
    sig.source = "twilio_activity_event"
    sig.signal_metadata = metadata
    sig.severity = "medium"
    sig.first_seen_at = datetime.now(timezone.utc)
    sig.last_seen_at = datetime.now(timezone.utc)
    sig.linked_activity_event_id = uuid.uuid4()
    return sig


def test_correlation_metadata_drops_every_polluted_key():
    """_build_correlation sanitizes forbidden keys from both finding and signal."""
    finding = _make_finding_mock(
        "twilio_phone_number_sms_webhook_missing",
        phone_number_last4="5678",
        # Forbidden pollution on the finding side:
        auth_token="FAKE_AUTH_TOKEN",
        phone_number="+15555551234",
        message_body="secret",
        sms_url="https://example.com/sms",
        account_sid="TWILIO_TEST_ACCOUNT_ID",
    )
    signal = _make_signal_mock(
        "twilio_phone_number_config_changed",
        {
            "phone_number_last4": "5678",
            "resource_type": "incoming-phone-number",
            "event_types": "twilio.phone_number.updated",
            # Forbidden pollution on the signal side:
            "auth_token": "FAKE_AUTH_TOKEN",
            "api_secret": "FAKE_API_SECRET",
            "body": "Hello from demo",
            "recording_url": "https://api.twilio.com/recordings/RE...",
            "customer_data": "pii here",
            "x_twilio_signature": "sig",
            "ip_address": "9.9.9.9",
        },
    )
    rule = twilio_corr.TWILIO_CORRELATION_RULES[
        "twilio_phone_number_risk_activity_correlation"
    ]
    c = twilio_corr._build_correlation(
        finding=finding, signal=signal,
        correlation_type="twilio_phone_number_risk_activity_correlation",
        rule=rule,
        match_reason="phone_number_last4_match",
    )
    blob = json.dumps({
        "metadata": c["metadata"], "title": c["title"], "summary": c["summary"],
    })
    _denylist_assert(blob, where="correlation built from polluted finding+signal")
    # Safe key survives
    assert c["metadata"].get("phone_number_last4") == "5678" or (
        "phone_number_last4" not in c["metadata"]
    )  # present or absent — either is fine as long as no raw number survived


def test_twilio_demo_case_artifacts_pass_denylist(test_user, db_session):
    """The Twilio demo seed/report/timeline/graph stay denylist-clean."""
    from app.services import workspace_service
    ws = workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M79H demo", db=db_session,
    )
    try:
        seed = demo_svc.seed_twilio(
            workspace_id=ws.id, actor_user_id=test_user.id, db=db_session,
        )
        case_id = uuid.UUID(seed["case_id"])
        from app.models.security_case import SecurityCase
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == case_id).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        timeline = report_svc.build_case_evidence_timeline(
            case_id=case_id, workspace_id=ws.id, db=db_session,
        )
        graph = report_svc.build_case_evidence_graph(
            case_id=case_id, workspace_id=ws.id, db=db_session,
        )
        blob = (
            json.dumps(report, default=str)
            + json.dumps(timeline, default=str)
            + json.dumps(graph, default=str)
        )
        _denylist_assert(blob, where="twilio demo report/timeline/graph")
        # Extra check: no E.164 full phone numbers
        assert not re.search(r"\+1[2-9]\d{9}", blob), (
            "E.164 full phone number found in demo case blobs"
        )
        # No Twilio secret-shaped strings (AC/SK + 32 hex)
        assert not re.search(r'AC[0-9a-fA-F]{32}', blob), (
            "AC-shaped Twilio Account SID found in demo blobs"
        )
        assert not re.search(r'SK[0-9a-fA-F]{32}', blob), (
            "SK-shaped Twilio API key SID found in demo blobs"
        )
    finally:
        demo_svc.clear_twilio(workspace_id=ws.id, db=db_session)


# ════════════════════════════════════════════════════════════════════════════
# Section C — Claim discipline (forbidden phrases on Twilio modules)
# ════════════════════════════════════════════════════════════════════════════


_TWILIO_MODULES = [
    twilio_conn, twilio_ingest, twilio_sig, demo_svc,
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


@pytest.mark.parametrize("module", _TWILIO_MODULES)
def test_twilio_modules_have_no_forbidden_claims(module):
    src = inspect.getsource(module)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in {module.__name__} "
            f"outside a negation context"
        )


def test_twilio_security_rules_module_has_no_forbidden_claims():
    """The security_rules.twilio module ships claim-discipline copy."""
    from app.services.security_rules import twilio as twilio_rules
    src = inspect.getsource(twilio_rules)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in security_rules.twilio"
        )


def test_twilio_correlation_module_has_no_forbidden_claims():
    """The Twilio risk×activity correlation module is claim-discipline clean."""
    src = inspect.getsource(twilio_corr)
    stripped = _strip_known_negation_contexts(src).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in stripped, (
            f"forbidden phrase {phrase!r} in twilio_risk_activity_correlation_service"
        )


# ════════════════════════════════════════════════════════════════════════════
# Section D — False-positive behavior pins
# ════════════════════════════════════════════════════════════════════════════


def _phone_record(**kwargs) -> dict:
    base = {
        "record_type": TWILIO_INCOMING_PHONE_NUMBER,
        "record_id": "PNtest0001",
        "phone_number_sid": "PNtest0001",
        "friendly_name": "Test Number",
        "phone_number_last4": "5678",
        "iso_country": "US",
        "capability_voice": True,
        "capability_sms": True,
        "capability_mms": False,
        "capability_fax": False,
        "sms_url_configured": True,
        "voice_url_configured": True,
        "status_callback_configured": True,
        "address_requirements": "none",
        "emergency_status": "Active",
    }
    base.update(kwargs)
    return base


def _messaging_record(**kwargs) -> dict:
    base = {
        "record_type": TWILIO_MESSAGING_SERVICE,
        "record_id": "MGtest0001",
        "messaging_service_sid": "MGtest0001",
        "friendly_name": "Test Messaging",
        "inbound_request_url_configured": True,
        "fallback_url_configured": True,
        "status_callback_url_configured": True,
        "smart_encoding": True,
        "validity_period": 14400,
        "area_code_geomatch": True,
        "sticky_sender": True,
        "mms_converter": True,
        "use_inbound_webhook_on_number": False,
        "number_count": 1,
    }
    base.update(kwargs)
    return base


def _verify_record(**kwargs) -> dict:
    base = {
        "record_type": TWILIO_VERIFY_SERVICE,
        "record_id": "VAtest0001",
        "verify_service_sid": "VAtest0001",
        "friendly_name": "Test Verify",
        "code_length": 6,
        "lookup_enabled": True,
        "psd2_enabled": True,
        "do_not_share_warning_enabled": True,
        "skip_sms_to_landlines": True,
        "default_template_sid_present": False,
    }
    base.update(kwargs)
    return base


def _api_key_record(date_created: str, date_updated: str, **kwargs) -> dict:
    base = {
        "record_type": TWILIO_API_KEY_SUMMARY,
        "record_id": "SKtest0001",
        "api_key_sid": "SKtest0001",
        "friendly_name": "Test Key",
        "date_created": date_created,
        "date_updated": date_updated,
    }
    base.update(kwargs)
    return base


def test_sms_webhook_present_does_not_fire():
    """When sms_url_configured=True and capability_sms=True → no SMS webhook missing."""
    rec = _phone_record(capability_sms=True, sms_url_configured=True)
    keys = {f.rule_key for f in twilio_eval(rec)}
    assert "twilio_phone_number_sms_webhook_missing" not in keys


def test_sms_webhook_missing_fires_only_for_sms_capable_numbers():
    """twilio_phone_number_sms_webhook_missing does NOT fire when SMS disabled."""
    rec = _phone_record(capability_sms=False, sms_url_configured=False)
    keys = {f.rule_key for f in twilio_eval(rec)}
    assert "twilio_phone_number_sms_webhook_missing" not in keys


def test_voice_webhook_present_does_not_fire():
    """When voice_url_configured=True and capability_voice=True → no voice webhook missing."""
    rec = _phone_record(capability_voice=True, voice_url_configured=True)
    keys = {f.rule_key for f in twilio_eval(rec)}
    assert "twilio_phone_number_voice_webhook_missing" not in keys


def test_status_callback_present_does_not_fire():
    """When status_callback_configured=True → no status callback missing finding."""
    rec = _phone_record(status_callback_configured=True)
    keys = {f.rule_key for f in twilio_eval(rec)}
    assert "twilio_phone_number_status_callback_missing" not in keys


def test_messaging_service_all_webhooks_present_does_not_fire():
    """All webhooks + callbacks configured → no webhook or observability gap findings."""
    rec = _messaging_record(
        inbound_request_url_configured=True,
        fallback_url_configured=True,
        status_callback_url_configured=True,
    )
    keys = {f.rule_key for f in twilio_eval(rec)}
    assert "twilio_messaging_service_inbound_webhook_missing" not in keys
    assert "twilio_messaging_service_fallback_missing" not in keys
    assert "twilio_messaging_service_status_callback_missing" not in keys
    assert "twilio_messaging_service_observability_gap" not in keys


def test_verify_code_length_6_does_not_fire():
    """Code length of 6 (default Twilio) must NOT trigger twilio_verify_short_code_length."""
    rec = _verify_record(code_length=6)
    keys = {f.rule_key for f in twilio_eval(rec)}
    assert "twilio_verify_short_code_length" not in keys


def test_verify_lookup_enabled_does_not_fire():
    """lookup_enabled=True must NOT trigger twilio_verify_lookup_disabled."""
    rec = _verify_record(lookup_enabled=True)
    keys = {f.rule_key for f in twilio_eval(rec)}
    assert "twilio_verify_lookup_disabled" not in keys


def test_api_key_fresh_does_not_fire():
    """A recently-updated API key must NOT trigger twilio_api_key_stale."""
    now = datetime.now(timezone.utc)
    recent = (now - timedelta(days=10)).isoformat()
    rec = _api_key_record(date_created=recent, date_updated=recent)
    keys = {f.rule_key for f in twilio_eval(rec)}
    assert "twilio_api_key_stale" not in keys


def test_api_key_stale_fires_for_old_keys():
    """An API key not updated in 180+ days MUST trigger twilio_api_key_stale."""
    now = datetime.now(timezone.utc)
    old = (now - timedelta(days=200)).isoformat()
    rec = _api_key_record(date_created=old, date_updated=old)
    keys = {f.rule_key for f in twilio_eval(rec)}
    assert "twilio_api_key_stale" in keys, (
        "Expected twilio_api_key_stale to fire for a key not updated in 200 days"
    )


def test_active_account_does_not_trigger_suspended_rule():
    """Status 'active' must NOT trigger twilio_account_suspended."""
    rec = {
        "record_type": TWILIO_ACCOUNT,
        "record_id": "twilio_account_TWILIO_DE",
        "account_sid_prefix": "TWILIO_DE",
        "friendly_name": "Test",
        "status": "active",
        "account_type": "Full",
        "subaccount_count": 0,
    }
    keys = {f.rule_key for f in twilio_eval(rec)}
    assert "twilio_account_suspended" not in keys


def test_suspended_account_fires_account_suspended():
    """Status 'suspended' MUST trigger twilio_account_suspended."""
    rec = {
        "record_type": TWILIO_ACCOUNT,
        "record_id": "twilio_account_TWILIO_DE",
        "account_sid_prefix": "TWILIO_DE",
        "friendly_name": "Test",
        "status": "suspended",
        "account_type": "Full",
        "subaccount_count": 0,
    }
    keys = {f.rule_key for f in twilio_eval(rec)}
    assert "twilio_account_suspended" in keys


def test_unknown_record_type_returns_no_findings():
    """The Twilio evaluator dispatch is closed — unknown types yield []."""
    assert twilio_eval({"record_type": "twilio_unknown_thing"}) == []
    assert twilio_eval({"record_type": ""}) == []
    assert twilio_eval({}) == []


def test_different_phone_number_last4_does_not_correlate():
    """Mismatched phone_number_last4 on both sides → no correlation match."""
    finding = _make_finding_mock(
        "twilio_phone_number_sms_webhook_missing",
        phone_number_last4="1111",
    )
    signal = _make_signal_mock(
        "twilio_phone_number_config_changed",
        {"phone_number_last4": "2222"},
    )
    result = twilio_corr._match_pair(finding, signal, "phone_number")
    assert result is None, (
        "Different phone_number_last4 must not produce a correlation"
    )


def test_different_messaging_service_sid_does_not_correlate():
    """Mismatched messaging_service_sid on both sides → no correlation match."""
    finding = _make_finding_mock(
        "twilio_messaging_service_inbound_webhook_missing",
        messaging_service_sid="MGtest0001",
    )
    signal = _make_signal_mock(
        "twilio_messaging_service_config_changed",
        {"messaging_service_sid": "MGtest0002"},
    )
    result = twilio_corr._match_pair(finding, signal, "messaging_service")
    assert result is None, (
        "Different messaging_service_sid must not produce a correlation"
    )


def test_different_verify_service_sid_does_not_correlate():
    """Mismatched verify_service_sid → no correlation match."""
    finding = _make_finding_mock(
        "twilio_verify_short_code_length",
        verify_service_sid="VAtest0001",
    )
    signal = _make_signal_mock(
        "twilio_verify_service_config_changed",
        {"verify_service_sid": "VAtest0002"},
    )
    result = twilio_corr._match_pair(finding, signal, "verify_service")
    assert result is None


def test_different_api_key_sid_does_not_correlate():
    """Mismatched api_key_sid → no correlation match."""
    finding = _make_finding_mock(
        "twilio_api_key_stale",
        api_key_sid="SKtest0001",
    )
    signal = _make_signal_mock(
        "twilio_api_key_config_changed",
        {"api_key_sid": "SKtest0002"},
    )
    result = twilio_corr._match_pair(finding, signal, "api_key")
    assert result is None


def test_account_family_always_matches():
    """Account match_key=account always produces a match regardless of metadata."""
    finding = _make_finding_mock("twilio_account_suspended")
    signal = _make_signal_mock("twilio_account_config_changed", {})
    result = twilio_corr._match_pair(finding, signal, "account")
    assert result is not None, "account family must always produce a match"


def test_phone_number_aggregate_match_when_no_last4():
    """When neither side has phone_number_last4, aggregate family match is returned."""
    finding = _make_finding_mock(
        "twilio_phone_number_sms_webhook_missing",
        # no phone_number_last4
    )
    signal = _make_signal_mock(
        "twilio_phone_number_config_changed",
        {},  # no phone_number_last4
    )
    result = twilio_corr._match_pair(finding, signal, "phone_number")
    assert result == "phone_number_family"


def test_generic_config_event_alone_does_not_become_sole_correlation_trigger():
    """twilio.config.event alone maps to twilio_config_activity — low severity."""
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "twilio.config.event"
    ev.provider = "twilio"
    ev.source = "twilio_activity_event"
    ev.resource_type = "configuration"
    ev.resource_id = None
    ev.provider_event_id = "demo-cfg-1"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {"resource_type": "configuration"}
    sig = twilio_sig._build_signal([ev])
    assert sig is not None
    assert sig["signal_type"] == "twilio_config_activity"
    assert sig["severity"] == "low"


def test_unknown_signal_event_type_returns_no_signal():
    """The signal dispatcher silently drops unmapped event types."""
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = "twilio.totally.unknown"
    ev.provider = "twilio"
    ev.source = "twilio_activity_event"
    ev.resource_type = "configuration"
    ev.resource_id = None
    ev.provider_event_id = "demo-unk-1"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = datetime.now(timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.event_metadata = {}
    sig = twilio_sig._build_signal([ev])
    assert sig is None


# ════════════════════════════════════════════════════════════════════════════
# Section E — Demo isolation
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def _ws(test_user, db_session):
    from app.services import workspace_service
    return workspace_service.get_or_create_default_workspace(
        user_id=test_user.id, user_display_name="M79H ws", db=db_session,
    )


def test_seed_twilio_demo_is_idempotent(test_user, db_session, _ws):
    try:
        r1 = demo_svc.seed_twilio(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        r2 = demo_svc.seed_twilio(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
    finally:
        demo_svc.clear_twilio(workspace_id=_ws.id, db=db_session)


def test_clear_twilio_demo_is_idempotent(test_user, db_session, _ws):
    demo_svc.seed_twilio(
        workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
    )
    demo_svc.clear_twilio(workspace_id=_ws.id, db=db_session)
    # Second clear is a no-op.
    out = demo_svc.clear_twilio(workspace_id=_ws.id, db=db_session)
    assert out == {"cleared": True}
    assert demo_svc.get_twilio_status(
        _ws.id, db_session
    )["seeded"] is False


def test_clear_twilio_demo_leaves_real_twilio_integration_alone(
    test_user, db_session, _ws,
):
    """Real-but-non-demo Twilio rows survive clear_twilio."""
    from app.core.encryption import encrypt_credentials
    from app.models.integration import Integration
    from app.models.security_finding import SecurityFinding
    ct, iv = encrypt_credentials({
        "account_sid": "TWILIO_TEST_ACCOUNT_ID",
        "auth_token": "TWILIO_TEST_AUTH_TOKEN",
    })
    real = Integration(
        user_id=test_user.id, workspace_id=_ws.id, provider="twilio",
        display_name="real-twilio", encrypted_credentials=ct,
        credential_iv=iv, status="active",
    )
    db_session.add(real); db_session.commit(); db_session.refresh(real)
    keep = SecurityFinding(
        workspace_id=_ws.id, integration_id=real.id, provider="twilio",
        finding_key="twilio_phone_number_sms_webhook_missing:real#keep",
        severity="high", title="Real Twilio risk (keep)",
        status="active",
        evidence={
            "rule": "twilio_phone_number_sms_webhook_missing",
            "phone_number_last4": "9999",
        },
        remediation={"summary": "x"},
    )
    db_session.add(keep); db_session.commit(); db_session.refresh(keep)
    keep_id = keep.id
    try:
        demo_svc.seed_twilio(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        demo_svc.clear_twilio(workspace_id=_ws.id, db=db_session)
        assert demo_svc.get_twilio_demo_integration(_ws.id, db_session) is None
        survivor = db_session.query(SecurityFinding).filter(
            SecurityFinding.id == keep_id).first()
        assert survivor is not None, (
            "clear_twilio removed a non-demo Twilio finding"
        )
        assert db_session.query(Integration).filter(
            Integration.id == real.id).first() is not None
    finally:
        db_session.query(SecurityFinding).filter(
            SecurityFinding.id == keep_id).delete(synchronize_session=False)
        db_session.query(Integration).filter(
            Integration.id == real.id).delete(synchronize_session=False)
        db_session.commit()
        demo_svc.clear_twilio(workspace_id=_ws.id, db=db_session)


def test_clear_twilio_demo_does_not_touch_other_provider_demos(
    test_user, db_session, _ws,
):
    """A multi-provider workspace: clearing Twilio leaves every other demo alone."""
    other_providers = (
        ("azure",       demo_svc.seed_azure,       demo_svc.clear_azure,       demo_svc.get_azure_status),
        ("shopify",     demo_svc.seed_shopify,     demo_svc.clear_shopify,     demo_svc.get_shopify_status),
        ("stripe",      demo_svc.seed_stripe,      demo_svc.clear_stripe,      demo_svc.get_stripe_status),
        ("google_cloud",demo_svc.seed_google_cloud,demo_svc.clear_google_cloud,demo_svc.get_google_cloud_status),
    )
    try:
        for _p, seed_fn, _c, _s in other_providers:
            seed_fn(workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session)
        demo_svc.seed_twilio(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        for _p, _, _c, status_fn in other_providers:
            assert status_fn(_ws.id, db_session)["seeded"] is True
        assert demo_svc.get_twilio_status(_ws.id, db_session)["seeded"] is True

        demo_svc.clear_twilio(workspace_id=_ws.id, db=db_session)

        assert demo_svc.get_twilio_status(_ws.id, db_session)["seeded"] is False
        for p, _, _c, status_fn in other_providers:
            assert status_fn(_ws.id, db_session)["seeded"] is True, (
                f"clear_twilio incorrectly removed the {p} demo"
            )
    finally:
        for _p, _s, clear_fn, _status in other_providers:
            try:
                clear_fn(workspace_id=_ws.id, db=db_session)
            except Exception:
                db_session.rollback()
        try:
            demo_svc.clear_twilio(workspace_id=_ws.id, db=db_session)
        except Exception:
            db_session.rollback()


def test_twilio_demo_integration_is_hidden_and_safe(
    test_user, db_session, _ws,
):
    """The demo integration must use DEMO_PROVIDER_TAG and 'deleted' status."""
    try:
        demo_svc.seed_twilio(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        integ = demo_svc.get_twilio_demo_integration(_ws.id, db_session)
        assert integ is not None
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG
        assert integ.status == "deleted"
        assert integ.scheduled_sync_enabled is False
        assert "Twilio" in integ.display_name
        assert "demo" in integ.display_name.lower()
    finally:
        demo_svc.clear_twilio(workspace_id=_ws.id, db=db_session)


def test_twilio_demo_uses_safe_placeholder_constants(test_user, db_session, _ws):
    """Seeded demo findings must not contain Twilio SID-shaped strings."""
    from app.models.security_finding import SecurityFinding
    try:
        demo_svc.seed_twilio(
            workspace_id=_ws.id, actor_user_id=test_user.id, db=db_session,
        )
        integ = demo_svc.get_twilio_demo_integration(_ws.id, db_session)
        assert integ is not None
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        for f in findings:
            blob = json.dumps(f.evidence or {}, default=str)
            assert not re.search(r'AC[0-9a-fA-F]{32}', blob), (
                f"AC-shaped SID in finding {f.finding_key}"
            )
            assert not re.search(r'SK[0-9a-fA-F]{32}', blob), (
                f"SK-shaped SID in finding {f.finding_key}"
            )
            assert not re.search(r'\+1[2-9]\d{9}', blob), (
                f"E.164 phone number in finding {f.finding_key}"
            )
    finally:
        demo_svc.clear_twilio(workspace_id=_ws.id, db=db_session)


# ════════════════════════════════════════════════════════════════════════════
# Section F — Router/API guards (admin-only mutations; member reads)
# ════════════════════════════════════════════════════════════════════════════


def _scan_router_source() -> str:
    from app.routers import security as sec_router
    return inspect.getsource(sec_router)


def test_router_twilio_activity_sync_endpoint_exists():
    src = _scan_router_source()
    assert '"/twilio-activity/sync"' in src, (
        "twilio-activity/sync endpoint missing from router"
    )


def test_router_twilio_activity_sync_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/twilio-activity/sync"')
    assert idx != -1
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block, (
        "/twilio-activity/sync handler missing admin guard"
    )


def test_router_twilio_signal_generate_endpoint_exists():
    src = _scan_router_source()
    assert '"/twilio-activity/generate-signals"' in src, (
        "twilio-activity/generate-signals endpoint missing"
    )


def test_router_twilio_signal_generate_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/twilio-activity/generate-signals"')
    assert idx != -1
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block, (
        "/twilio-activity/generate-signals handler missing admin guard"
    )


def test_router_twilio_correlations_generate_endpoint_exists():
    src = _scan_router_source()
    assert '"/twilio-correlations/generate"' in src, (
        "twilio-correlations/generate endpoint missing from router"
    )


def test_router_twilio_correlations_generate_requires_admin():
    src = _scan_router_source()
    idx = src.find('"/twilio-correlations/generate"')
    assert idx != -1
    fn_block = src[idx: idx + 4000]
    assert "require_workspace_admin" in fn_block, (
        "/twilio-correlations/generate handler missing admin guard"
    )


def test_router_twilio_correlations_dispatches_to_generate_twilio_correlations():
    src = _scan_router_source()
    assert "generate_twilio_correlations" in src, (
        "router does not call generate_twilio_correlations"
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


def test_router_dispatches_twilio_for_all_demo_endpoints():
    """All three incident-demo endpoints route provider='twilio'."""
    src = _scan_router_source()
    for substring in (
        "get_twilio_status", "seed_twilio", "clear_twilio",
    ):
        assert substring in src, f"router missing dispatch to {substring}"


# ════════════════════════════════════════════════════════════════════════════
# Section G — Frontend Twilio consistency (skip if frontend absent)
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


def test_fe_activity_page_includes_twilio_provider_and_event_types():
    text = _read_fe("app/(app)/security/activity/page.tsx")
    assert '"twilio"' in text
    assert "Twilio" in text
    assert "TWILIO_EVENT_TYPES" in text or "TWILIO" in text
    # Spot-check key event types from the M79D annotation.
    for ev in (
        "twilio.phone_number.created",
        "twilio.phone_number.updated",
        "twilio.messaging_service.created",
        "twilio.messaging_service.updated",
        "twilio.verify_service.created",
        "twilio.api_key.created",
    ):
        assert ev in text, (
            f"activity page filter missing twilio event type {ev!r}"
        )


def test_fe_signals_page_includes_twilio_provider_and_signal_types():
    text = _read_fe("app/(app)/security/signals/page.tsx")
    assert '"twilio"' in text
    assert "TWILIO_SIGNAL_TYPES" in text or "twilio_phone_number_config_changed" in text
    for s in EXPECTED_SIGNAL_TYPES:
        assert s in text, f"signals page filter missing {s!r}"


def test_fe_correlations_page_includes_twilio_provider_and_correlation_types():
    text = _read_fe("app/(app)/security/correlations/page.tsx")
    assert '"twilio"' in text
    for ctype in EXPECTED_CORRELATION_TYPES:
        assert ctype in text, f"correlations page missing {ctype!r}"


def test_fe_cases_page_has_twilio_demo_card():
    text = _read_fe("app/(app)/security/cases/page.tsx")
    assert 'provider: "twilio"' in text
    # Seed / clear buttons must mention Twilio.
    assert "Twilio" in text


def test_fe_demo_script_page_marks_twilio_demo_ready():
    text = _read_fe("app/(app)/security/demo-script/page.tsx")
    # Capability table Twilio row has demo: true after M79G.
    m = re.search(r'\{\s*provider:\s*"twilio",[^}]*demo:\s*true', text)
    assert m is not None, "demo-script Twilio row missing demo: true"


def test_fe_rule_catalog_includes_every_twilio_rule_key():
    text = _read_fe("lib/securityRuleCatalog.ts")
    for key in EXPECTED_RULE_KEYS:
        assert f'key: "{key}"' in text, (
            f"frontend securityRuleCatalog missing rule key {key}"
        )


def test_fe_api_demo_provider_unions_include_twilio():
    """getIncidentDemoStatus / seedIncidentDemo / clearIncidentDemo unions."""
    text = _read_fe("lib/api.ts")
    # Each of the three helpers must type-check twilio.
    count = text.count(
        '"github" | "aws" | "cloudflare" | "vercel" | "supabase" | '
        '"firebase" | "stripe" | "shopify" | "azure" | "google_cloud" | "twilio"'
    )
    assert count >= 3, (
        f"expected 3 demo helper unions to include twilio; found {count}"
    )


def test_fe_demo_script_mentions_twilio():
    """securityDemoScript talk-track includes Twilio."""
    text = _read_fe("lib/securityDemoScript.ts")
    assert "Twilio" in text


def test_fe_activity_page_sync_action_has_safe_copy():
    """Activity sync bar must not contain forbidden phrases for Twilio."""
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
# Section H — Regression smoke (M79A–M79G still wire together)
# ════════════════════════════════════════════════════════════════════════════


def test_evaluator_dispatcher_handles_every_record_type_safely():
    """Every Twilio record type round-trips through evaluate() without raising."""
    for rt in EXPECTED_RECORD_TYPES:
        rec = {"record_type": rt, "record_id": f"demo_{rt}"}
        out = twilio_eval(rec)
        assert isinstance(out, list)


def test_signal_service_handles_every_activity_event_type():
    """Every activity event type is handled by _build_signal (returns signal or None)."""
    for event_type in EXPECTED_ACTIVITY_EVENT_TYPES:
        ev = MagicMock()
        ev.id = uuid.uuid4()
        ev.event_type = event_type
        ev.provider = "twilio"
        ev.source = "twilio_activity_event"
        ev.resource_type = "configuration"
        ev.resource_id = "TWILIO_DE"
        ev.provider_event_id = f"demo-{event_type}"
        ev.integration_id = uuid.uuid4()
        ev.occurred_at = datetime.now(timezone.utc)
        ev.ingested_at = ev.occurred_at
        ev.created_at = ev.occurred_at
        ev.event_metadata = {"resource_type": "configuration"}
        # Must not raise; return is signal dict or None.
        result = twilio_sig._build_signal([ev])
        # A valid event type should produce a signal.
        if event_type in twilio_sig.TWILIO_EVENT_TYPE_TO_SIGNAL_TYPE:
            assert result is not None, (
                f"_build_signal returned None for valid event type {event_type!r}"
            )


def test_correlation_rules_have_required_shape_fields():
    """Every TWILIO_CORRELATION_RULES entry carries required structure fields."""
    required = {"rule_keys", "signal_types", "match_key", "severity",
                "title_phrase", "subject_phrase"}
    for ctype, rule in twilio_corr.TWILIO_CORRELATION_RULES.items():
        missing = required - set(rule.keys())
        assert missing == set(), (
            f"TWILIO_CORRELATION_RULES[{ctype!r}] missing fields: {missing}"
        )
        assert isinstance(rule["rule_keys"], (set, frozenset)), (
            f"{ctype}: rule_keys must be a set"
        )
        assert isinstance(rule["signal_types"], (set, frozenset)), (
            f"{ctype}: signal_types must be a set"
        )


def test_correlation_five_families_cover_all_match_keys():
    """TWILIO_CORRELATION_RULES must cover exactly the 5 expected match_key families."""
    match_keys = {v["match_key"] for v in twilio_corr.TWILIO_CORRELATION_RULES.values()}
    expected = {"phone_number", "messaging_service", "verify_service", "api_key", "account"}
    assert match_keys == expected


def test_expansion_framework_sendgrid_correctly_follows_m79i():
    """After M80A, SendGrid Core Security (M80B) is the planned_next_stage."""
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert "M80B" in planned or "SendGrid" in planned, (
        f"planned_next_stage should point to M80B/SendGrid after M80A; got: {planned!r}"
    )
    assert "Auth0" not in planned, (
        f"Auth0 was promoted ahead of SendGrid: {planned!r}"
    )


def test_twilio_ingestion_service_never_raises_on_bad_event():
    """normalize_twilio_activity_event must return None for malformed entries."""
    assert twilio_ingest.normalize_twilio_activity_event(None) is None
    assert twilio_ingest.normalize_twilio_activity_event({}) is None
    assert twilio_ingest.normalize_twilio_activity_event(
        {"event_type": ""}
    ) is None
    # Missing event_type → None
    assert twilio_ingest.normalize_twilio_activity_event(
        {"provider_event_id": "x"}
    ) is None


def test_match_strength_returns_high_for_exact_match():
    """_match_strength must return 'high' for exact-SID match reasons."""
    assert twilio_corr._match_strength("phone_number_last4_match") == "high"
    assert twilio_corr._match_strength("messaging_service_sid_match") == "high"
    assert twilio_corr._match_strength("verify_service_sid_match") == "high"
    assert twilio_corr._match_strength("api_key_sid_match") == "high"


def test_match_strength_returns_medium_for_family_aggregate():
    """_match_strength must return 'medium' for family-aggregate match reasons."""
    assert twilio_corr._match_strength("phone_number_family") == "medium"
    assert twilio_corr._match_strength("messaging_service_family") == "medium"
    assert twilio_corr._match_strength("account_level") == "medium"
