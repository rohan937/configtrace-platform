"""M82G — Datadog security demo + QA.

The Datadog incident demo seeds one coherent, clearly-marked synthetic story
on a hidden demo integration:

    Datadog webhook integration posture risks (missing secret headers,
    non-HTTPS endpoint, auth material in custom headers)
    -> Datadog configuration-state activity event
    (datadog.webhook_integration.updated)
    -> Datadog activity signal (datadog_webhook_integration_config_changed)
    -> Datadog risk x activity correlation
    (datadog_webhook_risk_activity_correlation)
    -> case.

These tests assert the seeded chain, demo isolation, seed/clear idempotency +
status, capability matrix, expansion framework pointer, frontend wording, and
claim/privacy discipline across all seeded evidence.

PRIVACY: the demo must never include API key values, application key values,
OAuth tokens, bearer tokens, webhook secrets, integration secrets, raw monitor
queries, raw monitor messages, raw dashboard JSON, raw widget queries,
notebook content, raw incident text, raw logs, raw traces, raw metric values,
raw event payloads, email addresses, user IDs, user names, team member
identities, notification channel destinations, Slack channel names, PagerDuty
service IDs, webhook URLs, customer data, raw audit payloads, IP addresses,
user agents, or PII. No strings may match
``eyJ[A-Za-z0-9_-]{10,}`` (JWT shape).
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from app.models.integration import Integration
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_case import SecurityCase, SecurityCaseLink
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.services import security_case_report_service as report_svc
from app.services import security_incident_demo_service as demo_svc
from app.services import workspace_service


REPO_ROOT = Path(__file__).resolve().parents[2]
FE_CASES = REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "cases" / "page.tsx"
FE_DEMO_SCRIPT_PAGE = REPO_ROOT / "frontend" / "src" / "app" / "(app)" / "security" / "demo-script" / "page.tsx"
FE_DEMO_SCRIPT_LIB = REPO_ROOT / "frontend" / "src" / "lib" / "securityDemoScript.ts"

# ── Forbidden wording ──────────────────────────────────────────────────────────

FORBIDDEN_PHRASES = [
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

# ── Forbidden demo-data patterns ───────────────────────────────────────────────

FORBIDDEN_DEMO_DATA_PATTERNS = [
    r"eyJ[A-Za-z0-9_-]{10,}",                       # JWT / token shape
    r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",  # SendGrid API key shape
    r"AC[0-9a-fA-F]{32}",                           # Twilio account SID shape
    r"SK[0-9a-fA-F]{32}",                           # Twilio API key SID shape
    r"https?://[a-zA-Z0-9]",                        # Raw URLs
]

# ── Forbidden metadata keys ────────────────────────────────────────────────────

FORBIDDEN_METADATA_KEYS = {
    # Datadog credential / secret material
    "api_key",
    "application_key",
    "oauth_token",
    "bearer_token",
    "webhook_secret",
    "integration_secret",
    "secret",
    "token",
    "headers",
    "authorization",
    "bearer",
    # Raw content fields that must never be stored
    "request",
    "response",
    "payload",
    "raw",
    "details",
    "body",
    "message",
    "query",
    "dashboard_json",
    "widget_query",
    "notebook_content",
    "incident_text",
    "log",
    "logs",
    "trace",
    "traces",
    "metric",
    "metrics",
    "event_payload",
    # PII
    "email",
    "user_email",
    "user_id",
    "user_name",
    "username",
    "ip_address",
    "device",
    "user_agent",
    "destination",
    "channel",
    "slack",
    "pagerduty",
    "webhook_url",
    "actor",
    "actor_id",
    "actor_name",
    "actor_email",
    "team_member",
    "customer_data",
    "pii",
    "raw_payload",
    "raw_response",
    "audit_payload",
    # Generic identifiers that could be PII when present as plain "user"
    "user",
}

# ── Expected Datadog finding rule keys ────────────────────────────────────────

_EXPECTED_FINDING_RULES = {
    "datadog_webhook_without_secret_headers",
    "datadog_webhook_non_https_endpoint",
    "datadog_webhook_auth_material_present",
}

# ── Expected activity event types ──────────────────────────────────────────────

_EXPECTED_EVENT_TYPES = {
    "datadog.webhook_integration.updated",
}

# ── Expected signal types ──────────────────────────────────────────────────────

_EXPECTED_SIGNAL_TYPES = {
    "datadog_webhook_integration_config_changed",
}

# ── Expected correlation types ─────────────────────────────────────────────────

_EXPECTED_CORRELATION_TYPES = {
    "datadog_webhook_risk_activity_correlation",
}


# ── Helpers ────────────────────────────────────────────────────────────────────


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M82G", db=db,
    )


def _seed(db, ws, user):
    return demo_svc.seed_datadog(
        workspace_id=ws.id, actor_user_id=user.id, db=db,
    )


def _cleanup(db, ws_id):
    demo_svc.clear_datadog(workspace_id=ws_id, db=db)


def _scan_for_patterns(blob: str, patterns: list[str]) -> list[str]:
    hits = []
    for pat in patterns:
        if re.search(pat, blob):
            hits.append(pat)
    return hits


# ══════════════════════════════════════════════════════════════════════════════
# A: Demo integration
# ══════════════════════════════════════════════════════════════════════════════


def test_a1_seed_creates_demo_integration(test_user, db_session):
    """A1: seed_datadog creates a demo integration (hidden, status='deleted')."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        assert integ is not None
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG
        assert integ.display_name == demo_svc.DATADOG_DEMO_INTEGRATION_NAME
    finally:
        _cleanup(db_session, ws.id)


def test_a2_demo_integration_status_deleted(test_user, db_session):
    """A2: Demo integration has status='deleted' (never synced/shown)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        assert integ is not None
        assert integ.status == "deleted"
        assert integ.scheduled_sync_enabled is False
    finally:
        _cleanup(db_session, ws.id)


def test_a3_get_datadog_status_seeded_true_after_seed(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        status = demo_svc.get_datadog_status(ws.id, db_session)
        assert status["seeded"] is True
        assert status["case_id"] is not None
        assert status["link_count"] > 0
    finally:
        _cleanup(db_session, ws.id)


def test_a4_get_datadog_status_seeded_false_before_seed(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    status = demo_svc.get_datadog_status(ws.id, db_session)
    assert status["seeded"] is False
    assert status["case_id"] is None


# ══════════════════════════════════════════════════════════════════════════════
# B: Seeded evidence chain
# ══════════════════════════════════════════════════════════════════════════════


def test_b1_at_least_3_findings(test_user, db_session):
    """B1: At least 3 Datadog webhook findings (covering 3 webhook posture rules)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
            SecurityFinding.provider == "datadog",
        ).all()
        assert len(findings) >= 3, f"expected >= 3 findings, got {len(findings)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b2_at_least_1_activity_event(test_user, db_session):
    """B2: At least 1 Datadog webhook integration activity event."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
            SecurityActivityEvent.provider == "datadog",
            SecurityActivityEvent.source == "datadog_activity_event",
        ).all()
        assert len(events) >= 1, f"expected >= 1 event, got {len(events)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b3_at_least_1_signal(test_user, db_session):
    """B3: At least 1 Datadog webhook integration activity signal."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "datadog",
            SecurityIncidentSignal.evidence_level == "activity",
        ).all()
        assert len(sigs) >= 1, f"expected >= 1 activity signal, got {len(sigs)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b4_at_least_1_correlation(test_user, db_session):
    """B4: At least 1 Datadog webhook risk x activity correlation."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "datadog",
        ).all()
        assert len(corrs) >= 1, f"expected >= 1 correlation, got {len(corrs)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b5_exactly_1_demo_case(test_user, db_session):
    """B5: Exactly 1 case with source=DATADOG_DEMO_CASE_SOURCE."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        cases = db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.DATADOG_DEMO_CASE_SOURCE,
        ).all()
        assert len(cases) == 1, f"expected exactly 1 demo case, got {len(cases)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b6_case_linked_to_all_evidence_types(test_user, db_session):
    """B6: Case is linked to findings, events, signals, and correlations."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        links = db_session.query(SecurityCaseLink).filter(
            SecurityCaseLink.case_id == case_id,
        ).all()
        link_types = {lnk.linked_object_type for lnk in links}
        assert "finding" in link_types
        assert "activity_event" in link_types
        assert "signal" in link_types
        assert "correlation" in link_types
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# C: Finding shapes (rule keys, privacy)
# ══════════════════════════════════════════════════════════════════════════════


def test_c1_finding_rule_keys(test_user, db_session):
    """C1: Findings use expected Datadog webhook rule keys."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        rules = {f.finding_key.split(":", 1)[0] for f in findings}
        assert _EXPECTED_FINDING_RULES <= rules, (
            f"missing rules: {_EXPECTED_FINDING_RULES - rules}"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_c2_no_forbidden_fields_in_finding_evidence(test_user, db_session):
    """C2: No finding evidence contains forbidden credential/secret/PII fields."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        for f in findings:
            ev = f.evidence or {}
            bad = FORBIDDEN_METADATA_KEYS & set(ev.keys())
            assert not bad, f"finding {f.finding_key} has forbidden keys: {bad}"
            ev_str = json.dumps(ev)
            hits = _scan_for_patterns(ev_str, FORBIDDEN_DEMO_DATA_PATTERNS)
            assert not hits, (
                f"finding {f.finding_key} evidence matches forbidden patterns: "
                f"{hits} in {ev_str[:200]}"
            )
    finally:
        _cleanup(db_session, ws.id)


def test_c3_findings_marked_as_demo(test_user, db_session):
    """C3: All findings include demo=True in evidence."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        for f in findings:
            ev = f.evidence or {}
            assert ev.get("demo") is True, (
                f"finding {f.finding_key} missing demo=True marker"
            )
    finally:
        _cleanup(db_session, ws.id)


def test_c4_findings_use_safe_placeholder_resource_id(test_user, db_session):
    """C4: All findings reference the safe demo webhook ID placeholder."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        for f in findings:
            ev = f.evidence or {}
            assert ev.get("record_id") == demo_svc._DATADOG_DEMO_WEBHOOK_ID, (
                f"finding {f.finding_key} record_id is not the safe placeholder"
            )
    finally:
        _cleanup(db_session, ws.id)


def test_c5_finding_descriptions_have_review_disclaimer(test_user, db_session):
    """C5: Finding descriptions include 'evidence for review' style disclaimer."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        for f in findings:
            desc = (f.description or "").lower()
            assert "evidence for review" in desc, (
                f"finding {f.finding_key} description missing review disclaimer"
            )
            assert "does not confirm" in desc, (
                f"finding {f.finding_key} description missing safety disclaimer"
            )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# D: Activity event shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_d1_event_types(test_user, db_session):
    """D1: Events include the expected Datadog webhook integration event type."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        etypes = {e.event_type for e in events}
        assert _EXPECTED_EVENT_TYPES <= etypes, (
            f"missing event types: {_EXPECTED_EVENT_TYPES - etypes}"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_d2_no_forbidden_fields_in_event_metadata(test_user, db_session):
    """D2: No event metadata contains forbidden credential/PII fields."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        for e in events:
            md = e.event_metadata or {}
            bad = FORBIDDEN_METADATA_KEYS & set(md.keys())
            assert not bad, f"event {e.event_type!r} has forbidden keys: {bad}"
    finally:
        _cleanup(db_session, ws.id)


def test_d3_no_jwt_patterns_in_event_metadata(test_user, db_session):
    """D3: No event metadata matches JWT/token secret-shape regex."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        for e in events:
            md_str = json.dumps(e.event_metadata or {})
            hits = _scan_for_patterns(md_str, FORBIDDEN_DEMO_DATA_PATTERNS)
            assert not hits, (
                f"event {e.event_type!r} metadata matches forbidden patterns: "
                f"{hits} in {md_str[:200]}"
            )
    finally:
        _cleanup(db_session, ws.id)


def test_d4_events_have_datadog_provider_and_source(test_user, db_session):
    """D4: Activity events have provider='datadog' and source='datadog_activity_event'."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        for e in events:
            assert e.provider == "datadog", f"event {e.event_type!r} has provider={e.provider!r}"
            assert e.source == "datadog_activity_event", (
                f"event {e.event_type!r} has source={e.source!r}"
            )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# E: Signal shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_e1_signal_types(test_user, db_session):
    """E1: Signals include the expected Datadog webhook signal type."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "datadog",
        ).all()
        stypes = {s.signal_type for s in sigs}
        assert _EXPECTED_SIGNAL_TYPES <= stypes, (
            f"missing signal types: {_EXPECTED_SIGNAL_TYPES - stypes}"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_e2_no_forbidden_fields_in_signal_metadata(test_user, db_session):
    """E2: No signal metadata contains forbidden credential/PII fields."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "datadog",
        ).all()
        for s in sigs:
            md = s.signal_metadata or {}
            bad = FORBIDDEN_METADATA_KEYS & set(md.keys())
            assert not bad, f"signal {s.signal_type!r} has forbidden keys: {bad}"
    finally:
        _cleanup(db_session, ws.id)


def test_e3_no_jwt_patterns_in_signal_metadata(test_user, db_session):
    """E3: No signal metadata matches JWT/token secret-shape regex."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "datadog",
        ).all()
        for s in sigs:
            md_str = json.dumps(s.signal_metadata or {})
            hits = _scan_for_patterns(md_str, FORBIDDEN_DEMO_DATA_PATTERNS)
            assert not hits, (
                f"signal {s.signal_type!r} metadata matches forbidden patterns: "
                f"{hits} in {md_str[:200]}"
            )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# F: Correlation shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_f1_correlation_types(test_user, db_session):
    """F1: Correlations include the expected Datadog webhook correlation type."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "datadog",
        ).all()
        ctypes = {c.correlation_type for c in corrs}
        assert _EXPECTED_CORRELATION_TYPES <= ctypes, (
            f"missing correlation types: {_EXPECTED_CORRELATION_TYPES - ctypes}"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_f2_no_forbidden_fields_in_correlation_metadata(test_user, db_session):
    """F2: No correlation metadata contains forbidden credential/PII fields."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "datadog",
        ).all()
        for c in corrs:
            md = c.correlation_metadata or {}
            bad = FORBIDDEN_METADATA_KEYS & set(md.keys())
            assert not bad, f"correlation {c.correlation_type!r} has forbidden keys: {bad}"
    finally:
        _cleanup(db_session, ws.id)


def test_f3_no_jwt_patterns_in_correlation_metadata(test_user, db_session):
    """F3: No correlation metadata matches JWT/token secret-shape regex."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "datadog",
        ).all()
        for c in corrs:
            md_str = json.dumps(c.correlation_metadata or {})
            hits = _scan_for_patterns(md_str, FORBIDDEN_DEMO_DATA_PATTERNS)
            assert not hits, (
                f"correlation {c.correlation_type!r} metadata matches forbidden "
                f"patterns: {hits} in {md_str[:200]}"
            )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# G: Idempotency + clear isolation
# ══════════════════════════════════════════════════════════════════════════════


def test_g1_seed_is_idempotent(test_user, db_session):
    """G1: Calling seed_datadog twice returns the existing case, no duplicates."""
    ws = _ws(test_user, db_session)
    try:
        r1 = _seed(db_session, ws, test_user)
        r2 = _seed(db_session, ws, test_user)
        assert r1["case_id"] == r2["case_id"]
        assert r2.get("created") is False
        cases = db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.DATADOG_DEMO_CASE_SOURCE,
        ).all()
        assert len(cases) == 1
    finally:
        _cleanup(db_session, ws.id)


def test_g2_clear_removes_all_demo_objects(test_user, db_session):
    """G2: clear_datadog removes integration, findings, events, signals, corrs, case."""
    ws = _ws(test_user, db_session)
    _seed(db_session, ws, test_user)
    _cleanup(db_session, ws.id)
    integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
    assert integ is None
    cases = db_session.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws.id,
        SecurityCase.case_metadata["source"].astext == demo_svc.DATADOG_DEMO_CASE_SOURCE,
    ).all()
    assert len(cases) == 0


def test_g3_clear_is_idempotent(test_user, db_session):
    """G3: clear_datadog can be safely run twice with no error."""
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    # No-op clear when nothing is seeded
    res1 = demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)
    assert res1.get("cleared") is True
    # Seed then clear twice
    _seed(db_session, ws, test_user)
    res2 = demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)
    assert res2.get("cleared") is True
    res3 = demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)
    assert res3.get("cleared") is True


def test_g4_clear_does_not_touch_auth0_demo(test_user, db_session):
    """G4: clear_datadog does not touch Auth0 demo objects."""
    ws = _ws(test_user, db_session)
    try:
        demo_svc.seed_auth0(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        _seed(db_session, ws, test_user)
        demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)
        dd_integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        assert dd_integ is None
        auth0_integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
        assert auth0_integ is not None
    finally:
        demo_svc.clear_auth0(workspace_id=ws.id, db=db_session)
        _cleanup(db_session, ws.id)


def test_g5_status_reports_correctly(test_user, db_session):
    """G5: Status is unseeded before seed, seeded after, unseeded after clear."""
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    s0 = demo_svc.get_datadog_status(ws.id, db_session)
    assert s0["seeded"] is False

    _seed(db_session, ws, test_user)
    s1 = demo_svc.get_datadog_status(ws.id, db_session)
    assert s1["seeded"] is True
    assert s1["link_count"] > 0

    _cleanup(db_session, ws.id)
    s2 = demo_svc.get_datadog_status(ws.id, db_session)
    assert s2["seeded"] is False


def test_g6_clear_does_not_touch_real_datadog_integrations(test_user, db_session):
    """G6: clear_datadog does not delete user Datadog integrations (provider='datadog')."""
    ws = _ws(test_user, db_session)
    try:
        # Insert a real (non-demo) Datadog integration row
        from app.core.encryption import encrypt_credentials
        ct, iv = encrypt_credentials({"api_key": "DATADOG_TEST_API_KEY_PLACEHOLDER"})
        real_integ = Integration(
            user_id=test_user.id,
            workspace_id=ws.id,
            provider="datadog",  # NOT "demo"
            display_name="Real user Datadog integration",
            encrypted_credentials=ct,
            credential_iv=iv,
            status="active",
            scheduled_sync_enabled=True,
        )
        db_session.add(real_integ)
        db_session.commit()
        real_id = real_integ.id

        _seed(db_session, ws, test_user)
        demo_svc.clear_datadog(workspace_id=ws.id, db=db_session)

        # The real integration must still exist
        still_there = db_session.query(Integration).filter(Integration.id == real_id).first()
        assert still_there is not None
        assert still_there.provider == "datadog"
        assert still_there.status == "active"
    finally:
        _cleanup(db_session, ws.id)
        db_session.query(Integration).filter(
            Integration.workspace_id == ws.id,
            Integration.provider == "datadog",
        ).delete(synchronize_session=False)
        db_session.commit()


# ══════════════════════════════════════════════════════════════════════════════
# H: Case + case report
# ══════════════════════════════════════════════════════════════════════════════


def test_h1_case_provider_is_datadog(test_user, db_session):
    """H1: The demo case has provider='datadog'."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])
        ).first()
        assert case is not None
        assert case.provider == "datadog"
    finally:
        _cleanup(db_session, ws.id)


def test_h2_case_metadata_has_demo_source(test_user, db_session):
    """H2: The demo case is tagged with the Datadog demo source."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])
        ).first()
        assert case is not None
        md = case.case_metadata or {}
        assert md.get("source") == demo_svc.DATADOG_DEMO_CASE_SOURCE
    finally:
        _cleanup(db_session, ws.id)


def test_h3_case_summary_no_forbidden_wording(test_user, db_session):
    """H3: Case title/summary do not contain forbidden claim wording."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])
        ).first()
        blob = ((case.title or "") + " " + (case.summary or "")).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in blob, f"forbidden phrase {phrase!r} in case copy"
    finally:
        _cleanup(db_session, ws.id)


def test_h4_case_report_renders_datadog(test_user, db_session):
    """H4: Case report builds and references datadog provider/source labels."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])
        ).first()
        assert case is not None
        report = report_svc.build_case_report(case=case, db=db_session)
        assert report is not None
        blob = json.dumps(report, default=str)
        hits = _scan_for_patterns(blob, FORBIDDEN_DEMO_DATA_PATTERNS)
        assert not hits, f"report contains forbidden patterns: {hits}"
        low = blob.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in low, f"forbidden phrase {phrase!r} in case report"
        assert "datadog" in low
    finally:
        _cleanup(db_session, ws.id)


def test_h5_case_summary_includes_safe_disclaimers(test_user, db_session):
    """H5: Case summary references 'evidence for review' and the safety disclaimer."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])
        ).first()
        summary = (case.summary or "").lower()
        assert "evidence for review" in summary
        assert "does not confirm" in summary
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# I: Capability matrix + expansion framework
# ══════════════════════════════════════════════════════════════════════════════


def test_i1_capability_matrix_demo_seed_clear_true():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("datadog")
    assert cap is not None
    assert cap.security.demo_seed_clear is True


def test_i2_capability_matrix_case_report_true():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("datadog")
    assert cap is not None
    assert cap.security.case_report is True


def test_i3_capability_matrix_activity_signals_correlations_still_true():
    """M82E/F caps remain true after M82G."""
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("datadog")
    assert cap is not None
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True


def test_i4_capability_matrix_partial_maturity():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("datadog")
    assert cap is not None
    assert cap.maturity == "partial"


def test_i5_notes_mention_m82g_or_demo():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("datadog")
    assert cap is not None
    assert "M82G" in cap.notes or "demo" in cap.notes.lower(), (
        f"capability notes should mention M82G or demo: {cap.notes!r}"
    )


def test_i6_expansion_framework_points_to_m83a():
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert ("M83A" in stage or "Clerk" in stage or "M84A" in stage or "PagerDuty" in stage
            or "M85A" in stage or "Linear" in stage
            or "M86" in stage or "Jira" in stage
            or "M87" in stage or "GitLab" in stage), (
        f"expected planned_next_stage to reference M83A/Clerk or later; got {stage!r}"
    )


def test_i7_expansion_framework_not_m82g():
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M82G" not in stage, (
        f"planned_next_stage should have advanced past M82G; got {stage!r}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# J: Frontend references
# ══════════════════════════════════════════════════════════════════════════════


def test_j1_cases_page_has_datadog_demo_card():
    """J1: Cases page has Datadog in PROVIDER_DEMO_CARDS."""
    text = FE_CASES.read_text()
    assert "datadog" in text
    assert "Datadog" in text
    assert "Load Datadog security demo" in text


def test_j2_cases_page_has_review_safe_copy():
    """J2: Cases page Datadog copy mentions review-safe + no API keys / webhook URLs."""
    text = FE_CASES.read_text()
    assert "review-safe Datadog" in text or "Datadog security demo" in text
    assert "API key" in text or "webhook URL" in text


def test_j3_demo_script_page_has_datadog_row_demo_true():
    """J3: Demo-script page has Datadog with demo: true."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert 'provider: "datadog"' in text
    match = re.search(r'\{ provider: "datadog".*?demo: (true|false)', text)
    assert match is not None, "Datadog row not found in demo capability table"
    assert match.group(1) == "true", (
        f"Datadog demo should be true (M82G), got {match.group(1)}"
    )


def test_j4_demo_script_page_datadog_signals_true():
    """J4: Demo-script page has Datadog with signals: true."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    match = re.search(r'\{ provider: "datadog".*?signals: (true|false)', text)
    assert match is not None, "Datadog row not found in demo capability table"
    assert match.group(1) == "true", (
        f"Datadog signals should be true (M82E), got {match.group(1)}"
    )


def test_j5_demo_script_page_datadog_correlations_true():
    """J5: Demo-script page has Datadog with correlations: true."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    match = re.search(r'\{ provider: "datadog".*?correlations: (true|false)', text)
    assert match is not None, "Datadog row not found in demo capability table"
    assert match.group(1) == "true", (
        f"Datadog correlations should be true (M82F), got {match.group(1)}"
    )


def test_j6_demo_script_lib_mentions_datadog():
    """J6: securityDemoScript.ts mentions Datadog in the demo script."""
    text = FE_DEMO_SCRIPT_LIB.read_text()
    assert "Datadog" in text, "securityDemoScript should mention Datadog (M82G)"


def test_j7_cases_page_no_forbidden_wording():
    text = FE_CASES.read_text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text, f"forbidden phrase {phrase!r} in cases page"


def test_j8_demo_script_page_no_forbidden_wording():
    text = FE_DEMO_SCRIPT_PAGE.read_text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text, f"forbidden phrase {phrase!r} in demo-script page"


def test_j9_case_report_timeline_label_datadog():
    """J9: Case report timeline labels include Datadog."""
    from app.services import security_case_report_service
    import inspect
    src = inspect.getsource(security_case_report_service)
    assert '"datadog": "Datadog"' in src, (
        "case report timeline labels should include 'datadog': 'Datadog'"
    )


# ══════════════════════════════════════════════════════════════════════════════
# K: Secret-shape scan + safe-placeholder constants
# ══════════════════════════════════════════════════════════════════════════════


def test_k1_no_jwt_shapes_in_demo_service_source():
    """K1: The demo service source itself has no JWT/token secret-shape strings."""
    import inspect
    from app.services import security_incident_demo_service
    src = inspect.getsource(security_incident_demo_service)
    hits = _scan_for_patterns(src, [
        r"eyJ[A-Za-z0-9_-]{10,}",
        r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"AC[0-9a-fA-F]{32}",
        r"SK[0-9a-fA-F]{32}",
    ])
    assert not hits, f"secret-shape patterns in demo service source: {hits}"


def test_k2_no_secret_shapes_in_test_module():
    """K2: This test module has no secret-shape strings (placeholders only)."""
    text = Path(__file__).read_text()
    lines = [
        ln for ln in text.splitlines()
        if "FORBIDDEN_DEMO_DATA_PATTERNS" not in ln
        and 'r"eyJ' not in ln
        and 'r"SG' not in ln
        and 'r"AC' not in ln
        and 'r"SK' not in ln
    ]
    scrubbed = "\n".join(lines)
    hits = _scan_for_patterns(scrubbed, [
        r"eyJ[A-Za-z0-9_-]{10,}",
        r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"AC[0-9a-fA-F]{32}",
        r"SK[0-9a-fA-F]{32}",
    ])
    assert not hits, f"secret-shape patterns in test module: {hits}"


def test_k3_demo_service_datadog_constants_are_safe_placeholders():
    """K3: Datadog demo constants use only safe placeholder strings."""
    assert demo_svc.DATADOG_DEMO_INTEGRATION_NAME == (
        "ConfigTrace Datadog incident demo (sample data)"
    )
    assert demo_svc.DATADOG_DEMO_CASE_SOURCE == "demo_datadog_incident"
    # Placeholder ID is a clearly-labelled demo sentinel string, never a JWT/secret
    assert demo_svc._DATADOG_DEMO_WEBHOOK_ID == "demo_datadog_webhook_001"


def test_k4_no_real_url_in_seeded_evidence(test_user, db_session):
    """K4: No real URL appears in seeded finding evidence / event metadata."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_datadog_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        # Findings: evidence should not contain raw URLs (only url_present booleans)
        for f in findings:
            ev_str = json.dumps(f.evidence or {})
            # The "http" string is allowed as a category value ("url_scheme_category": "http")
            # so we only forbid full http(s):// URLs.
            assert not re.search(r'https?://[a-zA-Z0-9]', ev_str), (
                f"finding {f.finding_key} evidence contains a raw URL: {ev_str[:200]}"
            )
        for e in events:
            md_str = json.dumps(e.event_metadata or {})
            assert not re.search(r'https?://[a-zA-Z0-9]', md_str), (
                f"event {e.event_type!r} metadata contains a raw URL: {md_str[:200]}"
            )
    finally:
        _cleanup(db_session, ws.id)
