"""M80G — SendGrid security demo + QA hardening.

The SendGrid incident demo seeds one coherent, clearly-marked synthetic story
on a hidden demo integration:

    SendGrid configuration risks (API key broad scope, sender identity
    unverified, domain authentication invalid, spam check disabled, subscription
    tracking disabled, inbound parse spam check disabled, suppression settings
    empty)
    -> SendGrid configuration-state activity events (sendgrid.api_key.updated,
    sendgrid.sender_identity.updated, sendgrid.domain_authentication.updated,
    sendgrid.mail_settings.updated, sendgrid.tracking_settings.updated,
    sendgrid.event_webhook.updated, sendgrid.inbound_parse.updated,
    sendgrid.suppression_settings.updated)
    -> SendGrid activity signals -> SendGrid risk x activity correlations -> case.

These tests assert the seeded chain, demo isolation, seed/clear idempotency +
status, capability matrix, expansion framework pointer, frontend wording, and
claim/privacy discipline across all seeded evidence.

PRIVACY: the demo must never include API key values, bearer tokens, auth
headers, email bodies, subject lines, recipient emails, sender personal emails,
suppression recipient emails, template content, raw webhook URLs, raw inbound
parse hostnames, mail event payloads, message IDs, DNS token values, or
customer data. No strings may match SG.[A-Za-z0-9_-]{10,}.[A-Za-z0-9_-]{10,}.
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
    r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",  # SendGrid API key shape
    r"AC[0-9a-fA-F]{32}",                            # Twilio account SID shape
    r"SK[0-9a-fA-F]{32}",                            # Twilio API key SID shape
    r"https?://[a-zA-Z0-9]",                         # Raw URLs
]

# ── Forbidden metadata fields ──────────────────────────────────────────────────

FORBIDDEN_METADATA_KEYS = {
    "api_key",
    "api_key_value",
    "api_key_secret",
    "bearer",
    "authorization",
    "access_token",
    "secret",
    "from_email",
    "reply_to",
    "recipient_email",
    "sender_email",
    "suppressed_email",
    "to_email",
    "owner_email",
    "url",
    "webhook_url",
    "hostname",
    "template_content",
    "html_content",
    "plain_text_content",
    "subject",
    "body",
    "raw_payload",
    "request_body",
    "response_body",
    "message_id",
    "sg_message_id",
    "smtp_id",
    "ip_address",
    "customer",
    "contact",
}

# ── Expected SendGrid finding rule keys ────────────────────────────────────────

_EXPECTED_FINDING_RULES = {
    "sendgrid_api_key_broad_scopes",
    "sendgrid_sender_identity_unverified",
    "sendgrid_domain_authentication_invalid",
    "sendgrid_spam_check_disabled",
    "sendgrid_subscription_tracking_disabled",
    "sendgrid_inbound_parse_spam_check_disabled",
    "sendgrid_suppression_settings_empty",
}

# ── Expected activity event types ──────────────────────────────────────────────

_EXPECTED_EVENT_TYPES = {
    "sendgrid.api_key.updated",
    "sendgrid.sender_identity.updated",
    "sendgrid.domain_authentication.updated",
    "sendgrid.mail_settings.updated",
    "sendgrid.tracking_settings.updated",
    "sendgrid.event_webhook.updated",
    "sendgrid.inbound_parse.updated",
    "sendgrid.suppression_settings.updated",
}

# ── Expected signal types ──────────────────────────────────────────────────────

_EXPECTED_SIGNAL_TYPES = {
    "sendgrid_api_key_config_changed",
    "sendgrid_sender_identity_config_changed",
    "sendgrid_domain_authentication_config_changed",
    "sendgrid_mail_settings_config_changed",
    "sendgrid_tracking_settings_config_changed",
    "sendgrid_event_webhook_config_changed",
    "sendgrid_inbound_parse_config_changed",
    "sendgrid_suppression_settings_config_changed",
}

# ── Expected correlation types ─────────────────────────────────────────────────

_EXPECTED_CORRELATION_TYPES = {
    "sendgrid_api_key_risk_activity_correlation",
    "sendgrid_sender_identity_risk_activity_correlation",
    "sendgrid_domain_authentication_risk_activity_correlation",
    "sendgrid_mail_settings_risk_activity_correlation",
    "sendgrid_tracking_settings_risk_activity_correlation",
    "sendgrid_webhook_risk_activity_correlation",
    "sendgrid_suppression_settings_risk_activity_correlation",
}


# ── Helpers ────────────────────────────────────────────────────────────────────


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M80G", db=db,
    )


def _seed(db, ws, user):
    return demo_svc.seed_sendgrid(
        workspace_id=ws.id, actor_user_id=user.id, db=db,
    )


def _cleanup(db, ws_id):
    demo_svc.clear_sendgrid(workspace_id=ws_id, db=db)


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
    """A1: seed_sendgrid creates a demo integration (hidden, status='deleted')."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
        assert integ is not None
        # Integration uses DEMO_PROVIDER_TAG so it stays hidden and never syncs.
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG
        assert integ.display_name == demo_svc.SENDGRID_DEMO_INTEGRATION_NAME
    finally:
        _cleanup(db_session, ws.id)


def test_a2_demo_integration_name(test_user, db_session):
    """A2: Demo integration name is SENDGRID_DEMO_INTEGRATION_NAME."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
        assert integ is not None
        assert integ.display_name == demo_svc.SENDGRID_DEMO_INTEGRATION_NAME
    finally:
        _cleanup(db_session, ws.id)


def test_a3_demo_integration_has_sentinel_marker(test_user, db_session):
    """A3: Demo integration has the sentinel marker and status='deleted'."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
        assert integ is not None
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG
        assert integ.status == "deleted"
    finally:
        _cleanup(db_session, ws.id)


def test_a4_get_sendgrid_status_seeded_true_after_seed(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        status = demo_svc.get_sendgrid_status(ws.id, db_session)
        assert status["seeded"] is True
        assert status["case_id"] is not None
        assert status["link_count"] > 0
    finally:
        _cleanup(db_session, ws.id)


def test_a5_get_sendgrid_status_seeded_false_before_seed(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    status = demo_svc.get_sendgrid_status(ws.id, db_session)
    assert status["seeded"] is False
    assert status["case_id"] is None


# ══════════════════════════════════════════════════════════════════════════════
# B: Seeded evidence chain
# ══════════════════════════════════════════════════════════════════════════════


def test_b1_at_least_7_findings(test_user, db_session):
    """B1: At least 7 SendGrid findings on the demo integration."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
            SecurityFinding.provider == "sendgrid",
        ).all()
        assert len(findings) >= 7, f"expected >= 7 findings, got {len(findings)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b2_at_least_8_activity_events(test_user, db_session):
    """B2: At least 8 SendGrid activity events on the demo integration."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
            SecurityActivityEvent.provider == "sendgrid",
            SecurityActivityEvent.source == "sendgrid_activity_event",
        ).all()
        assert len(events) >= 8, f"expected >= 8 events, got {len(events)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b3_at_least_7_signals(test_user, db_session):
    """B3: At least 7 SendGrid signals (one per surface)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "sendgrid",
            SecurityIncidentSignal.evidence_level == "activity",
        ).all()
        assert len(sigs) >= 7, f"expected >= 7 activity signals, got {len(sigs)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b4_at_least_7_correlations(test_user, db_session):
    """B4: At least 7 SendGrid correlations (one per family)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "sendgrid",
        ).all()
        assert len(corrs) >= 7, f"expected >= 7 correlations, got {len(corrs)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b5_exactly_1_demo_case(test_user, db_session):
    """B5: Exactly 1 case with source=SENDGRID_DEMO_CASE_SOURCE."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        cases = db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.SENDGRID_DEMO_CASE_SOURCE,
        ).all()
        assert len(cases) == 1, f"expected exactly 1 demo case, got {len(cases)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b6_case_linked_to_evidence(test_user, db_session):
    """B6: Case is linked to findings, events, signals, correlations."""
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
    """C1: Findings use expected SendGrid rule keys."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        rules = {f.finding_key.split(":", 1)[0] for f in findings}
        assert _EXPECTED_FINDING_RULES <= rules, (
            f"missing rules: {_EXPECTED_FINDING_RULES - rules}"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_c2_no_secret_fields_in_finding_evidence(test_user, db_session):
    """C2: No finding evidence contains forbidden secret/email fields."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
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
        integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
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


# ══════════════════════════════════════════════════════════════════════════════
# D: Activity event shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_d1_event_types(test_user, db_session):
    """D1: Events include the expected 8 SendGrid event types."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
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
    """D2: No event metadata contains forbidden fields (api keys, emails, URLs)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        for e in events:
            md = e.event_metadata or {}
            bad = FORBIDDEN_METADATA_KEYS & set(md.keys())
            assert not bad, f"event {e.event_type!r} has forbidden keys: {bad}"
    finally:
        _cleanup(db_session, ws.id)


def test_d3_no_secret_patterns_in_event_metadata(test_user, db_session):
    """D3: No event metadata matches SendGrid/Twilio secret-shape regex."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
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


# ══════════════════════════════════════════════════════════════════════════════
# E: Signal shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_e1_signal_types(test_user, db_session):
    """E1: Signals include the expected 8 SendGrid signal types."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "sendgrid",
        ).all()
        stypes = {s.signal_type for s in sigs}
        assert _EXPECTED_SIGNAL_TYPES <= stypes, (
            f"missing signal types: {_EXPECTED_SIGNAL_TYPES - stypes}"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_e2_no_forbidden_fields_in_signal_metadata(test_user, db_session):
    """E2: No signal metadata contains forbidden fields."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "sendgrid",
        ).all()
        for s in sigs:
            md = s.signal_metadata or {}
            bad = FORBIDDEN_METADATA_KEYS & set(md.keys())
            assert not bad, f"signal {s.signal_type!r} has forbidden keys: {bad}"
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# F: Correlation shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_f1_correlation_types(test_user, db_session):
    """F1: Correlations include the expected 7 SendGrid correlation types."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "sendgrid",
        ).all()
        ctypes = {c.correlation_type for c in corrs}
        assert _EXPECTED_CORRELATION_TYPES <= ctypes, (
            f"missing correlation types: {_EXPECTED_CORRELATION_TYPES - ctypes}"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_f2_no_forbidden_fields_in_correlation_metadata(test_user, db_session):
    """F2: No correlation metadata contains forbidden fields."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "sendgrid",
        ).all()
        for c in corrs:
            md = c.correlation_metadata or {}
            bad = FORBIDDEN_METADATA_KEYS & set(md.keys())
            assert not bad, f"correlation {c.correlation_type!r} has forbidden keys: {bad}"
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# G: Idempotency + clear isolation
# ══════════════════════════════════════════════════════════════════════════════


def test_g1_seed_is_idempotent(test_user, db_session):
    """G1: Calling seed twice returns the existing case, no duplicate evidence."""
    ws = _ws(test_user, db_session)
    try:
        r1 = _seed(db_session, ws, test_user)
        r2 = _seed(db_session, ws, test_user)
        assert r1["case_id"] == r2["case_id"]
        assert r2.get("created") is False
        # Only 1 case for the demo source
        cases = db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.SENDGRID_DEMO_CASE_SOURCE,
        ).all()
        assert len(cases) == 1
    finally:
        _cleanup(db_session, ws.id)


def test_g2_clear_removes_all_demo_objects(test_user, db_session):
    """G2: clear_sendgrid removes integration, findings, events, signals, corrs, case."""
    ws = _ws(test_user, db_session)
    _seed(db_session, ws, test_user)
    _cleanup(db_session, ws.id)
    # After clear, demo integration is gone.
    integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
    assert integ is None
    # No demo case left.
    cases = db_session.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws.id,
        SecurityCase.case_metadata["source"].astext == demo_svc.SENDGRID_DEMO_CASE_SOURCE,
    ).all()
    assert len(cases) == 0


def test_g3_clear_does_not_touch_other_demos(test_user, db_session):
    """G3: clear_sendgrid does not touch Twilio demo objects."""
    ws = _ws(test_user, db_session)
    try:
        # Seed both demos.
        demo_svc.seed_twilio(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        _seed(db_session, ws, test_user)
        # Clear ONLY SendGrid.
        demo_svc.clear_sendgrid(workspace_id=ws.id, db=db_session)
        # SendGrid demo objects are gone.
        sg_integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
        assert sg_integ is None
        # Twilio demo objects are still there.
        tw_integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        assert tw_integ is not None
    finally:
        # Cleanup Twilio too.
        demo_svc.clear_twilio(workspace_id=ws.id, db=db_session)
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# H: Case + case report
# ══════════════════════════════════════════════════════════════════════════════


def test_h1_case_provider_is_sendgrid(test_user, db_session):
    """H1: The demo case has provider='sendgrid'."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])
        ).first()
        assert case is not None
        assert case.provider == "sendgrid"
    finally:
        _cleanup(db_session, ws.id)


def test_h2_case_metadata_has_demo_source(test_user, db_session):
    """H2: The demo case is tagged with the SendGrid demo source."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])
        ).first()
        assert case is not None
        md = case.case_metadata or {}
        assert md.get("source") == demo_svc.SENDGRID_DEMO_CASE_SOURCE
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


def test_h4_case_report_renders_sendgrid(test_user, db_session):
    """H4: Case report builds and references sendgrid provider/source labels."""
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
        # No forbidden patterns / wording in the rendered report
        hits = _scan_for_patterns(blob, FORBIDDEN_DEMO_DATA_PATTERNS)
        assert not hits, f"report contains forbidden patterns: {hits}"
        low = blob.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in low, f"forbidden phrase {phrase!r} in case report"
        # Should reference sendgrid
        assert "sendgrid" in low
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# I: Capability matrix + expansion framework
# ══════════════════════════════════════════════════════════════════════════════


def test_i1_capability_matrix_demo_seed_clear_true():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("sendgrid")
    assert cap.security.demo_seed_clear is True


def test_i2_capability_matrix_case_report_true():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("sendgrid")
    assert cap.security.case_report is True


def test_i3_capability_matrix_partial_maturity():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("sendgrid")
    assert cap.maturity == "partial"


def test_i4_notes_mention_m80g_or_demo():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("sendgrid")
    assert "M80G" in cap.notes or "demo" in cap.notes.lower(), (
        f"capability notes should mention M80G or demo: {cap.notes!r}"
    )


def test_i5_expansion_framework_points_to_m80h():
    """Regression note: Kubernetes launched (message 1 / M89A) — Sentry/M90A is now next."""
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M90A" in stage or "Sentry" in stage, (
        f"planned_next_stage should reference M90A Sentry; got: {stage!r}"
    )


def test_i6_expansion_framework_not_m80g():
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M80G" not in stage


# ══════════════════════════════════════════════════════════════════════════════
# J: Frontend references
# ══════════════════════════════════════════════════════════════════════════════


def test_j1_cases_page_has_sendgrid_demo_card():
    """J1: Cases page has SendGrid in PROVIDER_DEMO_CARDS."""
    text = FE_CASES.read_text()
    assert "sendgrid" in text
    assert "SendGrid" in text
    # Should have a SendGrid demo card
    assert "SendGrid security demo" in text or "Load SendGrid security demo" in text


def test_j2_cases_page_has_review_safe_copy():
    """J2: Cases page SendGrid copy mentions review-safe + no API keys / email bodies."""
    text = FE_CASES.read_text()
    # Find the SendGrid card section
    assert "review-safe SendGrid" in text or "SendGrid security demo" in text
    # Should mention not storing email bodies or API keys (in SendGrid card body)
    assert "email bodies" in text
    assert "API key" in text


def test_j3_demo_script_page_has_sendgrid_row():
    """J3: Demo-script page has SendGrid in the capability table."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    # SendGrid row exists
    assert 'provider: "sendgrid"' in text
    # SendGrid is now marked demo: true (M80G)
    # Find SendGrid row and assert demo: true
    match = re.search(r'\{ provider: "sendgrid".*?demo: (true|false)', text)
    assert match is not None, "SendGrid row not found in demo capability table"
    assert match.group(1) == "true", f"SendGrid demo should be true (M80G), got {match.group(1)}"


def test_j4_demo_script_lib_mentions_sendgrid():
    """J4: securityDemoScript.ts mentions SendGrid in the demo script."""
    text = FE_DEMO_SCRIPT_LIB.read_text()
    assert "SendGrid" in text


def test_j5_cases_page_no_forbidden_wording():
    text = FE_CASES.read_text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text, f"forbidden phrase {phrase!r} in cases page"


def test_j6_demo_script_page_no_forbidden_wording():
    text = FE_DEMO_SCRIPT_PAGE.read_text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text, f"forbidden phrase {phrase!r} in demo-script page"


def test_j7_demo_script_lib_mentions_sendgrid():
    """J7: securityDemoScript mentions SendGrid in the demo script tour."""
    # NOTE: not a forbidden-phrase grep — securityDemoScript contains
    # intentional anti-example references ("Avoid 'breach detected'...")
    # and disclaimer text ("does not confirm... that someone has access")
    # which are review-safe by design. Forbidden-wording checks are scoped
    # to NEW M80G code (backend service + frontend cases page).
    text = FE_DEMO_SCRIPT_LIB.read_text()
    assert "SendGrid" in text, "securityDemoScript should mention SendGrid (M80G)"


# ══════════════════════════════════════════════════════════════════════════════
# K: Secret-shape scan
# ══════════════════════════════════════════════════════════════════════════════


def test_k1_no_secret_shapes_in_demo_service_source():
    """K1: The demo service source itself has no SendGrid/Twilio secret-shape strings."""
    import inspect
    from app.services import security_incident_demo_service
    src = inspect.getsource(security_incident_demo_service)
    hits = _scan_for_patterns(src, [
        r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"AC[0-9a-fA-F]{32}",
        r"SK[0-9a-fA-F]{32}",
    ])
    assert not hits, f"secret-shape patterns in demo service source: {hits}"


def test_k2_no_secret_shapes_in_test_module():
    """K2: This test module has no secret-shape strings (placeholders only)."""
    text = Path(__file__).read_text()
    # We have to exclude regex pattern lines (which describe the shape).
    # Strip lines that contain '_PATTERN' or 'pattern' to avoid the regex defs.
    lines = [
        ln for ln in text.splitlines()
        if "FORBIDDEN_DEMO_DATA_PATTERNS" not in ln
        and 'r"SG' not in ln
        and 'r"AC' not in ln
        and 'r"SK' not in ln
    ]
    scrubbed = "\n".join(lines)
    hits = _scan_for_patterns(scrubbed, [
        r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"AC[0-9a-fA-F]{32}",
        r"SK[0-9a-fA-F]{32}",
    ])
    assert not hits, f"secret-shape patterns in test module: {hits}"
