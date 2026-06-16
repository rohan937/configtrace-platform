"""M79G — Twilio security demo + QA hardening.

The Twilio incident demo seeds one coherent, clearly-marked synthetic story on
a hidden demo integration:

    Twilio configuration risks (phone number SMS webhook missing, messaging
    service observability gap, Verify service short code length, stale API key)
    -> Twilio Monitor-style activity events (twilio.phone_number.updated,
    twilio.messaging_service.updated, twilio.messaging_service.sender_pool.updated,
    twilio.verify_service.updated, twilio.api_key.updated)
    -> Twilio activity signals -> Twilio risk x activity correlations -> a case.

These tests assert the seeded chain, demo isolation, seed/clear idempotency +
status, capability matrix, expansion framework pointer, frontend wording, and
claim/privacy discipline across all seeded evidence.
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
    r"AC[0-9a-fA-F]{32}",   # Twilio account SID shape
    r"SK[0-9a-fA-F]{32}",   # Twilio API key SID shape
    r"\+1[0-9]{10}",         # E.164 US phone number
    r"https?://[a-zA-Z0-9]", # Raw URLs
]

# ── Expected Twilio finding rule keys ──────────────────────────────────────────

_EXPECTED_FINDING_RULES = {
    "twilio_phone_number_sms_webhook_missing",
    "twilio_messaging_service_observability_gap",
    "twilio_verify_short_code_length",
    "twilio_api_key_stale",
}

# ── Expected activity event types ─────────────────────────────────────────────

_EXPECTED_EVENT_TYPES = {
    "twilio.phone_number.updated",
    "twilio.messaging_service.updated",
    "twilio.messaging_service.sender_pool.updated",
    "twilio.verify_service.updated",
    "twilio.api_key.updated",
}

# ── Expected signal types ──────────────────────────────────────────────────────

_EXPECTED_SIGNAL_TYPES = {
    "twilio_phone_number_config_changed",
    "twilio_messaging_service_config_changed",
    "twilio_verify_service_config_changed",
    "twilio_api_key_config_changed",
}

# ── Expected correlation types ─────────────────────────────────────────────────

_EXPECTED_CORRELATION_TYPES = {
    "twilio_phone_number_risk_activity_correlation",
    "twilio_messaging_service_risk_activity_correlation",
    "twilio_verify_service_risk_activity_correlation",
    "twilio_api_key_risk_activity_correlation",
}


# ── Helpers ────────────────────────────────────────────────────────────────────


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M79G", db=db,
    )


def _seed(db, ws, user):
    return demo_svc.seed_twilio(
        workspace_id=ws.id, actor_user_id=user.id, db=db,
    )


def _cleanup(db, ws_id):
    demo_svc.clear_twilio(workspace_id=ws_id, db=db)


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
    """A1: seed_twilio creates a demo integration with provider='twilio'.

    The demo integration uses DEMO_PROVIDER_TAG ('demo') as the provider so
    it stays hidden (never synced), while findings/events/signals/correlations
    are tagged provider='twilio'.
    """
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        assert integ is not None
        # Integration uses the demo sentinel provider tag (not the real 'twilio'
        # tag) so it remains hidden from the provider list and is never synced.
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG
        assert integ.display_name == demo_svc.TWILIO_DEMO_INTEGRATION_NAME
    finally:
        _cleanup(db_session, ws.id)


def test_a2_demo_integration_name(test_user, db_session):
    """A2: Demo integration name is TWILIO_DEMO_INTEGRATION_NAME."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        assert integ is not None
        assert integ.display_name == demo_svc.TWILIO_DEMO_INTEGRATION_NAME
    finally:
        _cleanup(db_session, ws.id)


def test_a3_demo_integration_has_sentinel_marker(test_user, db_session):
    """A3: Demo integration has a sentinel/demo marker (not real credentials)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        assert integ is not None
        # The integration uses DEMO_PROVIDER_TAG as the provider — that IS the
        # sentinel marker that flags it as a demo/synthetic integration rather
        # than a real connected Twilio account.
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG
        # Status is "deleted" so it's hidden from the provider list.
        assert integ.status == "deleted"
    finally:
        _cleanup(db_session, ws.id)


def test_a4_get_twilio_status_returns_seeded_true_after_seed(test_user, db_session):
    """A4: get_twilio_status returns seeded=True after seed."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        status = demo_svc.get_twilio_status(ws.id, db_session)
        assert status["seeded"] is True
    finally:
        _cleanup(db_session, ws.id)


def test_a5_get_twilio_status_returns_seeded_false_before_seed(test_user, db_session):
    """A5: get_twilio_status returns seeded=False before seed (fresh workspace)."""
    ws = _ws(test_user, db_session)
    # Ensure no pre-existing demo for this workspace.
    _cleanup(db_session, ws.id)
    status = demo_svc.get_twilio_status(ws.id, db_session)
    assert status["seeded"] is False


# ══════════════════════════════════════════════════════════════════════════════
# B: Seeded evidence chain
# ══════════════════════════════════════════════════════════════════════════════


def test_b1_at_least_4_findings(test_user, db_session):
    """B1: At least 4 findings with provider='twilio'."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
            SecurityFinding.provider == "twilio",
        ).all()
        assert len(findings) >= 4, f"expected >= 4 findings, got {len(findings)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b2_at_least_5_activity_events(test_user, db_session):
    """B2: At least 5 activity events with provider='twilio' and source='twilio_activity_event'."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
            SecurityActivityEvent.provider == "twilio",
            SecurityActivityEvent.source == "twilio_activity_event",
        ).all()
        assert len(events) >= 5, f"expected >= 5 activity events, got {len(events)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b3_at_least_4_signals(test_user, db_session):
    """B3: At least 4 signals with provider='twilio' and evidence_level='activity'."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "twilio",
            SecurityIncidentSignal.evidence_level == "activity",
        ).all()
        assert len(sigs) >= 4, f"expected >= 4 activity signals, got {len(sigs)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b4_at_least_4_correlations(test_user, db_session):
    """B4: At least 4 correlations with provider='twilio'."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "twilio",
        ).all()
        assert len(corrs) >= 4, f"expected >= 4 correlations, got {len(corrs)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b5_exactly_1_demo_case(test_user, db_session):
    """B5: Exactly 1 case with source=TWILIO_DEMO_CASE_SOURCE."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        cases = db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.TWILIO_DEMO_CASE_SOURCE,
        ).all()
        assert len(cases) == 1, f"expected exactly 1 demo case, got {len(cases)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b6_case_linked_to_evidence(test_user, db_session):
    """B6: Case is linked to Twilio findings, events, signals, correlations via SecurityCaseLink."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        links = db_session.query(SecurityCaseLink).filter(
            SecurityCaseLink.case_id == case_id,
        ).all()
        link_types = {lnk.linked_object_type for lnk in links}
        assert "finding" in link_types, "case missing finding links"
        assert "activity_event" in link_types, "case missing activity_event links"
        assert "signal" in link_types, "case missing signal links"
        assert "correlation" in link_types, "case missing correlation links"
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# C: Finding shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_c1_finding_rule_keys(test_user, db_session):
    """C1: Findings use expected Twilio rule keys."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        rules = {f.finding_key.split(":", 1)[0] for f in findings}
        assert _EXPECTED_FINDING_RULES <= rules, (
            f"missing rules: {_EXPECTED_FINDING_RULES - rules}"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_c2_no_secret_fields_in_finding_metadata(test_user, db_session):
    """C2: No finding metadata contains auth_token, api_secret, phone_number (full), raw URL."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        for f in findings:
            ev = f.evidence or {}
            assert "auth_token" not in ev, f"auth_token in {f.finding_key} evidence"
            assert "api_secret" not in ev, f"api_secret in {f.finding_key} evidence"
            assert "phone_number" not in ev, (
                f"phone_number (full) in {f.finding_key} evidence — use phone_number_last4"
            )
            # No raw URLs.
            ev_str = json.dumps(ev)
            url_hits = _scan_for_patterns(ev_str, [r"https?://[a-zA-Z0-9]"])
            assert not url_hits, (
                f"raw URL in {f.finding_key} evidence: {ev_str[:120]}"
            )
    finally:
        _cleanup(db_session, ws.id)


def test_c3_phone_number_last4_length(test_user, db_session):
    """C3: If phone_number_last4 present, value has length <= 4."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        for f in findings:
            ev = f.evidence or {}
            if "phone_number_last4" in ev:
                val = str(ev["phone_number_last4"])
                assert len(val) <= 4, (
                    f"phone_number_last4 too long ({val!r}) in {f.finding_key}"
                )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# D: Activity event shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_d1_event_types(test_user, db_session):
    """D1: Events use expected Twilio event types."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
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
    """D2: No event metadata contains forbidden fields."""
    forbidden_keys = {"auth_token", "api_secret", "phone_number", "account_sid"}
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        for e in events:
            md = e.event_metadata or {}
            bad = forbidden_keys & set(md.keys())
            assert not bad, (
                f"event {e.event_type!r} has forbidden metadata keys: {bad}"
            )
    finally:
        _cleanup(db_session, ws.id)


def test_d3_no_secret_patterns_in_event_metadata(test_user, db_session):
    """D3: No event metadata value matches AC/SK hex pattern or E.164 phone number."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        for e in events:
            md_str = json.dumps(e.event_metadata or {})
            hits = _scan_for_patterns(md_str, [
                r"AC[0-9a-fA-F]{32}",
                r"SK[0-9a-fA-F]{32}",
                r"\+1[0-9]{10}",
            ])
            assert not hits, (
                f"event {e.event_type!r} metadata contains secret-shaped value: "
                f"{hits}, metadata={md_str[:200]}"
            )
    finally:
        _cleanup(db_session, ws.id)


def test_d4_provider_event_id_safe_format(test_user, db_session):
    """D4: provider_event_id uses safe placeholder format (not AC/SK hex)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        for e in events:
            eid = e.provider_event_id or ""
            hits = _scan_for_patterns(eid, [
                r"AC[0-9a-fA-F]{32}",
                r"SK[0-9a-fA-F]{32}",
            ])
            assert not hits, (
                f"event {e.event_type!r} provider_event_id looks like a real SID: {eid!r}"
            )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# E: Signal shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_e1_signal_types(test_user, db_session):
    """E1: Signals use expected signal types."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "twilio",
        ).all()
        sig_types = {s.signal_type for s in sigs}
        assert _EXPECTED_SIGNAL_TYPES <= sig_types, (
            f"missing signal types: {_EXPECTED_SIGNAL_TYPES - sig_types}"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_e2_signal_metadata_safe(test_user, db_session):
    """E2: Signal metadata is safe — no forbidden fields."""
    forbidden_keys = {"auth_token", "api_secret", "phone_number", "account_sid"}
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "twilio",
        ).all()
        for s in sigs:
            md = s.signal_metadata or {}
            bad = forbidden_keys & set(md.keys())
            assert not bad, (
                f"signal {s.signal_type!r} has forbidden metadata keys: {bad}"
            )
            md_str = json.dumps(md)
            hits = _scan_for_patterns(md_str, [
                r"AC[0-9a-fA-F]{32}",
                r"SK[0-9a-fA-F]{32}",
                r"\+1[0-9]{10}",
            ])
            assert not hits, (
                f"signal {s.signal_type!r} metadata contains secret-shaped value: {hits}"
            )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# F: Correlation shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_f1_correlation_types(test_user, db_session):
    """F1: Correlations use expected correlation types."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "twilio",
        ).all()
        ctypes = {c.correlation_type for c in corrs}
        assert _EXPECTED_CORRELATION_TYPES <= ctypes, (
            f"missing correlation types: {_EXPECTED_CORRELATION_TYPES - ctypes}"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_f2_correlation_metadata_safe(test_user, db_session):
    """F2: Correlation metadata is safe."""
    forbidden_keys = {"auth_token", "api_secret", "phone_number", "account_sid"}
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "twilio",
        ).all()
        for c in corrs:
            md = c.correlation_metadata or {}
            bad = forbidden_keys & set(md.keys())
            assert not bad, (
                f"correlation {c.correlation_type!r} has forbidden metadata keys: {bad}"
            )
            md_str = json.dumps(md)
            hits = _scan_for_patterns(md_str, [
                r"AC[0-9a-fA-F]{32}",
                r"SK[0-9a-fA-F]{32}",
                r"\+1[0-9]{10}",
            ])
            assert not hits, (
                f"correlation {c.correlation_type!r} metadata contains secret-shaped "
                f"value: {hits}"
            )
    finally:
        _cleanup(db_session, ws.id)


def test_f3_correlations_linked_to_findings_and_signals(test_user, db_session):
    """F3: Correlations are linked to findings/signals."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "twilio",
        ).all()
        assert corrs, "no correlations found"
        for c in corrs:
            assert c.linked_finding_id is not None, (
                f"correlation {c.correlation_type!r} has no linked_finding_id"
            )
            assert c.linked_signal_id is not None, (
                f"correlation {c.correlation_type!r} has no linked_signal_id"
            )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# G: Idempotency
# ══════════════════════════════════════════════════════════════════════════════


def test_g1_seed_twice_no_double_create(test_user, db_session):
    """G1: Calling seed_twilio twice doesn't double-create evidence."""
    ws = _ws(test_user, db_session)
    try:
        r1 = _seed(db_session, ws, test_user)
        r2 = _seed(db_session, ws, test_user)
        assert r1["created"] is True
        assert r2["created"] is False
        assert r1["case_id"] == r2["case_id"]
    finally:
        _cleanup(db_session, ws.id)


def test_g2_counts_same_after_second_seed(test_user, db_session):
    """G2: Final counts are the same after second seed call."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)

        def _counts():
            f = db_session.query(SecurityFinding).filter(
                SecurityFinding.integration_id == integ.id,
            ).count()
            e = db_session.query(SecurityActivityEvent).filter(
                SecurityActivityEvent.integration_id == integ.id,
            ).count()
            s = db_session.query(SecurityIncidentSignal).filter(
                SecurityIncidentSignal.workspace_id == ws.id,
                SecurityIncidentSignal.provider == "twilio",
            ).count()
            c = db_session.query(SecuritySignalCorrelation).filter(
                SecuritySignalCorrelation.workspace_id == ws.id,
                SecuritySignalCorrelation.provider == "twilio",
            ).count()
            return (f, e, s, c)

        counts_before = _counts()
        _seed(db_session, ws, test_user)
        counts_after = _counts()
        assert counts_before == counts_after, (
            f"counts changed after second seed: {counts_before} -> {counts_after}"
        )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# H: Clear
# ══════════════════════════════════════════════════════════════════════════════


def test_h1_clear_removes_demo_integration_and_evidence(test_user, db_session):
    """H1: clear_twilio removes demo integration and all linked evidence."""
    ws = _ws(test_user, db_session)
    _seed(db_session, ws, test_user)
    demo_svc.clear_twilio(workspace_id=ws.id, db=db_session)

    assert demo_svc.get_twilio_demo_integration(ws.id, db_session) is None
    cases = db_session.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws.id,
        SecurityCase.case_metadata["source"].astext == demo_svc.TWILIO_DEMO_CASE_SOURCE,
    ).all()
    assert len(cases) == 0


def test_h2_after_clear_status_seeded_false(test_user, db_session):
    """H2: After clear, get_twilio_status returns seeded=False."""
    ws = _ws(test_user, db_session)
    _seed(db_session, ws, test_user)
    demo_svc.clear_twilio(workspace_id=ws.id, db=db_session)
    status = demo_svc.get_twilio_status(ws.id, db_session)
    assert status["seeded"] is False


def test_h3_clear_twilio_does_not_remove_non_demo_data(test_user, db_session):
    """H3: clear_twilio does NOT remove non-demo Twilio data (isolation test)."""
    from app.core.encryption import encrypt_credentials
    ws = _ws(test_user, db_session)
    # Create a real (non-demo) Twilio integration + finding.
    ct, iv = encrypt_credentials({
        "account_sid": "REAL_ACCOUNT_SID_PLACEHOLDER",
        "auth_token": "REAL_AUTH_TOKEN_PLACEHOLDER",
    })
    real_integ = Integration(
        user_id=test_user.id, workspace_id=ws.id, provider="twilio",
        display_name="real-twilio-production", encrypted_credentials=ct,
        credential_iv=iv, status="active",
    )
    db_session.add(real_integ)
    db_session.commit()
    db_session.refresh(real_integ)
    real_finding = SecurityFinding(
        workspace_id=ws.id, integration_id=real_integ.id, provider="twilio",
        finding_key="twilio_api_key_stale:real_key#keep",
        severity="medium", title="Real Twilio stale key (keep)", status="active",
        evidence={"rule": "twilio_api_key_stale"},
        remediation={"summary": "rotate the key"},
    )
    db_session.add(real_finding)
    db_session.commit()
    db_session.refresh(real_finding)
    real_id = real_finding.id
    try:
        _seed(db_session, ws, test_user)
        demo_svc.clear_twilio(workspace_id=ws.id, db=db_session)
        # Demo gone.
        assert demo_svc.get_twilio_demo_integration(ws.id, db_session) is None
        # Real finding preserved.
        assert db_session.query(SecurityFinding).filter(
            SecurityFinding.id == real_id,
        ).first() is not None
    finally:
        db_session.query(SecurityFinding).filter(
            SecurityFinding.id == real_id,
        ).delete(synchronize_session=False)
        db_session.query(Integration).filter(
            Integration.id == real_integ.id,
        ).delete(synchronize_session=False)
        db_session.commit()
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# I: Case report
# ══════════════════════════════════════════════════════════════════════════════


def test_i1_case_evidence_timeline_builds_without_error(test_user, db_session):
    """I1: Build case evidence timeline for the demo case — verify it builds without error."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        timeline = report_svc.build_case_evidence_timeline(
            case_id=case_id, workspace_id=ws.id, db=db_session,
        )
        assert timeline is not None
        assert "timeline_items" in timeline
        assert timeline["timeline_items"]
    finally:
        _cleanup(db_session, ws.id)


def test_i2_timeline_provider_label_twilio(test_user, db_session):
    """I2: _TIMELINE_PROVIDER_LABELS['twilio'] == 'Twilio'."""
    assert report_svc._TIMELINE_PROVIDER_LABELS["twilio"] == "Twilio"


def test_i3_case_report_metadata_previews_safe(test_user, db_session):
    """I3: Case report metadata previews contain only safe fields."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case_id = uuid.UUID(res["case_id"])
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == case_id,
        ).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        blob = json.dumps(report, default=str)
        hits = _scan_for_patterns(blob, FORBIDDEN_DEMO_DATA_PATTERNS)
        assert not hits, (
            f"case report contains secret-shaped values for patterns: {hits}"
        )
        lower = blob.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in lower, (
                f"forbidden phrase {phrase!r} in case report"
            )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# J: Privacy — no secret-shaped values
# ══════════════════════════════════════════════════════════════════════════════


def test_j1_no_ac_sk_patterns_in_seeded_data(test_user, db_session):
    """J1: Scan ALL seeded data for AC/SK hex patterns."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "twilio",
        ).all()
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "twilio",
        ).all()
        blob = json.dumps({
            "findings": [f.evidence for f in findings],
            "events": [e.event_metadata for e in events],
            "signals": [s.signal_metadata for s in sigs],
            "correlations": [c.correlation_metadata for c in corrs],
        }, default=str)
        for pat in [r"AC[0-9a-fA-F]{32}", r"SK[0-9a-fA-F]{32}"]:
            assert not re.search(pat, blob), (
                f"secret-SID pattern {pat!r} found in seeded data"
            )
    finally:
        _cleanup(db_session, ws.id)


def test_j2_no_full_e164_phone_numbers(test_user, db_session):
    """J2: Scan for full E.164 phone numbers (+1xxxxxxxxxx)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        blob = json.dumps({
            "findings": [f.evidence for f in findings],
            "events": [e.event_metadata for e in events],
        }, default=str)
        assert not re.search(r"\+1[0-9]{10}", blob), (
            "full E.164 phone number found in seeded data"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_j3_no_raw_urls_in_seeded_data(test_user, db_session):
    """J3: Scan for raw URL strings (https://...)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "twilio",
        ).all()
        blob = json.dumps({
            "findings": [f.evidence for f in findings],
            "events": [e.event_metadata for e in events],
            "signals": [s.signal_metadata for s in sigs],
        }, default=str)
        assert not re.search(r"https?://[a-zA-Z0-9]", blob), (
            "raw URL found in seeded data"
        )
    finally:
        _cleanup(db_session, ws.id)


def test_j4_no_auth_token_or_api_secret_in_metadata(test_user, db_session):
    """J4: Scan for auth_token, api_secret, api_key_secret in any metadata."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_twilio_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "twilio",
        ).all()
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "twilio",
        ).all()
        blob = json.dumps({
            "findings": [f.evidence for f in findings],
            "events": [e.event_metadata for e in events],
            "signals": [s.signal_metadata for s in sigs],
            "correlations": [c.correlation_metadata for c in corrs],
        }, default=str).lower()
        for forbidden_key in ("auth_token", "api_secret", "api_key_secret"):
            assert f'"{forbidden_key}"' not in blob, (
                f"forbidden key {forbidden_key!r} found in seeded metadata"
            )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# K: Frontend
# ══════════════════════════════════════════════════════════════════════════════


def test_k1_cases_page_has_twilio_demo_buttons():
    """K1: cases/page.tsx contains 'Load Twilio security demo' and 'Clear Twilio demo'."""
    fe_path = (
        Path(__file__).resolve().parents[2]
        / "frontend" / "src" / "app" / "(app)" / "security" / "cases" / "page.tsx"
    )
    if not fe_path.exists():
        import pytest
        pytest.skip("frontend not mounted")
    text = fe_path.read_text()
    assert "Load Twilio security demo" in text
    assert "Clear Twilio demo" in text


def test_k2_cases_page_has_twilio_provider_entry():
    """K2: cases/page.tsx contains provider: 'twilio' demo card entry."""
    fe_path = (
        Path(__file__).resolve().parents[2]
        / "frontend" / "src" / "app" / "(app)" / "security" / "cases" / "page.tsx"
    )
    if not fe_path.exists():
        import pytest
        pytest.skip("frontend not mounted")
    text = fe_path.read_text()
    assert 'provider: "twilio"' in text


def test_k3_demo_script_page_has_twilio_with_demo_true():
    """K3: demo-script/page.tsx contains Twilio in PROVIDER_CAPABILITY_TABLE with demo: true."""
    fe_path = (
        Path(__file__).resolve().parents[2]
        / "frontend" / "src" / "app" / "(app)" / "security" / "demo-script" / "page.tsx"
    )
    if not fe_path.exists():
        import pytest
        pytest.skip("frontend not mounted")
    text = fe_path.read_text()
    assert "Twilio" in text
    # The twilio row must have demo: true
    assert 'provider: "twilio"' in text
    assert "demo: true" in text


def test_k4_security_demo_script_mentions_twilio():
    """K4: securityDemoScript.ts mentions Twilio in talk track."""
    fe_path = (
        Path(__file__).resolve().parents[2]
        / "frontend" / "src" / "lib" / "securityDemoScript.ts"
    )
    if not fe_path.exists():
        import pytest
        pytest.skip("frontend not mounted")
    text = fe_path.read_text()
    assert "Twilio" in text


# ══════════════════════════════════════════════════════════════════════════════
# L: Capability matrix + expansion framework
# ══════════════════════════════════════════════════════════════════════════════


def test_l1_twilio_demo_seed_clear_capability():
    """L1: get_provider_capability('twilio').security.demo_seed_clear is True."""
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("twilio")
    assert cap is not None
    assert cap.security.demo_seed_clear is True


def test_l2_twilio_case_report_capability():
    """L2: get_provider_capability('twilio').security.case_report is True."""
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("twilio")
    assert cap is not None
    assert cap.security.case_report is True


def test_l3_twilio_maturity_partial():
    """L3: get_provider_capability('twilio').maturity == 'partial'."""
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("twilio")
    assert cap is not None
    assert cap.maturity == "partial"


def test_l4_planned_next_stage_contains_m79h():
    """L4: planned_next_stage contains 'M80A' (M79I complete)."""
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M80B" in stage


def test_l5_planned_next_stage_does_not_contain_m79g():
    """L5: planned_next_stage does NOT contain 'M79G'."""
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M79G" not in stage


# ══════════════════════════════════════════════════════════════════════════════
# M: Forbidden wording
# ══════════════════════════════════════════════════════════════════════════════


def test_m1_demo_seed_clear_source_no_forbidden_phrases():
    """M1: Scan demo seed/clear functions for forbidden claim phrases."""
    import inspect
    src = inspect.getsource(demo_svc.seed_twilio)
    src += inspect.getsource(demo_svc.clear_twilio)
    lower = src.lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in lower, (
            f"forbidden phrase {phrase!r} in seed/clear source"
        )


def test_m2_case_summary_no_forbidden_phrases(test_user, db_session):
    """M2: Import and check case summary does not contain forbidden phrases."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"]),
        ).first()
        text = (case.title + " " + (case.summary or "")).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase not in text, (
                f"forbidden phrase {phrase!r} in case summary"
            )
        # Must use review-safe wording.
        assert "evidence for review" in text or "may require review" in text
        assert "does not confirm" in text
    finally:
        _cleanup(db_session, ws.id)
