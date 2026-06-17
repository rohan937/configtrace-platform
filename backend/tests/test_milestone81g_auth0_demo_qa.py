"""M81G — Auth0 security demo + QA.

The Auth0 incident demo seeds one coherent, clearly-marked synthetic story
on a hidden demo integration:

    Auth0 configuration risks (tenant session lifetime extended, application
    token endpoint auth none, connection weak password policy, resource server
    RBAC disabled, auth-pipeline rule disabled, action secrets present, MFA
    factor disabled, custom domain not ready)
    -> Auth0 configuration-state activity events (auth0.tenant.updated,
    auth0.application.updated, auth0.connection.updated,
    auth0.resource_server.updated, auth0.rule.updated, auth0.action.deployed,
    auth0.mfa_factor.updated, auth0.custom_domain.updated)
    -> Auth0 activity signals -> Auth0 risk x activity correlations -> case.

These tests assert the seeded chain, demo isolation, seed/clear idempotency +
status, capability matrix, expansion framework pointer, frontend wording, and
claim/privacy discipline across all seeded evidence.

PRIVACY: the demo must never include client secrets, management API tokens,
access tokens, refresh tokens, ID tokens, JWTs, JWKS private material, signing
private keys, authorization headers, raw Auth0 API responses, raw callback/
logout/origin URLs, audience URIs, custom domain name strings, rule/action
script content, action secret values, user emails, user IDs, user names, profile
data, login history, IP addresses, device fingerprints, session data, MFA
recovery codes, organization member data, connection credentials, database
passwords, social provider secrets, SAML certificates, LDAP credentials,
custom domain verification tokens, webhook/action secrets, customer data, or PII.
No strings may match eyJ[A-Za-z0-9_-]{10,} (JWT shape).
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
    r"eyJ[A-Za-z0-9_-]{10,}",              # JWT / token shape
    r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",  # SendGrid API key shape
    r"AC[0-9a-fA-F]{32}",                  # Twilio account SID shape
    r"SK[0-9a-fA-F]{32}",                  # Twilio API key SID shape
    r"https?://[a-zA-Z0-9]",               # Raw URLs
]

# ── Forbidden metadata keys ────────────────────────────────────────────────────

FORBIDDEN_METADATA_KEYS = {
    # Auth0 credential / secret material
    "client_secret",
    "management_api_token",
    "management_token",
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "jwt",
    "jwks",
    "signing_key",
    "private_key",
    "authorization",
    "bearer",
    # Raw URL material
    "callback_url",
    "callbacks",
    "logout_url",
    "allowed_logout_urls",
    "allowed_origin",
    "allowed_origins",
    "web_origins",
    "audience",
    "custom_domain",
    # User / identity data
    "email",
    "user_email",
    "user_id",
    "user_name",
    "username",
    "name",
    "profile",
    "identities",
    "login_history",
    "ip_address",
    "ip",
    "device",
    "session",
    "mfa_recovery_code",
    # Rule/action code
    "script",
    "code",
    # Raw API response / log data
    "raw_payload",
    "raw_response",
    "raw_log",
    "log_description",
    "log_detail",
    # Customer / PII
    "customer",
    "contact",
}

# ── Expected Auth0 finding rule keys ──────────────────────────────────────────

_EXPECTED_FINDING_RULES = {
    "auth0_tenant_session_lifetime_extended",
    "auth0_application_token_endpoint_auth_none",
    "auth0_connection_weak_password_policy",
    "auth0_resource_server_rbac_disabled",
    "auth0_rule_disabled",
    "auth0_action_secrets_present",
    "auth0_mfa_factor_disabled",
    "auth0_custom_domain_not_ready",
}

# ── Expected activity event types ──────────────────────────────────────────────

_EXPECTED_EVENT_TYPES = {
    "auth0.tenant.updated",
    "auth0.application.updated",
    "auth0.connection.updated",
    "auth0.resource_server.updated",
    "auth0.rule.updated",
    "auth0.action.deployed",
    "auth0.mfa_factor.updated",
    "auth0.custom_domain.updated",
}

# ── Expected signal types ──────────────────────────────────────────────────────

_EXPECTED_SIGNAL_TYPES = {
    "auth0_tenant_config_changed",
    "auth0_application_config_changed",
    "auth0_connection_config_changed",
    "auth0_resource_server_config_changed",
    "auth0_rule_config_changed",
    "auth0_action_config_changed",
    "auth0_mfa_factor_config_changed",
    "auth0_custom_domain_config_changed",
}

# ── Expected correlation types ─────────────────────────────────────────────────

_EXPECTED_CORRELATION_TYPES = {
    "auth0_tenant_risk_activity_correlation",
    "auth0_application_risk_activity_correlation",
    "auth0_connection_risk_activity_correlation",
    "auth0_resource_server_risk_activity_correlation",
    "auth0_rule_risk_activity_correlation",
    "auth0_action_risk_activity_correlation",
    "auth0_mfa_factor_risk_activity_correlation",
    "auth0_custom_domain_risk_activity_correlation",
}


# ── Helpers ────────────────────────────────────────────────────────────────────


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M81G", db=db,
    )


def _seed(db, ws, user):
    return demo_svc.seed_auth0(
        workspace_id=ws.id, actor_user_id=user.id, db=db,
    )


def _cleanup(db, ws_id):
    demo_svc.clear_auth0(workspace_id=ws_id, db=db)


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
    """A1: seed_auth0 creates a demo integration (hidden, status='deleted')."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
        assert integ is not None
        assert integ.provider == demo_svc.DEMO_PROVIDER_TAG
        assert integ.display_name == demo_svc.AUTH0_DEMO_INTEGRATION_NAME
    finally:
        _cleanup(db_session, ws.id)


def test_a2_demo_integration_status_deleted(test_user, db_session):
    """A2: Demo integration has status='deleted' (never synced/shown)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
        assert integ is not None
        assert integ.status == "deleted"
        assert integ.scheduled_sync_enabled is False
    finally:
        _cleanup(db_session, ws.id)


def test_a3_get_auth0_status_seeded_true_after_seed(test_user, db_session):
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        status = demo_svc.get_auth0_status(ws.id, db_session)
        assert status["seeded"] is True
        assert status["case_id"] is not None
        assert status["link_count"] > 0
    finally:
        _cleanup(db_session, ws.id)


def test_a4_get_auth0_status_seeded_false_before_seed(test_user, db_session):
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    status = demo_svc.get_auth0_status(ws.id, db_session)
    assert status["seeded"] is False
    assert status["case_id"] is None


# ══════════════════════════════════════════════════════════════════════════════
# B: Seeded evidence chain
# ══════════════════════════════════════════════════════════════════════════════


def test_b1_at_least_8_findings(test_user, db_session):
    """B1: At least 8 Auth0 findings (one per drift surface)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
            SecurityFinding.provider == "auth0",
        ).all()
        assert len(findings) >= 8, f"expected >= 8 findings, got {len(findings)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b2_at_least_8_activity_events(test_user, db_session):
    """B2: At least 8 Auth0 activity events (one per drift surface)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
            SecurityActivityEvent.provider == "auth0",
            SecurityActivityEvent.source == "auth0_activity_event",
        ).all()
        assert len(events) >= 8, f"expected >= 8 events, got {len(events)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b3_at_least_8_signals(test_user, db_session):
    """B3: At least 8 Auth0 signals (one per surface)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "auth0",
            SecurityIncidentSignal.evidence_level == "activity",
        ).all()
        assert len(sigs) >= 8, f"expected >= 8 activity signals, got {len(sigs)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b4_at_least_8_correlations(test_user, db_session):
    """B4: At least 8 Auth0 correlations (one per resource family)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "auth0",
        ).all()
        assert len(corrs) >= 8, f"expected >= 8 correlations, got {len(corrs)}"
    finally:
        _cleanup(db_session, ws.id)


def test_b5_exactly_1_demo_case(test_user, db_session):
    """B5: Exactly 1 case with source=AUTH0_DEMO_CASE_SOURCE."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        cases = db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.AUTH0_DEMO_CASE_SOURCE,
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
    """C1: Findings use expected Auth0 rule keys (one per drift surface)."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
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
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
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
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
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


def test_c4_findings_cover_all_8_resource_types(test_user, db_session):
    """C4: Findings cover tenant, application, connection, resource_server, rule,
    action, mfa_factor, and custom_domain surfaces."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.integration_id == integ.id,
        ).all()
        rules = {f.finding_key.split(":", 1)[0] for f in findings}
        # Check each surface is represented
        surfaces = {
            "tenant": any("tenant" in r for r in rules),
            "application": any("application" in r for r in rules),
            "connection": any("connection" in r for r in rules),
            "resource_server": any("resource_server" in r for r in rules),
            "rule": any(r.startswith("auth0_rule") for r in rules),
            "action": any("action" in r for r in rules),
            "mfa_factor": any("mfa_factor" in r for r in rules),
            "custom_domain": any("custom_domain" in r for r in rules),
        }
        missing = [s for s, found in surfaces.items() if not found]
        assert not missing, f"missing finding surfaces: {missing}"
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# D: Activity event shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_d1_event_types(test_user, db_session):
    """D1: Events include the expected 8 Auth0 event types."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
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
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
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
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
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


def test_d4_events_have_auth0_provider_and_source(test_user, db_session):
    """D4: Activity events have provider='auth0' and source='auth0_activity_event'."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
        events = db_session.query(SecurityActivityEvent).filter(
            SecurityActivityEvent.integration_id == integ.id,
        ).all()
        for e in events:
            assert e.provider == "auth0", f"event {e.event_type!r} has provider={e.provider!r}"
            assert e.source == "auth0_activity_event", (
                f"event {e.event_type!r} has source={e.source!r}"
            )
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# E: Signal shapes
# ══════════════════════════════════════════════════════════════════════════════


def test_e1_signal_types(test_user, db_session):
    """E1: Signals include the expected 8 Auth0 signal types."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        sigs = db_session.query(SecurityIncidentSignal).filter(
            SecurityIncidentSignal.workspace_id == ws.id,
            SecurityIncidentSignal.provider == "auth0",
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
            SecurityIncidentSignal.provider == "auth0",
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
            SecurityIncidentSignal.provider == "auth0",
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
    """F1: Correlations include the expected 8 Auth0 correlation types."""
    ws = _ws(test_user, db_session)
    try:
        _seed(db_session, ws, test_user)
        corrs = db_session.query(SecuritySignalCorrelation).filter(
            SecuritySignalCorrelation.workspace_id == ws.id,
            SecuritySignalCorrelation.provider == "auth0",
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
            SecuritySignalCorrelation.provider == "auth0",
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
            SecuritySignalCorrelation.provider == "auth0",
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
    """G1: Calling seed_auth0 twice returns the existing case, no duplicates."""
    ws = _ws(test_user, db_session)
    try:
        r1 = _seed(db_session, ws, test_user)
        r2 = _seed(db_session, ws, test_user)
        assert r1["case_id"] == r2["case_id"]
        assert r2.get("created") is False
        cases = db_session.query(SecurityCase).filter(
            SecurityCase.workspace_id == ws.id,
            SecurityCase.case_metadata["source"].astext == demo_svc.AUTH0_DEMO_CASE_SOURCE,
        ).all()
        assert len(cases) == 1
    finally:
        _cleanup(db_session, ws.id)


def test_g2_clear_removes_all_demo_objects(test_user, db_session):
    """G2: clear_auth0 removes integration, findings, events, signals, corrs, case."""
    ws = _ws(test_user, db_session)
    _seed(db_session, ws, test_user)
    _cleanup(db_session, ws.id)
    integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
    assert integ is None
    cases = db_session.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws.id,
        SecurityCase.case_metadata["source"].astext == demo_svc.AUTH0_DEMO_CASE_SOURCE,
    ).all()
    assert len(cases) == 0


def test_g3_clear_does_not_touch_sendgrid_demo(test_user, db_session):
    """G3: clear_auth0 does not touch SendGrid demo objects."""
    ws = _ws(test_user, db_session)
    try:
        demo_svc.seed_sendgrid(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        _seed(db_session, ws, test_user)
        demo_svc.clear_auth0(workspace_id=ws.id, db=db_session)
        auth0_integ = demo_svc.get_auth0_demo_integration(ws.id, db_session)
        assert auth0_integ is None
        sg_integ = demo_svc.get_sendgrid_demo_integration(ws.id, db_session)
        assert sg_integ is not None
    finally:
        demo_svc.clear_sendgrid(workspace_id=ws.id, db=db_session)
        _cleanup(db_session, ws.id)


def test_g4_status_reports_correctly(test_user, db_session):
    """G4: Status is unseeded before seed, seeded after, unseeded after clear."""
    ws = _ws(test_user, db_session)
    _cleanup(db_session, ws.id)
    s0 = demo_svc.get_auth0_status(ws.id, db_session)
    assert s0["seeded"] is False

    _seed(db_session, ws, test_user)
    s1 = demo_svc.get_auth0_status(ws.id, db_session)
    assert s1["seeded"] is True
    assert s1["link_count"] > 0

    _cleanup(db_session, ws.id)
    s2 = demo_svc.get_auth0_status(ws.id, db_session)
    assert s2["seeded"] is False


# ══════════════════════════════════════════════════════════════════════════════
# H: Case + case report
# ══════════════════════════════════════════════════════════════════════════════


def test_h1_case_provider_is_auth0(test_user, db_session):
    """H1: The demo case has provider='auth0'."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])
        ).first()
        assert case is not None
        assert case.provider == "auth0"
    finally:
        _cleanup(db_session, ws.id)


def test_h2_case_metadata_has_demo_source(test_user, db_session):
    """H2: The demo case is tagged with the Auth0 demo source."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])
        ).first()
        assert case is not None
        md = case.case_metadata or {}
        assert md.get("source") == demo_svc.AUTH0_DEMO_CASE_SOURCE
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


def test_h4_case_report_renders_auth0(test_user, db_session):
    """H4: Case report builds and references auth0 provider/source labels."""
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
        assert "auth0" in low
    finally:
        _cleanup(db_session, ws.id)


def test_h5_case_report_evidence_previews_safe(test_user, db_session):
    """H5: Evidence previews in case report contain only safe Auth0 metadata."""
    ws = _ws(test_user, db_session)
    try:
        res = _seed(db_session, ws, test_user)
        case = db_session.query(SecurityCase).filter(
            SecurityCase.id == uuid.UUID(res["case_id"])
        ).first()
        report = report_svc.build_case_report(case=case, db=db_session)
        # Check the evidence_timeline previews
        timeline = report.get("evidence_timeline", {})
        for item in timeline.get("timeline_items", []):
            preview = item.get("metadata_preview", {})
            bad = FORBIDDEN_METADATA_KEYS & set(preview.keys())
            assert not bad, f"timeline item preview has forbidden keys: {bad}"
            preview_str = json.dumps(preview)
            hits = _scan_for_patterns(preview_str, FORBIDDEN_DEMO_DATA_PATTERNS)
            assert not hits, f"timeline item preview has forbidden patterns: {hits}"
    finally:
        _cleanup(db_session, ws.id)


# ══════════════════════════════════════════════════════════════════════════════
# I: Capability matrix + expansion framework
# ══════════════════════════════════════════════════════════════════════════════


def test_i1_capability_matrix_demo_seed_clear_true():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("auth0")
    assert cap is not None
    assert cap.security.demo_seed_clear is True


def test_i2_capability_matrix_case_report_true():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("auth0")
    assert cap is not None
    assert cap.security.case_report is True


def test_i3_capability_matrix_partial_maturity():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("auth0")
    assert cap is not None
    assert cap.maturity == "partial"


def test_i4_notes_mention_m81g_or_demo():
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("auth0")
    assert cap is not None
    assert "M81G" in cap.notes or "demo" in cap.notes.lower(), (
        f"capability notes should mention M81G or demo: {cap.notes!r}"
    )


def test_i5_expansion_framework_points_to_m81h():
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M81H" in stage, (
        f"expected planned_next_stage to reference M81H; got {stage!r}"
    )


def test_i6_expansion_framework_not_m81g():
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    assert "M81G" not in stage, (
        f"planned_next_stage should have advanced past M81G; got {stage!r}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# J: Frontend references
# ══════════════════════════════════════════════════════════════════════════════


def test_j1_cases_page_has_auth0_demo_card():
    """J1: Cases page has Auth0 in PROVIDER_DEMO_CARDS."""
    text = FE_CASES.read_text()
    assert "auth0" in text
    assert "Auth0" in text
    assert "Load Auth0 security demo" in text


def test_j2_cases_page_has_review_safe_copy():
    """J2: Cases page Auth0 copy mentions review-safe + no client secrets / JWTs."""
    text = FE_CASES.read_text()
    assert "review-safe Auth0" in text or "Auth0 security demo" in text
    assert "client secrets" in text or "JWTs" in text or "client secret" in text


def test_j3_demo_script_page_has_auth0_row_demo_true():
    """J3: Demo-script page has Auth0 with demo: true."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert 'provider: "auth0"' in text
    match = re.search(r'\{ provider: "auth0".*?demo: (true|false)', text)
    assert match is not None, "Auth0 row not found in demo capability table"
    assert match.group(1) == "true", (
        f"Auth0 demo should be true (M81G), got {match.group(1)}"
    )


def test_j4_demo_script_page_auth0_signals_true():
    """J4: Demo-script page has Auth0 with signals: true."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    match = re.search(r'\{ provider: "auth0".*?signals: (true|false)', text)
    assert match is not None, "Auth0 row not found in demo capability table"
    assert match.group(1) == "true", (
        f"Auth0 signals should be true (M81E), got {match.group(1)}"
    )


def test_j5_demo_script_page_auth0_correlations_true():
    """J5: Demo-script page has Auth0 with correlations: true."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    match = re.search(r'\{ provider: "auth0".*?correlations: (true|false)', text)
    assert match is not None, "Auth0 row not found in demo capability table"
    assert match.group(1) == "true", (
        f"Auth0 correlations should be true (M81F), got {match.group(1)}"
    )


def test_j6_demo_script_lib_mentions_auth0():
    """J6: securityDemoScript.ts mentions Auth0 in the demo script."""
    text = FE_DEMO_SCRIPT_LIB.read_text()
    assert "Auth0" in text, "securityDemoScript should mention Auth0 (M81G)"


def test_j7_cases_page_no_forbidden_wording():
    text = FE_CASES.read_text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text, f"forbidden phrase {phrase!r} in cases page"


def test_j8_demo_script_page_no_forbidden_wording():
    text = FE_DEMO_SCRIPT_PAGE.read_text().lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text, f"forbidden phrase {phrase!r} in demo-script page"


# ══════════════════════════════════════════════════════════════════════════════
# K: Secret-shape scan (source files)
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


def test_k3_demo_service_auth0_constants_are_safe_placeholders():
    """K3: Auth0 demo constants use only safe uppercase placeholder strings."""
    assert demo_svc.AUTH0_DEMO_INTEGRATION_NAME == "ConfigTrace Auth0 incident demo (sample data)"
    assert demo_svc.AUTH0_DEMO_CASE_SOURCE == "demo_auth0_incident"
    # Placeholder IDs should be all-caps ASCII sentinel strings, never JWT/secret
    assert demo_svc._AUTH0_DEMO_CLIENT_ID == "AUTH0_DEMO_CLIENT_ID"
    assert demo_svc._AUTH0_DEMO_CONNECTION_ID == "AUTH0_DEMO_CONNECTION_ID"
    assert demo_svc._AUTH0_DEMO_RESOURCE_SERVER_ID == "AUTH0_DEMO_RESOURCE_SERVER_ID"
    assert demo_svc._AUTH0_DEMO_RULE_ID == "AUTH0_DEMO_RULE_ID"
    assert demo_svc._AUTH0_DEMO_ACTION_ID == "AUTH0_DEMO_ACTION_ID"
    assert demo_svc._AUTH0_DEMO_CUSTOM_DOMAIN_ID == "AUTH0_DEMO_CUSTOM_DOMAIN_ID"
    assert demo_svc._AUTH0_DEMO_FACTOR_NAME == "otp"
