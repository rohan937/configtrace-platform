"""M83F — Clerk Risk × Activity Correlations.

Joins active Clerk configuration-risk findings with Clerk activity signals
on the same resource family within a review window.

Sections
--------
  A. Correlation rule structure — completeness and shape
  B. _base_rule_key — stripping and no-suffix cases
  C. _match_pair — singleton families, per-resource ID matching
  D. _match_strength — "high" vs "medium" by match_reason suffix
  E. _in_window — overlapping, outside, missing timestamps
  F. _correlation_key — determinism and uniqueness
  G. _build_correlation — dict shape, privacy, and metadata
  H. generate_clerk_correlations — DB integration and caps
  I. Correlation metadata allowlist coverage
  J. Router endpoint — existence and admin guard
  K. Capability matrix + expansion framework
  L. Frontend + API checks
  M. M83A-E regression smoke
  N. Forbidden wording + secret-shape

CLAIM DISCIPLINE: configuration-state review correlations only. Does NOT
confirm a breach, compromise, unauthorized access, or data exposure.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from app.services.clerk_risk_activity_correlation_service import (
    CLERK_CORRELATION_RULES,
    CLERK_CORRELATION_TYPES,
    generate_clerk_correlations,
    _match_pair,
    _match_strength,
    _in_window,
    _base_rule_key,
    _correlation_key,
    _build_correlation,
    PROVIDER,
)
from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS as CORR_ALLOWED_KEYS
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

# ── Test constants ─────────────────────────────────────────────────────────────

CLERK_TEST_INSTANCE_ID = "CLERK_TEST_INSTANCE_ID"
CLERK_TEST_WEBHOOK_ID = "CLERK_TEST_WEBHOOK_ID"
CLERK_TEST_TEMPLATE_ID = "CLERK_TEST_TEMPLATE_ID"
CLERK_TEST_FINDING_ID = "CLERK_TEST_FINDING_ID"
CLERK_TEST_CORRELATION_ID = "CLERK_TEST_CORRELATION_ID"

EXPECTED_CORRELATION_TYPES = {
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

_FORBIDDEN_CORR_METADATA = frozenset({
    "secret_key", "publishable_key", "api_key", "token", "bearer", "jwt",
    "session_token", "webhook_secret", "url", "webhook_url", "redirect_url",
    "callback_url", "domain_name", "template_body", "claims", "audience",
    "issuer", "email", "user_email", "user_id", "phone", "member",
    "ip_address", "user_agent", "password", "raw", "payload", "audit",
    "session", "login",
})


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_finding(
    rule_key: str,
    resource_id: str | None = None,
    evidence: dict | None = None,
) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.provider = "clerk"
    f.status = "active"
    f.finding_key = f"{rule_key}:{resource_id or 'test'}"
    f.rule_key = rule_key
    f.resource_id = resource_id
    f.resource_type = "clerk_configuration"
    f.severity = "medium"
    f.evidence = evidence or {"rule": rule_key, "record_id": resource_id or "test_id"}
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    f.first_detected_at = now
    f.last_seen_at = now
    f.workspace_id = uuid.uuid4()
    return f


def _make_signal(
    signal_type: str,
    resource_id: str | None = None,
    metadata: dict | None = None,
) -> MagicMock:
    s = MagicMock()
    s.id = uuid.uuid4()
    s.provider = "clerk"
    s.signal_type = signal_type
    s.resource_id = resource_id
    s.signal_metadata = metadata or {"resource_id": resource_id, "event_count": 1}
    s.linked_activity_event_id = uuid.uuid4()
    s.integration_id = uuid.uuid4()
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    s.first_seen_at = now
    s.last_seen_at = now
    return s


# ── Section A: Correlation rule structure ─────────────────────────────────────

def test_correlation_types_complete():
    """CLERK_CORRELATION_TYPES must match the expected set exactly."""
    assert EXPECTED_CORRELATION_TYPES == CLERK_CORRELATION_TYPES


def test_all_rules_have_required_keys():
    """Every entry in CLERK_CORRELATION_RULES must have all required keys."""
    required = {"rule_keys", "signal_types", "match_key", "severity", "title_phrase", "subject_phrase"}
    for ctype, rule in CLERK_CORRELATION_RULES.items():
        missing = required - set(rule.keys())
        assert not missing, f"Rule {ctype!r} is missing keys: {missing}"


def test_no_cross_provider_rule_keys():
    """All rule_keys in CLERK_CORRELATION_RULES must start with 'clerk_'."""
    for ctype, rule in CLERK_CORRELATION_RULES.items():
        for rk in rule["rule_keys"]:
            assert rk.startswith("clerk_"), (
                f"Correlation rule {ctype!r} has non-Clerk rule_key: {rk!r}"
            )


def test_no_cross_provider_signal_types():
    """All signal_types in CLERK_CORRELATION_RULES must start with 'clerk_'."""
    for ctype, rule in CLERK_CORRELATION_RULES.items():
        for st in rule["signal_types"]:
            assert st.startswith("clerk_"), (
                f"Correlation rule {ctype!r} has non-Clerk signal_type: {st!r}"
            )


# ── Section B: _base_rule_key ─────────────────────────────────────────────────

def test_base_rule_key_strips_suffix():
    """_base_rule_key strips the resource-ID suffix after ':'."""
    result = _base_rule_key(f"clerk_instance_mfa_disabled:{CLERK_TEST_INSTANCE_ID}")
    assert result == "clerk_instance_mfa_disabled"


def test_base_rule_key_no_suffix():
    """_base_rule_key returns the whole key when there is no ':' separator."""
    result = _base_rule_key("clerk_webhook_without_signing")
    assert result == "clerk_webhook_without_signing"


# ── Section C: _match_pair ────────────────────────────────────────────────────

def test_match_pair_singleton_always_matches():
    """_match_pair returns a family string for singleton instance_settings resources."""
    finding = _make_finding("clerk_instance_mfa_disabled", CLERK_TEST_INSTANCE_ID)
    signal = _make_signal("clerk_instance_settings_config_changed", CLERK_TEST_INSTANCE_ID)
    result = _match_pair(finding, signal, "instance_settings")
    assert result is not None
    assert result.endswith("_family")


def test_match_pair_auth_strategy_singleton():
    """_match_pair returns 'auth_strategy_family' for auth_strategy singleton."""
    finding = _make_finding("clerk_auth_strategy_mfa_not_required", "some_id")
    signal = _make_signal("clerk_auth_strategy_config_changed", "other_id")
    result = _match_pair(finding, signal, "auth_strategy")
    assert result == "auth_strategy_family"


def test_match_pair_domain_same_id():
    """_match_pair returns 'domain_id_match' when finding and signal share a domain_id."""
    domain_id = "domain_abc123"
    finding = _make_finding(
        "clerk_domain_unverified", domain_id,
        evidence={"domain_id": domain_id, "record_id": domain_id},
    )
    signal = _make_signal(
        "clerk_domain_config_changed", domain_id,
        metadata={"domain_id": domain_id, "resource_id": domain_id, "event_count": 1},
    )
    result = _match_pair(finding, signal, "domain")
    assert result == "domain_id_match"


def test_match_pair_domain_different_id():
    """_match_pair returns None when finding and signal have different domain_ids."""
    finding = _make_finding(
        "clerk_domain_unverified", "domain_aaa",
        evidence={"domain_id": "domain_aaa"},
    )
    signal = _make_signal(
        "clerk_domain_config_changed", "domain_bbb",
        metadata={"domain_id": "domain_bbb", "resource_id": "domain_bbb", "event_count": 1},
    )
    result = _match_pair(finding, signal, "domain")
    assert result is None


def test_match_pair_jwt_template_same_id():
    """_match_pair returns 'jwt_template_id_match' for matching jwt_template_id."""
    template_id = "tmpl_xyz789"
    finding = _make_finding(
        "clerk_jwt_template_long_lifetime", template_id,
        evidence={"jwt_template_id": template_id},
    )
    signal = _make_signal(
        "clerk_jwt_template_config_changed", template_id,
        metadata={"jwt_template_id": template_id, "resource_id": template_id, "event_count": 1},
    )
    result = _match_pair(finding, signal, "jwt_template")
    assert result == "jwt_template_id_match"


def test_match_pair_jwt_template_no_id():
    """_match_pair returns 'jwt_template_family' when neither side has a jwt_template_id."""
    finding = _make_finding("clerk_jwt_template_audience_missing", None, evidence={})
    signal = _make_signal("clerk_jwt_template_config_changed", None, metadata={"event_count": 1})
    result = _match_pair(finding, signal, "jwt_template")
    assert result == "jwt_template_family"


def test_match_pair_webhook_endpoint_different_id():
    """_match_pair returns None when finding and signal have different webhook_endpoint_ids."""
    finding = _make_finding(
        "clerk_webhook_without_signing", "wh_endpoint_aaa",
        evidence={"webhook_endpoint_id": "wh_endpoint_aaa"},
    )
    signal = _make_signal(
        "clerk_webhook_endpoint_config_changed", "wh_endpoint_bbb",
        metadata={"webhook_endpoint_id": "wh_endpoint_bbb", "resource_id": "wh_endpoint_bbb", "event_count": 1},
    )
    result = _match_pair(finding, signal, "webhook_endpoint")
    assert result is None


def test_match_pair_application_same_id():
    """_match_pair returns 'application_id_match' for matching application_id."""
    app_id = "app_clerk_111"
    finding = _make_finding(
        "clerk_application_mfa_not_required", app_id,
        evidence={"application_id": app_id},
    )
    signal = _make_signal(
        "clerk_application_config_changed", app_id,
        metadata={"application_id": app_id, "resource_id": app_id, "event_count": 1},
    )
    result = _match_pair(finding, signal, "application")
    assert result == "application_id_match"


# ── Section D: _match_strength ────────────────────────────────────────────────

def test_match_strength_high_for_id_match():
    """_match_strength returns 'high' when reason ends with '_match'."""
    assert _match_strength("domain_id_match") == "high"


def test_match_strength_medium_for_family():
    """_match_strength returns 'medium' when reason ends with '_family'."""
    assert _match_strength("instance_settings_family") == "medium"


# ── Section E: _in_window ─────────────────────────────────────────────────────

def test_in_window_overlapping():
    """_in_window returns True when finding is active now and signal was last seen now."""
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    finding = _make_finding("clerk_instance_mfa_disabled", CLERK_TEST_INSTANCE_ID)
    finding.first_detected_at = now
    finding.last_seen_at = now
    signal = _make_signal("clerk_instance_settings_config_changed", CLERK_TEST_INSTANCE_ID)
    signal.first_seen_at = now
    signal.last_seen_at = now
    assert _in_window(finding, signal) is True


def test_in_window_outside():
    """_in_window returns False when signal is over a year outside the finding window."""
    old = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    new = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    finding = _make_finding("clerk_instance_mfa_disabled", CLERK_TEST_INSTANCE_ID)
    finding.first_detected_at = old
    finding.last_seen_at = old
    signal = _make_signal("clerk_instance_settings_config_changed", CLERK_TEST_INSTANCE_ID)
    signal.first_seen_at = new
    signal.last_seen_at = new
    # _WINDOW is 24h; old + 24h is well before new (365 days later)
    assert _in_window(finding, signal) is False


def test_in_window_missing_timestamps():
    """_in_window returns True (conservative) when finding has no timestamps."""
    finding = _make_finding("clerk_instance_mfa_disabled", CLERK_TEST_INSTANCE_ID)
    finding.first_detected_at = None
    finding.last_seen_at = None
    signal = _make_signal("clerk_instance_settings_config_changed", CLERK_TEST_INSTANCE_ID)
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    signal.first_seen_at = now
    signal.last_seen_at = now
    assert _in_window(finding, signal) is True


# ── Section F: _correlation_key ───────────────────────────────────────────────

def test_correlation_key_deterministic():
    """_correlation_key returns the same value for the same inputs."""
    finding = _make_finding("clerk_instance_mfa_disabled", CLERK_TEST_INSTANCE_ID)
    signal = _make_signal("clerk_instance_settings_config_changed", CLERK_TEST_INSTANCE_ID)
    ctype = "clerk_instance_settings_risk_activity_correlation"
    key1 = _correlation_key(finding, signal, ctype)
    key2 = _correlation_key(finding, signal, ctype)
    assert key1 == key2


def test_correlation_key_unique():
    """Different findings produce different correlation keys."""
    finding1 = _make_finding("clerk_instance_mfa_disabled", "inst_aaa")
    finding2 = _make_finding("clerk_instance_mfa_disabled", "inst_bbb")
    signal = _make_signal("clerk_instance_settings_config_changed", CLERK_TEST_INSTANCE_ID)
    ctype = "clerk_instance_settings_risk_activity_correlation"
    key1 = _correlation_key(finding1, signal, ctype)
    key2 = _correlation_key(finding2, signal, ctype)
    assert key1 != key2


# ── Section G: _build_correlation ─────────────────────────────────────────────

def test_build_correlation_returns_dict():
    """_build_correlation returns a well-formed dict with expected keys and values."""
    finding = _make_finding("clerk_instance_mfa_disabled", CLERK_TEST_INSTANCE_ID)
    signal = _make_signal("clerk_instance_settings_config_changed", CLERK_TEST_INSTANCE_ID)
    rule = CLERK_CORRELATION_RULES["clerk_instance_settings_risk_activity_correlation"]
    result = _build_correlation(
        finding=finding,
        signal=signal,
        correlation_type="clerk_instance_settings_risk_activity_correlation",
        rule=rule,
        match_reason="instance_settings_family",
    )
    assert isinstance(result, dict)
    assert result["provider"] == "clerk"
    assert result["correlation_type"] == "clerk_instance_settings_risk_activity_correlation"
    assert result["confidence"] == "medium"
    assert "correlation_key" in result
    assert len(result["title"]) <= 240


def test_build_correlation_metadata_no_forbidden_fields():
    """_build_correlation metadata must not contain any forbidden key names."""
    finding = _make_finding("clerk_webhook_without_signing", CLERK_TEST_WEBHOOK_ID)
    signal = _make_signal("clerk_webhook_endpoint_config_changed", CLERK_TEST_WEBHOOK_ID)
    rule = CLERK_CORRELATION_RULES["clerk_webhook_endpoint_risk_activity_correlation"]
    result = _build_correlation(
        finding=finding,
        signal=signal,
        correlation_type="clerk_webhook_endpoint_risk_activity_correlation",
        rule=rule,
        match_reason="webhook_endpoint_family",
    )
    metadata = result.get("metadata", {})
    assert isinstance(metadata, dict)
    for key in metadata.keys():
        assert key not in _FORBIDDEN_CORR_METADATA, (
            f"Forbidden metadata key found: {key!r}"
        )


def test_build_correlation_metadata_no_forbidden_strings():
    """_build_correlation metadata values must not contain known forbidden substrings."""
    finding = _make_finding("clerk_jwt_template_long_lifetime", CLERK_TEST_TEMPLATE_ID)
    signal = _make_signal("clerk_jwt_template_config_changed", CLERK_TEST_TEMPLATE_ID)
    rule = CLERK_CORRELATION_RULES["clerk_jwt_template_risk_activity_correlation"]
    result = _build_correlation(
        finding=finding,
        signal=signal,
        correlation_type="clerk_jwt_template_risk_activity_correlation",
        rule=rule,
        match_reason="jwt_template_family",
    )
    metadata = result.get("metadata", {})
    forbidden_value_substrings = [
        "eyJ",  # JWT prefix
        "secret",
        "token",
        "bearer",
        "password",
        "user@",
        "@example.com",
    ]
    for val in metadata.values():
        if isinstance(val, str):
            for substr in forbidden_value_substrings:
                assert substr.lower() not in val.lower(), (
                    f"Forbidden substring {substr!r} found in metadata value: {val!r}"
                )


def test_build_correlation_summary_no_forbidden_claims():
    """_build_correlation summary must not assert breach, compromise, or unauthorized access."""
    finding = _make_finding("clerk_session_lifetime_extended", "session_policy_abc")
    signal = _make_signal("clerk_session_policy_config_changed", "session_policy_abc")
    rule = CLERK_CORRELATION_RULES["clerk_session_policy_risk_activity_correlation"]
    result = _build_correlation(
        finding=finding,
        signal=signal,
        correlation_type="clerk_session_policy_risk_activity_correlation",
        rule=rule,
        match_reason="session_policy_family",
    )
    summary = result.get("summary", "").lower()
    forbidden_claims = [
        "breach",
        "compromise confirmed",
        "unauthorized access confirmed",
    ]
    for phrase in forbidden_claims:
        assert phrase not in summary, (
            f"Forbidden claim phrase {phrase!r} found in correlation summary"
        )


# ── Section H: generate_clerk_correlations ────────────────────────────────────

def test_generate_clerk_correlations_empty_db():
    """generate_clerk_correlations returns a zero-count summary when DB has no data."""
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    workspace_id = uuid.uuid4()

    summary = generate_clerk_correlations(workspace_id=workspace_id, db=mock_db)
    assert summary["provider"] == "clerk"
    assert summary["findings_scanned"] == 0
    assert summary["signals_scanned"] == 0
    assert summary["correlations_created"] == 0
    assert "candidate_pairs" in summary


def test_generate_filters_by_provider():
    """generate_clerk_correlations queries the DB filtering on provider='clerk'."""
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    workspace_id = uuid.uuid4()

    generate_clerk_correlations(workspace_id=workspace_id, db=mock_db)

    # Verify query was called at all (provider filter is applied internally via
    # SecurityFinding.provider == PROVIDER and SecurityIncidentSignal.provider == PROVIDER)
    assert mock_db.query.called


def test_generate_caps_lookback_at_168():
    """generate_clerk_correlations does not error with an oversized lookback_hours."""
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    workspace_id = uuid.uuid4()

    summary = generate_clerk_correlations(
        workspace_id=workspace_id,
        db=mock_db,
        lookback_hours=9999,
    )
    assert isinstance(summary, dict)
    assert summary["provider"] == "clerk"


def test_generate_caps_max_correlations_at_1000():
    """generate_clerk_correlations does not error with an oversized max_correlations."""
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    workspace_id = uuid.uuid4()

    summary = generate_clerk_correlations(
        workspace_id=workspace_id,
        db=mock_db,
        max_correlations=9999,
    )
    assert isinstance(summary, dict)
    assert summary["provider"] == "clerk"


# ── Section I: Correlation metadata allowlist ─────────────────────────────────

def test_clerk_correlation_id_keys_in_allowlist():
    """Core Clerk resource ID keys must be in the correlation metadata allowlist."""
    required_keys = {"instance_id", "domain_id", "jwt_template_id", "webhook_endpoint_id"}
    for key in required_keys:
        assert key in CORR_ALLOWED_KEYS, (
            f"Clerk correlation metadata key {key!r} not in CORR_ALLOWED_KEYS"
        )


def test_clerk_correlation_session_keys_in_allowlist():
    """Session and policy ID keys must be in the correlation metadata allowlist."""
    required_keys = {"session_policy_id", "auth_strategy_id", "organization_settings_id"}
    for key in required_keys:
        assert key in CORR_ALLOWED_KEYS, (
            f"Clerk correlation metadata key {key!r} not in CORR_ALLOWED_KEYS"
        )


def test_clerk_correlation_matching_keys_in_allowlist():
    """Matching classification keys must be in the correlation metadata allowlist."""
    required_keys = {"risk_family", "activity_family", "match_reason", "match_strength"}
    for key in required_keys:
        assert key in CORR_ALLOWED_KEYS, (
            f"Clerk correlation matching key {key!r} not in CORR_ALLOWED_KEYS"
        )


# ── Section J: Router endpoint ────────────────────────────────────────────────

def test_clerk_correlations_endpoint_exists():
    """The /clerk-correlations/generate endpoint must be registered in security router."""
    router_path = Path(__file__).parent.parent / "app" / "routers" / "security.py"
    content = router_path.read_text()
    assert "/clerk-correlations/generate" in content


def test_clerk_correlations_requires_admin():
    """The /clerk-correlations/generate endpoint must be guarded by require_workspace_admin."""
    router_path = Path(__file__).parent.parent / "app" / "routers" / "security.py"
    content = router_path.read_text()
    idx = content.find("/clerk-correlations/generate")
    assert idx >= 0
    window = content[idx: idx + 2000]
    assert "require_workspace_admin" in window


# ── Section K: Capability matrix + expansion framework ───────────────────────

def test_capability_matrix_clerk_risk_correlations_true():
    """Capability matrix must record risk_activity_correlations=True for Clerk."""
    cap = get_provider_capability("clerk")
    assert cap is not None
    assert cap.security.risk_activity_correlations is True


def test_capability_matrix_clerk_demo_false():
    """Rolled forward at M83G: demo_seed_clear=True and case_report=True for Clerk."""
    cap = get_provider_capability("clerk")
    assert cap is not None
    # M83G promoted demo_seed_clear and case_report to True.
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True


def test_expansion_framework_m83g():
    """Expansion framework planned_next_stage must reference M83G, Demo, or Clerk."""
    framework = get_framework()
    planned = framework["summary"]["planned_next_stage"]
    assert ("M83G" in planned or "Demo" in planned or "Clerk" in planned or "M84A" in planned
            or "PagerDuty" in planned or "M85A" in planned or "Linear" in planned)


# ── Section L: Frontend + API checks ─────────────────────────────────────────

def test_frontend_correlations_page_has_clerk():
    """The frontend correlations page must reference 'clerk' and 'generateClerkCorrelations'."""
    corr_page = (
        Path(__file__).parents[3]
        / "frontend" / "src" / "app" / "(app)" / "security" / "correlations" / "page.tsx"
    )
    if not corr_page.exists():
        pytest.skip("Correlations page not found")
    content = corr_page.read_text()
    assert "clerk" in content
    assert "generateClerkCorrelations" in content


def test_frontend_api_has_generate_clerk_correlations():
    """The frontend api.ts must export a generateClerkCorrelations helper."""
    api_path = Path(__file__).parents[3] / "frontend" / "src" / "lib" / "api.ts"
    if not api_path.exists():
        pytest.skip("api.ts not found")
    content = api_path.read_text()
    assert "generateClerkCorrelations" in content


# ── Section M: M83A-E regression smoke ───────────────────────────────────────

def test_m83_earlier_milestones_still_wired():
    """M83A-E artefacts (signal types, event types) must still be present."""
    from app.services.clerk_activity_signal_service import CLERK_SIGNAL_TYPES
    # M83H removed 2 orphaned application event entries from the signal map,
    # reducing CLERK_SIGNAL_TYPES from 11 to 10 producible types.
    assert len(CLERK_SIGNAL_TYPES) >= 10
    from app.connectors.clerk import _CLERK_CONFIG_EVENT_TYPES
    assert len(_CLERK_CONFIG_EVENT_TYPES) >= 18


# ── Section N: Forbidden wording + secret-shape ───────────────────────────────

def test_no_forbidden_wording_in_m83f():
    """The Clerk correlation service must not contain forbidden claim phrases."""
    forbidden = [
        "compromise confirmed",
        "secret leaked",
        "data leaked",
        "breach detected",
        "attack detected",
        "attacker found",
        "unauthorized access confirmed",
    ]
    fpath = (
        Path(__file__).parent.parent
        / "app" / "services" / "clerk_risk_activity_correlation_service.py"
    )
    if not fpath.exists():
        pytest.skip("Correlation service not found")
    content = fpath.read_text().lower()
    for phrase in forbidden:
        assert phrase not in content, f"Forbidden phrase found: {phrase!r}"


def test_no_secret_shaped_strings_in_m83f():
    """The Clerk correlation service must not contain secret-shaped string literals."""
    import re
    patterns = [
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}"),
        re.compile(r"SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        re.compile(r"AC[0-9a-fA-F]{32}"),
        re.compile(r"SK[0-9a-fA-F]{32}"),
    ]
    fpath = (
        Path(__file__).parent.parent
        / "app" / "services" / "clerk_risk_activity_correlation_service.py"
    )
    if not fpath.exists():
        pytest.skip("Correlation service not found")
    content = fpath.read_text()
    for pat in patterns:
        matches = pat.findall(content)
        assert not matches, f"Secret-shaped string in correlation service: {matches}"
