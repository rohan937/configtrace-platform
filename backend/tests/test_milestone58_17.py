"""M58.17: Drift Control Score — unit tests.

All tests target ``_compute_score_from_inputs()`` directly using the
``_ScoreInputs`` dataclass.  No DB session, no mocking required.

Run:
    cd backend && python -m pytest tests/test_milestone58_17.py -v

All 15 tests must pass.
"""

from __future__ import annotations

import pytest

from app.services.drift_score_service import (
    _ScoreInputs,
    _compute_score_from_inputs,
    _grade,
)


# ── Fixture: "ideal" inputs (should yield score 100, grade "strong") ──────────

def _perfect() -> _ScoreInputs:
    """A workspace with zero problems — expected score: 100."""
    return _ScoreInputs(
        providers_connected=2,
        stale_integration_count=0,
        total_changes_7d=10,
        high_critical_changes_7d=4,
        unreviewed_critical_count=0,
        unreviewed_high_count=0,
        review_completion_rate=1.0,
        policy_violations_7d=0,
        any_policies_enabled=True,
        slack_app_configured=True,
        legacy_slack_configured=False,
        webhook_configured=False,
        push_configured=False,
        weekly_digest_enabled=True,
        approved_window_count=1,
    )


# ── 1. Perfect workspace ──────────────────────────────────────────────────────

def test_perfect_workspace_score_100():
    """A workspace with no problems scores 100 with grade 'strong'."""
    resp = _compute_score_from_inputs(_perfect())
    assert resp.score == 100
    assert resp.grade == "strong"
    assert resp.trend == "unknown"
    assert resp.period_days == 7
    assert resp.factors == []


# ── 2. No providers → hard cap at 40 ─────────────────────────────────────────

def test_no_providers_capped_at_40():
    """Workspace with no providers: score must not exceed 40."""
    inputs = _perfect()
    inputs.providers_connected = 0
    inputs.total_changes_7d = 0
    inputs.high_critical_changes_7d = 0
    inputs.unreviewed_critical_count = 0
    inputs.unreviewed_high_count = 0
    inputs.review_completion_rate = 1.0
    inputs.policy_violations_7d = 0
    inputs.stale_integration_count = 0
    resp = _compute_score_from_inputs(inputs)
    assert resp.score <= 40
    assert resp.grade == "weak"
    assert any(f.key == "no_providers" for f in resp.factors)


# ── 3. Single unreviewed critical → -12 ──────────────────────────────────────

def test_single_unreviewed_critical_penalty():
    """One unreviewed critical change applies a -12 penalty."""
    inputs = _perfect()
    inputs.unreviewed_critical_count = 1
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 88
    assert any(f.key == "unreviewed_critical" and f.impact == -12 for f in resp.factors)


# ── 4. Three+ unreviewed criticals → cap -30 ─────────────────────────────────

def test_many_unreviewed_criticals_capped_at_30():
    """Three or more unreviewed criticals hit the -30 cap."""
    inputs = _perfect()
    inputs.unreviewed_critical_count = 5  # 5 * 12 = 60, capped at 30
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 70
    critical_factor = next(f for f in resp.factors if f.key == "unreviewed_critical")
    assert critical_factor.impact == -30


# ── 5. Single unreviewed high → -8 ───────────────────────────────────────────

def test_single_unreviewed_high_penalty():
    """One unreviewed high-risk change applies a -8 penalty."""
    inputs = _perfect()
    inputs.unreviewed_high_count = 1
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 92
    assert any(f.key == "unreviewed_high" and f.impact == -8 for f in resp.factors)


# ── 6. Three+ unreviewed highs → cap -24 ─────────────────────────────────────

def test_many_unreviewed_highs_capped_at_24():
    """Three or more unreviewed highs hit the -24 cap."""
    inputs = _perfect()
    inputs.unreviewed_high_count = 10  # 10 * 8 = 80, capped at 24
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 76
    high_factor = next(f for f in resp.factors if f.key == "unreviewed_high")
    assert high_factor.impact == -24


# ── 7. Single policy violation → -10 ─────────────────────────────────────────

def test_single_policy_violation_penalty():
    """One policy violation applies a -10 penalty."""
    inputs = _perfect()
    inputs.policy_violations_7d = 1
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 90
    assert any(f.key == "policy_violations" and f.impact == -10 for f in resp.factors)


# ── 8. Three+ policy violations → cap -30 ────────────────────────────────────

def test_many_policy_violations_capped_at_30():
    """Three or more distinct policy violations hit the -30 cap."""
    inputs = _perfect()
    inputs.policy_violations_7d = 8  # 8 * 10 = 80, capped at 30
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 70
    pv_factor = next(f for f in resp.factors if f.key == "policy_violations")
    assert pv_factor.impact == -30


# ── 9. Single stale integration → -8 ─────────────────────────────────────────

def test_single_stale_integration_penalty():
    """One stale integration applies a -8 penalty."""
    inputs = _perfect()
    inputs.stale_integration_count = 1
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 92
    assert any(f.key == "stale_integrations" and f.impact == -8 for f in resp.factors)


# ── 10. Three+ stale integrations → cap -20 ──────────────────────────────────

def test_many_stale_integrations_capped_at_20():
    """Three or more stale integrations hit the -20 cap."""
    inputs = _perfect()
    inputs.stale_integration_count = 5  # 5 * 8 = 40, capped at 20
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 80
    stale_factor = next(f for f in resp.factors if f.key == "stale_integrations")
    assert stale_factor.impact == -20


# ── 11. No alert channels → -15 ──────────────────────────────────────────────

def test_no_alert_channels_penalty():
    """A workspace with no alert channels at all loses 15 points."""
    inputs = _perfect()
    inputs.slack_app_configured = False
    inputs.legacy_slack_configured = False
    inputs.webhook_configured = False
    inputs.push_configured = False
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 85
    assert any(f.key == "no_alert_channels" and f.impact == -15 for f in resp.factors)


# ── 12. Push-only alert channels → -5 ────────────────────────────────────────

def test_push_only_alerts_limited_penalty():
    """Push-only (no Slack/webhook) loses only 5 points for limited channels."""
    inputs = _perfect()
    inputs.slack_app_configured = False
    inputs.legacy_slack_configured = False
    inputs.webhook_configured = False
    inputs.push_configured = True
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 95
    assert any(f.key == "limited_alert_channels" and f.impact == -5 for f in resp.factors)


# ── 13. Review completion rate < 50% → -15 ───────────────────────────────────

def test_very_low_review_rate_penalty():
    """Review completion rate below 50% incurs a -15 penalty."""
    inputs = _perfect()
    inputs.high_critical_changes_7d = 10
    inputs.review_completion_rate = 0.30
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 85
    rate_factor = next(f for f in resp.factors if f.key == "low_review_rate")
    assert rate_factor.impact == -15
    assert rate_factor.status == "critical"


# ── 14. Review completion rate ≥50% but <75% → -8 ────────────────────────────

def test_moderate_low_review_rate_penalty():
    """Review completion rate between 50% and 75% incurs a -8 penalty."""
    inputs = _perfect()
    inputs.high_critical_changes_7d = 10
    inputs.review_completion_rate = 0.60
    resp = _compute_score_from_inputs(inputs)
    assert resp.score == 92
    rate_factor = next(f for f in resp.factors if f.key == "low_review_rate")
    assert rate_factor.impact == -8
    assert rate_factor.status == "needs_attention"


# ── 15. Combined penalties — additive + clamp to [0, 100] ────────────────────

def test_combined_penalties_additive_and_clamped():
    """Multiple factors combine correctly; result is clamped to [0, 100]."""
    inputs = _ScoreInputs(
        providers_connected=1,
        stale_integration_count=3,          # -20 (capped)
        total_changes_7d=20,
        high_critical_changes_7d=10,
        unreviewed_critical_count=3,        # -30 (capped)
        unreviewed_high_count=3,            # -24 (capped)
        review_completion_rate=0.0,         # -15 (< 50%)
        policy_violations_7d=4,             # -30 (capped at 30: 4*10=40)
        any_policies_enabled=True,
        slack_app_configured=False,
        legacy_slack_configured=False,
        webhook_configured=False,
        push_configured=False,              # -15 (no alert channels)
        weekly_digest_enabled=False,
        approved_window_count=0,
    )
    resp = _compute_score_from_inputs(inputs)
    # 100 - 30 - 24 - 30 - 20 - 15 - 15 = -34 → clamped to 0
    assert resp.score == 0
    assert resp.grade == "weak"
    # Verify all expected factor keys are present
    factor_keys = {f.key for f in resp.factors}
    assert "unreviewed_critical" in factor_keys
    assert "unreviewed_high" in factor_keys
    assert "policy_violations" in factor_keys
    assert "stale_integrations" in factor_keys
    assert "no_alert_channels" in factor_keys
    assert "low_review_rate" in factor_keys


# ── Grade helper unit tests (bonus coverage) ─────────────────────────────────

@pytest.mark.parametrize("score,expected_grade", [
    (100, "strong"),
    (90,  "strong"),
    (89,  "good"),
    (75,  "good"),
    (74,  "needs_attention"),
    (55,  "needs_attention"),
    (54,  "weak"),
    (0,   "weak"),
])
def test_grade_thresholds(score, expected_grade):
    """_grade() returns the correct label for every threshold boundary."""
    assert _grade(score) == expected_grade
