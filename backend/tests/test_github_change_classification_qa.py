"""GitHub change-classification QA regression coverage (message-2 pass).

This file covers bugs found while auditing classification correctness for
every currently emitted and tracked GitHub field (severity, unknown-value
safety, added/removed record inspection, and Change/Finding severity
parity), building on the detection-QA pass in test_github_detection_qa.py:

  1. ``_classify_environment_protection``'s ``reviewers_count`` and
     ``wait_timer`` blocks used ``int(value or 0)``, which silently
     collapses an unknown (``None``) count to an explicit zero — an
     environment whose reviewer count became unreadable would be reported
     as a confirmed "decreased to 0 reviewers" instead of "unknown".
  2. ``_classify_ruleset``'s ``bypass_actor_count``, ``required_status_
     checks_count``, and ``branch_patterns_count`` blocks used the shared
     ``_to_int()`` helper (``int(v) except -> 0``), the same unknown-as-zero
     bug.
  3. ``_classify_automation_permissions``'s ``broad_permission_count`` block
     (added in the message-1 pass) had the same ``_to_int()`` bug.
  4. The shared ``_to_bool()`` helper returned ``False`` for ``None``/
     unrecognised input instead of ``None`` — every ruleset boolean field
     (``restrict_force_pushes``, ``restrict_deletions``,
     ``required_pr_reviews_required``, ``require_signed_commits``) and
     automation-permission boolean field (``repository_permission_admin``,
     ``token_broad_scopes``) silently treated "unknown" as an explicit
     "disabled"/"lost" state — the *opposite* of the field's actual
     (unknown) status, because each call site's if/else pattern assumed
     only True/False were possible.
  5. ``_classify_webhook``'s "added" branch never inspected the newly
     added webhook's own record for risky posture (plain http://, SSL
     verification disabled) — every new webhook was flatly "medium"
     regardless of how insecure it was from creation, unlike
     ``_classify_deploy_key``'s "added" branch, which does inspect the new
     record.
  6. ``allowed_actions == "all"`` was classified "medium" as a Change, but
     the equivalent static ``github_actions_broad_permissions`` Security
     Finding is "high" — the transition into a risky state was rated
     *below* the already-risky static state. Bumped to "high".

These tests exercise the REAL compute_diff() -> classify_github_change()
pipeline (not hand-built mocks) wherever practical, matching the
established regression pattern from this session's other detection/
classification QA passes.
"""

from __future__ import annotations

from app.services.diff_service import compute_diff
from app.services.risk_rules.github import classify_github_change


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]):
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


def _change(**kwargs) -> dict:
    base = {
        "change_type": "modified",
        "field_path": None,
        "prev_value": None,
        "new_value": None,
        "provider_metadata": {},
    }
    base.update(kwargs)
    return base


_ENV_BASE = {
    "record_type": "github_environment_protection",
    "record_id": "acme/widgets#environment#production",
    "name": "production",
    "environment_name": "production",
    "wait_timer": 10,
    "reviewers_count": 2,
    "prevent_self_review": True,
    "protected_branches": True,
    "custom_branch_policies": False,
}

_RULESET_BASE = {
    "record_type": "github_ruleset",
    "record_id": "acme/widgets#ruleset#1",
    "name": "main-protection",
    "ruleset_id": "1",
    "target": "branch",
    "enforcement": "active",
    "branch_patterns_count": 1,
    "targets_protected_branch": True,
    "bypass_actor_count": 0,
    "required_status_checks_count": 2,
    "restrict_force_pushes": True,
    "restrict_deletions": True,
    "required_pr_reviews_required": True,
    "require_signed_commits": False,
    "requires_linear_history": False,
    "requires_code_scanning": False,
}

_AUTOMATION_BASE = {
    "record_type": "github_automation_permissions",
    "record_id": "acme/widgets#automation_permissions",
    "name": "acme/widgets",
    "credential_type": "github_token",
    "permissions_present": True,
    "repository_permission_admin": False,
    "repository_permission_maintain": False,
    "repository_permission_push": True,
    "repository_permission_triage": False,
    "repository_permission_pull": True,
    "broad_permission_count": 1,
    "token_scope_names": ["repo"],
    "token_scope_count": 1,
    "token_broad_scopes": False,
    "broad_scope_names": [],
}


class TestNumericUnknownIsNotZero:
    """Unknown counts must never be described as a confirmed zero."""

    def test_environment_reviewers_count_unknown_prev_is_not_a_confirmed_decrease(self):
        change = _change(
            provider_metadata={"record_type": "github_environment_protection",
                                "record_name": "production"},
            field_path="reviewers_count",
            prev_value=None,
            new_value=2,
        )
        level, reason = classify_github_change(change)
        assert level == "medium"
        assert "decreased" not in reason.lower()
        assert "0" not in reason

    def test_environment_reviewers_count_unknown_new_is_not_a_confirmed_removal(self):
        change = _change(
            provider_metadata={"record_type": "github_environment_protection",
                                "record_name": "production"},
            field_path="reviewers_count",
            prev_value=3,
            new_value=None,
        )
        level, reason = classify_github_change(change)
        assert level == "medium"
        assert "decreased from 3 to 0" not in reason

    def test_environment_reviewers_count_explicit_decrease_still_high(self):
        change = _change(
            provider_metadata={"record_type": "github_environment_protection",
                                "record_name": "production"},
            field_path="reviewers_count",
            prev_value=3,
            new_value=1,
        )
        level, reason = classify_github_change(change)
        assert level == "high"
        assert "3" in reason and "1" in reason

    def test_environment_wait_timer_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "github_environment_protection",
                                "record_name": "production"},
            field_path="wait_timer",
            prev_value=None,
            new_value=0,
        )
        level, reason = classify_github_change(change)
        assert level == "low"
        assert "could not be determined" in reason

    def test_ruleset_bypass_actor_count_unknown_via_real_compute_diff(self):
        prev = [dict(_RULESET_BASE)]
        # Simulate a pre-existing snapshot predating this field's addition:
        # the key is entirely absent, so .get() returns None.
        stale_prev = {k: v for k, v in _RULESET_BASE.items() if k != "bypass_actor_count"}
        prev = [stale_prev]
        new = [{**_RULESET_BASE, "bypass_actor_count": 5}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "bypass_actor_count"]
        assert len(matching) == 1
        level, reason = classify_github_change(matching[0])
        assert level == "medium"
        assert "increased from 0" not in reason

    def test_ruleset_required_status_checks_count_unknown_via_real_compute_diff(self):
        stale_prev = {k: v for k, v in _RULESET_BASE.items() if k != "required_status_checks_count"}
        new = [{**_RULESET_BASE, "required_status_checks_count": 0}]
        changes = _real_changes([stale_prev], new)
        matching = [c for c in changes if c["field_path"] == "required_status_checks_count"]
        assert len(matching) == 1
        level, reason = classify_github_change(matching[0])
        assert level == "medium"
        assert "lowered from 0" not in reason

    def test_automation_broad_permission_count_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "github_automation_permissions",
                                "name": "acme/widgets"},
            field_path="broad_permission_count",
            prev_value=None,
            new_value=2,
        )
        level, reason = classify_github_change(change)
        assert level == "medium"
        assert "increased from 0" not in reason


class TestBooleanUnknownIsNotOverstated:
    """Unknown booleans must not be reported as an explicit True/False state."""

    def test_ruleset_restrict_force_pushes_unknown_is_not_a_weakening_claim(self):
        change = _change(
            provider_metadata={"record_type": "github_ruleset", "name": "main-protection",
                                "targets_protected_branch": True},
            field_path="restrict_force_pushes",
            prev_value=True,
            new_value=None,
        )
        level, reason = classify_github_change(change)
        assert level == "medium"
        assert "no longer restricts force-pushes" not in reason

    def test_ruleset_restrict_force_pushes_unknown_is_not_a_restore_claim_either(self):
        # Before the fix, _to_bool(None) returned False, so `is False` never
        # matched and this fell into the unconditional else branch, which
        # claimed "now restricts force-pushes" — an equally wrong overstatement
        # in the opposite (falsely reassuring) direction.
        change = _change(
            provider_metadata={"record_type": "github_ruleset", "name": "main-protection",
                                "targets_protected_branch": True},
            field_path="restrict_force_pushes",
            prev_value=True,
            new_value=None,
        )
        _, reason = classify_github_change(change)
        assert "now restricts force-pushes" not in reason

    def test_ruleset_require_signed_commits_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "github_ruleset", "name": "main-protection"},
            field_path="require_signed_commits",
            prev_value=True,
            new_value="not-a-bool",
        )
        level, reason = classify_github_change(change)
        assert level == "medium"
        assert "no longer requires signed commits" not in reason
        assert "now requires signed commits" not in reason

    def test_automation_admin_permission_unknown_is_not_a_restore_claim(self):
        change = _change(
            provider_metadata={"record_type": "github_automation_permissions",
                                "name": "acme/widgets"},
            field_path="repository_permission_admin",
            prev_value=True,
            new_value=None,
        )
        level, reason = classify_github_change(change)
        assert level == "medium"
        assert "no longer has admin" not in reason

    def test_automation_token_broad_scopes_unknown_is_safe(self):
        change = _change(
            provider_metadata={"record_type": "github_automation_permissions",
                                "name": "acme/widgets"},
            field_path="token_broad_scopes",
            prev_value=True,
            new_value=None,
        )
        level, reason = classify_github_change(change)
        assert level == "medium"
        assert "no longer carries broad" not in reason

    def test_ruleset_boolean_fields_still_work_for_real_true_false(self):
        """Regression guard: the None-safety fix must not break the ordinary
        True/False cases still exercised via real compute_diff()."""
        prev = [dict(_RULESET_BASE)]
        new = [{**_RULESET_BASE, "restrict_force_pushes": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "restrict_force_pushes"]
        assert len(matching) == 1
        level, reason = classify_github_change(matching[0])
        assert level in ("high", "critical")
        assert "no longer restricts force-pushes" in reason


class TestWebhookAddedInspectsNewRecord:
    """A newly added webhook must be classified by its own risky posture,
    not a flat 'medium' regardless of how insecure it is from creation."""

    def test_added_http_webhook_is_critical(self):
        new_record = {
            "record_type": "github_webhook", "record_id": "acme/widgets#webhook#1",
            "name": "hook #1", "hook_id": 1, "url": "http://example.com/hook",
            "active": True, "events": ["push"], "content_type": "json",
            "webhook_secret_configured": True, "insecure_ssl_enabled": False,
            "ssl_verification_enabled": True,
        }
        changes = _real_changes([], [new_record])
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        level, reason = classify_github_change(added[0])
        assert level == "critical"
        assert "http://" in reason

    def test_added_webhook_with_ssl_verification_disabled_is_high(self):
        new_record = {
            "record_type": "github_webhook", "record_id": "acme/widgets#webhook#2",
            "name": "hook #2", "hook_id": 2, "url": "https://example.com/hook",
            "active": True, "events": ["push"], "content_type": "json",
            "webhook_secret_configured": True, "insecure_ssl_enabled": True,
            "ssl_verification_enabled": False,
        }
        changes = _real_changes([], [new_record])
        added = [c for c in changes if c["change_type"] == "added"]
        level, reason = classify_github_change(added[0])
        assert level == "high"
        assert "SSL verification disabled" in reason

    def test_added_secure_webhook_is_still_medium(self):
        new_record = {
            "record_type": "github_webhook", "record_id": "acme/widgets#webhook#3",
            "name": "hook #3", "hook_id": 3, "url": "https://example.com/hook",
            "active": True, "events": ["push"], "content_type": "json",
            "webhook_secret_configured": True, "insecure_ssl_enabled": False,
            "ssl_verification_enabled": True,
        }
        changes = _real_changes([], [new_record])
        added = [c for c in changes if c["change_type"] == "added"]
        level, _ = classify_github_change(added[0])
        assert level == "medium"


class TestSecurityFindingSeverityParity:
    """A risky Change transition must not be rated below the equivalent
    static Security Finding."""

    def test_allowed_actions_all_matches_finding_severity_high(self):
        change = _change(
            provider_metadata={"record_type": "github_actions_permissions"},
            field_path="allowed_actions",
            prev_value="selected",
            new_value="all",
        )
        level, _ = classify_github_change(change)
        # github_actions_broad_permissions Security Finding is severity "high"
        # (security_rule_pack.py) — the Change transition must not be lower.
        assert level == "high"


class TestRestorationDirectionCopy:
    """Restoration/improvement directions get distinct, accurate copy."""

    def test_repository_unarchived_is_low_and_says_restored(self):
        change = _change(
            provider_metadata={"record_type": "github_repo_settings"},
            field_path="archived",
            prev_value=True,
            new_value=False,
        )
        level, reason = classify_github_change(change)
        assert level == "low"
        assert "unarchived" in reason.lower()

    def test_pages_https_enforcement_restored_is_low(self):
        change = _change(
            provider_metadata={"record_type": "github_pages"},
            field_path="pages_https_enforced",
            prev_value=False,
            new_value=True,
        )
        level, reason = classify_github_change(change)
        assert level == "low"
        assert "enabled" in reason.lower()
