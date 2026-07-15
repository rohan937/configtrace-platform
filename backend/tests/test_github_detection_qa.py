"""GitHub detection-QA regression coverage (message-1 detection pass).

This file covers bugs found while auditing GitHub connector -> compute_diff
-> classify_github_change reachability:

  1. ``github_ruleset`` and ``github_automation_permissions`` are both live,
     connector-emitted record types (M69.5A / M69.5B), but
     ``_GITHUB_TRACKED_FIELDS_BY_TYPE`` in diff_service.py had NO entry for
     either — the safe ``.get(rt, ())`` fallback meant compute_diff() always
     used an EMPTY tracked-fields tuple for them, so real field-level drift
     (enforcement disabled, admin permission granted, etc.) was silently
     never detected, even though full classifier logic already existed
     (``_classify_ruleset``) or was added in this pass
     (``_classify_automation_permissions``).
  2. ``github_automation_permissions`` additionally had NO dispatch branch
     in ``classify_github_change`` at all — any Change that *did* somehow
     reach it (e.g. after fixing bug #1) fell through to the generic
     "unrecognised record type" low-severity fallback.
  3. ``_classify_ruleset`` reads ``pm.get("targets_protected_branch")`` and
     ``pm.get("name")`` from provider_metadata, but ``_build_provider_
     metadata()`` had no GitHub-specific stanza — only the generic
     ``record_name``/``record_content`` keys were populated — so
     ``targets_protected_branch`` was always the ``False`` default in
     production, permanently capping ruleset-removal/weakening severity at
     "high" even when the ruleset targeted main/release branches.

These tests exercise the REAL compute_diff() -> classify_github_change()
pipeline (not hand-built mocks), matching the established regression
pattern from the Cloudflare/Shopify/Vercel detection-QA passes.
"""

from __future__ import annotations

from app.services.diff_service import compute_diff
from app.services.risk_rules.github import classify_github_change


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]):
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


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
    "token_broad_scopes": True,
    "broad_scope_names": ["repo"],
}


class TestRulesetRealComputeDiff:
    def test_enforcement_disabled_is_detected_and_critical_for_protected_branch(self):
        prev = [dict(_RULESET_BASE)]
        new = [{**_RULESET_BASE, "enforcement": "disabled"}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "enforcement"]
        assert len(matching) == 1, "ruleset enforcement change was not detected by compute_diff"
        change = matching[0]
        assert change["provider_metadata"]["targets_protected_branch"] is True
        level, reason = classify_github_change(change)
        assert level == "critical", f"expected critical for protected-branch ruleset disable, got {level} ({reason})"

    def test_enforcement_disabled_is_only_high_for_non_protected_branch(self):
        prev = [{**_RULESET_BASE, "targets_protected_branch": False}]
        new = [{**prev[0], "enforcement": "disabled"}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "enforcement"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["targets_protected_branch"] is False
        level, _ = classify_github_change(matching[0])
        assert level == "high"

    def test_bypass_actor_count_increase_is_detected(self):
        prev = [dict(_RULESET_BASE)]
        new = [{**_RULESET_BASE, "bypass_actor_count": 3}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "bypass_actor_count"]
        assert len(matching) == 1
        level, reason = classify_github_change(matching[0])
        assert level in ("high", "critical")
        assert "3" in reason

    def test_ruleset_name_comes_from_provider_metadata_not_record_id(self):
        prev = [dict(_RULESET_BASE)]
        new = [{**_RULESET_BASE, "restrict_force_pushes": False}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "restrict_force_pushes"]
        assert len(matching) == 1
        assert matching[0]["provider_metadata"]["name"] == "main-protection"
        _, reason = classify_github_change(matching[0])
        assert "main-protection" in reason


class TestAutomationPermissionsRealComputeDiff:
    def test_admin_permission_granted_is_detected_and_high(self):
        prev = [dict(_AUTOMATION_BASE)]
        new = [{**_AUTOMATION_BASE, "repository_permission_admin": True}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "repository_permission_admin"]
        assert len(matching) == 1, "automation_permissions admin-grant was not detected by compute_diff"
        level, reason = classify_github_change(matching[0])
        assert level == "high", f"expected high, got {level} ({reason})"
        assert "admin" in reason.lower()

    def test_broad_permission_count_increase_is_medium(self):
        prev = [dict(_AUTOMATION_BASE)]
        new = [{**_AUTOMATION_BASE, "broad_permission_count": 2}]
        changes = _real_changes(prev, new)
        matching = [c for c in changes if c["field_path"] == "broad_permission_count"]
        assert len(matching) == 1
        level, _ = classify_github_change(matching[0])
        assert level == "medium"

    def test_unrecognised_fallback_no_longer_used_for_admin_grant(self):
        """Regression guard: before this fix, github_automation_permissions had
        no dispatch branch at all, so any detected change fell through to the
        generic 'unrecognised GitHub configuration record' low-severity
        fallback regardless of what actually changed."""
        prev = [dict(_AUTOMATION_BASE)]
        new = [{**_AUTOMATION_BASE, "repository_permission_admin": True}]
        changes = _real_changes(prev, new)
        _, reason = classify_github_change(changes[0])
        assert "unrecognised" not in reason.lower()
