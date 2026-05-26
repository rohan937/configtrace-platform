"""Tests for M58.14 — Policy Engine MVP.

Strategy
--------
Pure unit tests using MagicMock for DB sessions.  No real DB connection;
DATABASE_URL=sqlite:///test.db is fine.

Test categories
---------------
evaluate_change — provider-level matcher tests:
  1.  AWS SG SSH + 0.0.0.0/0  → aws_no_public_ssh violation produced
  2.  AWS SG RDP + 0.0.0.0/0  → aws_no_public_rdp violation produced
  3.  AWS CloudTrail removed   → aws_cloudtrail_must_log violation produced
  4.  Firebase Firestore ruleset public write → firebase_no_public_writes violation
  5.  Supabase table RLS disabled in risk_reason → supabase_rls_required violation
  6.  GitHub reviewers_count→0 (falsy new_value) → github_required_reviewers violation
  7.  GitHub allow_force_push→True (truthy new_value) → github_no_force_pushes violation
  8.  Cloudflare WAF ruleset removed → cloudflare_waf_enabled violation
  9.  Stripe webhook endpoint removed → stripe_webhooks_must_stay_enabled violation
  10. Vercel deploy hook added/modified → vercel_production_branch_stable violation
  11. Shopify app scope write added → shopify_sensitive_scopes_review violation
  12. Unrelated record_type (e.g. "dns_record") → zero violations from all matchers

Policy control:
  13. evaluate_change excludes a policy whose key is not in enabled_keys
  14. get_workspace_policies merges an explicit "disabled" override correctly
  15. set_policy_enabled creates a new WorkspacePolicy row when none exists
  16. set_policy_enabled raises KeyError for an unknown policy_key

Evidence safety:
  17. Evidence strings for all 11 trigger cases contain zero raw new_value /
      prev_value string content (data-safety guarantee)
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_change(
    *,
    record_type: str = "aws_security_group",
    field_path: str | None = None,
    risk_level: str = "high",
    risk_reason: str = "",
    change_type: str = "modified",
    new_value=None,
    prev_value=None,
    integration_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
) -> MagicMock:
    c = MagicMock()
    c.id = uuid.uuid4()
    c.user_id = user_id or uuid.uuid4()
    c.integration_id = integration_id or uuid.uuid4()
    c.change_type = change_type
    c.record_identifier = "resource-001"
    c.field_path = field_path
    c.new_value = new_value
    c.prev_value = prev_value
    c.risk_level = risk_level
    c.risk_reason = risk_reason
    c.provider_metadata = {"record_type": record_type}
    return c


ALL_KEYS: set[str] = {
    "aws_no_public_ssh",
    "aws_no_public_rdp",
    "aws_cloudtrail_must_log",
    "aws_waf_must_remain_attached",
    "firebase_no_public_writes",
    "firebase_app_check_required",
    "supabase_rls_required",
    "supabase_auth_security_required",
    "github_required_reviewers",
    "github_no_force_pushes",
    "cloudflare_waf_enabled",
    "cloudflare_https_required",
    "stripe_webhooks_must_stay_enabled",
    "stripe_api_keys_least_privilege",
    "vercel_deployment_protection_required",
    "vercel_production_branch_stable",
    "shopify_sensitive_scopes_review",
    "shopify_webhooks_https_required",
}


def _eval(change) -> list:
    """Run evaluate_change with all policies enabled."""
    from app.services.policy_engine_service import evaluate_change
    return evaluate_change(change, ALL_KEYS)


def _violation_keys(change) -> set[str]:
    """Return the set of policy_key strings triggered for change."""
    return {v.policy_key for v in _eval(change)}


# ── 1–12: evaluate_change matcher tests ──────────────────────────────────────


class TestEvaluateChangeMatchers:

    def test_aws_ssh_public_triggers_violation(self):
        """AWS SG with SSH port 22 + 0.0.0.0/0 → aws_no_public_ssh fires."""
        c = _make_change(
            record_type="aws_security_group",
            risk_reason="Public inbound rule: SSH (port 22) open to 0.0.0.0/0",
        )
        assert "aws_no_public_ssh" in _violation_keys(c)

    def test_aws_rdp_public_triggers_violation(self):
        """AWS SG with RDP port 3389 + 0.0.0.0/0 → aws_no_public_rdp fires."""
        c = _make_change(
            record_type="aws_security_group",
            risk_reason="Public inbound rule: RDP (port 3389) open to 0.0.0.0/0",
        )
        assert "aws_no_public_rdp" in _violation_keys(c)

    def test_aws_cloudtrail_removed_triggers_violation(self):
        """CloudTrail record removed → aws_cloudtrail_must_log fires."""
        c = _make_change(
            record_type="aws_cloudtrail",
            change_type="removed",
        )
        assert "aws_cloudtrail_must_log" in _violation_keys(c)

    def test_firebase_public_writes_triggers_violation(self):
        """Firebase Firestore ruleset with public write risk → firebase_no_public_writes fires."""
        c = _make_change(
            record_type="firebase_firestore_ruleset",
            risk_level="critical",
            risk_reason="Public write: allow write detected in ruleset",
            change_type="modified",
        )
        assert "firebase_no_public_writes" in _violation_keys(c)

    def test_supabase_rls_disabled_triggers_violation(self):
        """Supabase table with RLS disabled in risk_reason → supabase_rls_required fires."""
        c = _make_change(
            record_type="supabase_table",
            risk_reason="RLS disabled on orders table",
            risk_level="critical",
        )
        assert "supabase_rls_required" in _violation_keys(c)

    def test_github_reviewers_to_zero_triggers_violation(self):
        """GitHub branch protection reviewers_count set to 0 → github_required_reviewers fires."""
        c = _make_change(
            record_type="github_environment",
            field_path="required_reviewers_count",
            new_value=False,  # falsy — count removed
            risk_reason="Required reviewer count reduced",
        )
        assert "github_required_reviewers" in _violation_keys(c)

    def test_github_force_push_enabled_triggers_violation(self):
        """GitHub allow_force_push set to True → github_no_force_pushes fires."""
        c = _make_change(
            record_type="github_branch_protection",
            field_path="allow_force_pushes",
            new_value=True,
        )
        assert "github_no_force_pushes" in _violation_keys(c)

    def test_cloudflare_waf_removed_triggers_violation(self):
        """Cloudflare WAF ruleset removed → cloudflare_waf_enabled fires."""
        c = _make_change(
            record_type="cloudflare_ruleset",
            change_type="removed",
            risk_reason="WAF ruleset removed",
        )
        assert "cloudflare_waf_enabled" in _violation_keys(c)

    def test_stripe_webhook_removed_triggers_violation(self):
        """Stripe webhook removed → stripe_webhooks_must_stay_enabled fires."""
        c = _make_change(
            record_type="stripe_webhook",
            change_type="removed",
        )
        assert "stripe_webhooks_must_stay_enabled" in _violation_keys(c)

    def test_vercel_deploy_hook_modified_triggers_violation(self):
        """Vercel deploy hook modified → vercel_production_branch_stable fires."""
        c = _make_change(
            record_type="vercel_deploy_hook",
            change_type="modified",
            risk_reason="Deploy hook URL changed",
        )
        assert "vercel_production_branch_stable" in _violation_keys(c)

    def test_shopify_write_scope_added_triggers_violation(self):
        """Shopify app write scope added → shopify_sensitive_scopes_review fires."""
        c = _make_change(
            record_type="shopify_app",
            change_type="added",
            risk_reason="Sensitive write scope added: write_orders",
        )
        assert "shopify_sensitive_scopes_review" in _violation_keys(c)

    def test_unrelated_record_type_produces_no_violations(self):
        """A change with no provider-matching record_type → zero violations."""
        c = _make_change(
            record_type="unknown_dns_record",
            risk_level="medium",
            risk_reason="Generic change to a DNS record",
        )
        violations = _eval(c)
        assert violations == [], (
            f"Expected no violations for unrelated record type, got: "
            f"{[v.policy_key for v in violations]}"
        )


# ── 13–16: Policy control ─────────────────────────────────────────────────────


class TestPolicyControl:

    def test_disabled_policy_key_excluded_from_evaluation(self):
        """When aws_no_public_ssh is absent from enabled_keys it never fires."""
        from app.services.policy_engine_service import evaluate_change

        c = _make_change(
            record_type="aws_security_group",
            risk_reason="Public inbound rule: SSH (port 22) open to 0.0.0.0/0",
        )
        # Remove the SSH policy from enabled set
        reduced_keys = ALL_KEYS - {"aws_no_public_ssh"}
        violations = evaluate_change(c, reduced_keys)
        assert all(v.policy_key != "aws_no_public_ssh" for v in violations), (
            "aws_no_public_ssh fired even though it was not in enabled_keys"
        )

    def test_get_workspace_policies_applies_disabled_override(self):
        """get_workspace_policies returns enabled=False when workspace override is False."""
        from app.services.policy_engine_service import get_workspace_policies
        from app.models.workspace_policy import WorkspacePolicy

        workspace_id = uuid.uuid4()

        # Build a mock WorkspacePolicy row that disables supabase_rls_required
        override_row = MagicMock(spec=WorkspacePolicy)
        override_row.policy_key = "supabase_rls_required"
        override_row.enabled = False

        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [override_row]

        result = get_workspace_policies(workspace_id, db)

        rls_policy = next(
            (p for p in result.policies if p.policy_key == "supabase_rls_required"),
            None,
        )
        assert rls_policy is not None, "supabase_rls_required missing from catalog"
        assert rls_policy.enabled is False, (
            "Override to disabled not reflected — expected enabled=False"
        )
        assert result.total == 18, f"Expected 18 policies in catalog, got {result.total}"

    def test_set_policy_enabled_creates_new_row(self):
        """set_policy_enabled inserts a WorkspacePolicy row when none exists."""
        from app.services.policy_engine_service import set_policy_enabled

        workspace_id = uuid.uuid4()
        db = MagicMock()

        # No existing row found
        db.query.return_value.filter.return_value.first.return_value = None

        result = set_policy_enabled(
            workspace_id=workspace_id,
            policy_key="aws_no_public_ssh",
            enabled=False,
            db=db,
        )

        # db.add should have been called with a WorkspacePolicy instance
        db.add.assert_called_once()
        added = db.add.call_args[0][0]
        from app.models.workspace_policy import WorkspacePolicy
        assert isinstance(added, WorkspacePolicy)
        assert added.enabled is False
        assert added.policy_key == "aws_no_public_ssh"

        # Return value carries catalog metadata
        assert result.policy_key == "aws_no_public_ssh"
        assert result.enabled is False
        assert result.built_in is True

    def test_set_policy_enabled_raises_for_unknown_key(self):
        """set_policy_enabled raises KeyError for a policy_key not in the catalog."""
        from app.services.policy_engine_service import set_policy_enabled

        db = MagicMock()
        with pytest.raises(KeyError, match="Unknown policy key"):
            set_policy_enabled(
                workspace_id=uuid.uuid4(),
                policy_key="totally_fake_policy",
                enabled=True,
                db=db,
            )


# ── 17: Evidence safety ───────────────────────────────────────────────────────


class TestEvidenceSafety:

    CANARY_NEW = "SUPER_SECRET_NEW_VALUE_DO_NOT_EXPOSE"
    CANARY_PREV = "SUPER_SECRET_PREV_VALUE_DO_NOT_EXPOSE"

    def _trigger_cases(self):
        """Return a list of (label, change) pairs for each triggering matcher."""
        return [
            (
                "aws_ssh",
                _make_change(
                    record_type="aws_security_group",
                    risk_reason="Public inbound rule: SSH (port 22) open to 0.0.0.0/0",
                    new_value=self.CANARY_NEW,
                    prev_value=self.CANARY_PREV,
                ),
            ),
            (
                "aws_rdp",
                _make_change(
                    record_type="aws_security_group",
                    risk_reason="Public inbound rule: RDP (port 3389) open to 0.0.0.0/0",
                    new_value=self.CANARY_NEW,
                    prev_value=self.CANARY_PREV,
                ),
            ),
            (
                "cloudtrail",
                _make_change(
                    record_type="aws_cloudtrail",
                    change_type="removed",
                    new_value=self.CANARY_NEW,
                    prev_value=self.CANARY_PREV,
                ),
            ),
            (
                "firebase_writes",
                _make_change(
                    record_type="firebase_firestore_ruleset",
                    risk_level="critical",
                    risk_reason="Public write: allow write detected in ruleset",
                    change_type="modified",
                    new_value=self.CANARY_NEW,
                    prev_value=self.CANARY_PREV,
                ),
            ),
            (
                "supabase_rls",
                _make_change(
                    record_type="supabase_table",
                    risk_reason="RLS disabled on orders table",
                    risk_level="critical",
                    new_value=self.CANARY_NEW,
                    prev_value=self.CANARY_PREV,
                ),
            ),
            (
                "github_reviewers",
                _make_change(
                    record_type="github_environment",
                    field_path="required_reviewers_count",
                    new_value=False,
                    prev_value=self.CANARY_PREV,
                    risk_reason="Required reviewer count reduced",
                ),
            ),
            (
                "github_force_push",
                _make_change(
                    record_type="github_branch_protection",
                    field_path="allow_force_pushes",
                    new_value=True,
                    prev_value=self.CANARY_PREV,
                ),
            ),
            (
                "cloudflare_waf",
                _make_change(
                    record_type="cloudflare_ruleset",
                    change_type="removed",
                    risk_reason="WAF ruleset removed",
                    new_value=self.CANARY_NEW,
                    prev_value=self.CANARY_PREV,
                ),
            ),
            (
                "stripe_webhook",
                _make_change(
                    record_type="stripe_webhook",
                    change_type="removed",
                    new_value=self.CANARY_NEW,
                    prev_value=self.CANARY_PREV,
                ),
            ),
            (
                "vercel_deploy_hook",
                _make_change(
                    record_type="vercel_deploy_hook",
                    change_type="modified",
                    risk_reason="Deploy hook URL changed",
                    new_value=self.CANARY_NEW,
                    prev_value=self.CANARY_PREV,
                ),
            ),
            (
                "shopify_scope",
                _make_change(
                    record_type="shopify_app",
                    change_type="added",
                    risk_reason="Sensitive write scope added: write_orders",
                    new_value=self.CANARY_NEW,
                    prev_value=self.CANARY_PREV,
                ),
            ),
        ]

    def test_evidence_never_contains_raw_value_content(self):
        """Evidence strings must never contain raw new_value / prev_value string content.

        The canary strings are placed in new_value and prev_value.  If any evidence
        string contains either canary, the service has leaked raw configuration data.
        """
        leaked: list[str] = []

        for label, change in self._trigger_cases():
            violations = _eval(change)
            for v in violations:
                for item in v.evidence:
                    if self.CANARY_NEW in item or self.CANARY_PREV in item:
                        leaked.append(
                            f"{label}/{v.policy_key}: evidence item contains canary: {item!r}"
                        )

        assert leaked == [], (
            "Evidence safety violation — raw value content leaked:\n"
            + "\n".join(leaked)
        )
