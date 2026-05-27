"""GitHub risk accuracy audit — local-only regression tests.

Documents ConfigTrace's GitHub risk policy across all eight record types
(repo_settings, branch_protection, actions_secret, actions_variable,
webhook, actions_permissions, deploy_key, environment_protection).
Any future regression that mis-rates one of these scenarios fails loudly
here.

Special safety rules for GitHub:
  • Secret values are NEVER stored, fetched, or echoed. Only the secret
    NAME appears (which is public in the repo settings UI).
  • Deploy key material is NEVER echoed — only key title and read/write
    flag are surfaced.
  • Webhook URLs are referenced in reasons only when the URL itself
    changed; full URLs and embedded query secrets must not appear.
  • Reasons hedge with "may allow", "could weaken", "may disrupt" rather
    than claiming guaranteed outages or compromised systems.

Pure-mock; no DB, no network, no GitHub API.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _change(
    *,
    record_type: str,
    field_path: str | None = None,
    change_type: str = "modified",
    new_value: Any = None,
    prev_value: Any = None,
    record_name: str = "",
    extra_metadata: dict[str, Any] | None = None,
) -> MagicMock:
    pm: dict[str, Any] = {
        "record_type": record_type,
        "record_name": record_name,
    }
    if extra_metadata:
        pm.update(extra_metadata)
    c = MagicMock(name="Change")
    c.field_path        = field_path
    c.change_type       = change_type
    c.new_value         = new_value
    c.prev_value        = prev_value
    c.provider_metadata = pm
    return c


def _classify(change):
    from app.services.risk_rules.github import classify_github_change
    return classify_github_change(change)


# ═════════════════════════════════════════════════════════════════════════════
# A. Repository settings
# ═════════════════════════════════════════════════════════════════════════════

class TestRepoSettings:
    def test_A1_visibility_private_to_public_is_critical(self):
        c = _change(
            record_type="github_repo_settings",
            field_path="visibility",
            new_value="public",
            prev_value="private",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_A2_visibility_public_to_private_is_medium(self):
        c = _change(
            record_type="github_repo_settings",
            field_path="visibility",
            new_value="private",
            prev_value="public",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_A3_default_branch_changed_is_high(self):
        c = _change(
            record_type="github_repo_settings",
            field_path="default_branch",
            new_value="release",
            prev_value="main",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A4_archived_is_medium(self):
        c = _change(
            record_type="github_repo_settings",
            field_path="archived",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# B. Branch protection
# ═════════════════════════════════════════════════════════════════════════════

class TestBranchProtection:
    def test_B1_protection_removed_is_critical(self):
        c = _change(
            record_type="github_branch_protection",
            change_type="removed",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_B2_protection_enabled_false_is_critical(self):
        c = _change(
            record_type="github_branch_protection",
            field_path="protection_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_B3_allow_force_pushes_is_critical(self):
        c = _change(
            record_type="github_branch_protection",
            field_path="allow_force_pushes",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_B4_allow_deletions_is_critical(self):
        c = _change(
            record_type="github_branch_protection",
            field_path="allow_deletions",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_B5_required_status_checks_disabled_is_critical(self):
        c = _change(
            record_type="github_branch_protection",
            field_path="required_status_checks_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_B6_required_pr_reviews_disabled_is_critical(self):
        c = _change(
            record_type="github_branch_protection",
            field_path="required_pull_request_reviews_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_B7_enforce_admins_disabled_is_high(self):
        c = _change(
            record_type="github_branch_protection",
            field_path="enforce_admins",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B8_required_linear_history_disabled_is_high(self):
        c = _change(
            record_type="github_branch_protection",
            field_path="required_linear_history",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B9_required_review_count_reduced_is_high(self):
        c = _change(
            record_type="github_branch_protection",
            field_path="required_approving_review_count",
            new_value=1,
            prev_value=2,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B10_required_review_count_increased_is_medium(self):
        c = _change(
            record_type="github_branch_protection",
            field_path="required_approving_review_count",
            new_value=2,
            prev_value=1,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_B11_dismiss_stale_reviews_disabled_is_high(self):
        # Per brief: "dismiss stale reviews disabled is High."
        c = _change(
            record_type="github_branch_protection",
            field_path="dismiss_stale_reviews",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B12_protection_added_is_low(self):
        c = _change(
            record_type="github_branch_protection",
            change_type="added",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_B13_protection_strengthening_is_low(self):
        c = _change(
            record_type="github_branch_protection",
            field_path="enforce_admins",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# C. Actions secrets
# ═════════════════════════════════════════════════════════════════════════════

class TestActionsSecrets:
    @pytest.mark.parametrize("name", [
        "STRIPE_SECRET_KEY",
        "DATABASE_URL",
        "CLERK_SECRET_KEY",
        "JWT_SECRET",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "SLACK_BOT_TOKEN",
    ])
    def test_C1_sensitive_secret_removed_is_at_least_high(self, name):
        c = _change(
            record_type="github_actions_secret",
            change_type="removed",
            record_name=name,
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")

    @pytest.mark.parametrize("name", [
        "STRIPE_SECRET_KEY", "DATABASE_URL", "JWT_SECRET",
    ])
    def test_C2_sensitive_secret_rotated_is_at_least_high(self, name):
        c = _change(
            record_type="github_actions_secret",
            field_path="last_updated_at",
            new_value="2024-12-01T00:00:00Z",
            prev_value="2024-11-01T00:00:00Z",
            record_name=name,
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")

    def test_C3_non_sensitive_secret_removed_is_medium(self):
        c = _change(
            record_type="github_actions_secret",
            change_type="removed",
            record_name="FEATURE_FLAG",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_C4_sensitive_secret_added_is_medium(self):
        c = _change(
            record_type="github_actions_secret",
            change_type="added",
            record_name="STRIPE_SECRET_KEY",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_C5_non_sensitive_secret_added_is_low(self):
        c = _change(
            record_type="github_actions_secret",
            change_type="added",
            record_name="FEATURE_FLAG",
        )
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# D. Actions variables
# ═════════════════════════════════════════════════════════════════════════════

class TestActionsVariables:
    def test_D1_sensitive_variable_modified_is_high(self):
        c = _change(
            record_type="github_actions_variable",
            change_type="modified",
            new_value="new-value",
            prev_value="old-value",
            record_name="DATABASE_URL",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_D2_non_sensitive_variable_changed_to_url_is_high(self):
        c = _change(
            record_type="github_actions_variable",
            change_type="modified",
            new_value="https://api.example.com",
            prev_value="https://old.example.com",
            record_name="API_URL_PUBLIC",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_D3_non_sensitive_variable_modified_is_low(self):
        c = _change(
            record_type="github_actions_variable",
            change_type="modified",
            new_value="v2",
            prev_value="v1",
            record_name="FEATURE_FLAG_VERSION",
        )
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# E. Webhooks
# ═════════════════════════════════════════════════════════════════════════════

class TestWebhooks:
    def test_E1_webhook_removed_is_high(self):
        c = _change(
            record_type="github_webhook",
            change_type="removed",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_E2_webhook_url_changed_https_is_high(self):
        c = _change(
            record_type="github_webhook",
            field_path="url",
            new_value="https://api.example.com/hooks/v2",
            prev_value="https://api.example.com/hooks/v1",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_E3_webhook_url_changed_to_http_is_critical(self):
        # Per brief: "webhook URL changed to HTTP for deploy/security/release
        # events" is Critical. The classifier should examine the new URL
        # scheme and escalate regardless of the event set.
        c = _change(
            record_type="github_webhook",
            field_path="url",
            new_value="http://api.example.com/hooks",
            prev_value="https://api.example.com/hooks",
        )
        level, reason = _classify(c)
        assert level == "critical", (
            f"HTTP webhook URL must escalate to critical; got {level} ({reason!r})"
        )

    def test_E4_webhook_active_false_is_high(self):
        c = _change(
            record_type="github_webhook",
            field_path="active",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_E5_webhook_added_is_medium(self):
        c = _change(
            record_type="github_webhook",
            change_type="added",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_E6_webhook_events_changed_is_medium(self):
        c = _change(
            record_type="github_webhook",
            field_path="events",
            new_value=["push", "pull_request"],
            prev_value=["push"],
        )
        level, _ = _classify(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# F. Actions permissions
# ═════════════════════════════════════════════════════════════════════════════

class TestActionsPermissions:
    def test_F1_actions_disabled_is_high(self):
        c = _change(
            record_type="github_actions_permissions",
            field_path="enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_F2_actions_re_enabled_is_medium(self):
        c = _change(
            record_type="github_actions_permissions",
            field_path="enabled",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_F3_allowed_actions_all_is_at_least_medium(self):
        c = _change(
            record_type="github_actions_permissions",
            field_path="allowed_actions",
            new_value="all",
            prev_value="selected",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")


# ═════════════════════════════════════════════════════════════════════════════
# G. Deploy keys
# ═════════════════════════════════════════════════════════════════════════════

class TestDeployKeys:
    def test_G1_write_deploy_key_added_is_critical(self):
        c = _change(
            record_type="github_deploy_key",
            change_type="added",
            new_value={"read_only": False, "title": "ci-write"},
            record_name="ci-write",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_G2_read_only_deploy_key_added_is_medium(self):
        c = _change(
            record_type="github_deploy_key",
            change_type="added",
            new_value={"read_only": True, "title": "ci-read"},
            record_name="ci-read",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_G3_deploy_key_removed_is_high(self):
        c = _change(
            record_type="github_deploy_key",
            change_type="removed",
            record_name="ci-read",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_G4_deploy_key_upgraded_to_write_is_at_least_high(self):
        # Per brief: "deploy key write access enabled is Critical/High."
        c = _change(
            record_type="github_deploy_key",
            field_path="read_only",
            new_value=False,
            prev_value=True,
            record_name="ci-key",
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")


# ═════════════════════════════════════════════════════════════════════════════
# H. Environment protection
# ═════════════════════════════════════════════════════════════════════════════

class TestEnvironmentProtection:
    def test_H1_environment_removed_is_high(self):
        c = _change(
            record_type="github_environment_protection",
            change_type="removed",
            record_name="production",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_H2_environment_added_is_low(self):
        c = _change(
            record_type="github_environment_protection",
            change_type="added",
            record_name="production",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_H3_reviewers_count_decreased_is_high(self):
        c = _change(
            record_type="github_environment_protection",
            field_path="reviewers_count",
            new_value=0,
            prev_value=2,
            record_name="production",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_H4_reviewers_count_increased_is_low(self):
        c = _change(
            record_type="github_environment_protection",
            field_path="reviewers_count",
            new_value=3,
            prev_value=1,
            record_name="production",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_H5_protected_branches_disabled_is_high(self):
        c = _change(
            record_type="github_environment_protection",
            field_path="protected_branches",
            new_value=False,
            prev_value=True,
            record_name="production",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_H6_wait_timer_decreased_is_medium(self):
        c = _change(
            record_type="github_environment_protection",
            field_path="wait_timer",
            new_value=0,
            prev_value=15,
            record_name="production",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_H7_prevent_self_review_disabled_is_medium(self):
        c = _change(
            record_type="github_environment_protection",
            field_path="prevent_self_review",
            new_value=False,
            prev_value=True,
            record_name="production",
        )
        level, _ = _classify(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# I. Unknown subtype + dispatcher safety
# ═════════════════════════════════════════════════════════════════════════════

class TestUnknownAndSafety:
    def test_I1_unknown_subtype_falls_back_safely(self):
        c = _change(record_type="github_future_thing")
        level, reason = _classify(c)
        assert level == "low"
        assert isinstance(reason, str) and len(reason) > 0

    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_I2_malformed_provider_metadata_does_not_crash(self, bad_pm):
        c = MagicMock(name="Change")
        c.field_path        = "field"
        c.change_type       = "modified"
        c.new_value         = None
        c.prev_value        = None
        c.provider_metadata = bad_pm
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# J. Secret / webhook / deploy-key safety
# ═════════════════════════════════════════════════════════════════════════════

class TestSecretAndKeySafety:
    """Risk reasons must never expose GitHub tokens, App private keys,
    installation tokens, webhook secrets, deploy key material, full
    webhook URLs with embedded tokens, or Authorization headers."""

    @pytest.mark.parametrize("change_args", [
        # Secret rotation — must not echo timestamps as if they were tokens
        dict(record_type="github_actions_secret",
             field_path="last_updated_at",
             new_value="2024-12-01T00:00:00Z", prev_value="2024-11-01T00:00:00Z",
             record_name="STRIPE_SECRET_KEY"),
        # Secret deletion — record_name only
        dict(record_type="github_actions_secret",
             change_type="removed", record_name="GITHUB_TOKEN"),
        # Webhook URL change — must not echo new_value verbatim
        dict(record_type="github_webhook", field_path="url",
             new_value="https://hooks.example.com/x?token=SECRET",
             prev_value="https://hooks.example.com/y"),
        # Deploy key added with write access — must not echo key material
        dict(record_type="github_deploy_key", change_type="added",
             new_value={"read_only": False, "title": "ci-key",
                        "key": "ssh-rsa AAAA-FAKE-KEY-MATERIAL-DO-NOT-LOG"},
             record_name="ci-key"),
        # Branch protection removed
        dict(record_type="github_branch_protection", change_type="removed"),
    ])
    def test_J1_reason_does_not_leak_secrets_or_keys(self, change_args):
        c = _change(**change_args)
        _, reason = _classify(c)
        lower = reason.lower()
        # Secret prefixes (Stripe / GitHub / generic)
        for prefix in (
            "sk_live_", "sk_test_", "whsec_",
            "ghp_", "gho_", "ghu_", "ghs_", "github_pat_",
            "-----begin", "ssh-rsa aaaa", "ssh-ed25519",
        ):
            assert prefix not in lower, (
                f"reason contains a secret/key prefix {prefix!r}: {reason!r}"
            )
        # Auth headers
        for marker in ("authorization:", "bearer "):
            assert marker not in lower, (
                f"reason contains an auth marker: {reason!r}"
            )

    def test_J2_webhook_url_change_reason_does_not_echo_new_url(self):
        # Even when the connector hands us a URL, the classifier must
        # describe the change without including the literal URL — could
        # carry embedded query secrets.
        c = _change(
            record_type="github_webhook",
            field_path="url",
            new_value="https://hooks.example.com/x?token=SECRET-VALUE",
            prev_value="https://hooks.example.com/y",
        )
        _, reason = _classify(c)
        assert "secret-value" not in reason.lower()
        assert "token=" not in reason.lower()
        assert "hooks.example.com" not in reason

    def test_J3_deploy_key_added_reason_does_not_echo_key_material(self):
        c = _change(
            record_type="github_deploy_key",
            change_type="added",
            new_value={
                "read_only": False,
                "title": "ci-write",
                "key": "ssh-rsa AAAA-FAKE-KEY-MATERIAL-DO-NOT-LOG",
            },
            record_name="ci-write",
        )
        _, reason = _classify(c)
        lower = reason.lower()
        assert "ssh-rsa" not in lower
        assert "aaaa-fake" not in lower
        assert "key-material" not in lower

    def test_J4_no_long_base64_or_token_shaped_strings_echoed(self):
        import re
        cases = [
            dict(record_type="github_actions_secret",
                 field_path="last_updated_at",
                 new_value="2024-12-01", prev_value="2024-11-01",
                 record_name="JWT_SECRET"),
            dict(record_type="github_webhook", field_path="url",
                 new_value="https://hooks.example.com/" + "A" * 80,
                 prev_value="https://hooks.example.com/old"),
            dict(record_type="github_deploy_key", change_type="added",
                 new_value={"read_only": False,
                            "key": "BBBBBBBBBB" * 12},
                 record_name="ci-write"),
        ]
        for args in cases:
            _, reason = _classify(_change(**args))
            assert not re.search(r"[A-Za-z0-9+/=]{60,}", reason), (
                f"reason contains a token-shaped string: {reason!r}"
            )

    def test_J5_no_auto_fix_or_compromised_language(self):
        cases = [
            dict(record_type="github_repo_settings", field_path="visibility",
                 new_value="public", prev_value="private"),
            dict(record_type="github_branch_protection", change_type="removed"),
            dict(record_type="github_actions_secret",
                 change_type="removed", record_name="STRIPE_SECRET_KEY"),
            dict(record_type="github_deploy_key", change_type="added",
                 new_value={"read_only": False}, record_name="ci-write"),
            dict(record_type="github_environment_protection",
                 field_path="reviewers_count",
                 new_value=0, prev_value=2, record_name="production"),
        ]
        bad = (
            "auto-fix", "automatically fix", "guaranteed", "auto fix",
            "guaranteed outage", "is compromised",
            "definitely compromised", "definitely down",
        )
        for args in cases:
            _, reason = _classify(_change(**args))
            lower = reason.lower()
            for phrase in bad:
                assert phrase not in lower, (
                    f"reason contains {phrase!r}: {reason!r}"
                )
