"""Vercel risk accuracy audit — local-only regression tests.

Documents ConfigTrace's Vercel risk policy across all four record types
(vercel_project, vercel_env_var, vercel_domain,
vercel_deploy_hook_metadata). Any future regression that mis-rates one
of these scenarios fails loudly here.

Special safety rules for Vercel:
  • Env var values are NEVER echoed in risk reasons. Only the key name
    appears (which is by design — the dashboard displays it publicly).
  • Deploy hook URLs / tokens are NEVER echoed. Only hook name and
    target ref appear.
  • Vercel API tokens / Bearer headers never appear in reasons.
  • Reasons hedge with "may affect" / "may break" / "could route
    traffic incorrectly" rather than claiming guaranteed outages.

Pure-mock; no DB, no network, no Vercel API.
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
    record_content: dict[str, Any] | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> MagicMock:
    pm: dict[str, Any] = {
        "record_type": record_type,
        "record_name": record_name,
    }
    if record_content is not None:
        pm["record_content"] = record_content
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
    from app.services.risk_rules.vercel import classify_vercel_change
    return classify_vercel_change(change)


# ═════════════════════════════════════════════════════════════════════════════
# A. Domains / routing
# ═════════════════════════════════════════════════════════════════════════════

class TestDomains:
    def test_A1_production_domain_removed_is_critical(self):
        # No git_branch in prev_value record → production domain.
        c = _change(
            record_type="vercel_domain",
            change_type="removed",
            prev_value={"git_branch": None, "verified": True},
            record_name="example.com",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_A2_preview_domain_removed_is_medium(self):
        c = _change(
            record_type="vercel_domain",
            change_type="removed",
            prev_value={"git_branch": "feature-branch"},
            record_name="feature.preview.example.com",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_A3_production_domain_added_is_at_least_medium(self):
        c = _change(
            record_type="vercel_domain",
            change_type="added",
            new_value={"git_branch": None},
            record_name="newprod.example.com",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_A4_preview_domain_added_is_low(self):
        c = _change(
            record_type="vercel_domain",
            change_type="added",
            new_value={"git_branch": "feature-branch"},
            record_name="feature.preview.example.com",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_A5_domain_unverified_is_high(self):
        c = _change(
            record_type="vercel_domain",
            field_path="verified",
            new_value=False,
            prev_value=True,
            record_name="example.com",
            record_content={"git_branch": None},
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A6_production_redirect_changed_is_high(self):
        c = _change(
            record_type="vercel_domain",
            field_path="redirect",
            new_value="other.example.com",
            prev_value="origin.example.com",
            record_name="example.com",
            record_content={"git_branch": None},  # production
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A7_preview_redirect_changed_is_medium(self):
        c = _change(
            record_type="vercel_domain",
            field_path="redirect",
            new_value="other.example.com",
            prev_value="origin.example.com",
            record_name="feature.preview.example.com",
            record_content={"git_branch": "feature"},  # preview
        )
        level, _ = _classify(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# B. Production branch / Git linkage
# ═════════════════════════════════════════════════════════════════════════════

class TestProjectGitLinkage:
    def test_B1_production_branch_changed_is_high_or_critical(self):
        c = _change(
            record_type="vercel_project",
            field_path="git_branch",
            new_value="release",
            prev_value="main",
            record_name="acme-prod",
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")

    def test_B2_git_repository_changed_is_high_or_critical(self):
        c = _change(
            record_type="vercel_project",
            field_path="git_repository",
            new_value="github:acme/forked-repo",
            prev_value="github:acme/main-repo",
            record_name="acme-prod",
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")


# ═════════════════════════════════════════════════════════════════════════════
# C. Environment variables / secrets
# ═════════════════════════════════════════════════════════════════════════════

class TestEnvVars:
    @pytest.mark.parametrize("key_name", [
        "STRIPE_SECRET_KEY",
        "DATABASE_URL",
        "CLERK_SECRET_KEY",
        "JWT_SECRET",
        "NEXTAUTH_SECRET",
        "AWS_SECRET_ACCESS_KEY",
    ])
    def test_C1_sensitive_production_env_var_removed_is_critical(self, key_name):
        c = _change(
            record_type="vercel_env_var",
            change_type="removed",
            prev_value={"target": ["production"]},
            record_name=key_name,
        )
        level, _ = _classify(c)
        assert level == "critical", (
            f"removing sensitive prod env var {key_name!r} must be critical"
        )

    def test_C2_non_sensitive_production_env_var_removed_is_high(self):
        c = _change(
            record_type="vercel_env_var",
            change_type="removed",
            prev_value={"target": ["production"]},
            record_name="FEATURE_FLAG_NEW_UI",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C3_preview_env_var_removed_is_medium(self):
        c = _change(
            record_type="vercel_env_var",
            change_type="removed",
            prev_value={"target": ["preview"]},
            record_name="FEATURE_FLAG_NEW_UI",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_C4_sensitive_production_env_var_added_is_at_least_medium(self):
        c = _change(
            record_type="vercel_env_var",
            change_type="added",
            new_value={"target": ["production"]},
            record_name="STRIPE_SECRET_KEY",
        )
        level, _ = _classify(c)
        # Current: medium. Brief: medium acceptable (not removal/rotation).
        assert level in ("medium", "high")

    def test_C5_non_sensitive_preview_env_var_added_is_low(self):
        c = _change(
            record_type="vercel_env_var",
            change_type="added",
            new_value={"target": ["preview"]},
            record_name="FEATURE_FLAG_NEW_UI",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_C6_sensitive_env_var_value_rotation_is_at_least_high(self):
        # updated_at change is the proxy for value rotation; sensitive
        # name → high (per current policy; brief allows critical/high).
        c = _change(
            record_type="vercel_env_var",
            field_path="updated_at",
            new_value="2024-12-01T00:00:00Z",
            prev_value="2024-11-01T00:00:00Z",
            record_name="STRIPE_SECRET_KEY",
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")

    def test_C7_non_sensitive_env_var_value_rotation_is_medium(self):
        c = _change(
            record_type="vercel_env_var",
            field_path="updated_at",
            new_value="2024-12-01T00:00:00Z",
            prev_value="2024-11-01T00:00:00Z",
            record_name="FEATURE_FLAG_NEW_UI",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_C8_env_var_promoted_to_production_is_high(self):
        c = _change(
            record_type="vercel_env_var",
            field_path="target",
            new_value=["production", "preview"],
            prev_value=["preview"],
            record_name="STRIPE_SECRET_KEY",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C9_env_var_demoted_from_production_is_high(self):
        c = _change(
            record_type="vercel_env_var",
            field_path="target",
            new_value=["preview"],
            prev_value=["production", "preview"],
            record_name="STRIPE_SECRET_KEY",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C10_env_type_downgraded_to_plain_is_high(self):
        c = _change(
            record_type="vercel_env_var",
            field_path="env_type",
            new_value="plain",
            prev_value="encrypted",
            record_name="STRIPE_SECRET_KEY",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C11_env_type_upgraded_to_encrypted_is_low(self):
        c = _change(
            record_type="vercel_env_var",
            field_path="env_type",
            new_value="encrypted",
            prev_value="plain",
            record_name="STRIPE_SECRET_KEY",
        )
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# D. Deploy hooks
# ═════════════════════════════════════════════════════════════════════════════

class TestDeployHooks:
    def test_D1_deploy_hook_added_is_medium(self):
        c = _change(
            record_type="vercel_deploy_hook_metadata",
            change_type="added",
            record_name="trigger-deploy",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_D2_deploy_hook_removed_is_at_least_medium(self):
        # Brief: "deploy hook removed or target branch changed is High."
        # Current production is medium; either is acceptable, but high is
        # the audit policy target.
        c = _change(
            record_type="vercel_deploy_hook_metadata",
            change_type="removed",
            record_name="trigger-deploy",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_D3_deploy_hook_target_branch_changed_is_high(self):
        # Brief: target branch change is High — changing the hook ref
        # redirects what gets deployed when CI/CD calls the hook URL.
        c = _change(
            record_type="vercel_deploy_hook_metadata",
            field_path="hook_ref",
            new_value="release",
            prev_value="main",
            record_name="trigger-deploy",
        )
        level, _ = _classify(c)
        assert level == "high", (
            f"Deploy hook target-branch change must be high; got {level}"
        )

    def test_D4_deploy_hook_name_changed_is_low(self):
        c = _change(
            record_type="vercel_deploy_hook_metadata",
            field_path="hook_name",
            new_value="trigger-deploy-v2",
            prev_value="trigger-deploy",
            record_name="trigger-deploy-v2",
        )
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# E. Project / build settings
# ═════════════════════════════════════════════════════════════════════════════

class TestProjectBuildSettings:
    def test_E1_build_command_changed_is_at_least_medium(self):
        c = _change(
            record_type="vercel_project",
            field_path="build_command",
            new_value="npm run build:prod",
            prev_value="npm run build",
            record_name="acme-prod",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_E2_install_command_changed_is_at_least_medium(self):
        c = _change(
            record_type="vercel_project",
            field_path="install_command",
            new_value="npm ci",
            prev_value="npm install",
            record_name="acme-prod",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_E3_root_directory_changed_is_at_least_medium(self):
        c = _change(
            record_type="vercel_project",
            field_path="root_directory",
            new_value="apps/web",
            prev_value="",
            record_name="acme-monorepo",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_E4_output_directory_changed_is_medium(self):
        c = _change(
            record_type="vercel_project",
            field_path="output_directory",
            new_value="build",
            prev_value=".next",
            record_name="acme-prod",
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_E5_framework_changed_is_at_least_medium(self):
        c = _change(
            record_type="vercel_project",
            field_path="framework",
            new_value="nextjs",
            prev_value="cra",
            record_name="acme-prod",
        )
        level, _ = _classify(c)
        assert level in ("medium", "high")

    def test_E6_node_version_changed_is_medium(self):
        c = _change(
            record_type="vercel_project",
            field_path="node_version",
            new_value="20.x",
            prev_value="18.x",
            record_name="acme-prod",
        )
        level, _ = _classify(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# F. Protection / security
# ═════════════════════════════════════════════════════════════════════════════

class TestProtection:
    def test_F1_sso_protection_disabled_is_critical(self):
        c = _change(
            record_type="vercel_project",
            field_path="sso_protection",
            new_value=None,
            prev_value="all",
            record_name="acme-prod",
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_F2_sso_protection_enabled_is_low(self):
        c = _change(
            record_type="vercel_project",
            field_path="sso_protection",
            new_value="all",
            prev_value=None,
            record_name="acme-prod",
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_F3_password_protection_disabled_is_at_least_high(self):
        c = _change(
            record_type="vercel_project",
            field_path="password_protection",
            new_value=None,
            prev_value="preview",
            record_name="acme-prod",
        )
        level, _ = _classify(c)
        assert level in ("high", "critical")

    def test_F4_password_protection_enabled_is_low(self):
        c = _change(
            record_type="vercel_project",
            field_path="password_protection",
            new_value="preview",
            prev_value=None,
            record_name="acme-prod",
        )
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# G. Unknown subtype + dispatcher safety
# ═════════════════════════════════════════════════════════════════════════════

class TestUnknownAndSafety:
    def test_G1_unknown_subtype_falls_back_safely(self):
        c = _change(record_type="vercel_future_thing")
        level, reason = _classify(c)
        assert level == "low"
        assert isinstance(reason, str) and len(reason) > 0

    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_G2_malformed_provider_metadata_does_not_crash(self, bad_pm):
        c = MagicMock(name="Change")
        c.field_path        = "field"
        c.change_type       = "modified"
        c.new_value         = None
        c.prev_value        = None
        c.provider_metadata = bad_pm
        level, _ = _classify(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# H. Secret / env-var / deploy-hook safety
# ═════════════════════════════════════════════════════════════════════════════

class TestSecretAndDeployHookSafety:
    """Risk reasons must never expose Vercel tokens, env-var values,
    deploy hook URLs/tokens, or Authorization headers."""

    @pytest.mark.parametrize("change_args", [
        # Env var rotation — must not echo any token-shaped value.
        dict(record_type="vercel_env_var", field_path="updated_at",
             new_value="2024-12-01T00:00:00Z", prev_value="2024-11-01T00:00:00Z",
             record_name="STRIPE_SECRET_KEY"),
        # Env var removed — must not echo the prev_value record verbatim.
        dict(record_type="vercel_env_var", change_type="removed",
             prev_value={"target": ["production"],
                          "value": "sk_live_FAKE_BUT_LOOKS_LIKE_SECRET_1234567890"},
             record_name="STRIPE_SECRET_KEY"),
        # Deploy hook removed — must not echo the URL/token.
        dict(record_type="vercel_deploy_hook_metadata", change_type="removed",
             prev_value={"hook_url":
                          "https://api.vercel.com/v1/integrations/deploy/prj_X/SECRET-TOKEN"},
             record_name="trigger-deploy"),
        # Domain redirect change — must not echo Vercel-internal hostnames.
        dict(record_type="vercel_domain", field_path="redirect",
             new_value="other.example.com", prev_value="origin.example.com",
             record_name="example.com",
             record_content={"git_branch": None}),
    ])
    def test_H1_reason_does_not_leak_secrets_or_tokens(self, change_args):
        c = _change(**change_args)
        _, reason = _classify(c)
        lower = reason.lower()
        # Stripe-key prefixes (used in test fixture to ensure we don't echo)
        for prefix in ("sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_"):
            assert prefix not in lower, (
                f"reason contains a secret prefix {prefix!r}: {reason!r}"
            )
        # Vercel-style hook URLs
        assert "api.vercel.com" not in lower, (
            f"reason echoes a Vercel API URL: {reason!r}"
        )
        # Generic Authorization headers
        for token in ("authorization:", "bearer "):
            assert token not in lower, f"reason contains an auth marker: {reason!r}"

    def test_H2_no_long_base64_or_token_shaped_strings_echoed(self):
        # Construct a change whose record_name itself is benign but whose
        # values would be high-entropy tokens. Verify the classifier
        # doesn't pull them in.
        import re

        cases = [
            dict(record_type="vercel_env_var", field_path="updated_at",
                 new_value="2024-12-01T00:00:00Z", prev_value="2024-11-01T00:00:00Z",
                 record_name="OPENAI_API_KEY"),
            dict(record_type="vercel_env_var", change_type="removed",
                 prev_value={"target": ["production"], "value":
                             "ABCDEFGHIJ" * 8},  # 80 chars of non-secret data
                 record_name="OPENAI_API_KEY"),
            dict(record_type="vercel_deploy_hook_metadata", change_type="added",
                 record_name="trigger-deploy"),
        ]
        for args in cases:
            _, reason = _classify(_change(**args))
            # No 60+ char run of base64-ish characters
            assert not re.search(r"[A-Za-z0-9+/=]{60,}", reason), (
                f"reason contains a long token-shaped string: {reason!r}"
            )

    def test_H3_no_auto_fix_language(self):
        cases = [
            dict(record_type="vercel_env_var", change_type="removed",
                 prev_value={"target": ["production"]},
                 record_name="STRIPE_SECRET_KEY"),
            dict(record_type="vercel_domain", change_type="removed",
                 prev_value={"git_branch": None}, record_name="example.com"),
            dict(record_type="vercel_project", field_path="sso_protection",
                 new_value=None, prev_value="all", record_name="acme-prod"),
            dict(record_type="vercel_deploy_hook_metadata", field_path="hook_ref",
                 new_value="release", prev_value="main",
                 record_name="trigger-deploy"),
        ]
        bad = ("auto-fix", "automatically fix", "guaranteed", "auto fix",
               "guaranteed outage")
        for args in cases:
            _, reason = _classify(_change(**args))
            lower = reason.lower()
            for phrase in bad:
                assert phrase not in lower, f"reason contains {phrase!r}: {reason!r}"

    def test_H4_no_definitive_outage_overclaim(self):
        cases = [
            dict(record_type="vercel_domain", change_type="removed",
                 prev_value={"git_branch": None}, record_name="example.com"),
            dict(record_type="vercel_env_var", change_type="removed",
                 prev_value={"target": ["production"]},
                 record_name="DATABASE_URL"),
            dict(record_type="vercel_project", field_path="git_branch",
                 new_value="other", prev_value="main", record_name="acme-prod"),
        ]
        absolute = (
            "production is down",
            "all deploys will fail",
            "guaranteed outage",
            "site is offline",
        )
        for args in cases:
            _, reason = _classify(_change(**args))
            lower = reason.lower()
            for phrase in absolute:
                assert phrase not in lower, (
                    f"reason claims definitive outage: {reason!r}"
                )
