"""Supabase risk accuracy audit — local-only regression tests.

Builds the scenario matrix from the verification brief and asserts the
expected severity for each scenario. Documents ConfigTrace's Supabase
risk policy so any future regression that mis-rates one of these
scenarios fails loudly here.

Pure-mock; no DB, no network, no Supabase API.
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
    extra_metadata: dict[str, Any] | None = None,
) -> MagicMock:
    pm: dict[str, Any] = {"record_type": record_type}
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
    from app.services.risk_rules.supabase import classify_supabase_change
    return classify_supabase_change(change)


# ─────────────────────────────────────────────────────────────────────────────
# A. RLS / database exposure
# ─────────────────────────────────────────────────────────────────────────────

class TestRls:
    def test_A1_rls_disabled_is_critical(self):
        c = _change(
            record_type="supabase_rls_status",
            field_path="rls_enabled",
            new_value=False,
            prev_value=True,
            extra_metadata={"table_name": "user_files", "schema_name": "public"},
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_A2_rls_enabled_is_low(self):
        c = _change(
            record_type="supabase_rls_status",
            field_path="rls_enabled",
            new_value=True,
            prev_value=False,
            extra_metadata={"table_name": "user_files", "schema_name": "public"},
        )
        level, _ = _classify(c)
        assert level == "low"

    def test_A3_rls_forced_removed_is_high(self):
        c = _change(
            record_type="supabase_rls_status",
            field_path="rls_forced",
            new_value=False,
            prev_value=True,
            extra_metadata={"table_name": "user_files", "schema_name": "public"},
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_A4_new_table_without_rls_is_medium(self):
        """Regression guard (Supabase classification-QA pass): for a real
        compute_diff()-produced "added" Change, new_value is the FULL new
        record dict (never a bare scalar) — the classifier inspects
        new_value.get("rls_enabled") directly."""
        c = _change(
            record_type="supabase_rls_status",
            change_type="added",
            new_value={"rls_enabled": False, "rls_forced": False},
            extra_metadata={"table_name": "logs", "schema_name": "public"},
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_A4b_new_table_with_rls_is_low(self):
        c = _change(
            record_type="supabase_rls_status",
            change_type="added",
            new_value={"rls_enabled": True, "rls_forced": False},
            extra_metadata={"table_name": "logs", "schema_name": "public"},
        )
        level, _ = _classify(c)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# B. Auth configuration
# ─────────────────────────────────────────────────────────────────────────────

class TestAuth:
    def test_B1_anonymous_enabled_is_critical(self):
        c = _change(
            record_type="supabase_auth_config",
            field_path="anonymous_enabled",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_B2_mfa_disabled_is_high(self):
        c = _change(
            record_type="supabase_auth_config",
            field_path="mfa_totp_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B3_leaked_password_protection_disabled_is_high(self):
        c = _change(
            record_type="supabase_auth_config",
            field_path="leaked_password_protection_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B4_site_url_changed_is_high(self):
        # OAuth callbacks resolve from site_url — an unexpected change here
        # can enable phishing/account-takeover via redirect hijack.
        c = _change(
            record_type="supabase_auth_config",
            field_path="site_url",
            new_value="https://evil.example",
            prev_value="https://app.example",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B5_refresh_token_rotation_disabled_is_high(self):
        # Disabling rotation widens the window in which a stolen refresh
        # token can be reused → high.
        c = _change(
            record_type="supabase_auth_config",
            field_path="refresh_token_rotation_enabled",
            new_value=False,
            prev_value=True,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B6_jwt_expiry_doubled_is_high(self):
        # Significant (≥2×) extension of JWT lifetime materially widens
        # the exposure window for a stolen token.
        c = _change(
            record_type="supabase_auth_config",
            field_path="jwt_exp",
            new_value=7200,
            prev_value=3600,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_B7_jwt_expiry_small_bump_is_medium(self):
        c = _change(
            record_type="supabase_auth_config",
            field_path="jwt_exp",
            new_value=3700,
            prev_value=3600,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_B8_email_disabled_is_medium(self):
        c = _change(
            record_type="supabase_auth_config",
            field_path="email_enabled",
            new_value=False,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_B9_captcha_disabled_is_medium(self):
        c = _change(
            record_type="supabase_auth_config",
            field_path="captcha_enabled",
            new_value=False,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_B10_additional_redirect_urls_increased_is_medium(self):
        c = _change(
            record_type="supabase_auth_config",
            field_path="additional_redirect_urls_count",
            new_value=5,
            prev_value=2,
        )
        level, _ = _classify(c)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# C. Storage
# ─────────────────────────────────────────────────────────────────────────────

class TestStorage:
    def test_C1_file_size_limit_removed_is_high(self):
        c = _change(
            record_type="supabase_storage_config",
            field_path="file_size_limit",
            new_value=None,
            prev_value=10_000_000,
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C2_allowed_mime_types_removed_is_high(self):
        # Brief: "file size/MIME restrictions weakened if represented".
        # An empty MIME allow-list means any file type can be uploaded —
        # a much wider attack surface than the previous code rated.
        c = _change(
            record_type="supabase_storage_config",
            field_path="allowed_mime_types",
            new_value=None,
            prev_value=["image/png", "image/jpeg"],
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_C3_allowed_mime_types_modified_is_medium(self):
        c = _change(
            record_type="supabase_storage_config",
            field_path="allowed_mime_types",
            new_value=["image/png"],
            prev_value=["image/png", "image/jpeg"],
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_C4_file_size_limit_increased_10x_is_medium(self):
        c = _change(
            record_type="supabase_storage_config",
            field_path="file_size_limit",
            new_value=200_000_000,
            prev_value=10_000_000,
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_C5_s3_protocol_enabled_is_medium(self):
        c = _change(
            record_type="supabase_storage_config",
            field_path="s3_protocol_enabled",
            new_value=True,
        )
        level, _ = _classify(c)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# D. Realtime / API / project / network
# ─────────────────────────────────────────────────────────────────────────────

class TestApiAndNetwork:
    def test_D1_postgrest_db_schema_changed_is_high(self):
        c = _change(
            record_type="supabase_api_config",
            field_path="db_schema",
            new_value="auth",
            prev_value="public",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_D2_network_unrestricted_is_critical(self):
        c = _change(
            record_type="supabase_network_restriction",
            field_path="is_unrestricted",
            new_value=True,
            prev_value=False,
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_D3_wildcard_cidr_added_is_critical(self):
        c = _change(
            record_type="supabase_network_restriction",
            change_type="added",
            extra_metadata={"cidr": "0.0.0.0/0"},
        )
        level, _ = _classify(c)
        assert level == "critical"

    def test_D4_specific_cidr_removed_is_high(self):
        c = _change(
            record_type="supabase_network_restriction",
            change_type="removed",
            extra_metadata={"cidr": "203.0.113.0/24"},
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_D5_project_status_paused_is_high(self):
        c = _change(
            record_type="supabase_project",
            field_path="status",
            new_value="paused",
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_D6_project_region_changed_is_medium(self):
        c = _change(
            record_type="supabase_project",
            field_path="region",
            new_value="us-east-1",
        )
        level, _ = _classify(c)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# E. Edge functions / secrets metadata
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeFunctions:
    def test_E1_verify_jwt_disabled_is_high(self):
        c = _change(
            record_type="supabase_edge_function",
            field_path="verify_jwt",
            new_value=False,
            prev_value=True,
            extra_metadata={"function_name": "process-payment"},
        )
        level, _ = _classify(c)
        assert level == "high"

    def test_E2_function_removed_is_medium(self):
        c = _change(
            record_type="supabase_edge_function",
            change_type="removed",
            extra_metadata={"function_name": "send-receipt"},
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_E3_env_var_count_changed_is_medium(self):
        c = _change(
            record_type="supabase_edge_function",
            field_path="env_var_key_count",
            new_value=8,
            prev_value=6,
            extra_metadata={"function_name": "send-receipt"},
        )
        level, _ = _classify(c)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# F. OAuth providers
# ─────────────────────────────────────────────────────────────────────────────

class TestOAuthProvider:
    def test_F1_oauth_added_is_medium(self):
        c = _change(
            record_type="supabase_oauth_provider",
            change_type="added",
            extra_metadata={"provider_name": "google"},
        )
        level, _ = _classify(c)
        assert level == "medium"

    def test_F2_oauth_removed_is_medium(self):
        # Brief: "OAuth provider added/removed is Medium unless risky
        # details are present." We don't have risky details (only name).
        c = _change(
            record_type="supabase_oauth_provider",
            change_type="removed",
            extra_metadata={"provider_name": "google"},
        )
        level, _ = _classify(c)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# G. Unknown subtype safety
# ─────────────────────────────────────────────────────────────────────────────

class TestUnknownSubtype:
    def test_G1_unknown_subtype_falls_back_safely(self):
        c = _change(record_type="supabase_future_feature")
        level, reason = _classify(c)
        assert level == "low"
        assert "supabase" in reason.lower()


# ─────────────────────────────────────────────────────────────────────────────
# H. Safety — no secrets, no auto-fix, no JWT/key values
# ─────────────────────────────────────────────────────────────────────────────

class TestSafetyInvariants:
    @pytest.mark.parametrize("change_args", [
        dict(record_type="supabase_rls_status", field_path="rls_enabled",
             new_value=False, prev_value=True,
             extra_metadata={"table_name": "users"}),
        dict(record_type="supabase_auth_config", field_path="anonymous_enabled",
             new_value=True, prev_value=False),
        dict(record_type="supabase_auth_config", field_path="site_url",
             new_value="https://evil.example", prev_value="https://app.example"),
        dict(record_type="supabase_storage_config", field_path="file_size_limit",
             new_value=None, prev_value=10_000_000),
        dict(record_type="supabase_edge_function", field_path="verify_jwt",
             new_value=False, prev_value=True,
             extra_metadata={"function_name": "process-payment"}),
        dict(record_type="supabase_network_restriction", field_path="is_unrestricted",
             new_value=True),
        dict(record_type="supabase_api_config", field_path="db_schema",
             new_value="auth", prev_value="public"),
    ])
    def test_H1_reason_does_not_leak_secrets(self, change_args):
        """Reasons must never contain a JWT, service-role key, anon key,
        or token-shaped string."""
        c = _change(**change_args)
        _, reason = _classify(c)
        lower = reason.lower()
        # No Supabase-shaped tokens (anon JWTs and service-role JWTs start
        # with 'eyJ' and are very long).
        assert "eyj" not in lower or "jwt access token" in lower, (
            f"reason should not contain a JWT-shaped string: {reason!r}"
        )
        # No "service_role" key value (the WORD service_role is OK in prose;
        # an actual key like 'service_role_AbCdEfGh' is not).
        for token_prefix in ("sbp_", "sbs_", "supabase_secret_"):
            assert token_prefix not in lower

    def test_H2_no_auto_fix_language(self):
        cases = [
            dict(record_type="supabase_rls_status", field_path="rls_enabled",
                 new_value=False, prev_value=True,
                 extra_metadata={"table_name": "users"}),
            dict(record_type="supabase_auth_config", field_path="anonymous_enabled",
                 new_value=True),
            dict(record_type="supabase_storage_config", field_path="allowed_mime_types",
                 new_value=None),
            dict(record_type="supabase_network_restriction", field_path="is_unrestricted",
                 new_value=True),
        ]
        bad = ("auto-fix", "automatically fix", "guaranteed", "auto fix")
        for args in cases:
            _, reason = _classify(_change(**args))
            lower = reason.lower()
            for phrase in bad:
                assert phrase not in lower, f"reason contains {phrase!r}: {reason!r}"

    def test_H3_unknown_subtype_does_not_raise(self):
        # The dispatcher must never propagate an exception for a malformed
        # provider_metadata payload — these are user-visible details.
        for bad_pm in (None, "not a dict", 42, []):
            c = MagicMock(name="Change")
            c.field_path        = None
            c.change_type       = "modified"
            c.new_value         = None
            c.prev_value        = None
            c.provider_metadata = bad_pm
            level, _ = _classify(c)
            assert level == "low"
