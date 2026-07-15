"""Cloudflare extras risk-rule audit — SSL/TLS, page rules, workers,
Access (Zero Trust), granular WAF rules.

Mirrors the audit pattern used for the DNS + ruleset classifier
(``tests/test_cloudflare_risk_audit.py``).  No Cloudflare APIs are called;
all fixtures are mock-built ``Change``-shaped MagicMocks.

Scope
-----
* cloudflare_zone_setting       — A1–A12 (SSL/TLS, HSTS, browser check, etc.)
* cloudflare_page_rule          — B1–B7  (removed, redirect, cache, status)
* cloudflare_worker_route       — C1–C7  (added, removed, pattern, script, enabled)
* cloudflare_worker_script      — D1–D5  (etag, env vars, bindings, removed/added)
* cloudflare_access_application — E1–E6  (visibility, enabled, IdPs, removed)
* cloudflare_access_policy      — F1–F6  (decision, enabled, include count)
* cloudflare_waf_rule           — G1–G6  (action, enabled, expression hash)
* Dispatcher / safety           — H1–H3  (unknown subtype, malformed pm,
                                          top-level routing via risk_service)
* Secret-safety tripwires       — S1–S3
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest

from app.services.risk_rules.cloudflare import classify_cloudflare_change
from app.services.risk_service import classify_change


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _ch(
    *,
    record_type: str,
    change_type: str = "modified",
    field_path: str | None = None,
    prev_value=None,
    new_value=None,
    pm_extra: dict | None = None,
):
    c = MagicMock(name="Change")
    c.change_type = change_type
    c.field_path = field_path
    c.prev_value = prev_value
    c.new_value = new_value
    pm = {"record_type": record_type}
    if pm_extra:
        pm.update(pm_extra)
    c.provider_metadata = pm
    return c


# ═════════════════════════════════════════════════════════════════════════════
# A. cloudflare_zone_setting
# ═════════════════════════════════════════════════════════════════════════════


class TestZoneSettingSSL:

    def test_A1_ssl_off_is_critical(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value="full", new_value="off",
            pm_extra={"setting_id": "ssl"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "critical"
        assert "ssl" in reason.lower() and "off" in reason.lower()

    def test_A2_ssl_full_to_flexible_is_high(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value="full", new_value="flexible",
            pm_extra={"setting_id": "ssl"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "high"
        assert "lowered" in reason.lower() or "tls" in reason.lower()

    def test_A3_ssl_off_to_full_is_low(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value="off", new_value="full",
            pm_extra={"setting_id": "ssl"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "low"


class TestZoneSettingAlwaysHttps:

    def test_A4_always_use_https_disabled_is_high(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value="on", new_value="off",
            pm_extra={"setting_id": "always_use_https"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "high"
        assert "https" in reason.lower()

    def test_A5_always_use_https_enabled_is_low(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value="off", new_value="on",
            pm_extra={"setting_id": "always_use_https"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "low"


class TestZoneSettingMinTLS:

    def test_A6_min_tls_to_1_0_is_critical(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value="1.2", new_value="1.0",
            pm_extra={"setting_id": "min_tls_version"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "critical"
        assert "tls" in reason.lower() and "1.0" in reason

    def test_A7_min_tls_to_1_1_is_high(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value="1.2", new_value="1.1",
            pm_extra={"setting_id": "min_tls_version"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_A8_min_tls_raised_is_low(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value="1.1", new_value="1.2",
            pm_extra={"setting_id": "min_tls_version"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "low"


class TestZoneSettingHSTS:

    def test_A9_hsts_disabled_is_high(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value={"enabled": True, "max_age": 31536000,
                        "include_subdomains": True, "preload": False},
            new_value={"enabled": False, "max_age": 0,
                       "include_subdomains": False, "preload": False},
            pm_extra={"setting_id": "security_header"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "high"
        assert "hsts" in reason.lower()

    def test_A10_hsts_max_age_drastically_lowered_is_high(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value={"enabled": True, "max_age": 31536000,
                        "include_subdomains": True, "preload": False},
            new_value={"enabled": True, "max_age": 60,
                       "include_subdomains": True, "preload": False},
            pm_extra={"setting_id": "security_header"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_A11_hsts_enabled_from_disabled_is_low(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value={"enabled": False, "max_age": 0},
            new_value={"enabled": True, "max_age": 31536000,
                       "include_subdomains": True, "preload": False},
            pm_extra={"setting_id": "security_header"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "low"


class TestZoneSettingOther:

    def test_A12_security_level_lowered_is_medium(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value="high", new_value="low",
            pm_extra={"setting_id": "security_level"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "medium"

    def test_A13_browser_check_disabled_is_medium(self):
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value="on", new_value="off",
            pm_extra={"setting_id": "browser_check"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# B. cloudflare_page_rule
# ═════════════════════════════════════════════════════════════════════════════


class TestPageRule:

    def test_B1_page_rule_removed_on_prod_is_high(self):
        c = _ch(
            record_type="cloudflare_page_rule",
            change_type="removed",
            pm_extra={
                "target_url_pattern": "api.example.com/admin/*",
                "rule_kind": "page_rule",
            },
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_B2_redirect_to_unknown_domain_on_prod_is_critical(self):
        c = _ch(
            record_type="cloudflare_page_rule",
            field_path="forwarding_url",
            prev_value="https://api.example.com/legacy",
            new_value="https://attacker.example.net/handoff",
            pm_extra={
                "target_url_pattern": "api.example.com/*",
                "rule_kind": "redirect",
            },
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "critical"
        assert "attacker.example.net" in reason or "different domain" in reason.lower()

    def test_B3_redirect_within_same_apex_is_high_not_critical(self):
        c = _ch(
            record_type="cloudflare_page_rule",
            field_path="forwarding_url",
            prev_value="https://www.example.com/a",
            new_value="https://www.example.com/b",
            pm_extra={
                "target_url_pattern": "www.example.com/*",
                "rule_kind": "redirect",
            },
        )
        level, _ = classify_cloudflare_change(c)
        # same domain — no critical escalation
        assert level in ("high", "medium")

    def test_B4_cache_rule_cache_everything_on_prod_is_high(self):
        c = _ch(
            record_type="cloudflare_page_rule",
            field_path="actions_summary",
            prev_value="cache_level:standard",
            new_value="cache_level:cache_everything",
            pm_extra={
                "target_url_pattern": "api.example.com/users/*",
                "rule_kind": "cache_rule",
            },
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "high"
        assert "cache" in reason.lower() and "private" in reason.lower()

    def test_B5_cache_rule_bypass_is_medium(self):
        c = _ch(
            record_type="cloudflare_page_rule",
            field_path="actions_summary",
            prev_value="cache_level:standard",
            new_value="cache_level:bypass",
            pm_extra={
                "target_url_pattern": "static.example.com/*",
                "rule_kind": "cache_rule",
            },
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "medium"

    def test_B6_page_rule_disabled_on_prod_is_high(self):
        c = _ch(
            record_type="cloudflare_page_rule",
            field_path="status",
            prev_value="active", new_value="disabled",
            pm_extra={
                "target_url_pattern": "api.example.com/*",
                "rule_kind": "page_rule",
            },
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_B7_page_rule_re_enabled_is_low(self):
        c = _ch(
            record_type="cloudflare_page_rule",
            field_path="status",
            prev_value="disabled", new_value="active",
            pm_extra={
                "target_url_pattern": "api.example.com/*",
                "rule_kind": "page_rule",
            },
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# C. cloudflare_worker_route
# ═════════════════════════════════════════════════════════════════════════════


class TestWorkerRoute:

    def test_C1_route_added_on_prod_is_high(self):
        c = _ch(
            record_type="cloudflare_worker_route",
            change_type="added",
            pm_extra={"pattern": "api.example.com/*", "script_name": "edge-handler"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_C2_route_removed_on_prod_is_high(self):
        c = _ch(
            record_type="cloudflare_worker_route",
            change_type="removed",
            pm_extra={"pattern": "api.example.com/*", "script_name": "edge-handler"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_C3_route_added_on_non_prod_is_medium(self):
        c = _ch(
            record_type="cloudflare_worker_route",
            change_type="added",
            pm_extra={
                "pattern": "blog-staging.example.com/*",
                "script_name": "edge-handler",
            },
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "medium"

    def test_C4_route_script_changed_on_prod_is_critical(self):
        c = _ch(
            record_type="cloudflare_worker_route",
            field_path="script_name",
            prev_value="edge-handler", new_value="someone-elses-script",
            pm_extra={"pattern": "api.example.com/*"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "critical"
        assert "script" in reason.lower()

    def test_C5_route_pattern_changed_on_prod_is_high(self):
        c = _ch(
            record_type="cloudflare_worker_route",
            field_path="pattern",
            prev_value="api.example.com/v1/*",
            new_value="api.example.com/*",
            pm_extra={"script_name": "edge-handler"},
        )
        # Field pattern updates use the NEW pattern via pm; here pm doesn't
        # carry it, so the new_value drives via the hostname extracted from pm.
        # When the prev/new are pattern strings, we still want a non-low level.
        c.provider_metadata["pattern"] = "api.example.com/*"
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_C6_route_disabled_on_prod_is_high(self):
        c = _ch(
            record_type="cloudflare_worker_route",
            field_path="enabled",
            prev_value=True, new_value=False,
            pm_extra={"pattern": "api.example.com/*", "script_name": "edge"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_C7_route_re_enabled_is_low(self):
        c = _ch(
            record_type="cloudflare_worker_route",
            field_path="enabled",
            prev_value=False, new_value=True,
            pm_extra={"pattern": "api.example.com/*", "script_name": "edge"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# D. cloudflare_worker_script
# ═════════════════════════════════════════════════════════════════════════════


class TestWorkerScript:

    def test_D1_script_etag_changed_is_high(self):
        c = _ch(
            record_type="cloudflare_worker_script",
            field_path="script_etag",
            prev_value="aaaaaa", new_value="bbbbbb",
            pm_extra={"script_name": "edge-handler"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "high"
        assert "new code" in reason.lower() or "hash changed" in reason.lower()

    def test_D2_script_removed_is_high(self):
        c = _ch(
            record_type="cloudflare_worker_script",
            change_type="removed",
            pm_extra={"script_name": "edge-handler"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_D3_script_added_is_medium(self):
        c = _ch(
            record_type="cloudflare_worker_script",
            change_type="added",
            pm_extra={"script_name": "new-handler"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "medium"

    def test_D4_env_var_count_change_is_medium_and_value_safe(self):
        c = _ch(
            record_type="cloudflare_worker_script",
            field_path="env_var_count",
            prev_value=3, new_value=5,
            pm_extra={"script_name": "edge-handler"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "medium"
        # Reason MUST NOT echo any env var value — only count + reassurance.
        assert "never reads or stores env var values" in reason.lower() or \
               "count" in reason.lower()

    def test_D5_binding_count_change_is_medium(self):
        c = _ch(
            record_type="cloudflare_worker_script",
            field_path="binding_count",
            prev_value=2, new_value=4,
            pm_extra={"script_name": "edge-handler"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "medium"


# ═════════════════════════════════════════════════════════════════════════════
# E. cloudflare_access_application
# ═════════════════════════════════════════════════════════════════════════════


class TestAccessApplication:

    def test_E1_app_visibility_made_public_is_critical(self):
        c = _ch(
            record_type="cloudflare_access_application",
            field_path="visibility",
            prev_value="private", new_value="public",
            pm_extra={"name": "Admin Panel", "domain": "admin.example.com"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "critical"
        assert "public" in reason.lower()

    def test_E2_app_disabled_is_critical(self):
        c = _ch(
            record_type="cloudflare_access_application",
            field_path="enabled",
            prev_value=True, new_value=False,
            pm_extra={"name": "Admin Panel"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "critical"

    def test_E3_app_removed_is_critical(self):
        c = _ch(
            record_type="cloudflare_access_application",
            change_type="removed",
            pm_extra={"name": "Admin Panel"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "critical"

    def test_E4_all_idps_removed_is_high(self):
        c = _ch(
            record_type="cloudflare_access_application",
            field_path="allowed_idps_count",
            prev_value=2, new_value=0,
            pm_extra={"name": "Admin Panel"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_E5_some_idps_removed_is_medium(self):
        c = _ch(
            record_type="cloudflare_access_application",
            field_path="allowed_idps_count",
            prev_value=3, new_value=1,
            pm_extra={"name": "Admin Panel"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "medium"

    def test_E6_session_duration_changed_is_low(self):
        c = _ch(
            record_type="cloudflare_access_application",
            field_path="session_duration",
            prev_value="24h", new_value="720h",
            pm_extra={"name": "Admin Panel"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "low"


# ═════════════════════════════════════════════════════════════════════════════
# F. cloudflare_access_policy
# ═════════════════════════════════════════════════════════════════════════════


class TestAccessPolicy:

    def test_F1_policy_removed_is_high(self):
        c = _ch(
            record_type="cloudflare_access_policy",
            change_type="removed",
            pm_extra={"name": "Engineers"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_F2_decision_changed_to_bypass_is_high(self):
        c = _ch(
            record_type="cloudflare_access_policy",
            field_path="decision",
            prev_value="allow", new_value="bypass",
            pm_extra={"name": "Engineers"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "high"
        assert "bypass" in reason.lower()

    def test_F3_deny_to_allow_is_high(self):
        c = _ch(
            record_type="cloudflare_access_policy",
            field_path="decision",
            prev_value="deny", new_value="allow",
            pm_extra={"name": "Quarantine"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_F4_policy_disabled_is_high(self):
        c = _ch(
            record_type="cloudflare_access_policy",
            field_path="enabled",
            prev_value=True, new_value=False,
            pm_extra={"name": "Engineers"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_F5_include_count_broadened_is_high(self):
        """Adding more include rules = more users match this policy."""
        c = _ch(
            record_type="cloudflare_access_policy",
            field_path="include_count",
            prev_value=2, new_value=8,
            pm_extra={"name": "Engineers"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_F6_new_bypass_policy_added_is_high(self):
        c = _ch(
            record_type="cloudflare_access_policy",
            change_type="added",
            pm_extra={"name": "Office IP bypass", "decision": "bypass"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"


# ═════════════════════════════════════════════════════════════════════════════
# G. cloudflare_waf_rule (granular)
# ═════════════════════════════════════════════════════════════════════════════


class TestGranularWAFRule:

    def test_G1_block_to_allow_is_critical(self):
        c = _ch(
            record_type="cloudflare_waf_rule",
            field_path="action",
            prev_value="block", new_value="allow",
            pm_extra={"description": "SQLi block"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "critical"
        assert "weaken" in reason.lower() or "permitted" in reason.lower()

    def test_G2_challenge_to_log_is_high(self):
        c = _ch(
            record_type="cloudflare_waf_rule",
            field_path="action",
            prev_value="challenge", new_value="log",
            pm_extra={"description": "Bot challenge"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_G3_block_to_skip_is_critical(self):
        c = _ch(
            record_type="cloudflare_waf_rule",
            field_path="action",
            prev_value="block", new_value="skip",
            pm_extra={"description": "XSS block"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "critical"

    def test_G4_allow_to_block_is_low(self):
        c = _ch(
            record_type="cloudflare_waf_rule",
            field_path="action",
            prev_value="allow", new_value="block",
            pm_extra={"description": "Strengthened"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "low"

    def test_G5_rule_disabled_is_high(self):
        c = _ch(
            record_type="cloudflare_waf_rule",
            field_path="enabled",
            prev_value=True, new_value=False,
            pm_extra={"description": "SQLi block"},
        )
        level, _ = classify_cloudflare_change(c)
        assert level == "high"

    def test_G6_expression_hash_changed_is_medium_and_safe(self):
        c = _ch(
            record_type="cloudflare_waf_rule",
            field_path="expression_hash",
            prev_value="hash_aaa", new_value="hash_bbb",
            pm_extra={"description": "SQLi block"},
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "medium"
        # The reason must NOT echo any rule expression text — only refer
        # to the change abstractly.
        assert "hash_aaa" not in reason and "hash_bbb" not in reason


# ═════════════════════════════════════════════════════════════════════════════
# H. Dispatcher + safety
# ═════════════════════════════════════════════════════════════════════════════


class TestDispatcherSafety:

    def test_H1_unknown_cloudflare_subtype_falls_back_safely(self):
        c = _ch(
            record_type="cloudflare_does_not_exist",
            field_path="x", prev_value="a", new_value="b",
        )
        level, reason = classify_cloudflare_change(c)
        assert level == "low"
        assert "unknown" in reason.lower() or "no specific" in reason.lower()

    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_H2_malformed_provider_metadata_does_not_crash(self, bad_pm):
        c = MagicMock(name="Change")
        c.change_type = "modified"
        c.field_path = "x"
        c.prev_value = "a"
        c.new_value = "b"
        c.provider_metadata = bad_pm
        level, _ = classify_cloudflare_change(c)
        assert level in ("critical", "high", "medium", "low")

    def test_H3_top_level_classify_change_routes_new_record_types(self):
        """``risk_service.classify_change`` must dispatch the new record types
        to ``classify_cloudflare_change`` (not the DNS classifier)."""
        c = _ch(
            record_type="cloudflare_zone_setting", field_path="value",
            prev_value="full", new_value="off",
            pm_extra={"setting_id": "ssl"},
        )
        level, reason = classify_change(c)
        assert level == "critical"
        assert "ssl" in reason.lower()

    def test_H4_top_level_still_routes_ruleset_correctly(self):
        """Regression: cloudflare_ruleset must continue routing to the
        legacy ruleset classifier, not the new module."""
        c = MagicMock()
        c.change_type = "removed"
        c.field_path = None
        c.prev_value = None
        c.old_value = None
        c.new_value = None
        c.provider_metadata = {
            "record_type": "cloudflare_ruleset",
            "phase": "http_request_firewall_managed",
        }
        level, reason = classify_change(c)
        assert level == "critical"
        assert "ruleset" in reason.lower()


# ═════════════════════════════════════════════════════════════════════════════
# S. Secret-safety tripwires across all new surfaces
# ═════════════════════════════════════════════════════════════════════════════


# Realistic credential-shaped fixtures.  No reason or remediation output
# from any classifier path should ever echo these substrings.
_SECRET_FIXTURES: dict[str, str] = {
    "cloudflare_api_token": "S" * 40,
    "github_pat": "ghp_" + ("G" * 36),
    "stripe_sk_live": "sk_live_" + ("A" * 99),
    "aws_akia": "AKIA" + ("K" * 16),
    "bearer_jwt": "Bearer eyJhbGciOi" + ("N" * 80),
    "webhook_url_with_token": "https://hooks.example.com/intake?token=" + ("Q" * 48),
    "private_key_pem": (
        "-----BEGIN PRIVATE KEY-----\n"
        + ("O" * 60) + "\n"
        + ("P" * 60) + "\n"
        "-----END PRIVATE KEY-----"
    ),
}


_FORBIDDEN_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{6,}", re.IGNORECASE),
    re.compile(r"\bAuthorization:\s*Bearer", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{32,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[A-Z0-9]{16}"),
    re.compile(r"[A-Za-z0-9_\-]{40,}"),  # long high-entropy blob
)


def _assert_reason_secret_safe(reason: str, secret: str) -> None:
    # Direct substring containment.
    assert secret not in reason, f"Reason leaked secret substring: {reason!r}"
    # Pattern-level paranoia.
    for p in _FORBIDDEN_PATTERNS:
        assert not p.search(reason), (
            f"Reason matched forbidden pattern {p.pattern!r}: {reason!r}"
        )


class TestSecretSafety:

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S1_worker_script_env_var_value_never_in_reason(self, name, secret):
        """Env var COUNT changes must never emit the value — we deliberately
        feed the credential through the ``prev_value`` / ``new_value`` channels
        (where Cloudflare itself would NOT pass them, but where a misbuilt
        diff might).  The classifier must echo only the count delta."""
        c = _ch(
            record_type="cloudflare_worker_script",
            field_path="env_var_count",
            prev_value=secret, new_value=secret,
            pm_extra={"script_name": "edge-handler"},
        )
        _, reason = classify_cloudflare_change(c)
        _assert_reason_secret_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S2_waf_rule_expression_hash_does_not_echo_secret(self, name, secret):
        c = _ch(
            record_type="cloudflare_waf_rule",
            field_path="expression_hash",
            prev_value="hash_aaa", new_value=secret,
            pm_extra={"description": "block bad inputs"},
        )
        _, reason = classify_cloudflare_change(c)
        _assert_reason_secret_safe(reason, secret)

    @pytest.mark.parametrize("name,secret", list(_SECRET_FIXTURES.items()))
    def test_S3_page_rule_redirect_target_does_not_echo_secret(self, name, secret):
        c = _ch(
            record_type="cloudflare_page_rule",
            field_path="forwarding_url",
            prev_value="https://api.example.com/legacy",
            new_value=secret,
            pm_extra={
                "target_url_pattern": "api.example.com/*",
                "rule_kind": "redirect",
            },
        )
        _, reason = classify_cloudflare_change(c)
        # The reason DOES mention the destination domain (extracted via
        # ``_domain_of_url``) but never the full URL or query string.
        # Confirm no long secret-shaped substring appears.
        assert secret not in reason
        # No bearer / private-key / authorization markers.
        for p in _FORBIDDEN_PATTERNS[:5]:
            assert not p.search(reason), (
                f"Reason matched forbidden pattern: {reason!r}"
            )

    def test_S4_no_forbidden_phrases_in_any_classifier_output(self):
        """Hedged-wording policy: no 'definitely down' / 'compromised' /
        'guaranteed outage' across the most-severe scenarios."""
        scenarios = [
            _ch(record_type="cloudflare_zone_setting", field_path="value",
                prev_value="full", new_value="off",
                pm_extra={"setting_id": "ssl"}),
            _ch(record_type="cloudflare_zone_setting", field_path="value",
                prev_value="1.2", new_value="1.0",
                pm_extra={"setting_id": "min_tls_version"}),
            _ch(record_type="cloudflare_access_application",
                field_path="visibility",
                prev_value="private", new_value="public",
                pm_extra={"name": "Admin"}),
            _ch(record_type="cloudflare_waf_rule", field_path="action",
                prev_value="block", new_value="allow",
                pm_extra={"description": "SQLi"}),
            _ch(record_type="cloudflare_worker_route",
                field_path="script_name",
                prev_value="ours", new_value="theirs",
                pm_extra={"pattern": "api.example.com/*"}),
        ]
        bad_phrases = (
            "definitely down", "guaranteed outage", "compromised",
            "site is down", "auto-fix", "auto fix",
        )
        for c in scenarios:
            _, reason = classify_cloudflare_change(c)
            r = reason.lower()
            for bad in bad_phrases:
                assert bad not in r, f"Forbidden phrase {bad!r} in: {reason!r}"


# ═════════════════════════════════════════════════════════════════════════════
# I. Real compute_diff() integration — regression guard against the detection
# bug found in this QA pass: _CLOUDFLARE_TRACKED_FIELDS_BY_TYPE only had an
# entry for cloudflare_ruleset. All 7 of these record types silently fell
# back to the DNS-record _TRACKED_FIELDS tuple (record_type, name, content,
# ttl, proxied, priority, comment), which shares almost no real field names
# with these record shapes — so compute_diff() produced ZERO Change rows for
# real drift (e.g. a zone's SSL mode going "strict" -> "off"), even though
# every classifier branch above already existed and was fully tested via
# hand-built MagicMock Changes. These tests exercise the REAL
# compute_diff() -> classify_cloudflare_change() pipeline, not a mock.
# ═════════════════════════════════════════════════════════════════════════════

class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]):
    from app.services.diff_service import compute_diff
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


class TestRealComputeDiffIntegration:
    def test_I1_zone_setting_ssl_off_detected_and_critical(self):
        prev = [{
            "record_type": "cloudflare_zone_setting", "record_id": "ssl",
            "setting_id": "ssl", "value": "strict", "editable": True,
            "modified_on": None,
        }]
        new = [{**prev[0], "value": "off"}]
        changes = _real_changes(prev, new)
        assert len(changes) == 1, "expected the zone setting 'value' change to be detected"
        level, reason = classify_cloudflare_change(changes[0])
        assert level == "critical", f"expected critical, got {level} ({reason})"

    def test_I2_page_rule_disabled_detected(self):
        prev = [{
            "record_type": "cloudflare_page_rule", "record_id": "p1",
            "target_url_pattern": "example.com/*", "actions_summary": "always_use_https",
            "rule_kind": "page_rule", "priority": 1, "status": "active",
            "modified_on": None,
        }]
        new = [{**prev[0], "status": "disabled"}]
        changes = _real_changes(prev, new)
        assert len(changes) == 1
        level, _ = classify_cloudflare_change(changes[0])
        assert level in ("medium", "high")

    def test_I3_worker_route_script_changed_detected(self):
        prev = [{
            "record_type": "cloudflare_worker_route", "record_id": "w1",
            "pattern": "api.example.com/*", "script_name": "old-script",
            "enabled": True, "modified_on": None,
        }]
        new = [{**prev[0], "script_name": "new-script"}]
        changes = _real_changes(prev, new)
        assert len(changes) == 1
        level, _ = classify_cloudflare_change(changes[0])
        assert level in ("high", "critical")

    def test_I4_worker_script_etag_changed_detected(self):
        prev = [{
            "record_type": "cloudflare_worker_script", "record_id": "s1",
            "script_name": "s1", "script_etag": "aaa", "env_var_count": 2,
            "binding_count": 3, "modified_on": None,
        }]
        new = [{**prev[0], "script_etag": "bbb"}]
        changes = _real_changes(prev, new)
        assert len(changes) == 1
        level, _ = classify_cloudflare_change(changes[0])
        assert level == "high"

    def test_I5_access_application_visibility_public_detected(self):
        prev = [{
            "record_type": "cloudflare_access_application", "record_id": "a1",
            "name": "internal", "type": "self_hosted", "domain": "admin.example.com",
            "visibility": "private", "enabled": True, "session_duration": "24h",
            "allowed_idps_count": 2, "modified_on": None,
        }]
        new = [{**prev[0], "visibility": "public"}]
        changes = _real_changes(prev, new)
        assert len(changes) == 1
        level, reason = classify_cloudflare_change(changes[0])
        assert level == "critical", f"expected critical, got {level} ({reason})"

    def test_I6_access_policy_decision_bypass_detected(self):
        prev = [{
            "record_type": "cloudflare_access_policy", "record_id": "pol1",
            "application_id": "a1", "name": "default", "decision": "allow",
            "enabled": True, "precedence": 1, "include_count": 1,
            "exclude_count": 0, "require_count": 0, "modified_on": None,
        }]
        new = [{**prev[0], "decision": "bypass"}]
        changes = _real_changes(prev, new)
        assert len(changes) == 1
        level, _ = classify_cloudflare_change(changes[0])
        assert level == "high"

    def test_I7_waf_rule_action_block_to_allow_detected(self):
        prev = [{
            "record_type": "cloudflare_waf_rule", "record_id": "r1",
            "ruleset_id": "rs1", "description": "block sqli", "action": "block",
            "enabled": True, "expression_hash": "aaa", "modified_on": None,
        }]
        new = [{**prev[0], "action": "allow"}]
        changes = _real_changes(prev, new)
        assert len(changes) == 1
        level, reason = classify_cloudflare_change(changes[0])
        assert level == "critical", f"expected critical, got {level} ({reason})"

    def test_I8_dns_record_content_change_detected_and_routes_to_dns_classifier(self):
        """DNS records use bare type strings (e.g. "A") and must route to
        classify_dns_change(), never to classify_cloudflare_change()."""
        from app.services.risk_service import classify_change

        prev = [{
            "record_type": "A", "record_id": "d1", "name": "api.example.com",
            "content": "1.1.1.1", "ttl": 1, "proxied": True, "priority": None,
            "comment": None, "modified_on": None,
        }]
        new = [{**prev[0], "content": "2.2.2.2"}]
        changes = _real_changes(prev, new)
        assert len(changes) == 1
        assert changes[0]["field_path"] == "content"
        level, _ = classify_change(changes[0])
        assert level in ("low", "medium", "high", "critical")

    def test_I9_ruleset_enabled_rule_count_change_detected(self):
        prev = [{
            "record_type": "cloudflare_ruleset", "record_id": "rs1", "name": "Managed",
            "kind": "managed", "phase": "http_request_firewall_managed",
            "version": "1", "rule_count": 10, "enabled_rule_count": 10,
            "block_count": 5, "log_count": 0, "skip_count": 0,
            "challenge_count": 0, "managed_challenge_count": 0, "execute_count": 0,
            "last_updated": None,
        }]
        new = [{**prev[0], "enabled_rule_count": 5}]
        changes = _real_changes(prev, new)
        assert len(changes) == 1
        assert changes[0]["field_path"] == "enabled_rule_count"
        level, _ = classify_change(changes[0])
        assert level == "high"

    def test_I10_unmapped_cloudflare_subtype_returns_empty_not_dns_fields(self):
        """Regression guard for the tracked-fields fallback fix: a genuinely
        unmapped cloudflare_* subtype must return () (no fields diffed), NOT
        the DNS-record _TRACKED_FIELDS tuple."""
        from app.services.diff_service import _tracked_fields_for
        fields = _tracked_fields_for({"record_type": "cloudflare_totally_unknown_type"})
        assert fields == ()


# ═════════════════════════════════════════════════════════════════════════════
# J. Count-unknown-baseline safety — regression guard against the
# PagerDuty-style unknown-to-zero bug found in this QA pass: env_var_count,
# allowed_idps_count, and include_count all used int(value or 0), which
# silently coerced a genuinely unknown prior count to 0.
# ═════════════════════════════════════════════════════════════════════════════

class TestCountUnknownBaselineSafety:
    def test_J1_worker_script_env_var_count_unknown_prev_does_not_claim_specific_direction(self):
        c = _ch(record_type="cloudflare_worker_script", field_path="env_var_count",
                prev_value=None, new_value=3, pm_extra={"script_name": "s1"})
        level, reason = classify_cloudflare_change(c)
        assert "increased from 0" not in reason.lower()
        assert "decreased from 0" not in reason.lower()
        assert level != "high"

    def test_J2_worker_script_env_var_count_real_zero_baseline_still_detects_increase(self):
        c = _ch(record_type="cloudflare_worker_script", field_path="env_var_count",
                prev_value=0, new_value=3, pm_extra={"script_name": "s1"})
        level, reason = classify_cloudflare_change(c)
        assert level == "medium"
        assert "increased from 0 to 3" in reason.lower()

    def test_J3_access_application_allowed_idps_count_unknown_prev_is_not_high(self):
        """Regression guard: previously new_n==0 with prev_n coerced from
        None to 0 would NOT fire the 'all removed' high branch (0==0 is not
        > 0), but any other unknown-to-zero coercion path must still not
        claim a specific removal count."""
        c = _ch(record_type="cloudflare_access_application",
                field_path="allowed_idps_count",
                prev_value=None, new_value=2, pm_extra={"name": "Internal"})
        level, reason = classify_cloudflare_change(c)
        assert "→" not in reason or "unknown" in reason.lower()
        assert level != "high"

    def test_J4_access_policy_include_count_unknown_prev_does_not_claim_broadened(self):
        c = _ch(record_type="cloudflare_access_policy", field_path="include_count",
                prev_value=None, new_value=5, pm_extra={"name": "default"})
        level, reason = classify_cloudflare_change(c)
        assert "broadened" not in reason.lower()
        assert level != "high"

    def test_J5_access_policy_include_count_real_zero_baseline_still_detects_broadening(self):
        c = _ch(record_type="cloudflare_access_policy", field_path="include_count",
                prev_value=0, new_value=5, pm_extra={"name": "default"})
        level, reason = classify_cloudflare_change(c)
        assert level == "high"
        assert "0 → 5" in reason

    def test_J6_ruleset_skip_count_unknown_prev_does_not_claim_specific_increase(self):
        from app.services.risk_rules.cloudflare_dns import classify_cloudflare_ruleset_change
        c = _ch(record_type="cloudflare_ruleset", field_path="skip_count",
                prev_value=None, new_value=4)
        level, reason = classify_cloudflare_ruleset_change(c)
        assert "increased from" not in reason.lower()
        assert level != "high"

    def test_J7_ruleset_skip_count_real_zero_baseline_still_detects_increase(self):
        from app.services.risk_rules.cloudflare_dns import classify_cloudflare_ruleset_change
        c = _ch(record_type="cloudflare_ruleset", field_path="skip_count",
                prev_value=0, new_value=4)
        level, reason = classify_cloudflare_ruleset_change(c)
        assert level == "high"
        assert "increased from 0 to 4" in reason.lower()
