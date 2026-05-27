"""Cloudflare risk-rule audit suite — safe local tests only.

This suite mirrors the audit pattern used for Shopify / Supabase / Firebase /
AWS / Stripe / Vercel / GitHub.  It exercises every Cloudflare scenario the
brief calls out, plus safety tripwires (malformed metadata, secret-leakage
substrings).  No Cloudflare APIs are called; no real tokens are ever loaded;
no provider state is mutated.

Scope notes
-----------
ConfigTrace currently monitors exactly two Cloudflare record types:

* ``cloudflare_dns_record`` — DNS A/AAAA/CNAME/MX/TXT/NS/SOA/etc.
* ``cloudflare_ruleset``    — WAF managed/custom ruleset aggregate metadata.

It does NOT monitor: zone SSL/TLS settings (SSL mode, Always-Use-HTTPS,
HSTS, min TLS version), individual WAF rule expressions, page rules,
cache rules, worker scripts, worker routes, redirect rules, or
Access/Zero-Trust applications.  Tests for those surfaces are intentionally
omitted — see the audit report Section 12 "Known limitations".
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.services.risk_rules.cloudflare_dns import (
    classify_cloudflare_ruleset_change,
    classify_dns_change,
)
from app.services.risk_service import classify_change


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _dns_change(
    *,
    change_type: str = "modified",
    field_path: str | None = "content",
    record_type: str = "CNAME",
    record_name: str = "example.com",
    record_content: str = "",
    prev_value=None,
    new_value=None,
    extra_pm: dict | None = None,
):
    """Build a DNS-record-style MagicMock Change."""
    c = MagicMock(name="Change")
    c.change_type = change_type
    c.field_path = field_path
    c.prev_value = prev_value
    c.new_value = new_value
    pm = {
        "record_type": record_type,
        "record_name": record_name,
        "record_content": record_content,
    }
    if extra_pm:
        pm.update(extra_pm)
    c.provider_metadata = pm
    return c


def _ruleset_change(
    *,
    change_type: str = "modified",
    field_path: str | None = None,
    prev_value=None,
    new_value=None,
    phase: str = "http_request_firewall_managed",
    extra_pm: dict | None = None,
):
    """Build a cloudflare_ruleset-style MagicMock Change.

    NOTE: sets both ``prev_value`` (the model field) and ``old_value`` (the
    field name the current classifier reads).  After the prev_value fix lands,
    tests should still pass.
    """
    c = MagicMock(name="Change")
    c.change_type = change_type
    c.field_path = field_path
    c.prev_value = prev_value
    c.old_value = prev_value  # legacy alias the buggy classifier reads
    c.new_value = new_value
    pm = {
        "record_type": "cloudflare_ruleset",
        "phase": phase,
    }
    if extra_pm:
        pm.update(extra_pm)
    c.provider_metadata = pm
    return c


# ─────────────────────────────────────────────────────────────────────────────
# A. DNS — critical hostnames (apex / www / api / admin / auth / etc.)
# ─────────────────────────────────────────────────────────────────────────────

class TestDNSCriticalHostnames:

    def test_A1_apex_a_removed_is_critical(self):
        c = _dns_change(
            change_type="removed",
            field_path=None,
            record_type="A",
            record_name="example.com",
            prev_value={"record_type": "A", "name": "example.com", "content": "1.2.3.4"},
        )
        level, reason = classify_dns_change(c)
        assert level == "critical"
        assert "apex" in reason.lower() or "offline" in reason.lower()

    def test_A2_www_cname_removed_is_critical(self):
        c = _dns_change(
            change_type="removed", field_path=None,
            record_type="CNAME", record_name="www.example.com",
            prev_value={"record_type": "CNAME", "name": "www.example.com", "content": "example.com"},
        )
        level, _ = classify_dns_change(c)
        assert level == "critical"

    def test_A3_api_cname_changed_is_critical(self):
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="CNAME", record_name="api.example.com",
            prev_value="origin.example.com", new_value="evil.example.net",
        )
        level, reason = classify_dns_change(c)
        assert level == "critical"
        assert "production" in reason.lower() or "redirect" in reason.lower()

    def test_A4_admin_cname_removed_is_critical(self):
        c = _dns_change(
            change_type="removed", field_path=None,
            record_type="CNAME", record_name="admin.example.com",
            prev_value={"record_type": "CNAME", "name": "admin.example.com", "content": "h.example.com"},
        )
        level, _ = classify_dns_change(c)
        assert level == "critical"

    def test_A5_non_critical_cname_removed_is_high_not_critical(self):
        # "marketing.example.com" is not in critical-subdomain set → high not critical.
        c = _dns_change(
            change_type="removed", field_path=None,
            record_type="CNAME", record_name="marketing.example.com",
            prev_value={"record_type": "CNAME", "name": "marketing.example.com",
                        "content": "pages.example.io"},
        )
        level, _ = classify_dns_change(c)
        assert level == "high"

    def test_A6_apex_a_content_changed_is_critical(self):
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="A", record_name="example.com",
            prev_value="1.2.3.4", new_value="9.9.9.9",
        )
        level, _ = classify_dns_change(c)
        assert level == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# A (cont). DNS — MX records
# ─────────────────────────────────────────────────────────────────────────────

class TestDNSMX:

    def test_A7_mx_removed_is_critical(self):
        c = _dns_change(
            change_type="removed", field_path=None,
            record_type="MX", record_name="example.com",
            prev_value={"record_type": "MX", "name": "example.com", "content": "aspmx.l.google.com"},
        )
        level, reason = classify_dns_change(c)
        assert level == "critical"
        assert "email" in reason.lower() or "mail" in reason.lower()

    def test_A8_mx_content_changed_is_high(self):
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="MX", record_name="example.com",
            prev_value="aspmx.l.google.com", new_value="mx.attacker.net",
        )
        level, reason = classify_dns_change(c)
        assert level == "high"
        assert "email" in reason.lower() or "inbound" in reason.lower()

    def test_A9_mx_priority_changed_is_medium(self):
        c = _dns_change(
            change_type="modified", field_path="priority",
            record_type="MX", record_name="example.com",
            prev_value=10, new_value=20,
        )
        level, _ = classify_dns_change(c)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# A (cont). DNS — email auth (SPF / DKIM / DMARC)
# ─────────────────────────────────────────────────────────────────────────────

class TestDNSEmailAuth:

    def test_A10_dmarc_removed_is_critical(self):
        c = _dns_change(
            change_type="removed", field_path=None,
            record_type="TXT", record_name="_dmarc.example.com",
            record_content="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
            prev_value={"record_type": "TXT", "name": "_dmarc.example.com",
                        "content": "v=DMARC1; p=reject"},
        )
        level, reason = classify_dns_change(c)
        assert level == "critical"
        assert "dmarc" in reason.lower() or "spoof" in reason.lower()

    def test_A11_dmarc_weakened_reject_to_none_is_critical(self):
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="TXT", record_name="_dmarc.example.com",
            prev_value="v=DMARC1; p=reject",
            new_value="v=DMARC1; p=none",
        )
        level, reason = classify_dns_change(c)
        assert level == "critical"
        assert "weaken" in reason.lower() or "none" in reason.lower()

    def test_A12_dmarc_strengthened_none_to_reject_is_low(self):
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="TXT", record_name="_dmarc.example.com",
            prev_value="v=DMARC1; p=none",
            new_value="v=DMARC1; p=reject",
        )
        level, _ = classify_dns_change(c)
        assert level == "low"

    def test_A13_spf_removed_is_high(self):
        c = _dns_change(
            change_type="removed", field_path=None,
            record_type="TXT", record_name="example.com",
            record_content="v=spf1 include:_spf.google.com ~all",
            prev_value={"record_type": "TXT", "name": "example.com",
                        "content": "v=spf1 include:_spf.google.com ~all"},
        )
        level, reason = classify_dns_change(c)
        assert level == "high"
        assert "spf" in reason.lower() or "spoof" in reason.lower()

    def test_A14_dkim_removed_is_high(self):
        c = _dns_change(
            change_type="removed", field_path=None,
            record_type="TXT", record_name="selector1._domainkey.example.com",
            record_content="v=DKIM1; k=rsa; p=AAAA...truncated",
            prev_value={"record_type": "TXT", "name": "selector1._domainkey.example.com",
                        "content": "v=DKIM1; k=rsa; p=AAA"},
        )
        level, _ = classify_dns_change(c)
        assert level == "high"

    def test_A15_spf_content_modified_is_high(self):
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="TXT", record_name="example.com",
            prev_value="v=spf1 include:_spf.google.com ~all",
            new_value="v=spf1 ~all",
        )
        level, _ = classify_dns_change(c)
        assert level == "high"

    def test_A16_spf_added_is_low_hardening(self):
        c = _dns_change(
            change_type="added", field_path=None,
            record_type="TXT", record_name="example.com",
            record_content="v=spf1 include:_spf.google.com ~all",
            new_value={"record_type": "TXT", "name": "example.com",
                       "content": "v=spf1 include:_spf.google.com ~all"},
        )
        level, _ = classify_dns_change(c)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# A (cont). DNS — wildcards
# ─────────────────────────────────────────────────────────────────────────────

class TestDNSWildcard:

    def test_A17_wildcard_cname_removed_is_critical(self):
        c = _dns_change(
            change_type="removed", field_path=None,
            record_type="CNAME", record_name="*.example.com",
            prev_value={"record_type": "CNAME", "name": "*.example.com", "content": "origin.example.com"},
        )
        level, _ = classify_dns_change(c)
        assert level == "critical"

    def test_A18_wildcard_a_modified_is_critical(self):
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="A", record_name="*.example.com",
            prev_value="1.2.3.4", new_value="9.9.9.9",
        )
        level, _ = classify_dns_change(c)
        assert level == "critical"

    def test_A19_wildcard_cname_added_is_at_least_high(self):
        # Per brief: "wildcard DNS record added is High."
        c = _dns_change(
            change_type="added", field_path=None,
            record_type="CNAME", record_name="*.example.com",
            new_value={"record_type": "CNAME", "name": "*.example.com",
                       "content": "fallback.example.io"},
        )
        level, _ = classify_dns_change(c)
        assert level in ("high", "critical")


# ─────────────────────────────────────────────────────────────────────────────
# A (cont). DNS — NS / SOA
# ─────────────────────────────────────────────────────────────────────────────

class TestDNSNameserver:

    def test_A20_ns_modified_is_critical(self):
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="NS", record_name="example.com",
            prev_value="ns1.cloudflare.com", new_value="ns1.attacker.tld",
        )
        level, reason = classify_dns_change(c)
        assert level == "critical"
        assert "nameserver" in reason.lower() or "delegation" in reason.lower()

    def test_A21_soa_modified_is_critical(self):
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="SOA", record_name="example.com",
            prev_value="ns1.example.com", new_value="ns2.example.com",
        )
        level, _ = classify_dns_change(c)
        assert level == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# B. Proxy (orange-cloud)
# ─────────────────────────────────────────────────────────────────────────────

class TestDNSProxy:

    def test_B1_proxy_disabled_on_apex_is_critical(self):
        c = _dns_change(
            change_type="modified", field_path="proxied",
            record_type="A", record_name="example.com",
            prev_value=True, new_value=False,
        )
        level, reason = classify_dns_change(c)
        assert level == "critical"
        assert "origin" in reason.lower() or "ddos" in reason.lower()

    def test_B2_proxy_disabled_on_api_is_critical(self):
        c = _dns_change(
            change_type="modified", field_path="proxied",
            record_type="CNAME", record_name="api.example.com",
            prev_value=True, new_value=False,
        )
        level, _ = classify_dns_change(c)
        assert level == "critical"

    def test_B3_proxy_disabled_on_non_critical_is_high(self):
        c = _dns_change(
            change_type="modified", field_path="proxied",
            record_type="CNAME", record_name="marketing.example.com",
            prev_value=True, new_value=False,
        )
        level, _ = classify_dns_change(c)
        assert level == "high"

    def test_B4_proxy_enabled_is_medium(self):
        c = _dns_change(
            change_type="modified", field_path="proxied",
            record_type="CNAME", record_name="marketing.example.com",
            prev_value=False, new_value=True,
        )
        level, _ = classify_dns_change(c)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# A (cont). DNS — TTL
# ─────────────────────────────────────────────────────────────────────────────

class TestDNSTTL:

    def test_A22_ttl_dropped_to_30_is_high(self):
        c = _dns_change(
            change_type="modified", field_path="ttl",
            record_type="A", record_name="example.com",
            prev_value=3600, new_value=30,
        )
        level, _ = classify_dns_change(c)
        assert level == "high"

    def test_A23_ttl_changed_on_critical_hostname_is_medium(self):
        c = _dns_change(
            change_type="modified", field_path="ttl",
            record_type="A", record_name="api.example.com",
            prev_value=3600, new_value=300,
        )
        level, _ = classify_dns_change(c)
        assert level == "medium"

    def test_A24_ttl_changed_on_non_critical_hostname_is_low(self):
        c = _dns_change(
            change_type="modified", field_path="ttl",
            record_type="A", record_name="marketing.example.com",
            prev_value=3600, new_value=7200,
        )
        level, _ = classify_dns_change(c)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# A (cont). DNS — non-critical additions / verification records
# ─────────────────────────────────────────────────────────────────────────────

class TestDNSAdditions:

    def test_A25_non_critical_cname_added_is_medium(self):
        c = _dns_change(
            change_type="added", field_path=None,
            record_type="CNAME", record_name="status.example.com",
            new_value={"record_type": "CNAME", "name": "status.example.com",
                       "content": "statuspage.io"},
        )
        level, _ = classify_dns_change(c)
        # Non-critical CNAME add → Medium per current policy (brief: "Low/Medium").
        assert level in ("low", "medium")

    @pytest.mark.parametrize(
        "name,content",
        [
            ("_acme-challenge.example.com", ""),
            ("_github-pages-challenge.example.com", ""),
            ("example.com", "google-site-verification=ABCDEFG12345"),
            ("clkmail.example.com", ""),
        ],
    )
    def test_A26_verification_record_added_is_low(self, name, content):
        rtype = "TXT" if content else "CNAME"
        c = _dns_change(
            change_type="added", field_path=None,
            record_type=rtype, record_name=name, record_content=content,
            new_value={"record_type": rtype, "name": name, "content": content},
        )
        level, _ = classify_dns_change(c)
        assert level == "low"

    def test_A27_comment_changed_is_low(self):
        c = _dns_change(
            change_type="modified", field_path="comment",
            record_type="A", record_name="example.com",
            prev_value="old note", new_value="new note",
        )
        level, _ = classify_dns_change(c)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# C. WAF rulesets
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleset:

    def test_C1_ruleset_removed_is_critical(self):
        c = _ruleset_change(change_type="removed")
        level, reason = classify_cloudflare_ruleset_change(c)
        assert level == "critical"
        assert "ruleset" in reason.lower() and ("expose" in reason.lower() or "removed" in reason.lower())

    def test_C2_ruleset_added_is_high(self):
        c = _ruleset_change(change_type="added")
        level, _ = classify_cloudflare_ruleset_change(c)
        assert level == "high"

    def test_C3_skip_count_increased_is_high(self):
        # bypass rules grew — more traffic skipping WAF
        c = _ruleset_change(field_path="skip_count", prev_value=2, new_value=8)
        level, reason = classify_cloudflare_ruleset_change(c)
        assert level == "high"
        assert "bypass" in reason.lower() or "skip" in reason.lower()

    def test_C4_block_count_decreased_is_high(self):
        # Fewer rules actively blocking — protection weakened.
        # This is the prev_value/old_value bug case: prev_value=20, new_value=5
        # must reach the "decreased" branch.
        c = _ruleset_change(field_path="block_count", prev_value=20, new_value=5)
        level, reason = classify_cloudflare_ruleset_change(c)
        assert level == "high"
        assert "block" in reason.lower() and ("fewer" in reason.lower() or "decreased" in reason.lower())

    def test_C5_enabled_rule_count_decreased_is_high(self):
        c = _ruleset_change(field_path="enabled_rule_count", prev_value=50, new_value=10)
        level, reason = classify_cloudflare_ruleset_change(c)
        assert level == "high"
        assert "disabled" in reason.lower() or "decreased" in reason.lower()

    def test_C6_block_count_increased_is_low(self):
        c = _ruleset_change(field_path="block_count", prev_value=5, new_value=20)
        level, _ = classify_cloudflare_ruleset_change(c)
        assert level == "low"

    def test_C7_skip_count_decreased_is_low(self):
        c = _ruleset_change(field_path="skip_count", prev_value=8, new_value=2)
        level, _ = classify_cloudflare_ruleset_change(c)
        assert level == "low"

    def test_C8_rule_count_changed_is_medium(self):
        c = _ruleset_change(field_path="rule_count", prev_value=100, new_value=50)
        level, _ = classify_cloudflare_ruleset_change(c)
        assert level == "medium"

    def test_C9_version_only_is_low(self):
        c = _ruleset_change(field_path="version", prev_value="1", new_value="2")
        level, _ = classify_cloudflare_ruleset_change(c)
        assert level == "low"

    def test_C10_unknown_field_falls_back_low(self):
        c = _ruleset_change(field_path="some_unknown_attr", prev_value="x", new_value="y")
        level, _ = classify_cloudflare_ruleset_change(c)
        assert level == "low"

    def test_C11_block_count_decrease_uses_prev_value_attribute(self):
        # Regression: the canonical Change model attribute is ``prev_value``;
        # the ruleset classifier must read it (not just the legacy ``old_value``
        # key) so real ORM rows classify correctly.  We construct a MagicMock
        # where ONLY prev_value is set — old_value resolves to None.
        c = MagicMock(name="Change")
        c.change_type = "modified"
        c.field_path = "block_count"
        c.prev_value = 50
        # Intentionally do NOT set c.old_value; MagicMock auto-attrs would
        # return another MagicMock, so we explicitly None it out:
        c.old_value = None
        c.new_value = 5
        c.provider_metadata = {"record_type": "cloudflare_ruleset",
                               "phase": "http_request_firewall_managed"}
        level, reason = classify_cloudflare_ruleset_change(c)
        assert level == "high", (
            "Ruleset classifier must read prev_value (the model field), "
            f"not just legacy old_value. Got ({level}, {reason!r})."
        )

    def test_C12_enabled_rule_count_decrease_uses_prev_value(self):
        c = MagicMock(name="Change")
        c.change_type = "modified"
        c.field_path = "enabled_rule_count"
        c.prev_value = 100
        c.old_value = None
        c.new_value = 20
        c.provider_metadata = {"record_type": "cloudflare_ruleset",
                               "phase": "http_request_firewall_managed"}
        level, _ = classify_cloudflare_ruleset_change(c)
        assert level == "high"


# ─────────────────────────────────────────────────────────────────────────────
# F. Unknown subtype + malformed metadata + provider dispatch
# ─────────────────────────────────────────────────────────────────────────────

class TestDispatchAndSafety:

    def test_F1_unknown_cloudflare_subtype_does_not_crash(self):
        # Record type Cloudflare doesn't know — fallback to DNS classifier;
        # should return some (level, reason) without raising.
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="totally_unknown", record_name="x.example.com",
            prev_value="a", new_value="b",
        )
        level, reason = classify_dns_change(c)
        assert level in ("critical", "high", "medium", "low")
        assert isinstance(reason, str) and reason

    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_F2_malformed_provider_metadata_does_not_crash_dns(self, bad_pm):
        c = MagicMock(name="Change")
        c.change_type = "modified"
        c.field_path = "content"
        c.prev_value = "a"
        c.new_value = "b"
        c.provider_metadata = bad_pm
        # Must not raise; should return a (level, reason) tuple.
        level, _ = classify_dns_change(c)
        assert level in ("critical", "high", "medium", "low")

    @pytest.mark.parametrize("bad_pm", [None, "not a dict", 42, [], ()])
    def test_F3_malformed_provider_metadata_does_not_crash_ruleset(self, bad_pm):
        c = MagicMock(name="Change")
        c.change_type = "modified"
        c.field_path = "block_count"
        c.prev_value = 10
        c.old_value = 10
        c.new_value = 1
        c.provider_metadata = bad_pm
        level, _ = classify_cloudflare_ruleset_change(c)
        assert level in ("critical", "high", "medium", "low")

    def test_F4_top_level_classify_change_routes_ruleset(self):
        # Confirms risk_service.classify_change dispatches ruleset record_type
        # to the ruleset classifier.
        c = _ruleset_change(change_type="removed")
        level, reason = classify_change(c)
        assert level == "critical"
        assert "ruleset" in reason.lower()

    def test_F5_top_level_classify_change_routes_dns(self):
        c = _dns_change(
            change_type="removed", field_path=None,
            record_type="A", record_name="example.com",
            prev_value={"record_type": "A", "name": "example.com", "content": "1.2.3.4"},
        )
        # risk_service uses provider_metadata.record_type — DNS records here use
        # raw DNS-type strings like "A", "CNAME", so dispatch must NOT mistake
        # them for github/aws/etc. and must fall through to classify_dns_change.
        c.provider_metadata = {
            "record_type": "cloudflare_dns_record",
            "record_name": "example.com",
            "record_content": "1.2.3.4",
        }
        # The DNS classifier reads from provider_metadata too; set the inner
        # bits accordingly so apex detection still fires.
        c.provider_metadata["record_type"] = "A"  # DNS-type, not cloudflare_*
        # Wrap into a dict-style pm with both keys present (mirrors live state).
        level, _ = classify_change(c)
        assert level == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# Secret / token tripwires — reasons must never echo sensitive material
# ─────────────────────────────────────────────────────────────────────────────

import re

# Patterns that must never appear in any reason text.
_SECRET_PATTERNS = [
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{6,}", re.IGNORECASE),
    re.compile(r"Authorization:\s*Bearer", re.IGNORECASE),
    re.compile(r"\bcf_token[_\-A-Za-z0-9]*=", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9_\-]{40,}"),  # long secret-like blob (40+ chars)
]


def _reason_is_secret_safe(reason: str) -> bool:
    return not any(p.search(reason) for p in _SECRET_PATTERNS)


class TestSecretSafety:

    def test_S1_token_in_record_content_not_echoed_in_reason(self):
        # A pretend operator pasted an API token into a DNS TXT content.  The
        # classifier reason must not echo the long token blob.
        token = "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="TXT", record_name="api-key.example.com",
            prev_value="old text",
            new_value=token,
        )
        _, reason = classify_dns_change(c)
        # Reason must not contain the long token blob anywhere.
        assert token not in reason
        assert _reason_is_secret_safe(reason), f"Reason leaked a secret-like substring: {reason!r}"

    def test_S2_dkim_key_material_not_echoed(self):
        # DKIM keys are very long base64-like strings.  Modification reason
        # must talk about the change without quoting the public key blob.
        dkim_old = "v=DKIM1; k=rsa; p=" + ("A" * 200)
        dkim_new = "v=DKIM1; k=rsa; p=" + ("B" * 200)
        c = _dns_change(
            change_type="modified", field_path="content",
            record_type="TXT", record_name="sel._domainkey.example.com",
            prev_value=dkim_old, new_value=dkim_new,
        )
        _, reason = classify_dns_change(c)
        assert "A" * 50 not in reason  # no 50-char run of the key
        assert "B" * 50 not in reason
        assert _reason_is_secret_safe(reason), f"Reason leaked DKIM-like material: {reason!r}"

    def test_S3_authorization_header_substring_never_present(self):
        # Just enumerate the most-common DNS scenarios and verify reasons
        # never contain "Authorization:" or "Bearer ".
        cases = [
            _dns_change(change_type="removed", field_path=None, record_type="A",
                        record_name="example.com",
                        prev_value={"record_type": "A", "name": "example.com", "content": "1.2.3.4"}),
            _dns_change(change_type="modified", field_path="proxied",
                        record_type="CNAME", record_name="api.example.com",
                        prev_value=True, new_value=False),
            _dns_change(change_type="modified", field_path="content",
                        record_type="TXT", record_name="_dmarc.example.com",
                        prev_value="v=DMARC1; p=reject", new_value="v=DMARC1; p=none"),
        ]
        for c in cases:
            _, reason = classify_dns_change(c)
            assert "Authorization" not in reason
            assert "Bearer " not in reason

    def test_S4_no_auto_fix_or_definitely_down_phrasing(self):
        # Wording guardrail: classifier reasons must use hedged language and
        # never claim auto-fix capability or a "definitely down" outage.
        bad_phrases = ["auto-fix", "auto fix", "guaranteed outage", "definitely down",
                       "site is down", "we will fix"]
        cases = [
            _dns_change(change_type="removed", field_path=None, record_type="A",
                        record_name="example.com",
                        prev_value={"record_type": "A", "name": "example.com", "content": "1.2.3.4"}),
            _dns_change(change_type="modified", field_path="content",
                        record_type="MX", record_name="example.com",
                        prev_value="aspmx.l.google.com", new_value="mx.attacker.net"),
            _ruleset_change(change_type="removed"),
            _ruleset_change(field_path="block_count", prev_value=20, new_value=5),
        ]
        classifiers = [classify_dns_change, classify_dns_change,
                       classify_cloudflare_ruleset_change, classify_cloudflare_ruleset_change]
        for cls, c in zip(classifiers, cases):
            _, reason = cls(c)
            for bad in bad_phrases:
                assert bad.lower() not in reason.lower(), \
                    f"Found forbidden phrase {bad!r} in reason: {reason!r}"

    def test_S5_ruleset_reasons_have_no_secret_substrings(self):
        cases = [
            _ruleset_change(change_type="removed"),
            _ruleset_change(change_type="added"),
            _ruleset_change(field_path="block_count", prev_value=20, new_value=5),
            _ruleset_change(field_path="skip_count", prev_value=2, new_value=12),
            _ruleset_change(field_path="enabled_rule_count", prev_value=50, new_value=10),
        ]
        for c in cases:
            _, reason = classify_cloudflare_ruleset_change(c)
            assert _reason_is_secret_safe(reason), \
                f"Ruleset reason leaked secret-like substring: {reason!r}"
