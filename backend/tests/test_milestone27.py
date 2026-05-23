"""Milestone 27 tests: Cloudflare DNS risk-classification hardening.

Covers every new or changed rule introduced in M27.  All tests are pure
unit tests — no database or network required.

Run with:
    docker compose run --rm api pytest tests/test_milestone27.py -v

Rule map (classified by tier and rule number in cloudflare_dns.py)
------------------------------------------------------------------
CRITICAL:
  1  NS / SOA modified                       (unchanged from M10)
  2  Wildcard A / AAAA / CNAME removed       (NEW)
  3  Wildcard A / AAAA / CNAME content mod   (NEW)
  4  DMARC TXT removed                       (NEW)
  5  DMARC policy weakened                   (NEW)
  6  Critical hostname A/AAAA/CNAME removed  (EXPANDED — was apex-only)
  7  MX removed                              (unchanged)
  8  Critical hostname content modified      (NEW)
  9  Proxy disabled on critical hostname     (NEW escalation)

HIGH:
  10 Non-critical A/AAAA/CNAME removed       (unchanged)
  11 SPF TXT removed                         (NEW)
  12 DKIM TXT removed                        (NEW)
  13 MX content modified                     (unchanged)
  14 SPF / DKIM TXT content modified         (ESCALATED from MEDIUM)
  15 DMARC TXT content modified              (NEW / with LOW sub-case)
  16 A / AAAA content modified               (NEW explicit rule)
  17 CNAME content modified                  (NEW explicit rule)
  18 Proxy disabled on non-critical hostname (unchanged)
  19 TTL ≤ 60                                (unchanged)
  20 Any other non-TXT record removed        (unchanged)

MEDIUM:
  21 Critical hostname A/AAAA/CNAME added    (NEW)
  22 Non-critical A / AAAA added             (unchanged)
  23 CNAME added (non-critical)              (NEW explicit)
  24 MX added                                (NEW)
  25 MX priority modified                    (DOWNGRADED from HIGH)
  26 Generic TXT removed                     (DOWNGRADED from HIGH)
  27 TXT content modified (generic)          (unchanged)
  28 Proxy enabled                           (unchanged)
  29 TTL > 60 on critical hostname           (NEW split)

LOW:
  30 Email-auth TXT added                    (NEW)
  31 Verification record added               (NEW)
  32 TTL > 60 on non-critical hostname       (DOWNGRADED from MEDIUM)
  33 Comment changed                         (unchanged)
"""

from __future__ import annotations

from app.services.risk_rules.cloudflare_dns import (
    _is_critical_hostname,
    _is_wildcard,
    _content_is_spf,
    _content_is_dkim,
    _content_is_dmarc,
    _name_has_dmarc,
    _name_has_dkim,
    _get_dmarc_policy,
    _is_dmarc_weakening,
    _is_dmarc_strengthening,
    _is_verification_record,
    classify_dns_change,
)


# ─────────────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────────────

def _chg(
    change_type: str,
    record_type: str = "A",
    record_name: str = "example.com",
    field_path: str | None = None,
    prev_value=None,
    new_value=None,
    record_content: str = "",
    zone_name: str | None = None,
) -> dict:
    """Build a minimal change dict for classify_dns_change."""
    return {
        "change_type": change_type,
        "field_path": field_path,
        "prev_value": prev_value,
        "new_value": new_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
            "record_id": "rec-test",
            "record_content": record_content,
            **({"zone_name": zone_name} if zone_name is not None else {}),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helper function unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIsCriticalHostname:
    def test_apex_is_critical(self) -> None:
        assert _is_critical_hostname("example.com") is True

    def test_apex_with_zone_name_is_critical(self) -> None:
        assert _is_critical_hostname("example.com", zone_name="example.com") is True

    def test_www_is_critical(self) -> None:
        assert _is_critical_hostname("www.example.com") is True

    def test_api_is_critical(self) -> None:
        assert _is_critical_hostname("api.example.com") is True

    def test_auth_is_critical(self) -> None:
        assert _is_critical_hostname("auth.example.com") is True

    def test_login_is_critical(self) -> None:
        assert _is_critical_hostname("login.example.com") is True

    def test_dashboard_is_critical(self) -> None:
        assert _is_critical_hostname("dashboard.example.com") is True

    def test_admin_is_critical(self) -> None:
        assert _is_critical_hostname("admin.example.com") is True

    def test_checkout_is_critical(self) -> None:
        assert _is_critical_hostname("checkout.example.com") is True

    def test_payment_is_critical(self) -> None:
        assert _is_critical_hostname("payment.example.com") is True

    def test_billing_is_critical(self) -> None:
        assert _is_critical_hostname("billing.example.com") is True

    def test_mail_is_critical(self) -> None:
        assert _is_critical_hostname("mail.example.com") is True

    def test_cdn_is_critical(self) -> None:
        assert _is_critical_hostname("cdn.example.com") is True

    def test_staging_is_not_critical(self) -> None:
        assert _is_critical_hostname("staging.example.com") is False

    def test_blog_is_not_critical(self) -> None:
        assert _is_critical_hostname("blog.example.com") is False

    def test_dev_is_not_critical(self) -> None:
        assert _is_critical_hostname("dev.example.com") is False

    def test_empty_is_not_critical(self) -> None:
        assert _is_critical_hostname("") is False


class TestIsWildcard:
    def test_wildcard_a_true(self) -> None:
        assert _is_wildcard("*.example.com") is True

    def test_plain_subdomain_false(self) -> None:
        assert _is_wildcard("api.example.com") is False

    def test_empty_false(self) -> None:
        assert _is_wildcard("") is False


class TestEmailAuthDetectors:
    def test_spf_detected(self) -> None:
        assert _content_is_spf("v=spf1 include:example.com ~all") is True

    def test_spf_not_detected_on_random(self) -> None:
        assert _content_is_spf("google-site-verification=abc") is False

    def test_dkim_detected_by_content(self) -> None:
        assert _content_is_dkim("v=DKIM1; k=rsa; p=MIGf...") is True

    def test_dmarc_detected_by_content(self) -> None:
        assert _content_is_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com") is True

    def test_dmarc_name_detected(self) -> None:
        assert _name_has_dmarc("_dmarc.example.com") is True

    def test_dmarc_name_not_detected_on_other(self) -> None:
        assert _name_has_dmarc("mail.example.com") is False

    def test_dkim_name_detected(self) -> None:
        assert _name_has_dkim("selector1._domainkey.example.com") is True

    def test_dkim_name_not_detected_on_apex(self) -> None:
        assert _name_has_dkim("example.com") is False


class TestDmarcPolicyAnalysis:
    def test_policy_reject(self) -> None:
        assert _get_dmarc_policy("v=DMARC1; p=reject; rua=mailto:x@e.com") == "reject"

    def test_policy_quarantine(self) -> None:
        assert _get_dmarc_policy("v=DMARC1; p=quarantine") == "quarantine"

    def test_policy_none(self) -> None:
        assert _get_dmarc_policy("v=DMARC1; p=none") == "none"

    def test_policy_missing_returns_none(self) -> None:
        assert _get_dmarc_policy("v=DMARC1; rua=mailto:x@e.com") is None

    def test_weakening_reject_to_none(self) -> None:
        assert _is_dmarc_weakening("v=DMARC1; p=reject", "v=DMARC1; p=none") is True

    def test_weakening_quarantine_to_none(self) -> None:
        assert _is_dmarc_weakening("v=DMARC1; p=quarantine", "v=DMARC1; p=none") is True

    def test_not_weakening_none_to_none(self) -> None:
        assert _is_dmarc_weakening("v=DMARC1; p=none", "v=DMARC1; p=none") is False

    def test_not_weakening_none_to_reject(self) -> None:
        assert _is_dmarc_weakening("v=DMARC1; p=none", "v=DMARC1; p=reject") is False

    def test_strengthening_none_to_reject(self) -> None:
        assert _is_dmarc_strengthening("v=DMARC1; p=none", "v=DMARC1; p=reject") is True

    def test_strengthening_none_to_quarantine(self) -> None:
        assert _is_dmarc_strengthening("v=DMARC1; p=none", "v=DMARC1; p=quarantine") is True

    def test_not_strengthening_reject_to_quarantine(self) -> None:
        # Both are strong — not a "strengthening" from none
        assert _is_dmarc_strengthening("v=DMARC1; p=reject", "v=DMARC1; p=quarantine") is False


class TestVerificationRecordDetector:
    def test_google_site_verification_txt(self) -> None:
        assert _is_verification_record(
            "example.com", "google-site-verification=abc123", "TXT"
        ) is True

    def test_ms_verification_txt(self) -> None:
        assert _is_verification_record("example.com", "MS=ms12345", "TXT") is True

    def test_apple_verification_txt(self) -> None:
        assert _is_verification_record(
            "example.com", "apple-domain-verification=xyz", "TXT"
        ) is True

    def test_acme_challenge_name(self) -> None:
        assert _is_verification_record(
            "_acme-challenge.example.com", "", "CNAME"
        ) is True

    def test_clerk_cname(self) -> None:
        assert _is_verification_record("clerk.example.com", "", "CNAME") is True

    def test_clkmail_cname(self) -> None:
        assert _is_verification_record("clkmail.example.com", "", "CNAME") is True

    def test_resend_cname(self) -> None:
        assert _is_verification_record("resend.example.com", "", "CNAME") is True

    def test_spf_is_not_verification(self) -> None:
        assert _is_verification_record(
            "example.com", "v=spf1 include:sendgrid.net ~all", "TXT"
        ) is False

    def test_plain_a_record_not_verification(self) -> None:
        assert _is_verification_record("api.example.com", "1.2.3.4", "A") is False


# ─────────────────────────────────────────────────────────────────────────────
# CRITICAL rule tests (rules 1–9)
# ─────────────────────────────────────────────────────────────────────────────

class TestCriticalRules:
    # ── Rule 2: Wildcard removed ─────────────────────────────────────────────

    def test_wildcard_a_removed_is_critical(self) -> None:
        change = _chg("removed", record_type="A", record_name="*.example.com")
        level, reason = classify_dns_change(change)
        assert level == "critical"
        assert "wildcard" in reason.lower()

    def test_wildcard_aaaa_removed_is_critical(self) -> None:
        change = _chg("removed", record_type="AAAA", record_name="*.example.com")
        level, reason = classify_dns_change(change)
        assert level == "critical"

    def test_wildcard_cname_removed_is_critical(self) -> None:
        change = _chg("removed", record_type="CNAME", record_name="*.example.com")
        level, reason = classify_dns_change(change)
        assert level == "critical"

    # ── Rule 3: Wildcard content modified ───────────────────────────────────

    def test_wildcard_a_content_modified_is_critical(self) -> None:
        change = _chg(
            "modified",
            record_type="A",
            record_name="*.example.com",
            field_path="content",
            prev_value="1.2.3.4",
            new_value="5.6.7.8",
        )
        level, reason = classify_dns_change(change)
        assert level == "critical"
        assert "wildcard" in reason.lower()

    def test_wildcard_cname_content_modified_is_critical(self) -> None:
        change = _chg(
            "modified",
            record_type="CNAME",
            record_name="*.example.com",
            field_path="content",
            prev_value="origin.example.com",
            new_value="new.example.com",
        )
        level, reason = classify_dns_change(change)
        assert level == "critical"

    # ── Rule 4: DMARC TXT removed ───────────────────────────────────────────

    def test_dmarc_txt_removed_by_content_is_critical(self) -> None:
        change = _chg(
            "removed",
            record_type="TXT",
            record_name="_dmarc.example.com",
            record_content="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        )
        level, reason = classify_dns_change(change)
        assert level == "critical"
        assert "dmarc" in reason.lower() or "spoofing" in reason.lower()

    def test_dmarc_txt_removed_by_name_only_is_critical(self) -> None:
        """Removal matched by _dmarc label even when content is empty."""
        change = _chg(
            "removed",
            record_type="TXT",
            record_name="_dmarc.example.com",
            record_content="",
        )
        level, reason = classify_dns_change(change)
        assert level == "critical"

    # ── Rule 5: DMARC policy weakened ───────────────────────────────────────

    def test_dmarc_weakened_reject_to_none_is_critical(self) -> None:
        change = _chg(
            "modified",
            record_type="TXT",
            record_name="_dmarc.example.com",
            field_path="content",
            prev_value="v=DMARC1; p=reject; rua=mailto:r@e.com",
            new_value="v=DMARC1; p=none",
        )
        level, reason = classify_dns_change(change)
        assert level == "critical"
        assert "weakened" in reason.lower() or "none" in reason.lower()

    def test_dmarc_weakened_quarantine_to_none_is_critical(self) -> None:
        change = _chg(
            "modified",
            record_type="TXT",
            record_name="_dmarc.example.com",
            field_path="content",
            prev_value="v=DMARC1; p=quarantine",
            new_value="v=DMARC1; p=none",
        )
        level, reason = classify_dns_change(change)
        assert level == "critical"

    # ── Rule 6: Critical subdomain (non-apex) A/AAAA/CNAME removed ──────────

    def test_www_a_removed_is_critical(self) -> None:
        change = _chg("removed", record_type="A", record_name="www.example.com")
        level, reason = classify_dns_change(change)
        assert level == "critical"

    def test_login_cname_removed_is_critical(self) -> None:
        change = _chg("removed", record_type="CNAME", record_name="login.example.com")
        level, reason = classify_dns_change(change)
        assert level == "critical"

    def test_auth_aaaa_removed_is_critical(self) -> None:
        change = _chg("removed", record_type="AAAA", record_name="auth.example.com")
        level, reason = classify_dns_change(change)
        assert level == "critical"

    def test_admin_a_removed_is_critical(self) -> None:
        change = _chg("removed", record_type="A", record_name="admin.example.com")
        level, reason = classify_dns_change(change)
        assert level == "critical"

    # ── Rule 8: Critical hostname content modified ───────────────────────────

    def test_app_a_content_modified_is_critical(self) -> None:
        change = _chg(
            "modified",
            record_type="A",
            record_name="app.example.com",
            field_path="content",
            prev_value="1.2.3.4",
            new_value="5.6.7.8",
        )
        level, reason = classify_dns_change(change)
        assert level == "critical"

    def test_api_cname_content_modified_is_critical(self) -> None:
        change = _chg(
            "modified",
            record_type="CNAME",
            record_name="api.example.com",
            field_path="content",
            prev_value="old.example.com",
            new_value="new.example.com",
        )
        level, reason = classify_dns_change(change)
        assert level == "critical"
        assert "CNAME" in reason

    # ── Rule 9: Proxy disabled on critical hostname ──────────────────────────

    def test_proxy_disabled_on_admin_is_critical(self) -> None:
        change = _chg(
            "modified",
            record_type="A",
            record_name="admin.example.com",
            field_path="proxied",
            prev_value=True,
            new_value=False,
        )
        level, reason = classify_dns_change(change)
        assert level == "critical"
        assert "proxy" in reason.lower() or "ip" in reason.lower()

    def test_proxy_disabled_on_apex_is_critical(self) -> None:
        change = _chg(
            "modified",
            record_type="A",
            record_name="example.com",
            field_path="proxied",
            prev_value=True,
            new_value=False,
        )
        level, reason = classify_dns_change(change)
        assert level == "critical"

    def test_proxy_disabled_on_checkout_is_critical(self) -> None:
        change = _chg(
            "modified",
            record_type="A",
            record_name="checkout.example.com",
            field_path="proxied",
            prev_value=True,
            new_value=False,
        )
        level, reason = classify_dns_change(change)
        assert level == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# HIGH rule tests (rules 10–20)
# ─────────────────────────────────────────────────────────────────────────────

class TestHighRules:
    # ── Rule 10: Non-critical A/AAAA/CNAME removed ──────────────────────────

    def test_staging_a_removed_is_high(self) -> None:
        change = _chg("removed", record_type="A", record_name="staging.example.com")
        level, reason = classify_dns_change(change)
        assert level == "high"

    def test_blog_cname_removed_is_high(self) -> None:
        change = _chg("removed", record_type="CNAME", record_name="blog.example.com")
        level, reason = classify_dns_change(change)
        assert level == "high"

    # ── Rule 11: SPF TXT removed ─────────────────────────────────────────────

    def test_spf_txt_removed_is_high(self) -> None:
        change = _chg(
            "removed",
            record_type="TXT",
            record_name="example.com",
            record_content="v=spf1 include:sendgrid.net ~all",
        )
        level, reason = classify_dns_change(change)
        assert level == "high"
        assert "spf" in reason.lower() or "sender" in reason.lower()

    # ── Rule 12: DKIM TXT removed ────────────────────────────────────────────

    def test_dkim_txt_removed_by_content_is_high(self) -> None:
        change = _chg(
            "removed",
            record_type="TXT",
            record_name="selector1._domainkey.example.com",
            record_content="v=DKIM1; k=rsa; p=MIGf...",
        )
        level, reason = classify_dns_change(change)
        assert level == "high"
        assert "dkim" in reason.lower() or "signing" in reason.lower()

    def test_dkim_txt_removed_by_name_is_high(self) -> None:
        """DKIM TXT removed when content is unknown but name has _domainkey."""
        change = _chg(
            "removed",
            record_type="TXT",
            record_name="selector2._domainkey.example.com",
            record_content="",
        )
        level, reason = classify_dns_change(change)
        assert level == "high"

    # ── Rule 14: SPF / DKIM TXT content modified ─────────────────────────────

    def test_spf_content_modified_is_high(self) -> None:
        change = _chg(
            "modified",
            record_type="TXT",
            record_name="example.com",
            field_path="content",
            prev_value="v=spf1 include:old.com ~all",
            new_value="v=spf1 include:new.com ~all",
        )
        level, reason = classify_dns_change(change)
        assert level == "high"
        assert "SPF" in reason or "authentication" in reason.lower()

    def test_dkim_content_modified_is_high(self) -> None:
        change = _chg(
            "modified",
            record_type="TXT",
            record_name="selector1._domainkey.example.com",
            field_path="content",
            prev_value="v=DKIM1; k=rsa; p=OLD",
            new_value="v=DKIM1; k=rsa; p=NEW",
        )
        level, reason = classify_dns_change(change)
        assert level == "high"
        assert "DKIM" in reason or "authentication" in reason.lower()

    # ── Rule 15: DMARC TXT modified (non-weakening, non-strengthening) ───────

    def test_dmarc_content_modified_general_is_high(self) -> None:
        """DMARC none→none is neither weakening nor strengthening → HIGH."""
        change = _chg(
            "modified",
            record_type="TXT",
            record_name="_dmarc.example.com",
            field_path="content",
            prev_value="v=DMARC1; p=none; rua=mailto:old@e.com",
            new_value="v=DMARC1; p=none; rua=mailto:new@e.com",
        )
        level, reason = classify_dns_change(change)
        assert level == "high"
        assert "dmarc" in reason.lower() or "authentication" in reason.lower()

    # ── Rule 16: A / AAAA content modified (non-critical) ────────────────────

    def test_noncritical_a_content_modified_is_high(self) -> None:
        change = _chg(
            "modified",
            record_type="A",
            record_name="staging.example.com",
            field_path="content",
            prev_value="1.2.3.4",
            new_value="5.6.7.8",
        )
        level, reason = classify_dns_change(change)
        assert level == "high"

    def test_noncritical_aaaa_content_modified_is_high(self) -> None:
        change = _chg(
            "modified",
            record_type="AAAA",
            record_name="blog.example.com",
            field_path="content",
            prev_value="::1",
            new_value="::2",
        )
        level, reason = classify_dns_change(change)
        assert level == "high"

    # ── Rule 17: CNAME content modified (non-critical) ───────────────────────

    def test_noncritical_cname_content_modified_is_high(self) -> None:
        change = _chg(
            "modified",
            record_type="CNAME",
            record_name="docs.example.com",
            field_path="content",
            prev_value="old.example.com",
            new_value="new.example.com",
        )
        level, reason = classify_dns_change(change)
        assert level == "high"

    # ── Rule 18: Proxy disabled on non-critical hostname ─────────────────────

    def test_proxy_disabled_on_staging_is_high(self) -> None:
        change = _chg(
            "modified",
            record_type="A",
            record_name="staging.example.com",
            field_path="proxied",
            prev_value=True,
            new_value=False,
        )
        level, reason = classify_dns_change(change)
        assert level == "high"
        assert "proxy" in reason.lower() or "ip" in reason.lower()


# ─────────────────────────────────────────────────────────────────────────────
# MEDIUM rule tests (rules 21–29)
# ─────────────────────────────────────────────────────────────────────────────

class TestMediumRules:
    # ── Rule 21: Critical hostname A/AAAA/CNAME added ───────────────────────

    def test_www_a_added_is_medium(self) -> None:
        change = _chg(
            "added",
            record_type="A",
            record_name="www.example.com",
            new_value={"record_type": "A", "name": "www.example.com",
                       "content": "1.2.3.4", "record_id": "r1"},
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"
        assert "production" in reason.lower() or "critical" in reason.lower()

    def test_apex_cname_added_is_medium(self) -> None:
        change = _chg(
            "added",
            record_type="CNAME",
            record_name="example.com",
            new_value={"record_type": "CNAME", "name": "example.com",
                       "content": "target.example.com", "record_id": "r1"},
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"

    # ── Rule 23: CNAME added (non-critical) ──────────────────────────────────

    def test_noncritical_cname_added_is_medium(self) -> None:
        change = _chg(
            "added",
            record_type="CNAME",
            record_name="docs.example.com",
            new_value={"record_type": "CNAME", "name": "docs.example.com",
                       "content": "target.example.com", "record_id": "r1"},
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"
        assert "alias" in reason.lower() or "cname" in reason.lower()

    # ── Rule 24: MX added ────────────────────────────────────────────────────

    def test_mx_added_is_medium(self) -> None:
        change = _chg(
            "added",
            record_type="MX",
            record_name="example.com",
            new_value={"record_type": "MX", "name": "example.com",
                       "content": "mail2.example.com", "record_id": "r1"},
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"
        assert "mail" in reason.lower() or "mx" in reason.lower()

    # ── Rule 25: MX priority modified (downgraded from HIGH) ─────────────────

    def test_mx_priority_modified_is_medium(self) -> None:
        change = _chg(
            "modified",
            record_type="MX",
            record_name="example.com",
            field_path="priority",
            prev_value=10,
            new_value=20,
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"
        assert "priority" in reason.lower() or "mail" in reason.lower()

    def test_mx_priority_decreased_is_medium(self) -> None:
        """MX priority decrease (better preference) is still MEDIUM."""
        change = _chg(
            "modified",
            record_type="MX",
            record_name="example.com",
            field_path="priority",
            prev_value=20,
            new_value=5,
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"

    # ── Rule 26: Generic TXT removed (downgraded from HIGH) ──────────────────

    def test_generic_txt_removed_is_medium(self) -> None:
        change = _chg(
            "removed",
            record_type="TXT",
            record_name="example.com",
            record_content="some-custom-token-12345",
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"
        assert "txt" in reason.lower() or "verification" in reason.lower()

    def test_generic_txt_removed_no_content_is_medium(self) -> None:
        """TXT removed with unknown content (record_content absent) → medium."""
        change = _chg(
            "removed",
            record_type="TXT",
            record_name="example.com",
            record_content="",
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"

    # ── Rule 27: Generic TXT content modified ────────────────────────────────

    def test_generic_txt_content_modified_is_medium(self) -> None:
        change = _chg(
            "modified",
            record_type="TXT",
            record_name="example.com",
            field_path="content",
            prev_value="custom-value-old",
            new_value="custom-value-new",
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"

    # ── Rule 29: TTL > 60 on critical hostname ───────────────────────────────

    def test_ttl_change_on_critical_is_medium(self) -> None:
        change = _chg(
            "modified",
            record_type="A",
            record_name="api.example.com",
            field_path="ttl",
            prev_value=3600,
            new_value=300,
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"
        assert "300" in reason

    def test_ttl_change_on_apex_is_medium(self) -> None:
        change = _chg(
            "modified",
            record_type="A",
            record_name="example.com",
            field_path="ttl",
            prev_value=3600,
            new_value=1800,
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# LOW rule tests (rules 30–33 + default)
# ─────────────────────────────────────────────────────────────────────────────

class TestLowRules:
    # ── Rule 30: Email-auth TXT added ────────────────────────────────────────

    def test_spf_txt_added_is_low(self) -> None:
        change = _chg(
            "added",
            record_type="TXT",
            record_name="example.com",
            record_content="v=spf1 include:sendgrid.net ~all",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"
        assert "spf" in reason.lower() or "authentication" in reason.lower()

    def test_dkim_txt_added_by_content_is_low(self) -> None:
        change = _chg(
            "added",
            record_type="TXT",
            record_name="selector1._domainkey.example.com",
            record_content="v=DKIM1; k=rsa; p=MIGf...",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"
        assert "dkim" in reason.lower() or "authentication" in reason.lower()

    def test_dkim_txt_added_by_name_is_low(self) -> None:
        """DKIM TXT matched via _domainkey label even when content is empty."""
        change = _chg(
            "added",
            record_type="TXT",
            record_name="selector2._domainkey.example.com",
            record_content="",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"

    def test_dmarc_txt_added_is_low(self) -> None:
        change = _chg(
            "added",
            record_type="TXT",
            record_name="_dmarc.example.com",
            record_content="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"
        assert "dmarc" in reason.lower() or "authentication" in reason.lower()

    # ── Rule 31: Verification record added ───────────────────────────────────

    def test_google_site_verification_txt_added_is_low(self) -> None:
        change = _chg(
            "added",
            record_type="TXT",
            record_name="example.com",
            record_content="google-site-verification=abc123XYZ",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"
        assert "verification" in reason.lower()

    def test_acme_challenge_cname_added_is_low(self) -> None:
        change = _chg(
            "added",
            record_type="CNAME",
            record_name="_acme-challenge.example.com",
            record_content="acme-staging.example.com",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"

    def test_clerk_cname_added_is_low(self) -> None:
        change = _chg(
            "added",
            record_type="CNAME",
            record_name="clerk.example.com",
            record_content="frontend-api.clerk.accounts.dev",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"

    def test_resend_cname_added_is_low(self) -> None:
        change = _chg(
            "added",
            record_type="CNAME",
            record_name="resend.example.com",
            record_content="feedback-smtp.us-east-1.amazonses.com",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"

    def test_apple_domain_verification_txt_added_is_low(self) -> None:
        change = _chg(
            "added",
            record_type="TXT",
            record_name="example.com",
            record_content="apple-domain-verification=AAABBBCCC",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"

    # ── Rule 15 (LOW sub-case): DMARC strengthened ───────────────────────────

    def test_dmarc_strengthened_to_reject_is_low(self) -> None:
        change = _chg(
            "modified",
            record_type="TXT",
            record_name="_dmarc.example.com",
            field_path="content",
            prev_value="v=DMARC1; p=none",
            new_value="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"
        assert "strengthen" in reason.lower() or "hardening" in reason.lower() or "protect" in reason.lower()

    def test_dmarc_strengthened_to_quarantine_is_low(self) -> None:
        change = _chg(
            "modified",
            record_type="TXT",
            record_name="_dmarc.example.com",
            field_path="content",
            prev_value="v=DMARC1; p=none",
            new_value="v=DMARC1; p=quarantine",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"

    # ── Rule 32: TTL > 60 on non-critical hostname (downgraded from MEDIUM) ──

    def test_ttl_change_on_noncritical_is_low(self) -> None:
        change = _chg(
            "modified",
            record_type="A",
            record_name="staging.example.com",
            field_path="ttl",
            prev_value=3600,
            new_value=300,
        )
        level, reason = classify_dns_change(change)
        assert level == "low"
        assert "300" in reason

    def test_ttl_increase_on_blog_is_low(self) -> None:
        change = _chg(
            "modified",
            record_type="A",
            record_name="blog.example.com",
            field_path="ttl",
            prev_value=300,
            new_value=86400,
        )
        level, reason = classify_dns_change(change)
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# Boundary / edge-case tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_txt_added_with_non_auth_content_falls_to_default(self) -> None:
        """A TXT record added with non-email-auth, non-verification content → low (default)."""
        change = _chg(
            "added",
            record_type="TXT",
            record_name="example.com",
            record_content="some-random-custom-value",
        )
        level, _ = classify_dns_change(change)
        # Generic TXT added is not explicitly handled → falls to default low
        assert level == "low"

    def test_srv_record_removed_is_high(self) -> None:
        """SRV record removed falls to rule 20 (non-TXT generic removed) → HIGH."""
        change = _chg(
            "removed",
            record_type="SRV",
            record_name="_sip._tcp.example.com",
        )
        level, reason = classify_dns_change(change)
        assert level == "high"

    def test_caa_record_removed_is_high(self) -> None:
        """CAA record removed → HIGH (rule 20)."""
        change = _chg("removed", record_type="CAA", record_name="example.com")
        level, reason = classify_dns_change(change)
        assert level == "high"

    def test_wildcard_txt_removed_not_caught_by_wildcard_rule(self) -> None:
        """Wildcard TXT is not A/AAAA/CNAME so rule 2 does not fire → falls to
        DMARC/SPF/DKIM/generic TXT checks."""
        change = _chg(
            "removed",
            record_type="TXT",
            record_name="*.example.com",
            record_content="some-txt",
        )
        level, _ = classify_dns_change(change)
        # Not a wildcard A/AAAA/CNAME, not DMARC/SPF/DKIM → generic TXT → MEDIUM
        assert level == "medium"

    def test_proxy_disabled_then_enabled_non_critical(self) -> None:
        """proxy false→true on any hostname → MEDIUM (rule 28)."""
        change = _chg(
            "modified",
            record_type="A",
            record_name="staging.example.com",
            field_path="proxied",
            prev_value=False,
            new_value=True,
        )
        level, reason = classify_dns_change(change)
        assert level == "medium"
        assert "proxy" in reason.lower() or "cloudflare" in reason.lower()

    def test_ttl_reduced_to_60_on_noncritical_is_high(self) -> None:
        """TTL ≤ 60 always HIGH regardless of hostname criticality (rule 19 fires first)."""
        change = _chg(
            "modified",
            record_type="A",
            record_name="staging.example.com",
            field_path="ttl",
            prev_value=3600,
            new_value=60,
        )
        level, reason = classify_dns_change(change)
        assert level == "high"
        assert "60" in reason

    def test_ttl_reduced_to_30_on_critical_is_high(self) -> None:
        """TTL ≤ 60 always HIGH even on critical hostname (rule 19 before rule 29)."""
        change = _chg(
            "modified",
            record_type="A",
            record_name="api.example.com",
            field_path="ttl",
            prev_value=3600,
            new_value=30,
        )
        level, reason = classify_dns_change(change)
        assert level == "high"

    def test_dmarc_added_via_name_label_is_low(self) -> None:
        """DMARC TXT added recognised by _dmarc name label → LOW."""
        change = _chg(
            "added",
            record_type="TXT",
            record_name="_dmarc.example.com",
            record_content="v=DMARC1; p=none",
        )
        level, reason = classify_dns_change(change)
        assert level == "low"
        assert "dmarc" in reason.lower() or "authentication" in reason.lower()
