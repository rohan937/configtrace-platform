"""Cloudflare DNS risk rules — Milestone 10 + 27.

Classifies a Change (ORM object or plain dict) into one of four risk levels:
    critical  — changes that can take services completely offline or expose the
                domain to security attacks (email spoofing, IP exposure, etc.)
    high      — changes likely to disrupt traffic, degrade service, or break
                email authentication for many users
    medium    — changes that alter behaviour but are generally reversible and
                have a bounded blast radius
    low       — hardening changes, cosmetic edits, or additions with no
                traffic impact

Design decisions
----------------
* ``classify_dns_change`` accepts both ORM ``Change`` objects and plain dicts.
  The ``_get`` helper provides unified attribute/key access so pure unit tests
  can pass simple dicts without needing DB fixtures.

* ``is_apex_or_root_record`` uses a label-count heuristic (≤2 dot-separated
  labels = apex) when a ``zone_name`` is not available.  This works for
  standard TLDs (e.g. ``example.com``).  If ``provider_metadata`` ever gains a
  ``zone_name`` field, exact string matching is used instead — that path is
  already implemented and tested.

* ``_is_critical_hostname`` extends apex detection with a curated set of
  critical subdomain labels (www, api, app, auth, login, admin, etc.) that
  identify production-facing endpoints where an outage has company-wide impact.

* Rule order matters: more-specific / higher-severity rules are evaluated first
  so they short-circuit before falling through to generic catch-alls.

* Email-auth records (SPF, DKIM, DMARC) are treated as first-class entities
  because changes to them can break email authentication for the entire domain.

* DMARC policy direction is analysed via regex so weakening (reject/quarantine
  → none) triggers CRITICAL and strengthening (none → reject/quarantine) is
  recognised as a LOW hardening change.

* Verification TXT records (Google, ACME, Clerk, Resend) are LOW when added
  because they prove ownership but carry zero traffic impact.

* The final ``return ("low", "No specific...")`` is the universal default.
"""

from __future__ import annotations

import re
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Attribute-access helper (supports both ORM objects and plain dicts)
# ─────────────────────────────────────────────────────────────────────────────

def _get(obj: Any, key: str) -> Any:
    """Return *obj[key]* for dicts, or ``getattr(obj, key, None)`` for objects."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


# ─────────────────────────────────────────────────────────────────────────────
# Apex detection
# ─────────────────────────────────────────────────────────────────────────────

def is_apex_or_root_record(record_name: str, zone_name: str | None = None) -> bool:
    """Return ``True`` if *record_name* refers to the apex (root) of the zone.

    When *zone_name* is provided, uses an exact string match (most accurate).
    When *zone_name* is ``None`` (the common MVP case), falls back to a
    label-count heuristic: ≤2 dot-separated labels → apex.

    Examples::

        is_apex_or_root_record("example.com")          → True
        is_apex_or_root_record("api.example.com")      → False
        is_apex_or_root_record("example.com",
                               zone_name="example.com") → True
        is_apex_or_root_record("api.example.com",
                               zone_name="example.com") → False
        is_apex_or_root_record("sub.example.co.uk")    → False  (3 labels)

    Note: The label-count approach underclassifies multi-part TLDs such as
    ``example.co.uk`` (3 labels, but still an apex).  Milestone 10 ships with
    this known limitation; a zone-name exact-match path is available for
    future use when zone data is stored in ``provider_metadata``.
    """
    if not record_name:
        return False

    clean_name = record_name.rstrip(".")

    if zone_name:
        return clean_name == zone_name.rstrip(".")

    labels = clean_name.split(".")
    return len(labels) <= 2


# ─────────────────────────────────────────────────────────────────────────────
# Critical hostname detection
# ─────────────────────────────────────────────────────────────────────────────

#: Subdomain labels whose records serve production traffic at company scale.
#: Changes to these hostnames have the same blast radius as the apex domain.
_CRITICAL_SUBDOMAINS: frozenset[str] = frozenset({
    "www", "app", "api", "auth", "login", "dashboard", "admin",
    "checkout", "payment", "payments", "billing", "mail", "smtp",
    "cdn", "assets", "static",
})


def _is_critical_hostname(record_name: str, zone_name: str | None = None) -> bool:
    """Return ``True`` if *record_name* is apex or has a critical leftmost label.

    Combines ``is_apex_or_root_record`` with a curated set of production
    subdomain labels.  The leftmost DNS label is used because that is the
    sub-zone part that identifies the service (e.g. "api" in "api.example.com").
    """
    if is_apex_or_root_record(record_name, zone_name):
        return True
    clean = (record_name or "").rstrip(".")
    leftmost = clean.split(".")[0].lower() if clean else ""
    return leftmost in _CRITICAL_SUBDOMAINS


def _is_wildcard(record_name: str) -> bool:
    """Return ``True`` if *record_name* is a wildcard (starts with ``*``)."""
    return (record_name or "").startswith("*")


# ─────────────────────────────────────────────────────────────────────────────
# Email-auth content detection
# ─────────────────────────────────────────────────────────────────────────────

def _content_is_spf(content: str) -> bool:
    """Return ``True`` if *content* looks like an SPF TXT record."""
    return (content or "").strip().lower().startswith("v=spf1")


def _content_is_dkim(content: str) -> bool:
    """Return ``True`` if *content* looks like a DKIM TXT record."""
    return (content or "").strip().lower().startswith("v=dkim1")


def _content_is_dmarc(content: str) -> bool:
    """Return ``True`` if *content* looks like a DMARC TXT record."""
    return (content or "").strip().lower().startswith("v=dmarc1")


def _name_has_dmarc(record_name: str) -> bool:
    """Return ``True`` if the leftmost DNS label of *record_name* is ``_dmarc``."""
    labels = (record_name or "").lower().rstrip(".").split(".")
    return bool(labels) and labels[0] == "_dmarc"


def _name_has_dkim(record_name: str) -> bool:
    """Return ``True`` if *record_name* contains the ``_domainkey`` label."""
    return "_domainkey" in (record_name or "").lower()


def _is_email_auth_txt(content: str, record_name: str = "") -> bool:
    """Return ``True`` if the TXT record is SPF, DKIM, or DMARC."""
    return (
        _content_is_spf(content)
        or _content_is_dkim(content)
        or _content_is_dmarc(content)
        or _name_has_dmarc(record_name)
        or _name_has_dkim(record_name)
    )


# ─────────────────────────────────────────────────────────────────────────────
# DMARC policy analysis
# ─────────────────────────────────────────────────────────────────────────────

# Matches the `p=` tag at the start of the string or after a semicolon/space.
_DMARC_POLICY_RE = re.compile(r"(?:^|[;\s])p=(\w+)", re.IGNORECASE)
_STRONG_DMARC: frozenset[str] = frozenset({"reject", "quarantine"})


def _get_dmarc_policy(content: str) -> str | None:
    """Extract the DMARC ``p=`` policy value from *content*, lower-cased."""
    m = _DMARC_POLICY_RE.search(content or "")
    return m.group(1).lower() if m else None


def _is_dmarc_weakening(old_content: str, new_content: str) -> bool:
    """Return ``True`` if the DMARC policy changed from enforce to ``none``."""
    return (
        _get_dmarc_policy(old_content) in _STRONG_DMARC
        and _get_dmarc_policy(new_content) == "none"
    )


def _is_dmarc_strengthening(old_content: str, new_content: str) -> bool:
    """Return ``True`` if the DMARC policy changed from ``none`` to enforcing."""
    return (
        _get_dmarc_policy(old_content) == "none"
        and _get_dmarc_policy(new_content) in _STRONG_DMARC
    )


# ─────────────────────────────────────────────────────────────────────────────
# Verification record detection
# ─────────────────────────────────────────────────────────────────────────────

#: TXT content prefixes that indicate domain-ownership verification records.
#: These carry zero DNS-traffic impact when added.
_VERIFICATION_TXT_PREFIXES: tuple[str, ...] = (
    "google-site-verification=",
    "ms=ms",
    "apple-domain-verification=",
    "atlassian-domain-verification=",
    "facebook-domain-verification=",
)

#: DNS label keywords that indicate ACME challenge / platform verification CNAMEs
#: or ownership-proof TXT records.
_VERIFICATION_LABEL_KEYWORDS: frozenset[str] = frozenset({
    "_acme-challenge",
    "_github-pages-challenge",
    "_github-challenge",
    "clerk",
    "clkmail",
    "resend",
})


def _is_verification_record(record_name: str, content: str, record_type: str) -> bool:
    """Return ``True`` if the record is a third-party domain-verification record.

    Checks both the TXT content (prefix matching) and the DNS labels in
    *record_name* (substring matching against known platform keywords).
    """
    name_labels = set((record_name or "").lower().rstrip(".").split("."))
    c = (content or "").strip().lower()

    if record_type == "TXT":
        for prefix in _VERIFICATION_TXT_PREFIXES:
            if c.startswith(prefix.lower()):
                return True

    if name_labels & _VERIFICATION_LABEL_KEYWORDS:
        return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# DNS risk classifier
# ─────────────────────────────────────────────────────────────────────────────

def classify_dns_change(change: Any) -> tuple[str, str]:
    """Classify a Cloudflare DNS change and return ``(risk_level, risk_reason)``.

    Accepts either a SQLAlchemy ``Change`` ORM object or a plain ``dict``
    (e.g. from unit tests).

    Risk levels
    -----------
    ``critical``  changes that can take services completely offline or expose
                  the domain to security attacks
    ``high``      changes likely to disrupt traffic or break email
                  authentication
    ``medium``    changes that alter behaviour but have bounded impact and are
                  generally reversible
    ``low``       hardening changes, ownership verification records, cosmetic
                  edits, or additions with no traffic impact

    Rule evaluation order
    ---------------------
    Rules are ordered from most-severe to least-severe.  The first matching
    rule short-circuits the remaining checks.  Within each severity tier,
    rules are ordered from most-specific to most-generic.

    Args:
        change: A ``Change`` ORM instance or a ``dict`` with the same field
                names (``change_type``, ``field_path``, ``prev_value``,
                ``new_value``, ``provider_metadata``).

    Returns:
        ``(risk_level, risk_reason)`` where *risk_level* is one of
        ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
    """
    change_type = (_get(change, "change_type") or "").lower()
    field_path = _get(change, "field_path")
    prev_value = _get(change, "prev_value")
    new_value = _get(change, "new_value")
    provider_metadata: dict[str, Any] = _get(change, "provider_metadata") or {}

    record_type = (provider_metadata.get("record_type") or "").upper()
    record_name = provider_metadata.get("record_name") or ""
    zone_name = provider_metadata.get("zone_name")  # None in MVP; used when available
    record_content = provider_metadata.get("record_content") or ""

    # ── Fallback: extract record_type / record_name / record_content from the
    # full record dict stored in prev_value (removed) or new_value (added) when
    # provider_metadata is incomplete.
    if change_type == "removed" and isinstance(prev_value, dict):
        if not record_type:
            record_type = (prev_value.get("record_type") or "").upper()
        if not record_name:
            record_name = prev_value.get("name") or ""
        if not record_content:
            record_content = prev_value.get("content") or ""

    if change_type == "added" and isinstance(new_value, dict):
        if not record_type:
            record_type = (new_value.get("record_type") or "").upper()
        if not record_name:
            record_name = new_value.get("name") or ""
        if not record_content:
            record_content = new_value.get("content") or ""

    is_apex = is_apex_or_root_record(record_name, zone_name)
    is_critical = _is_critical_hostname(record_name, zone_name)
    is_wc = _is_wildcard(record_name)

    # ══════════════════════════════════════════════════════════════════════════
    # CRITICAL rules
    # Ordered: NS/SOA first, then wildcards, then email-auth removals, then
    # critical-hostname address changes, then MX removal, then proxy.
    # ══════════════════════════════════════════════════════════════════════════

    # 1. NS / SOA modified — changes nameserver delegation; all DNS fails.
    if change_type == "modified" and record_type in ("NS", "SOA"):
        return (
            "critical",
            f"Modification of an {record_type} record changes nameserver delegation "
            "and can disrupt all DNS resolution for the domain.",
        )

    # 2. Wildcard A / AAAA / CNAME removed — removes catch-all resolution for
    #    every subdomain not explicitly configured.
    if is_wc and record_type in ("A", "AAAA", "CNAME") and change_type == "removed":
        return (
            "critical",
            f"Deletion of a wildcard {record_type} record removes DNS resolution "
            "for all unmatched subdomains simultaneously.",
        )

    # 3. Wildcard A / AAAA / CNAME content modified — redirects all unmatched
    #    subdomain traffic to a new destination.
    if is_wc and record_type in ("A", "AAAA", "CNAME"):
        if change_type == "modified" and field_path == "content":
            return (
                "critical",
                f"Modification of a wildcard {record_type} record redirects DNS "
                "resolution for all unmatched subdomains simultaneously.",
            )

    # 4. DMARC TXT removed — eliminates email authentication policy, exposing
    #    the domain to email spoofing.
    if change_type == "removed" and record_type == "TXT":
        if _content_is_dmarc(record_content) or _name_has_dmarc(record_name):
            return (
                "critical",
                "Deletion of the DMARC TXT record removes the domain email "
                "authentication policy, exposing the domain to email spoofing "
                "and phishing attacks.",
            )

    # 5. DMARC policy weakened (reject/quarantine → none) — disables enforcement
    #    so unauthenticated messages are no longer rejected.
    if change_type == "modified" and record_type == "TXT" and field_path == "content":
        _is_dmarc_record = _name_has_dmarc(record_name) or _content_is_dmarc(
            str(prev_value or "")
        )
        if _is_dmarc_record and _is_dmarc_weakening(
            str(prev_value or ""), str(new_value or "")
        ):
            return (
                "critical",
                "The DMARC policy has been weakened from reject/quarantine to none, "
                "allowing unauthenticated email to pass through without enforcement.",
            )

    # 6. Critical hostname A / AAAA / CNAME removed — takes a production
    #    service offline for all users (apex, www, api, auth, admin, etc.).
    if change_type == "removed" and record_type in ("A", "AAAA", "CNAME"):
        if is_critical:
            hostname_type = "apex" if is_apex else "critical subdomain"
            return (
                "critical",
                f"Deletion of an {hostname_type} {record_type} record can take the "
                "associated service completely offline for all users.",
            )

    # 7. MX removed — stops all email delivery for the domain.
    if change_type == "removed" and record_type == "MX":
        return (
            "critical",
            "Deletion of an MX record stops email delivery for the domain.",
        )

    # 8. Critical hostname A / AAAA / CNAME content modified — redirects all
    #    production traffic to a new destination (IP or target).
    if change_type == "modified" and record_type in ("A", "AAAA", "CNAME"):
        if field_path == "content" and is_critical:
            hostname_type = "apex" if is_apex else "critical subdomain"
            return (
                "critical",
                f"Modification of the {record_type} target for a {hostname_type} "
                "hostname redirects all production traffic to a new destination.",
            )

    # 9. Proxy disabled on a critical hostname (true → false) — exposes origin
    #    IP and removes DDoS protection from a production endpoint.
    if change_type == "modified" and field_path == "proxied":
        if prev_value is True and new_value is False and is_critical:
            hostname_type = "apex" if is_apex else "critical subdomain"
            return (
                "critical",
                f"Disabling Cloudflare proxy on a {hostname_type} hostname exposes "
                "the origin server IP directly to the internet, removing DDoS "
                "protection from a production endpoint.",
            )

    # ══════════════════════════════════════════════════════════════════════════
    # HIGH rules
    # Ordered: address-record deletions, email-auth record changes, content
    # modifications, proxy/TTL changes, then generic deletion catch-all.
    # ══════════════════════════════════════════════════════════════════════════

    # 10. Non-critical A / AAAA / CNAME removed — removes a DNS entry; the
    #     affected hostname stops resolving.
    if change_type == "removed" and record_type in ("A", "AAAA", "CNAME"):
        return (
            "high",
            f"Deletion of a {record_type} record removes a DNS entry and may "
            "disrupt dependent services.",
        )

    # 11. SPF TXT removed — removes the authorised sender list; email spoofing
    #     risk increases for the domain.
    if change_type == "removed" and record_type == "TXT":
        if _content_is_spf(record_content):
            return (
                "high",
                "Deletion of the SPF TXT record removes the authorised sender list, "
                "increasing the risk of email spoofing for the domain.",
            )

    # 12. DKIM TXT removed — breaks email signing for the associated selector;
    #     messages may fail DKIM validation and land in spam.
    if change_type == "removed" and record_type == "TXT":
        if _content_is_dkim(record_content) or _name_has_dkim(record_name):
            return (
                "high",
                "Deletion of a DKIM TXT record breaks email signing for the "
                "associated selector, causing messages to fail DKIM validation.",
            )

    # 13. MX content modified — changes where inbound email is delivered.
    if change_type == "modified" and record_type == "MX" and field_path == "content":
        return (
            "high",
            "Modification of the MX target changes where inbound email is delivered.",
        )

    # 14. SPF / DKIM TXT content modified — changing an email authentication
    #     record can break email delivery or allow spoofing.
    if change_type == "modified" and record_type == "TXT" and field_path == "content":
        _is_spf_prev = _content_is_spf(str(prev_value or ""))
        _is_dkim_prev = _content_is_dkim(str(prev_value or "")) or _name_has_dkim(
            record_name
        )
        # Exclude DMARC records — handled by rule 15 (with strengthening check).
        _is_dmarc_rec = _name_has_dmarc(record_name) or _content_is_dmarc(
            str(prev_value or "")
        )
        if (_is_spf_prev or _is_dkim_prev) and not _is_dmarc_rec:
            auth_type = "SPF" if _is_spf_prev else "DKIM"
            return (
                "high",
                f"Modification of the {auth_type} TXT record may break email "
                "authentication and cause messages to be rejected or marked as spam.",
            )

    # 15. DMARC TXT content modified — two sub-cases:
    #     a. DMARC policy strengthened (none → reject/quarantine) → LOW (hardening)
    #     b. All other DMARC changes → HIGH
    if change_type == "modified" and record_type == "TXT" and field_path == "content":
        if _name_has_dmarc(record_name) or _content_is_dmarc(str(prev_value or "")):
            if _is_dmarc_strengthening(str(prev_value or ""), str(new_value or "")):
                return (
                    "low",
                    "The DMARC policy has been strengthened to enforce email "
                    "authentication, improving protection against email spoofing.",
                )
            return (
                "high",
                "Modification of the DMARC TXT record changes the domain email "
                "authentication policy, which may affect email deliverability.",
            )

    # 16. A / AAAA content modified (non-critical hostname) — redirects the
    #     hostname's traffic to a new IP address.
    if change_type == "modified" and record_type in ("A", "AAAA") and field_path == "content":
        return (
            "high",
            f"Modification of the {record_type} record's IP address redirects "
            "traffic for this hostname to a new destination.",
        )

    # 17. CNAME content modified (non-critical hostname) — redirects the
    #     hostname's traffic to a new alias target.
    if change_type == "modified" and record_type == "CNAME" and field_path == "content":
        return (
            "high",
            "Modification of the CNAME target redirects traffic for this hostname "
            "to a new destination.",
        )

    # 18. Proxy disabled on non-critical hostname (true → false) — exposes the
    #     origin IP and removes Cloudflare DDoS protection.
    if change_type == "modified" and field_path == "proxied":
        if prev_value is True and new_value is False:
            return (
                "high",
                "Disabling Cloudflare proxy exposes the origin server IP address "
                "directly to the internet, removing DDoS protection and masking.",
            )

    # 19. Very short TTL (≤ 60 s) — shrinks the rollback window after a bad
    #     change; DNS resolvers flush the record nearly immediately.
    if change_type == "modified" and field_path == "ttl":
        if isinstance(new_value, (int, float)) and new_value <= 60:
            return (
                "high",
                f"TTL reduced to {new_value} second(s). Very short TTLs shrink the "
                "rollback window if a bad change needs to be reverted.",
            )

    # 20. Any other non-TXT record removed (SRV, CAA, PTR, etc.) — removes a
    #     configured DNS entry; TXT is excluded because non-email-auth TXT
    #     removals are MEDIUM (rule 26).
    if change_type == "removed" and record_type != "TXT":
        return (
            "high",
            f"Deletion of a {record_type or 'DNS'} record removes a configured DNS "
            "entry and may disrupt dependent services.",
        )

    # ══════════════════════════════════════════════════════════════════════════
    # MEDIUM rules
    # Ordered: record additions, MX priority, TXT removals, TXT modifications,
    # proxy-enable, and TTL changes on critical hostnames.
    # ══════════════════════════════════════════════════════════════════════════

    # Pre-check: verification records added (CNAME / TXT / A) → always LOW.
    # Must come before rules 21–24 so that a verification CNAME such as
    # _acme-challenge, clerk, or resend is not promoted to MEDIUM by the
    # generic "CNAME added" rule.
    if change_type == "added":
        if _is_verification_record(record_name, record_content, record_type):
            return (
                "low",
                "Addition of a domain verification record for a third-party service. "
                "This has no effect on DNS traffic.",
            )

    # 21. Critical hostname A / AAAA / CNAME added — introduces a new DNS
    #     entry for a production-facing service.
    if change_type == "added" and record_type in ("A", "AAAA", "CNAME"):
        if is_critical:
            hostname_type = "apex" if is_apex else "critical subdomain"
            return (
                "medium",
                f"Addition of a new {record_type} record for a {hostname_type} "
                "hostname creates a new DNS entry for a production endpoint.",
            )

    # 22. Non-critical subdomain A / AAAA added — creates a new DNS entry
    #     point that was not previously configured.
    if change_type == "added" and record_type in ("A", "AAAA"):
        return (
            "medium",
            f"Addition of a new subdomain {record_type} record creates a new "
            "DNS entry point that was not previously configured.",
        )

    # 23. CNAME added (non-critical) — creates a DNS alias to an external target.
    if change_type == "added" and record_type == "CNAME":
        return (
            "medium",
            "Addition of a new CNAME record creates a DNS alias to an external target.",
        )

    # 24. MX added — introduces a new mail server for the domain.
    if change_type == "added" and record_type == "MX":
        return (
            "medium",
            "Addition of a new MX record introduces a new mail server for this domain.",
        )

    # 25. MX priority modified — changes the preference order for mail server
    #     selection; delivery still works but may use a different server first.
    if change_type == "modified" and record_type == "MX" and field_path == "priority":
        return (
            "medium",
            "Modification of MX priority changes the preference order for mail "
            "server selection.",
        )

    # 26. Generic TXT removed (non-email-auth) — removes a text record that is
    #     not SPF/DKIM/DMARC; may affect service verification or configuration.
    if change_type == "removed" and record_type == "TXT":
        return (
            "medium",
            "Deletion of a TXT record removes a DNS text entry. Verify it is not "
            "used for service verification or configuration.",
        )

    # 27. TXT content modified (non-email-auth) — changes a text record not
    #     classified as SPF, DKIM, or DMARC.
    if change_type == "modified" and record_type == "TXT" and field_path == "content":
        return (
            "medium",
            "Modification of a TXT record value may affect service verification or "
            "other DNS-based configuration.",
        )

    # 28. Proxy enabled (false → true) — routes traffic through Cloudflare;
    #     changes performance characteristics and adds DDoS protection.
    if change_type == "modified" and field_path == "proxied":
        if prev_value is False and new_value is True:
            return (
                "medium",
                "Enabling Cloudflare proxy routes traffic through Cloudflare's "
                "network, changing performance characteristics and adding protection.",
            )

    # 29. TTL change on a critical hostname (> 60 s) — affects caching duration
    #     for a production endpoint; more meaningful than a non-critical change.
    if change_type == "modified" and field_path == "ttl" and is_critical:
        return (
            "medium",
            f"TTL changed to {new_value} seconds on a production hostname. "
            "DNS resolvers will cache this record for the new duration.",
        )

    # ══════════════════════════════════════════════════════════════════════════
    # LOW rules
    # Ordered: email-auth additions (hardening), verification records, TTL on
    # non-critical hostnames, comment edits, then default catch-all.
    # ══════════════════════════════════════════════════════════════════════════

    # 30. Email-auth TXT added (SPF / DKIM / DMARC) — sets up or strengthens
    #     email authentication; a hardening change with positive security impact.
    if change_type == "added" and record_type == "TXT":
        if _is_email_auth_txt(record_content, record_name):
            auth_type = (
                "SPF"
                if _content_is_spf(record_content)
                else (
                    "DKIM"
                    if (_content_is_dkim(record_content) or _name_has_dkim(record_name))
                    else "DMARC"
                )
            )
            return (
                "low",
                f"Addition of a {auth_type} TXT record strengthens email "
                "authentication for the domain.",
            )

    # 32. TTL change on a non-critical hostname (> 60 s) — affects caching
    #     duration for a low-impact endpoint.
    if change_type == "modified" and field_path == "ttl":
        return (
            "low",
            f"TTL changed to {new_value} seconds. DNS resolvers will cache this "
            "record for the new duration.",
        )

    # 33. Comment changed — metadata only; zero DNS resolution impact.
    if change_type == "modified" and field_path == "comment":
        return (
            "low",
            "Comment modification has no effect on DNS resolution.",
        )

    # ══════════════════════════════════════════════════════════════════════════
    # Default catch-all
    # ══════════════════════════════════════════════════════════════════════════
    return (
        "low",
        "No specific risk pattern matched. This change may be routine configuration "
        "maintenance.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# M57.7 — Cloudflare WAF ruleset risk rules
# ─────────────────────────────────────────────────────────────────────────────

def classify_cloudflare_ruleset_change(change: object) -> tuple[str, str]:
    """Classify risk for ``cloudflare_ruleset`` record changes (M57.7).

    Rule order (highest-priority first):

    1. Ruleset removed   → critical  (WAF protection gap created)
    2. Ruleset added     → high      (new WAF policy — review for unintended bypass)
    3. skip_count ↑      → high      (more rules bypassing WAF checks)
    4. block_count ↓     → high      (fewer rules actively blocking attacks)
    5. enabled_rule_count ↓ → high   (more rules disabled — reduced protection)
    6. rule_count ↓      → medium    (rules removed — may be intentional cleanup)
    7. rule_count ↑      → medium    (rules added — scope expansion)
    8. skip_count ↓      → low       (hardening: fewer bypass rules)
    9. block_count ↑     → low       (hardening: more blocking rules)
    10. enabled_rule_count ↑ → low   (hardening: more rules enabled)
    11. version / phase / kind changes → low (administrative / metadata change)
    """
    pm: dict = _get(change, "provider_metadata") or {}
    change_type: str = (_get(change, "change_type") or "").lower()
    field_path: str = (_get(change, "field_path") or "").lower()
    old_value = _get(change, "old_value")
    new_value = _get(change, "new_value")

    # 1. Ruleset removed — WAF protection gap
    if change_type == "removed":
        phase: str = (pm.get("phase") or "unknown")
        return (
            "critical",
            f"WAF ruleset removed (phase: {phase}). "
            "This eliminates all rules in the ruleset and may expose the zone to attacks.",
        )

    # 2. Ruleset added — new WAF policy deployed
    if change_type == "added":
        phase = (pm.get("phase") or "unknown")
        return (
            "high",
            f"New WAF ruleset deployed (phase: {phase}). "
            "Review the ruleset to ensure it enforces the intended security posture.",
        )

    # ── Modified field rules ──────────────────────────────────────────────────

    def _int(v: object) -> int:
        try:
            return int(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return 0

    # 3. skip_count increased — more bypass rules
    if field_path == "skip_count":
        old_n, new_n = _int(old_value), _int(new_value)
        if new_n > old_n:
            return (
                "high",
                f"WAF ruleset skip_count increased from {old_n} to {new_n}. "
                "Additional rules now bypass WAF checks, potentially widening attack surface.",
            )
        if new_n < old_n:
            return (
                "low",
                f"WAF ruleset skip_count decreased from {old_n} to {new_n}. "
                "Fewer WAF bypass rules — security posture improved.",
            )

    # 4. block_count decreased — fewer blocking rules
    if field_path == "block_count":
        old_n, new_n = _int(old_value), _int(new_value)
        if new_n < old_n:
            return (
                "high",
                f"WAF ruleset block_count decreased from {old_n} to {new_n}. "
                "Fewer rules are actively blocking attacks.",
            )
        if new_n > old_n:
            return (
                "low",
                f"WAF ruleset block_count increased from {old_n} to {new_n}. "
                "More rules are actively blocking attacks — security posture improved.",
            )

    # 5. enabled_rule_count decreased — more rules disabled
    if field_path == "enabled_rule_count":
        old_n, new_n = _int(old_value), _int(new_value)
        if new_n < old_n:
            return (
                "high",
                f"WAF enabled rule count decreased from {old_n} to {new_n}. "
                "Disabled rules provide no protection.",
            )
        if new_n > old_n:
            return (
                "low",
                f"WAF enabled rule count increased from {old_n} to {new_n}. "
                "More rules are now active — protection expanded.",
            )

    # 6–7. rule_count changed
    if field_path == "rule_count":
        old_n, new_n = _int(old_value), _int(new_value)
        if new_n < old_n:
            return (
                "medium",
                f"WAF ruleset rule_count decreased from {old_n} to {new_n}. "
                "Rules were removed — verify this was intentional.",
            )
        if new_n > old_n:
            return (
                "medium",
                f"WAF ruleset rule_count increased from {old_n} to {new_n}. "
                "New rules were added to the ruleset.",
            )

    # 8. challenge_count / managed_challenge_count changed
    if field_path in ("challenge_count", "managed_challenge_count"):
        old_n, new_n = _int(old_value), _int(new_value)
        direction = "increased" if new_n > old_n else "decreased"
        return (
            "medium",
            f"WAF {field_path.replace('_count', '')} rule count {direction} "
            f"from {old_n} to {new_n}.",
        )

    # 9. version changed — administrative update
    if field_path == "version":
        return (
            "low",
            f"WAF ruleset version updated from {old_value!r} to {new_value!r}. "
            "This is recorded on every ruleset modification.",
        )

    # 10. phase or kind changed — structural change
    if field_path in ("phase", "kind"):
        return (
            "medium",
            f"WAF ruleset {field_path} changed from {old_value!r} to {new_value!r}. "
            "Review to confirm this reflects an intentional restructuring.",
        )

    return (
        "low",
        "WAF ruleset metadata updated — no high-risk field changes detected.",
    )
