"""Cloudflare DNS risk rules — Milestone 10.

Classifies a Change (ORM object or plain dict) into one of four risk levels:
    critical  — changes that can take services completely offline
    high      — changes likely to disrupt traffic or degrade service
    medium    — changes that alter behaviour but are generally reversible
    low       — cosmetic or low-impact changes

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

* Rule order matters: more-specific / higher-severity rules are evaluated first
  so they short-circuit before falling through to generic catch-alls.

* The final ``return ("low", "No specific...")`` is the universal default.
  It is also the catch-all for any record type not explicitly covered above.
"""

from __future__ import annotations

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
# DNS risk classifier
# ─────────────────────────────────────────────────────────────────────────────

def classify_dns_change(change: Any) -> tuple[str, str]:
    """Classify a Cloudflare DNS change and return ``(risk_level, risk_reason)``.

    Accepts either a SQLAlchemy ``Change`` ORM object or a plain ``dict``
    (e.g. from unit tests).

    Risk levels
    -----------
    ``critical``  changes that can take services completely offline
    ``high``      changes likely to disrupt traffic or degrade service
    ``medium``    changes that alter behaviour but are generally reversible
    ``low``       cosmetic or low-impact changes

    Rule evaluation order
    ---------------------
    Rules are ordered from most-severe to least-severe.  The first matching
    rule short-circuits the remaining checks.

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

    # ── Fallback: extract record_type / record_name from the full record dict
    # stored in prev_value (removed) or new_value (added) when provider_metadata
    # is incomplete.  This covers edge cases in unit tests and future providers.
    if change_type == "removed" and isinstance(prev_value, dict):
        if not record_type:
            record_type = (prev_value.get("record_type") or "").upper()
        if not record_name:
            record_name = prev_value.get("name") or ""

    if change_type == "added" and isinstance(new_value, dict):
        if not record_type:
            record_type = (new_value.get("record_type") or "").upper()
        if not record_name:
            record_name = new_value.get("name") or ""

    is_apex = is_apex_or_root_record(record_name, zone_name)

    # ══════════════════════════════════════════════════════════════════════════
    # CRITICAL rules
    # ══════════════════════════════════════════════════════════════════════════

    # Deletion of an apex A / AAAA / CNAME record — can take the entire domain
    # offline because there is nothing left to resolve.
    if change_type == "removed" and record_type in ("A", "AAAA", "CNAME"):
        if is_apex:
            return (
                "critical",
                f"Deletion of an apex {record_type} record disrupts DNS resolution "
                "for the root domain and can take all services offline.",
            )

    # Deletion of any MX record — stops email delivery for the domain.
    if change_type == "removed" and record_type == "MX":
        return (
            "critical",
            "Deletion of an MX record stops email delivery for the domain.",
        )

    # Modification of NS or SOA — changes nameserver delegation.
    if change_type == "modified" and record_type in ("NS", "SOA"):
        return (
            "critical",
            f"Modification of an {record_type} record changes nameserver delegation "
            "and can disrupt all DNS resolution for the domain.",
        )

    # ══════════════════════════════════════════════════════════════════════════
    # HIGH rules
    # ══════════════════════════════════════════════════════════════════════════

    # Any other record deletion — removes a configured entry, may disrupt
    # dependent services.
    if change_type == "removed":
        return (
            "high",
            f"Deletion of a {record_type or 'DNS'} record removes a configured DNS "
            "entry and may disrupt dependent services.",
        )

    # CNAME or MX content change — redirects traffic or mail to a different target.
    if change_type == "modified" and field_path == "content" and record_type in ("CNAME", "MX"):
        return (
            "high",
            f"Modification of the {record_type} target changes where traffic or mail "
            "is directed.",
        )

    # MX priority change — affects mail server selection order.
    if change_type == "modified" and field_path == "priority" and record_type == "MX":
        return (
            "high",
            "Modification of MX priority affects the order in which mail servers are "
            "tried and can disrupt email delivery.",
        )

    # Proxy disabled — exposes origin IP, removes DDoS protection.
    if change_type == "modified" and field_path == "proxied":
        if prev_value is True and new_value is False:
            return (
                "high",
                "Disabling Cloudflare proxy exposes the origin server IP address "
                "directly to the internet, removing DDoS protection and masking.",
            )

    # Very short TTL — shrinks the rollback window after a bad change.
    if change_type == "modified" and field_path == "ttl":
        if isinstance(new_value, (int, float)) and new_value <= 60:
            return (
                "high",
                f"TTL reduced to {new_value} second(s). Very short TTLs shrink the "
                "rollback window if a bad change needs to be reverted.",
            )

    # ══════════════════════════════════════════════════════════════════════════
    # MEDIUM rules
    # ══════════════════════════════════════════════════════════════════════════

    # Proxy enabled — changes performance/protection characteristics.
    if change_type == "modified" and field_path == "proxied":
        if prev_value is False and new_value is True:
            return (
                "medium",
                "Enabling Cloudflare proxy routes traffic through Cloudflare's "
                "network, changing performance characteristics and adding protection.",
            )

    # TTL change (non-critical range) — affects caching duration.
    if change_type == "modified" and field_path == "ttl":
        return (
            "medium",
            f"TTL changed to {new_value} seconds. DNS resolvers will cache this "
            "record for the new duration.",
        )

    # TXT record content change — may affect SPF/DKIM/DMARC.
    if change_type == "modified" and field_path == "content" and record_type == "TXT":
        return (
            "medium",
            "Modification of a TXT record value may affect SPF, DKIM, DMARC, or "
            "other verification mechanisms.",
        )

    # New subdomain A / AAAA record — creates a new DNS entry point.
    if change_type == "added" and record_type in ("A", "AAAA"):
        if not is_apex:
            return (
                "medium",
                f"Addition of a new subdomain {record_type} record creates a new "
                "DNS entry point that was not previously configured.",
            )

    # ══════════════════════════════════════════════════════════════════════════
    # LOW rules
    # ══════════════════════════════════════════════════════════════════════════

    # Comment change — zero DNS impact.
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
