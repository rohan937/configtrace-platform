"""Normalised schema for Cloudflare DNS records and WAF rulesets.

``CloudflareDNSRecord`` is ConfigTrace's canonical representation of a single
Cloudflare DNS record.  Instances of this dict are stored verbatim inside
``Snapshot.state`` (a JSONB array) and are keyed by ``record_id`` when the
diff service compares two consecutive snapshots.

``CloudflareRuleset`` is ConfigTrace's canonical representation of a single
Cloudflare WAF ruleset.  Ruleset records track zone-level WAF posture changes
(managed rule enablement, action overrides, rule counts) without storing raw
rule expressions (which may contain sensitive host/path patterns).

Field mapping from the raw Cloudflare API response
---------------------------------------------------
    ``id``    → ``record_id``
    ``type``  → ``record_type``
    All other fields map directly.
"""

from __future__ import annotations

from typing import List, Optional

try:
    from typing import TypedDict
except ImportError:  # Python < 3.8 — not expected in this project
    from typing_extensions import TypedDict  # type: ignore[assignment]

# ── Record-type constants ─────────────────────────────────────────────────────

# DNS record type (legacy bare strings or explicit prefix)
CLOUDFLARE_DNS_RECORD = "cloudflare_dns_record"

# WAF/firewall ruleset record — one per ruleset visible to the zone token.
# SECURITY: raw rule expressions are NEVER stored.
CLOUDFLARE_RULESET = "cloudflare_ruleset"


class CloudflareDNSRecord(TypedDict):
    """Normalised Cloudflare DNS record stored in ``Snapshot.state``.

    This TypedDict is the authoritative schema for Cloudflare records in
    ConfigTrace.  Do not rename or remove fields once records have been
    written to the database — doing so constitutes a breaking schema change
    that requires a migration plan.

    Fields
    ------
    record_id
        Cloudflare's stable unique identifier for this record (hex string).
        Used as the join key by the diff service.
    record_type
        DNS record type (e.g. ``"A"``, ``"AAAA"``, ``"CNAME"``, ``"MX"``).
    name
        Fully-qualified domain name for the record (e.g. ``"api.example.com"``).
    content
        Record value — an IP address for A/AAAA, a hostname for CNAME/MX, etc.
    ttl
        Time-to-live in seconds.  Cloudflare uses ``1`` to mean "automatic"
        (proxied records always have ``ttl=1``).
    proxied
        ``True`` if the record is proxied through Cloudflare (orange cloud).
    priority
        Numeric priority for MX and SRV records.  ``None`` for all other types.
    comment
        Optional user-supplied comment string.  ``None`` if not set.
    modified_on
        ISO 8601 timestamp of the last modification, as returned by Cloudflare.
    """

    record_id: str
    record_type: str
    name: str
    content: str
    ttl: int
    proxied: bool
    priority: Optional[int]
    comment: Optional[str]
    modified_on: str


class CloudflareRuleset(TypedDict):
    """Normalised Cloudflare WAF ruleset record stored in ``Snapshot.state``.

    One record is created per ruleset returned by
    ``GET /zones/{zone_id}/rulesets``.  Only security-relevant aggregate
    metadata is stored; raw rule expressions (which may contain sensitive
    host/path patterns) are NEVER fetched or stored.

    Fields
    ------
    record_type
        Always ``"cloudflare_ruleset"``.
    record_id
        Cloudflare's stable unique ruleset ID (UUID-like hex string).
    name
        Human-readable ruleset name (e.g. ``"Cloudflare Managed Ruleset"``).
    kind
        Ruleset kind: ``"managed"``, ``"zone"``, ``"root"``, or ``"custom"``.
    phase
        WAF processing phase (e.g. ``"http_request_firewall_managed"``,
        ``"http_request_firewall_custom"``).
    version
        Ruleset version string — increments on every modification.
    rule_count
        Total number of rules in the ruleset.
    enabled_rule_count
        Rules with ``enabled: true``.  Disabled rules have no traffic effect.
    block_count
        Rules whose default action is ``block``.
    log_count
        Rules whose default action is ``log``.
    skip_count
        Rules whose default action is ``skip`` (bypass WAF).
    challenge_count
        Rules whose action is ``challenge`` or ``js_challenge``.
    managed_challenge_count
        Rules whose action is ``managed_challenge``.
    execute_count
        Rules whose action is ``execute`` (deploys a managed ruleset).
    last_updated
        ISO 8601 timestamp from Cloudflare of the most recent ruleset update.
    """

    record_type: str          # always "cloudflare_ruleset"
    record_id: str            # Cloudflare ruleset ID
    name: str
    kind: str
    phase: str
    version: str
    rule_count: int
    enabled_rule_count: int
    block_count: int
    log_count: int
    skip_count: int
    challenge_count: int
    managed_challenge_count: int
    execute_count: int
    last_updated: Optional[str]
