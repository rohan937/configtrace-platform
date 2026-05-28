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

# ── M59.5 — Additional Cloudflare surfaces ────────────────────────────────────
# Zone-level edge settings (SSL mode, min TLS, HSTS, Always Use HTTPS, etc.).
# One record per monitored setting, keyed by ``setting_id``.
CLOUDFLARE_ZONE_SETTING = "cloudflare_zone_setting"

# Legacy page-rule / redirect-rule / cache-rule entries.  One record per rule.
# SECURITY: only URL pattern + action summary are stored; raw rule expressions
# that may encode sensitive paths are NEVER stored in full.
CLOUDFLARE_PAGE_RULE = "cloudflare_page_rule"

# Worker route binding — maps an incoming URL pattern to a worker script.
# One record per route.
CLOUDFLARE_WORKER_ROUTE = "cloudflare_worker_route"

# Worker script metadata.  Source code is NEVER stored — only the etag/hash,
# env var key count, and binding count.
CLOUDFLARE_WORKER_SCRIPT = "cloudflare_worker_script"

# Cloudflare Access application — protects an internal app behind Zero Trust.
# One record per application.
CLOUDFLARE_ACCESS_APPLICATION = "cloudflare_access_application"

# Cloudflare Access policy — one per policy attached to an application.
# SECURITY: include/exclude/require lists are stored as COUNTS only; raw
# email patterns or IdP IDs are NEVER stored in full.
CLOUDFLARE_ACCESS_POLICY = "cloudflare_access_policy"

# Individual WAF/firewall rule (within a ruleset).  Distinct from
# CLOUDFLARE_RULESET which carries aggregate counts only.
# SECURITY: rule expression strings are NEVER stored — only the rule id,
# description, action, and enabled state.
CLOUDFLARE_WAF_RULE = "cloudflare_waf_rule"


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


# ── M59.5 — TypedDicts for new surfaces ───────────────────────────────────────


class CloudflareZoneSetting(TypedDict, total=False):
    """Normalised Cloudflare zone-level setting.

    Examples
    --------
    * ``setting_id="ssl"`` with ``value="full"`` / ``"strict"`` / ``"flexible"`` / ``"off"``
    * ``setting_id="always_use_https"`` with ``value="on"`` / ``"off"``
    * ``setting_id="min_tls_version"`` with ``value="1.0"`` / ``"1.1"`` / ``"1.2"`` / ``"1.3"``
    * ``setting_id="security_header"`` with a small dict value containing
      ``enabled``, ``max_age``, ``include_subdomains``, ``preload`` for HSTS.
    * ``setting_id="browser_check"`` / ``"security_level"`` / etc.

    Security
    --------
    Only the setting id + safe-to-display value are stored.  No tokens,
    no rule expressions, no customer data.
    """

    record_type: str             # always "cloudflare_zone_setting"
    record_id: str               # same as setting_id
    setting_id: str              # e.g. "ssl", "min_tls_version", "always_use_https"
    value: object                # str | bool | dict — depends on setting
    editable: bool
    modified_on: Optional[str]


class CloudflarePageRule(TypedDict, total=False):
    """Normalised page / redirect / cache rule.

    Security
    --------
    Only the URL pattern and a short ``actions_summary`` string are stored.
    Raw rule expressions that may encode sensitive customer paths are NOT
    persisted.
    """

    record_type: str             # always "cloudflare_page_rule"
    record_id: str               # Cloudflare rule id
    target_url_pattern: str      # e.g. "example.com/admin/*"
    actions_summary: str         # e.g. "forwarding_url:to=https://new.com,302"
    rule_kind: str               # "page_rule" | "redirect" | "cache_rule"
    priority: int
    status: str                  # "active" | "disabled"
    modified_on: Optional[str]


class CloudflareWorkerRoute(TypedDict, total=False):
    """Normalised worker route binding.

    Maps an incoming URL pattern to a worker script.  ``script_name`` is the
    short name of the worker; the script's source code is NEVER stored here.
    """

    record_type: str             # always "cloudflare_worker_route"
    record_id: str               # Cloudflare route id
    pattern: str                 # e.g. "example.com/api/*"
    script_name: str             # worker script name
    enabled: bool
    modified_on: Optional[str]


class CloudflareWorkerScript(TypedDict, total=False):
    """Normalised worker script metadata.

    Security
    --------
    The script source is NEVER fetched or stored.  Only the etag (script hash)
    plus the COUNT of env var bindings and KV/D1/R2/etc. bindings.  Env var
    values are NEVER stored — value changes are inferred from etag changes.
    """

    record_type: str             # always "cloudflare_worker_script"
    record_id: str               # script_name (unique per zone)
    script_name: str
    script_etag: str             # opaque content hash from Cloudflare
    env_var_count: int           # number of plain-text + secret env var bindings
    binding_count: int           # total bindings (KV, D1, R2, queues, etc.)
    modified_on: Optional[str]


class CloudflareAccessApplication(TypedDict, total=False):
    """Normalised Cloudflare Access (Zero Trust) application.

    Security
    --------
    Only enabled/visibility/type and aggregate identity-provider counts are
    stored.  No IdP credentials, OAuth client secrets, or service-token
    material is ever fetched or stored.
    """

    record_type: str             # always "cloudflare_access_application"
    record_id: str               # Cloudflare application id
    name: str
    type: str                    # "self_hosted" | "saas" | "ssh" | "vnc" | ...
    domain: str                  # protected hostname (e.g. "admin.example.com")
    visibility: str              # "private" | "public"
    enabled: bool
    session_duration: str        # e.g. "24h"
    allowed_idps_count: int
    modified_on: Optional[str]


class CloudflareAccessPolicy(TypedDict, total=False):
    """Normalised Cloudflare Access policy.

    Security
    --------
    include/exclude/require lists are stored as COUNTS only.  Raw email
    addresses, group IDs, and country codes are NOT persisted.
    """

    record_type: str             # always "cloudflare_access_policy"
    record_id: str               # Cloudflare policy id
    application_id: str          # parent application
    name: str
    decision: str                # "allow" | "deny" | "non_identity" | "bypass"
    enabled: bool
    precedence: int
    include_count: int
    exclude_count: int
    require_count: int
    modified_on: Optional[str]


class CloudflareWAFRule(TypedDict, total=False):
    """Normalised individual WAF/firewall rule.

    Distinct from :class:`CloudflareRuleset` which carries aggregate counts.
    One record per rule.

    Security
    --------
    The raw rule expression string (which may encode sensitive customer paths
    or matching logic) is NEVER stored.  Only the rule id, short description,
    action, and enabled state are persisted.
    """

    record_type: str             # always "cloudflare_waf_rule"
    record_id: str               # Cloudflare rule id
    ruleset_id: str              # parent ruleset id
    description: str             # short human-readable label
    action: str                  # "block" | "challenge" | "managed_challenge" |
                                  # "allow" | "skip" | "log" | "js_challenge"
    enabled: bool
    expression_hash: str         # hash of the rule expression (NEVER the text)
    modified_on: Optional[str]
