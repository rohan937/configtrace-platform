"""Cloudflare security exposure rules — M60.4.3.

Every rule fires only on explicit, reliable normalized fields produced by the
Cloudflare connector (app/connectors/cloudflare.py + cloudflare_schema.py).
Evidence is metadata-only: zone setting ids/values, DNS name/type/content/proxied,
WAF rule id/description/action/enabled. No tokens, origin credentials, raw rule
expressions, or customer data are ever read.

Language is deliberately careful ("may weaken", "could reduce protection") —
these are configuration-posture exposures, not proven compromises.

Record types consumed
---------------------
- ``cloudflare_zone_setting`` → weak SSL mode / Always-HTTPS off / weak min-TLS /
  low security level / development mode on / HSTS disabled
- ``cloudflare_waf_rule``     → a protective WAF rule explicitly disabled
- ``cloudflare_page_rule``    → a rule that forwards to a plain-HTTP destination
- ``cloudflare_access_application`` → an Access application explicitly disabled
- DNS records (``record_type`` is the DNS type, e.g. "A"/"AAAA") → A/AAAA record
  whose content is a private/loopback/reserved IP

Deferred Cloudflare rules (intentionally NOT implemented — see report)
---------------------------------------------------------------------
* Unproxied DNS for "sensitive" hostnames: requires subjective keyword guessing
  on the hostname, and unproxied records are frequently intentional (MX, TXT,
  mail, domain verification, third-party CNAME targets). Too noisy/unreliable.
* "WAF missing": absence cannot be inferred — no ruleset record does not mean no
  protection. We only flag an explicitly-disabled protective rule.
* Ruleset-level ``enabled_rule_count == 0``: ambiguous (a ruleset can be staged);
  the per-rule ``cloudflare_waf_rule.enabled`` flag is the precise signal used.
* ``automatic_https_rewrites`` / ``browser_check`` off: low-signal common
  settings; deferred to avoid noise.
* Page Rule enabled/disabled, cache/security actions other than plain-HTTP
  forwarding: too subjective/noisy for a static rule — most disabled Page
  Rules are paused business logic, not a security control being removed.
* Worker route / Worker script Findings: no static field on either record
  represents an unambiguous risky posture — mere existence, a pattern, or a
  script-content hash carry no reliable security signal on their own. Both
  remain Change-only (see cloudflare_change_classification_matrix.md).
* Access application "visibility" (App Launcher listing) and
  "allowed_idps_count == 0": visibility only controls App Launcher tile
  listing, not authentication gating (see risk_rules/cloudflare.py's
  ``_classify_access_application`` docstring note) — not a security signal
  at all. A zero IdP count is ambiguous (may indicate a service-token-only
  or bypass-only app) — deferred to avoid false positives.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from app.connectors.cloudflare_schema import (
    CLOUDFLARE_ACCESS_APPLICATION,
    CLOUDFLARE_ACCESS_POLICY,
    CLOUDFLARE_PAGE_RULE,
    CLOUDFLARE_WAF_RULE,
    CLOUDFLARE_ZONE_SETTING,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule keys ────────────────────────────────────────────────────────────────
_RULE_SSL_WEAK = "cloudflare_ssl_mode_weak"
_RULE_ALWAYS_HTTPS_OFF = "cloudflare_always_https_off"
_RULE_MIN_TLS_WEAK = "cloudflare_min_tls_weak"
_RULE_SECURITY_LEVEL_LOW = "cloudflare_security_level_low"
_RULE_DEV_MODE_ON = "cloudflare_development_mode_on"
_RULE_HSTS_DISABLED = "cloudflare_hsts_disabled"
_RULE_WAF_RULE_DISABLED = "cloudflare_waf_rule_disabled"
_RULE_DNS_PRIVATE_ORIGIN = "cloudflare_dns_private_origin"
# M68.3 — Access policy rules (data-backed: decision + enabled, counts only).
_RULE_ACCESS_POLICY_BYPASS = "cloudflare_access_policy_bypass"
_RULE_ACCESS_POLICY_DISABLED = "cloudflare_access_policy_disabled"
# Change-classification-QA pass — two new high-signal, low-noise static rules.
_RULE_PAGE_RULE_HTTP_FORWARD = "cloudflare_page_rule_http_forward"
_RULE_ACCESS_APPLICATION_DISABLED = "cloudflare_access_application_disabled"

# DNS record types whose content is an IP address (for the private-origin rule).
_IP_DNS_TYPES = {"A", "AAAA"}

# WAF actions that actually provide protection (a disabled one is a real loss).
_PROTECTIVE_WAF_ACTIONS = {"block", "challenge", "js_challenge", "managed_challenge"}


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Dispatch a normalized Cloudflare record to the relevant rule(s)."""
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == CLOUDFLARE_ZONE_SETTING:
        return _eval_zone_setting(record)
    if rtype == CLOUDFLARE_WAF_RULE:
        return _eval_waf_rule(record)
    if rtype == CLOUDFLARE_ACCESS_POLICY:
        return _eval_access_policy(record)
    if rtype == CLOUDFLARE_PAGE_RULE:
        return _eval_page_rule(record)
    if rtype == CLOUDFLARE_ACCESS_APPLICATION:
        return _eval_access_application(record)
    if rtype in _IP_DNS_TYPES:
        return _eval_dns_record(record)
    return []


# ── Zone settings ────────────────────────────────────────────────────────────


def _eval_zone_setting(record: dict[str, Any]) -> list[FindingCandidate]:
    setting_id = get_str(record, "setting_id")
    value = record.get("value")
    record_id = get_str(record, "record_id") or setting_id or None

    def cand(rule: str, severity: str, title: str, desc: str, ev: dict) -> FindingCandidate:
        return FindingCandidate(
            provider="cloudflare",
            rule_key=rule,
            finding_key=make_finding_key(rule, record_id),
            severity=severity,
            title=title,
            description=desc,
            evidence={"rule": rule, "setting": setting_id, **ev},
            remediation={"summary": title + ".", "steps": []},
            record_id=record_id,
        )

    if setting_id == "ssl":
        v = str(value).lower() if isinstance(value, str) else ""
        if v in ("off", "flexible"):
            severity = "high"
            c = cand(
                _RULE_SSL_WEAK,
                severity,
                "Cloudflare SSL/TLS mode is weak",
                (
                    f"The zone SSL/TLS mode is '{v}'. "
                    + (
                        "'off' disables encryption entirely. "
                        if v == "off"
                        else "'flexible' leaves the Cloudflare-to-origin hop unencrypted. "
                    )
                    + "Traffic to the origin may be sent in cleartext."
                ),
                {"value": v},
            )
            c.remediation["steps"] = [
                "Set SSL/TLS mode to 'Full (strict)'.",
                "Install a valid origin certificate if needed.",
            ]
            return [c]
        return []

    if setting_id == "always_use_https":
        if str(value).lower() == "off":
            c = cand(
                _RULE_ALWAYS_HTTPS_OFF,
                "medium",
                "Cloudflare 'Always Use HTTPS' is disabled",
                (
                    "'Always Use HTTPS' is off, so plain-HTTP requests are not "
                    "redirected to HTTPS. Visitors may transmit data over an "
                    "unencrypted connection."
                ),
                {"value": "off"},
            )
            c.remediation["steps"] = ["Enable 'Always Use HTTPS' for the zone."]
            return [c]
        return []

    if setting_id == "min_tls_version":
        v = str(value)
        if v in ("1.0", "1.1"):
            c = cand(
                _RULE_MIN_TLS_WEAK,
                "medium",
                "Cloudflare minimum TLS version is outdated",
                (
                    f"The minimum TLS version is {v}. TLS 1.0/1.1 are deprecated "
                    f"and may weaken transport security."
                ),
                {"value": v},
            )
            c.remediation["steps"] = ["Set the minimum TLS version to 1.2 or higher."]
            return [c]
        return []

    if setting_id == "security_level":
        v = str(value).lower() if isinstance(value, str) else ""
        if v in ("off", "essentially_off"):
            c = cand(
                _RULE_SECURITY_LEVEL_LOW,
                "medium",
                "Cloudflare security level is effectively off",
                (
                    f"The zone security level is '{v}', so Cloudflare applies "
                    f"little or no challenge to suspicious traffic."
                ),
                {"value": v},
            )
            c.remediation["steps"] = ["Raise the security level to at least 'Medium'."]
            return [c]
        return []

    if setting_id == "development_mode":
        if str(value).lower() == "on":
            c = cand(
                _RULE_DEV_MODE_ON,
                "medium",
                "Cloudflare development mode is enabled",
                (
                    "Development mode is on, which bypasses Cloudflare's edge "
                    "cache and some optimizations. It is meant to be temporary "
                    "and may reduce protection while active."
                ),
                {"value": "on"},
            )
            c.remediation["steps"] = ["Turn off development mode when finished."]
            return [c]
        return []

    if setting_id == "security_header":
        # HSTS. Cloudflare returns a dict; the enabled flag may be nested under
        # 'strict_transport_security'. Only flag an EXPLICIT enabled=False.
        hsts = _extract_hsts(value)
        if hsts is False:
            c = cand(
                _RULE_HSTS_DISABLED,
                "medium",
                "Cloudflare HSTS is disabled",
                (
                    "HTTP Strict Transport Security (HSTS) is disabled. Browsers "
                    "are not instructed to use HTTPS, which could allow protocol "
                    "downgrade on first contact."
                ),
                {"hsts_enabled": False},
            )
            c.remediation["steps"] = [
                "Enable HSTS with a reasonable max-age once HTTPS is verified.",
            ]
            return [c]
        return []

    return []


def _extract_hsts(value: Any) -> bool | None:
    """Return the HSTS enabled boolean, or None if not determinable."""
    if not isinstance(value, dict):
        return None
    inner = value.get("strict_transport_security")
    if isinstance(inner, dict) and "enabled" in inner:
        return bool(inner["enabled"])
    if "enabled" in value:
        return bool(value["enabled"])
    return None


# ── WAF rule explicitly disabled ─────────────────────────────────────────────


def _eval_waf_rule(record: dict[str, Any]) -> list[FindingCandidate]:
    # Require the explicit enabled flag; ignore malformed records.
    if "enabled" not in record:
        return []
    if record.get("enabled") is not False:
        return []
    action = get_str(record, "action").lower()
    # Only a disabled PROTECTIVE rule is a real loss (a disabled log/skip is not).
    if action not in _PROTECTIVE_WAF_ACTIONS:
        return []

    record_id = get_str(record, "record_id") or None
    description = get_str(record, "description") or "a WAF rule"
    severity = "high" if action == "block" else "medium"

    return [
        FindingCandidate(
            provider="cloudflare",
            rule_key=_RULE_WAF_RULE_DISABLED,
            finding_key=make_finding_key(_RULE_WAF_RULE_DISABLED, record_id),
            severity=severity,
            title="Cloudflare WAF rule is disabled",
            description=(
                f"A WAF rule ('{description}') with a protective '{action}' "
                f"action is disabled, so it no longer blocks or challenges "
                f"matching traffic. This could reduce protection."
            ),
            evidence={
                "rule": _RULE_WAF_RULE_DISABLED,
                "description": description,
                "action": action,
                "enabled": False,
                "ruleset_id": get_str(record, "ruleset_id"),
            },
            remediation={
                "summary": "Re-enable the WAF rule if it should be active.",
                "steps": [
                    "Confirm whether the rule was disabled intentionally.",
                    "Re-enable it, or document why it is intentionally off.",
                ],
            },
            record_id=record_id,
        )
    ]


# ── Access policy risks (M68.3) ──────────────────────────────────────────────
#
# Only fields the connector already exposes are used (decision + enabled). The
# raw include/exclude/require lists are NEVER fetched (only counts), so an
# "everyone allowed" rule cannot be inferred — that is intentionally DEFERRED to
# avoid faking findings from data we do not have.


def _eval_access_policy(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or None
    name = get_str(record, "name") or "an Access policy"
    decision = get_str(record, "decision").lower()
    app_id = get_str(record, "application_id")
    out: list[FindingCandidate] = []

    # A "bypass" decision lets matching requests skip Cloudflare Access identity
    # verification entirely — a precise, reliable risk signal.
    if decision == "bypass":
        out.append(
            FindingCandidate(
                provider="cloudflare",
                rule_key=_RULE_ACCESS_POLICY_BYPASS,
                finding_key=make_finding_key(_RULE_ACCESS_POLICY_BYPASS, record_id),
                severity="high",
                title="Cloudflare Access policy uses a bypass decision",
                description=(
                    f"The Access policy '{name}' has a 'bypass' decision, so matching "
                    f"requests skip Cloudflare Access identity verification. This may "
                    f"reduce protection for the application."
                ),
                evidence={
                    "rule": _RULE_ACCESS_POLICY_BYPASS,
                    "policy_name": name,
                    "decision": decision,
                    "application_id": app_id,
                },
                remediation={
                    "summary": "Review the Access bypass policy.",
                    "steps": [
                        "Confirm the bypass is intentional and tightly scoped.",
                        "Replace a broad bypass with an explicit allow/require policy.",
                    ],
                },
                record_id=record_id,
            )
        )

    # An explicitly-disabled Access policy no longer enforces its controls.
    if record.get("enabled") is False:
        out.append(
            FindingCandidate(
                provider="cloudflare",
                rule_key=_RULE_ACCESS_POLICY_DISABLED,
                finding_key=make_finding_key(_RULE_ACCESS_POLICY_DISABLED, record_id),
                severity="medium",
                title="Cloudflare Access policy is disabled",
                description=(
                    f"The Access policy '{name}' is disabled, so its access controls "
                    f"are not currently enforced. This could reduce protection for the "
                    f"application."
                ),
                evidence={
                    "rule": _RULE_ACCESS_POLICY_DISABLED,
                    "policy_name": name,
                    "enabled": False,
                    "application_id": app_id,
                },
                remediation={
                    "summary": "Re-enable the Access policy if it should be active.",
                    "steps": [
                        "Confirm whether the policy was disabled intentionally.",
                        "Re-enable it, or document why it is intentionally off.",
                    ],
                },
                record_id=record_id,
            )
        )
    return out


# ── Page Rule forwarding to plain HTTP ────────────────────────────────────────


def _eval_page_rule(record: dict[str, Any]) -> list[FindingCandidate]:
    """A Page Rule that forwards to an explicit plain-HTTP destination.

    High-signal, low-noise: ``actions_summary`` stores the redirect target
    reduced to ``scheme://host`` (see connector's ``_safe_redirect_target``),
    so ``to=http://...`` is a direct, unambiguous static fact — never an
    inference. Every other Page Rule posture (enabled/disabled, cache
    behaviour, priority) remains Change-only — see this module's docstring.
    """
    actions_summary = get_str(record, "actions_summary")
    if "forwarding_url" not in actions_summary or "to=http://" not in actions_summary:
        return []
    record_id = get_str(record, "record_id") or None
    pattern = get_str(record, "target_url_pattern") or "a hostname"

    return [
        FindingCandidate(
            provider="cloudflare",
            rule_key=_RULE_PAGE_RULE_HTTP_FORWARD,
            finding_key=make_finding_key(_RULE_PAGE_RULE_HTTP_FORWARD, record_id),
            severity="medium",
            title="Cloudflare Page Rule forwards to a plain-HTTP destination",
            description=(
                f"A Page Rule for '{pattern}' forwards matching requests to a "
                f"plain-HTTP destination. Forwarded traffic may transit "
                f"unencrypted after leaving Cloudflare. This is evidence for "
                f"review and does not confirm traffic interception or data "
                f"exposure."
            ),
            evidence={
                "rule": _RULE_PAGE_RULE_HTTP_FORWARD,
                "target_url_pattern": pattern,
            },
            remediation={
                "summary": "Update the forwarding destination to use HTTPS.",
                "steps": [
                    "Edit the Page Rule's forwarding URL action to an https:// destination.",
                    "Confirm the destination server supports HTTPS.",
                ],
            },
            record_id=record_id,
        )
    ]


# ── Access application explicitly disabled ───────────────────────────────────


def _eval_access_application(record: dict[str, Any]) -> list[FindingCandidate]:
    """An Access application with its authentication barrier disabled.

    High-signal, low-noise: ``enabled`` is an explicit boolean the connector
    already normalizes directly from Cloudflare's API — an explicit False
    means Access no longer gates this app at all. Other Access-application
    fields (visibility, allowed_idps_count, session_duration) are
    intentionally NOT used for a static rule — see this module's docstring.
    """
    if record.get("enabled") is not False:
        return []
    record_id = get_str(record, "record_id") or None
    name = get_str(record, "name") or get_str(record, "domain") or "an Access application"

    return [
        FindingCandidate(
            provider="cloudflare",
            rule_key=_RULE_ACCESS_APPLICATION_DISABLED,
            finding_key=make_finding_key(_RULE_ACCESS_APPLICATION_DISABLED, record_id),
            severity="high",
            title="Cloudflare Access application is disabled",
            description=(
                f"The Cloudflare Access application '{name}' is disabled, so "
                f"its authentication barrier is not currently enforced. This "
                f"is evidence for review and does not confirm unauthorized "
                f"access or compromise."
            ),
            evidence={
                "rule": _RULE_ACCESS_APPLICATION_DISABLED,
                "name": name,
                "enabled": False,
            },
            remediation={
                "summary": "Re-enable the Access application if it should be protected.",
                "steps": [
                    "Confirm whether the application was disabled intentionally.",
                    "Re-enable it, or document why it is intentionally off.",
                ],
            },
            record_id=record_id,
        )
    ]


# ── DNS A/AAAA pointing at a private/reserved IP ─────────────────────────────


def _eval_dns_record(record: dict[str, Any]) -> list[FindingCandidate]:
    content = get_str(record, "content").strip()
    if not content:
        return []
    try:
        ip = ipaddress.ip_address(content)
    except ValueError:
        return []  # not an IP literal → ignore safely

    # Public/global addresses are normal; only non-routable targets are flagged.
    if not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return []

    record_id = get_str(record, "record_id") or None
    name = get_str(record, "name") or "a DNS record"
    dns_type = get_str(record, "record_type")
    proxied = bool(record.get("proxied", False))

    kind = (
        "loopback"
        if ip.is_loopback
        else "private"
        if ip.is_private
        else "reserved/non-routable"
    )

    return [
        FindingCandidate(
            provider="cloudflare",
            rule_key=_RULE_DNS_PRIVATE_ORIGIN,
            finding_key=make_finding_key(_RULE_DNS_PRIVATE_ORIGIN, record_id),
            severity="high",
            title="Cloudflare DNS record points to a private or reserved IP",
            description=(
                f"The public DNS record '{name}' ({dns_type}) resolves to a "
                f"{kind} address ({content}). This is usually a misconfiguration "
                f"that may break routing or leak internal network details."
            ),
            evidence={
                "rule": _RULE_DNS_PRIVATE_ORIGIN,
                "name": name,
                "dns_type": dns_type,
                "content": content,
                "address_kind": kind,
                "proxied": proxied,
            },
            remediation={
                "summary": "Point the record at the correct public address or remove it.",
                "steps": [
                    "Verify the intended origin IP for this hostname.",
                    "Replace the private/reserved IP with the correct public IP.",
                    "Remove the record if it is no longer needed.",
                ],
            },
            record_id=record_id,
        )
    ]
