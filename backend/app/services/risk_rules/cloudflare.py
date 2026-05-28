"""Cloudflare risk rules for non-DNS surfaces — M59.5.

This module classifies changes for Cloudflare record types beyond the
DNS-record / WAF-ruleset summaries already handled in
:mod:`cloudflare_dns`.  Supported record types:

    cloudflare_zone_setting       — SSL/TLS, Always Use HTTPS, min TLS, HSTS,
                                    browser integrity, security level, …
    cloudflare_page_rule          — Page Rules / Redirect Rules / Cache Rules
    cloudflare_worker_route       — Worker route bindings
    cloudflare_worker_script      — Worker script metadata
    cloudflare_access_application — Cloudflare Access (Zero Trust) applications
    cloudflare_access_policy      — Cloudflare Access policies
    cloudflare_waf_rule           — Individual WAF rule (within a ruleset)

Wording policy
--------------
All risk reasons use hedged language: "may weaken", "could affect",
"may route", "may expose".  No "definitely down" / "guaranteed outage" /
"compromised" wording.  No raw rule expressions, tokens, secrets,
worker source, or webhook URLs appear in any reason.

Unknown subtype + malformed metadata
------------------------------------
``classify_cloudflare_change`` short-circuits to a safe Low / generic
reason on unknown subtypes and ``isinstance(pm, dict)``-guards every
metadata read so that a non-dict ``provider_metadata`` cannot crash the
dispatcher.
"""

from __future__ import annotations

import re
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Attribute-access helper (dicts + ORM objects)
# ─────────────────────────────────────────────────────────────────────────────


def _get(obj: Any, key: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _str(v: Any) -> str:
    return str(v) if v is not None else ""


# ─────────────────────────────────────────────────────────────────────────────
# Production-hostname / known-domain heuristics
# ─────────────────────────────────────────────────────────────────────────────

#: Subdomain labels that almost always serve production traffic.  Same set
#: used by the DNS classifier; duplicated here to avoid cross-module imports
#: that would create a circular dependency if cloudflare_dns ever needs to
#: call into this module.
_CRITICAL_SUBDOMAINS: frozenset[str] = frozenset({
    "www", "app", "api", "auth", "login", "dashboard", "admin",
    "checkout", "payment", "payments", "billing", "mail", "smtp",
    "cdn", "assets", "static",
})


def _hostname_from_url_or_pattern(pattern_or_url: str) -> str:
    """Extract a hostname from a URL or wildcard pattern.

    Accepts forms like:
      * ``https://api.example.com/path``
      * ``api.example.com/admin/*``
      * ``*.example.com/*``
      * ``example.com``
    """
    s = (pattern_or_url or "").strip()
    if not s:
        return ""
    # Strip scheme.
    s = re.sub(r"^[a-z]+://", "", s, flags=re.IGNORECASE)
    # Strip leading wildcard segment (``*.example.com`` → ``example.com``).
    s = s.lstrip("*")
    if s.startswith("."):
        s = s[1:]
    # Take everything up to the first ``/``.
    host = s.split("/", 1)[0]
    return host.lower()


def _is_production_hostname(host: str) -> bool:
    """Return True if *host* looks like a production-facing endpoint.

    Apex domains, www., or any of ``_CRITICAL_SUBDOMAINS`` count.
    """
    h = (host or "").rstrip(".").lower()
    if not h:
        return False
    labels = h.split(".")
    if len(labels) <= 2:
        return True  # apex
    return labels[0] in _CRITICAL_SUBDOMAINS


def _looks_like_url(value: Any) -> bool:
    return isinstance(value, str) and re.match(r"^https?://", value, re.IGNORECASE) is not None


def _domain_of_url(url: str) -> str:
    s = re.sub(r"^[a-z]+://", "", (url or "").strip(), flags=re.IGNORECASE)
    return s.split("/", 1)[0].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────────────────────────────────


def classify_cloudflare_change(change: Any) -> tuple[str, str]:
    """Dispatch to the per-record-type classifier.

    Args:
        change: Change ORM row or a dict with ``change_type``, ``field_path``,
                ``prev_value``, ``new_value``, ``provider_metadata``.

    Returns:
        ``(risk_level, risk_reason)`` — ``risk_level`` ∈ {critical, high,
        medium, low}.

    Malformed metadata is handled defensively: a non-dict ``provider_metadata``
    is treated as an empty dict, and an unknown record_type returns a safe
    Low default rather than raising.
    """
    change_type = (_get(change, "change_type") or "").lower()
    field_path = _get(change, "field_path") or ""
    prev_value = _get(change, "prev_value")
    new_value = _get(change, "new_value")
    raw_pm = _get(change, "provider_metadata")
    pm: dict[str, Any] = raw_pm if isinstance(raw_pm, dict) else {}
    record_type = (pm.get("record_type") or "").lower()

    if record_type == "cloudflare_zone_setting":
        return _classify_zone_setting(pm, change_type, field_path, prev_value, new_value)
    if record_type == "cloudflare_page_rule":
        return _classify_page_rule(pm, change_type, field_path, prev_value, new_value)
    if record_type == "cloudflare_worker_route":
        return _classify_worker_route(pm, change_type, field_path, prev_value, new_value)
    if record_type == "cloudflare_worker_script":
        return _classify_worker_script(pm, change_type, field_path, prev_value, new_value)
    if record_type == "cloudflare_access_application":
        return _classify_access_application(pm, change_type, field_path, prev_value, new_value)
    if record_type == "cloudflare_access_policy":
        return _classify_access_policy(pm, change_type, field_path, prev_value, new_value)
    if record_type == "cloudflare_waf_rule":
        return _classify_waf_rule(pm, change_type, field_path, prev_value, new_value)

    return (
        "low",
        "Unknown Cloudflare record type; no specific risk pattern matched.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# A. cloudflare_zone_setting
# ─────────────────────────────────────────────────────────────────────────────

_INSECURE_TLS_MINIMUMS: frozenset[str] = frozenset({"1.0"})
_WEAK_TLS_MINIMUMS: frozenset[str] = frozenset({"1.1"})
_SSL_OFF_VALUES: frozenset[str] = frozenset({"off"})
_SSL_FLEXIBLE_VALUES: frozenset[str] = frozenset({"flexible"})
_SSL_STRONG_VALUES: frozenset[str] = frozenset({"full", "strict"})


def _classify_zone_setting(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    setting_id = (pm.get("setting_id") or pm.get("record_id") or "").lower()
    prev_s = _str(prev_value).lower()
    new_s = _str(new_value).lower()

    # ── SSL mode (setting_id == "ssl") ────────────────────────────────────────
    if setting_id == "ssl":
        if new_s in _SSL_OFF_VALUES:
            return (
                "critical",
                "Zone SSL mode was set to 'off'.  Edge HTTPS is disabled for "
                "this zone, which may allow plaintext traffic and weaken "
                "browser/client security.",
            )
        if new_s in _SSL_FLEXIBLE_VALUES and prev_s in _SSL_STRONG_VALUES:
            return (
                "high",
                f"Zone SSL mode was lowered from '{prev_s}' to 'flexible'. "
                "Origin connections may now use HTTP, which may weaken edge "
                "TLS posture and customer trust.",
            )
        if new_s in _SSL_STRONG_VALUES and prev_s in (
            _SSL_OFF_VALUES | _SSL_FLEXIBLE_VALUES
        ):
            return (
                "low",
                f"Zone SSL mode was strengthened from '{prev_s}' to '{new_s}'.",
            )

    # ── Always Use HTTPS ──────────────────────────────────────────────────────
    if setting_id in ("always_use_https", "automatic_https_rewrites"):
        if new_s in ("off", "false", "0"):
            return (
                "high",
                f"'{setting_id}' was disabled.  Plain-HTTP requests will no "
                "longer be redirected to HTTPS, which may weaken HTTPS "
                "enforcement for visitors.",
            )
        if new_s in ("on", "true", "1"):
            return (
                "low",
                f"'{setting_id}' was enabled — HTTPS enforcement improved.",
            )

    # ── Minimum TLS version ───────────────────────────────────────────────────
    if setting_id == "min_tls_version":
        if new_s in _INSECURE_TLS_MINIMUMS:
            return (
                "critical",
                f"Minimum TLS version was lowered to {new_s}, which is "
                "considered insecure.  This may weaken browser/client "
                "security for the zone.",
            )
        if new_s in _WEAK_TLS_MINIMUMS:
            return (
                "high",
                f"Minimum TLS version was lowered to {new_s}.  Modern browsers "
                "may already refuse it; weaker handshakes may be accepted at "
                "the edge.",
            )
        # Strengthened TLS minimum (e.g. 1.1 → 1.2).
        try:
            if float(prev_s) < float(new_s):
                return (
                    "low",
                    f"Minimum TLS version was raised from {prev_s} to {new_s} — "
                    "edge TLS posture improved.",
                )
        except (TypeError, ValueError):
            pass

    # ── HSTS (security_header) ────────────────────────────────────────────────
    if setting_id == "security_header":
        # ``value`` is typically a dict like
        # {"enabled": True, "max_age": 31536000, ...}.  We detect changes
        # by reading enabled/max_age on prev and new dicts.
        prev_d = prev_value if isinstance(prev_value, dict) else {}
        new_d = new_value if isinstance(new_value, dict) else {}
        prev_enabled = bool(prev_d.get("enabled", False))
        new_enabled = bool(new_d.get("enabled", False))
        if prev_enabled and not new_enabled:
            return (
                "high",
                "HSTS was disabled on this zone.  Browsers will no longer be "
                "told to enforce HTTPS, which may weaken HTTPS posture for "
                "returning visitors.",
            )
        prev_age = int(prev_d.get("max_age") or 0)
        new_age = int(new_d.get("max_age") or 0)
        if prev_enabled and new_enabled and new_age and new_age < prev_age // 2:
            return (
                "high",
                f"HSTS max_age was lowered from {prev_age} to {new_age} "
                "seconds — browsers will cache the HTTPS-only policy for a "
                "shorter window.",
            )
        if not prev_enabled and new_enabled:
            return ("low", "HSTS was enabled — HTTPS posture improved.")

    # ── Browser integrity check / security level ──────────────────────────────
    if setting_id == "browser_check":
        if new_s in ("off", "false", "0"):
            return (
                "medium",
                "Browser integrity check was disabled.  Some attack-like "
                "client signatures may no longer be challenged at the edge.",
            )

    if setting_id == "security_level":
        # Cloudflare values: off < essentially_off < low < medium < high < under_attack
        levels = ["off", "essentially_off", "low", "medium", "high", "under_attack"]
        if prev_s in levels and new_s in levels:
            if levels.index(new_s) < levels.index(prev_s):
                return (
                    "medium",
                    f"Security level was lowered from '{prev_s}' to '{new_s}'. "
                    "Fewer suspicious requests may be challenged.",
                )
            if levels.index(new_s) > levels.index(prev_s):
                return (
                    "low",
                    f"Security level was raised from '{prev_s}' to '{new_s}'.",
                )

    # ── Development mode (orange-cloud bypass) ────────────────────────────────
    if setting_id == "development_mode" and new_s in ("on", "true", "1"):
        return (
            "medium",
            "Development mode was enabled.  Cloudflare caching and "
            "minification are temporarily bypassed for this zone (3 hours).",
        )

    # Catch-all for any other zone setting change.
    return (
        "low",
        f"Zone setting '{setting_id or 'unknown'}' changed; no specific risk "
        "pattern matched.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# B. cloudflare_page_rule  (page rules / redirects / cache rules)
# ─────────────────────────────────────────────────────────────────────────────


def _classify_page_rule(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    target = pm.get("target_url_pattern") or pm.get("record_id") or ""
    target_host = _hostname_from_url_or_pattern(_str(target))
    is_prod = _is_production_hostname(target_host)
    kind = (pm.get("rule_kind") or "page_rule").lower()

    # ── Rule removed ──────────────────────────────────────────────────────────
    if change_type == "removed":
        sev = "high" if is_prod else "medium"
        return (
            sev,
            f"A {kind} for {target_host or 'a hostname'} was removed.  "
            "Previously-configured redirect/cache/header behaviour is no "
            "longer applied and may affect production routing.",
        )

    # ── Rule added ────────────────────────────────────────────────────────────
    if change_type == "added":
        sev = "medium" if is_prod else "low"
        return (
            sev,
            f"A new {kind} was added for {target_host or 'a hostname'}.  "
            "Verify the rule matches the intended URL pattern.",
        )

    # ── Cache rule risky change (must run BEFORE redirect branch so a
    #     ``rule_kind=cache_rule`` change is not classified as a redirect) ───
    new_lc_early = _str(new_value).lower()
    if change_type == "modified" and (
        kind == "cache_rule"
        or "cache" in (field_path or "").lower()
        or "cache_level" in new_lc_early
        or "cache_everything" in new_lc_early
    ):
        new_s = new_lc_early
        if "bypass" in new_s or "no_cache" in new_s:
            return (
                "medium",
                f"A cache rule on {target_host or 'a hostname'} was set to "
                "bypass / no-cache.  Origin load may increase.",
            )
        if "cache_everything" in new_s or "edge_ttl" in new_s:
            sev = "high" if is_prod else "medium"
            return (
                sev,
                f"A cache rule on {target_host or 'a hostname'} was changed to "
                "cache more aggressively.  Verify the path does not serve "
                "per-user or otherwise private content — stale/private "
                "content could be cached.",
            )
        return (
            "medium",
            f"A cache rule on {target_host or 'a hostname'} was modified.",
        )

    # ── Forwarding/redirect target changed ────────────────────────────────────
    # We detect a redirect target change by looking at the actions_summary
    # field (or a path-based field "actions_summary"/"forwarding_url").
    if change_type == "modified" and field_path in (
        "actions_summary", "forwarding_url", "redirect_to"
    ):
        # Extract the new forwarding domain (if URL-shaped).
        new_url = _str(new_value)
        prev_url = _str(prev_value)
        if _looks_like_url(new_url):
            new_dom = _domain_of_url(new_url)
            prev_dom = _domain_of_url(prev_url) if _looks_like_url(prev_url) else ""
            # Different registrable domain → escalate.
            if (
                new_dom
                and prev_dom
                and new_dom != prev_dom
                and not new_dom.endswith("." + target_host)
                and new_dom != target_host
            ):
                sev = "critical" if is_prod else "high"
                return (
                    sev,
                    f"A {kind} on {target_host or 'a hostname'} now redirects "
                    f"to a different domain ({new_dom}).  Confirm the new "
                    "destination is controlled by your team — unintended "
                    "redirects may route traffic incorrectly.",
                )
        return (
            "high" if is_prod else "medium",
            f"The redirect target of a {kind} on {target_host or 'a hostname'} "
            "was changed.  Verify the new destination.",
        )

    # ── Status toggled ────────────────────────────────────────────────────────
    if change_type == "modified" and field_path == "status":
        new_s = _str(new_value).lower()
        if new_s == "disabled":
            sev = "high" if is_prod else "medium"
            return (
                sev,
                f"A {kind} on {target_host or 'a hostname'} was disabled. "
                "Configured behaviour is no longer applied.",
            )
        if new_s == "active":
            return (
                "low",
                f"A {kind} on {target_host or 'a hostname'} was re-enabled.",
            )

    # ── Generic modification ──────────────────────────────────────────────────
    return (
        "medium" if is_prod else "low",
        f"A {kind} for {target_host or 'a hostname'} was modified; "
        "verify the change is intentional.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# C. cloudflare_worker_route + cloudflare_worker_script
# ─────────────────────────────────────────────────────────────────────────────


def _classify_worker_route(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    pattern = pm.get("pattern") or pm.get("record_id") or ""
    host = _hostname_from_url_or_pattern(_str(pattern))
    is_prod = _is_production_hostname(host)

    if change_type == "added":
        sev = "high" if is_prod else "medium"
        return (
            sev,
            f"A new worker route was added for {host or 'a hostname'}.  "
            "Requests matching this pattern will now execute the configured "
            "worker, which may intercept or modify production traffic.",
        )

    if change_type == "removed":
        sev = "high" if is_prod else "medium"
        return (
            sev,
            f"A worker route for {host or 'a hostname'} was removed.  "
            "Requests matching this pattern will no longer execute the worker "
            "and may now reach the origin directly.",
        )

    if change_type == "modified" and field_path == "pattern":
        sev = "high" if is_prod else "medium"
        return (
            sev,
            f"A worker route's pattern was changed (now {host or 'a hostname'}). "
            "A different set of requests may now execute the worker.",
        )

    if change_type == "modified" and field_path == "script_name":
        sev = "critical" if is_prod else "high"
        return (
            sev,
            f"A worker route on {host or 'a hostname'} now points at a "
            "different worker script.  This may change request handling for "
            "production traffic — verify the new script is owned by your team.",
        )

    if change_type == "modified" and field_path == "enabled":
        new_s = _str(new_value).lower()
        if new_s in ("false", "0", "off"):
            sev = "high" if is_prod else "medium"
            return (
                sev,
                f"A worker route on {host or 'a hostname'} was disabled.  "
                "The configured worker will not run for matching requests.",
            )
        return (
            "low",
            f"A worker route on {host or 'a hostname'} was re-enabled.",
        )

    return (
        "medium" if is_prod else "low",
        f"A worker route on {host or 'a hostname'} was modified; verify the "
        "change is intentional.",
    )


def _classify_worker_script(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    script_name = pm.get("script_name") or pm.get("record_id") or ""

    if change_type == "removed":
        return (
            "high",
            f"Worker script '{script_name or 'unknown'}' was removed.  Routes "
            "previously bound to it will no longer execute that script.",
        )

    if change_type == "added":
        return (
            "medium",
            f"A new worker script '{script_name or 'unknown'}' was deployed. "
            "Verify the script is owned by your team.",
        )

    if change_type == "modified" and field_path == "script_etag":
        return (
            "high",
            f"Worker script '{script_name or 'unknown'}' content hash changed — "
            "new code was deployed.  Review the deploy and verify the script "
            "is owned by your team.",
        )

    if change_type == "modified" and field_path == "env_var_count":
        # Important: we never inspect or reveal env var VALUES — only the count.
        try:
            prev_n = int(prev_value or 0)
            new_n = int(new_value or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        direction = "increased" if new_n > prev_n else "decreased"
        return (
            "medium",
            f"Worker script '{script_name or 'unknown'}' env var binding count "
            f"{direction} from {prev_n} to {new_n}.  Verify the change is "
            "intentional.  ConfigTrace never reads or stores env var values.",
        )

    if change_type == "modified" and field_path == "binding_count":
        return (
            "medium",
            f"Worker script '{script_name or 'unknown'}' binding count "
            "changed.  KV/D1/R2/Queues bindings may have been added or removed.",
        )

    return (
        "low",
        f"Worker script '{script_name or 'unknown'}' metadata changed; "
        "no specific risk pattern matched.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# D. cloudflare_access_application + cloudflare_access_policy
# ─────────────────────────────────────────────────────────────────────────────


def _classify_access_application(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    name = pm.get("name") or pm.get("domain") or pm.get("record_id") or ""

    if change_type == "removed":
        return (
            "critical",
            f"Cloudflare Access application '{name}' was removed.  The "
            "previously-protected internal app may now be reachable without "
            "Access authentication — verify intentional.",
        )

    if change_type == "added":
        return (
            "low",
            f"A new Cloudflare Access application '{name}' was created — "
            "a new identity-gated entry point is now configured.",
        )

    if change_type == "modified" and field_path == "visibility":
        new_s = _str(new_value).lower()
        if new_s == "public":
            return (
                "critical",
                f"Cloudflare Access application '{name}' visibility was "
                "changed to 'public'.  The previously-protected internal app "
                "may now be reachable without authentication — verify this "
                "is intentional and review access logs.",
            )

    if change_type == "modified" and field_path == "enabled":
        new_s = _str(new_value).lower()
        if new_s in ("false", "0", "off"):
            return (
                "critical",
                f"Cloudflare Access application '{name}' was disabled.  The "
                "authentication barrier is no longer enforced for this app.",
            )
        return (
            "low",
            f"Cloudflare Access application '{name}' was re-enabled.",
        )

    if change_type == "modified" and field_path == "allowed_idps_count":
        try:
            prev_n = int(prev_value or 0)
            new_n = int(new_value or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        if new_n == 0 and prev_n > 0:
            return (
                "high",
                f"Cloudflare Access application '{name}' has had all "
                "identity providers removed.  Users may no longer be able to "
                "authenticate, or the app may have been opened to anonymous "
                "access — verify.",
            )
        if new_n < prev_n:
            return (
                "medium",
                f"Cloudflare Access application '{name}' had identity "
                f"provider(s) removed ({prev_n} → {new_n}).  Verify users "
                "can still authenticate.",
            )
        return (
            "low",
            f"Cloudflare Access application '{name}' had identity provider(s) "
            f"added ({prev_n} → {new_n}).",
        )

    if change_type == "modified" and field_path == "session_duration":
        return (
            "low",
            f"Cloudflare Access application '{name}' session duration was "
            "changed.  Verify the new value matches your team's policy.",
        )

    return (
        "low",
        f"Cloudflare Access application '{name}' metadata was modified; "
        "no specific risk pattern matched.",
    )


def _classify_access_policy(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    name = pm.get("name") or pm.get("record_id") or ""

    if change_type == "removed":
        return (
            "high",
            f"Cloudflare Access policy '{name}' was removed.  The associated "
            "application may have weaker authorization than before — verify "
            "remaining policies still cover the intended users.",
        )

    if change_type == "modified" and field_path == "decision":
        prev_s = _str(prev_value).lower()
        new_s = _str(new_value).lower()
        if prev_s in ("allow", "deny", "non_identity") and new_s == "bypass":
            return (
                "high",
                f"Cloudflare Access policy '{name}' decision was changed from "
                f"'{prev_s}' to 'bypass'.  Matching users may now reach the "
                "protected app without identity checks.",
            )
        if prev_s == "deny" and new_s == "allow":
            return (
                "high",
                f"Cloudflare Access policy '{name}' decision was relaxed from "
                "'deny' to 'allow'.  Verify the change is intentional.",
            )
        return (
            "medium",
            f"Cloudflare Access policy '{name}' decision changed from "
            f"'{prev_s}' to '{new_s}'.",
        )

    if change_type == "modified" and field_path == "enabled":
        new_s = _str(new_value).lower()
        if new_s in ("false", "0", "off"):
            return (
                "high",
                f"Cloudflare Access policy '{name}' was disabled.  Other "
                "policies on the application may still enforce access, but "
                "this one no longer applies.",
            )
        return (
            "low",
            f"Cloudflare Access policy '{name}' was re-enabled.",
        )

    if change_type == "modified" and field_path == "include_count":
        try:
            prev_n = int(prev_value or 0)
            new_n = int(new_value or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        if new_n > prev_n:
            return (
                "high",
                f"Cloudflare Access policy '{name}' include list was broadened "
                f"({prev_n} → {new_n}).  More users/groups/emails may now "
                "match this policy — verify intentional.",
            )
        return (
            "low",
            f"Cloudflare Access policy '{name}' include list was narrowed "
            f"({prev_n} → {new_n}).",
        )

    if change_type == "added":
        new_decision = _str(pm.get("decision")).lower()
        if new_decision == "bypass":
            return (
                "high",
                f"A new Cloudflare Access policy '{name}' with decision "
                "'bypass' was added.  Matching users will skip identity "
                "checks for the protected app — verify intentional.",
            )
        return (
            "medium",
            f"A new Cloudflare Access policy '{name}' was added.",
        )

    return (
        "low",
        f"Cloudflare Access policy '{name}' metadata was modified; "
        "no specific risk pattern matched.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# E. cloudflare_waf_rule (granular per-rule)
# ─────────────────────────────────────────────────────────────────────────────

_PROTECTIVE_ACTIONS: frozenset[str] = frozenset(
    {"block", "challenge", "managed_challenge", "js_challenge"}
)
_PERMISSIVE_ACTIONS: frozenset[str] = frozenset({"allow", "skip", "log"})


def _classify_waf_rule(
    pm: dict, change_type: str, field_path: str, prev_value: Any, new_value: Any
) -> tuple[str, str]:
    description = pm.get("description") or pm.get("record_id") or ""

    if change_type == "removed":
        return (
            "high",
            f"WAF rule '{description}' was removed.  Whatever attack pattern "
            "or path it protected is no longer filtered at the edge.",
        )

    if change_type == "added":
        return (
            "medium",
            f"A new WAF rule '{description}' was added.  Review what traffic "
            "it now blocks/challenges.",
        )

    if change_type == "modified" and field_path == "action":
        prev_s = _str(prev_value).lower()
        new_s = _str(new_value).lower()
        if prev_s in _PROTECTIVE_ACTIONS and new_s in _PERMISSIVE_ACTIONS:
            # Critical when a block becomes allow/skip; high when challenge → log.
            sev = "critical" if (prev_s == "block" and new_s in ("allow", "skip")) else "high"
            return (
                sev,
                f"WAF rule '{description}' action was changed from '{prev_s}' "
                f"to '{new_s}'.  Traffic that was previously filtered is now "
                "permitted — this may weaken edge attack filtering.",
            )
        if prev_s in _PERMISSIVE_ACTIONS and new_s in _PROTECTIVE_ACTIONS:
            return (
                "low",
                f"WAF rule '{description}' action was strengthened from "
                f"'{prev_s}' to '{new_s}'.",
            )
        return (
            "medium",
            f"WAF rule '{description}' action changed from '{prev_s}' to "
            f"'{new_s}'.",
        )

    if change_type == "modified" and field_path == "enabled":
        new_s = _str(new_value).lower()
        if new_s in ("false", "0", "off"):
            return (
                "high",
                f"WAF rule '{description}' was disabled.  The attack pattern "
                "it covered is no longer filtered at the edge.",
            )
        return (
            "low",
            f"WAF rule '{description}' was re-enabled.",
        )

    if change_type == "modified" and field_path == "expression_hash":
        # We never see the expression body — only its hash.  A hash change
        # tells us the matching logic changed but not how.
        return (
            "medium",
            f"WAF rule '{description}' matching expression was changed.  "
            "Verify the new pattern matches the intended traffic.",
        )

    return (
        "low",
        f"WAF rule '{description}' metadata was modified; "
        "no specific risk pattern matched.",
    )
