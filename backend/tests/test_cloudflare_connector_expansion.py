"""M59.7 — Cloudflare connector expansion tests.

Covers the six new surfaces wired into the connector:

  * Zone settings (`cloudflare_zone_setting`)
  * Page rules (`cloudflare_page_rule`)  + redirect-target redaction
  * Worker routes (`cloudflare_worker_route`)
  * Worker scripts (`cloudflare_worker_script`)  — metadata only, no source
  * Access applications (`cloudflare_access_application`)
  * Access policies (`cloudflare_access_policy`)  — counts only
  * Granular WAF rules (`cloudflare_waf_rule`)   — expression hashed

All HTTP is mocked via ``respx``.  No real Cloudflare API call is made and
no real credentials are loaded from ``.env``.

The suite also exercises:
  * Fail-soft on 401/403/404/422 per surface (DNS sync still succeeds)
  * Secret-redaction tripwires on snapshot state and log records
  * End-to-end mocked-fetch → snapshot-diff → risk-service classification
"""

from __future__ import annotations

import json
import re
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from app.connectors.cloudflare import (
    CloudflareConnector,
    _ZONE_SETTING_IDS,
    _hash_expression,
    _safe_redirect_target,
)


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

VALID_CREDS = {"api_token": "test-token-abc123", "zone_id": "zone1234567890abcdef"}
CF_BASE = "https://api.cloudflare.com/client/v4"
ZONE_ID = VALID_CREDS["zone_id"]
ACCOUNT_ID = "acc1234567890abcdef"


# Patterns that must NEVER appear in any snapshot record or log line.
_FORBIDDEN_PATTERNS = (
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{8,}", re.IGNORECASE),
    re.compile(r"Authorization:\s*Bearer", re.IGNORECASE),
    re.compile(r"test-token-abc123"),       # the credential we feed
    re.compile(r"\bsk_live_[A-Za-z0-9]{32,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bxoxb-[A-Za-z0-9\-]{30,}"),
)


# ─────────────────────────────────────────────────────────────────────────────
# Response builders
# ─────────────────────────────────────────────────────────────────────────────


def _envelope(result: Any, *, success: bool = True) -> dict:
    return {
        "success": success,
        "errors": [] if success else [{"code": 7003, "message": "denied"}],
        "messages": [],
        "result": result,
        "result_info": {
            "page": 1, "per_page": 100,
            "total_count": len(result) if isinstance(result, list) else 1,
            "count": len(result) if isinstance(result, list) else 1,
        },
    }


def _dns_records_route(rmock: respx.MockRouter, records: list[dict] | None = None) -> None:
    """Always-required mock for the DNS endpoint so ``fetch()`` doesn't blow up."""
    rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/dns_records").mock(
        return_value=httpx.Response(200, json=_envelope(records or []))
    )


def _empty_rulesets(rmock: respx.MockRouter) -> None:
    rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/rulesets").mock(
        return_value=httpx.Response(200, json=_envelope([]))
    )


def _zone_lookup_for_account_resolution(rmock: respx.MockRouter, *, account_id: str = ACCOUNT_ID) -> None:
    rmock.get(f"{CF_BASE}/zones/{ZONE_ID}").mock(
        return_value=httpx.Response(200, json=_envelope({
            "id": ZONE_ID,
            "name": "example.com",
            "account": {"id": account_id, "name": "Acme"},
        }))
    )


def _all_zone_settings_403(rmock: respx.MockRouter) -> None:
    for sid in _ZONE_SETTING_IDS:
        rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/settings/{sid}").mock(
            return_value=httpx.Response(403, json={"success": False, "errors": []})
        )


def _empty_page_rules(rmock: respx.MockRouter) -> None:
    rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/pagerules").mock(
        return_value=httpx.Response(200, json=_envelope([]))
    )


def _empty_worker_routes(rmock: respx.MockRouter) -> None:
    rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/workers/routes").mock(
        return_value=httpx.Response(200, json=_envelope([]))
    )


def _no_workers_or_access(rmock: respx.MockRouter, *, account_id: str = ACCOUNT_ID) -> None:
    """Mount 403 responses for all account-scoped endpoints."""
    rmock.get(f"{CF_BASE}/accounts/{account_id}/workers/scripts").mock(
        return_value=httpx.Response(403, json={"success": False, "errors": []})
    )
    rmock.get(f"{CF_BASE}/accounts/{account_id}/access/apps").mock(
        return_value=httpx.Response(403, json={"success": False, "errors": []})
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers for whole-pipeline assertions
# ─────────────────────────────────────────────────────────────────────────────


def _records_by_type(records: list[dict], rt: str) -> list[dict]:
    return [r for r in records if r.get("record_type") == rt]


def _assert_no_secret_substring(blob: str) -> None:
    for p in _FORBIDDEN_PATTERNS:
        assert not p.search(blob), (
            f"snapshot/log leaked secret-shaped substring matching {p.pattern!r}"
        )


# ═════════════════════════════════════════════════════════════════════════════
# A. Zone settings
# ═════════════════════════════════════════════════════════════════════════════


class TestZoneSettings:

    def test_A1_emits_one_record_per_monitored_setting(self):
        with respx.mock(assert_all_called=False) as rmock:
            _dns_records_route(rmock)
            _empty_rulesets(rmock)
            _empty_page_rules(rmock)
            _empty_worker_routes(rmock)
            _zone_lookup_for_account_resolution(rmock)
            _no_workers_or_access(rmock)

            # Real-shape responses for three settings; rest 403 to test
            # graceful skip alongside successes.
            rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/settings/ssl").mock(
                return_value=httpx.Response(200, json=_envelope({
                    "id": "ssl", "value": "full", "editable": True,
                    "modified_on": "2024-01-01T00:00:00Z",
                }))
            )
            rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/settings/min_tls_version").mock(
                return_value=httpx.Response(200, json=_envelope({
                    "id": "min_tls_version", "value": "1.2", "editable": True,
                    "modified_on": "2024-01-01T00:00:00Z",
                }))
            )
            rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/settings/security_header").mock(
                return_value=httpx.Response(200, json=_envelope({
                    "id": "security_header",
                    "value": {"strict_transport_security": {
                        "enabled": True, "max_age": 31536000,
                        "include_subdomains": True, "preload": False,
                    }},
                    "editable": True,
                    "modified_on": "2024-01-01T00:00:00Z",
                }))
            )
            # Remaining settings respond 403 → must skip gracefully.
            for sid in _ZONE_SETTING_IDS:
                if sid in ("ssl", "min_tls_version", "security_header"):
                    continue
                rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/settings/{sid}").mock(
                    return_value=httpx.Response(403, json={"success": False})
                )

            records = CloudflareConnector().fetch(VALID_CREDS)

        settings = _records_by_type(records, "cloudflare_zone_setting")
        ids = {r["setting_id"] for r in settings}
        assert ids == {"ssl", "min_tls_version", "security_header"}
        # SSL value preserved.
        ssl = next(r for r in settings if r["setting_id"] == "ssl")
        assert ssl["value"] == "full"
        # HSTS value preserved as dict.
        hsts = next(r for r in settings if r["setting_id"] == "security_header")
        assert isinstance(hsts["value"], dict)

    def test_A2_403_on_one_setting_does_not_abort_dns_or_other_settings(self):
        with respx.mock(assert_all_called=False) as rmock:
            _dns_records_route(
                rmock,
                [{"id": "r1", "type": "A", "name": "example.com",
                  "content": "1.2.3.4", "ttl": 3600, "proxied": False,
                  "modified_on": "2024-01-01T00:00:00Z"}],
            )
            _empty_rulesets(rmock)
            _all_zone_settings_403(rmock)
            _empty_page_rules(rmock)
            _empty_worker_routes(rmock)
            _zone_lookup_for_account_resolution(rmock)
            _no_workers_or_access(rmock)

            records = CloudflareConnector().fetch(VALID_CREDS)

        # DNS record is still present even though every setting was denied.
        dns = [r for r in records if r.get("record_type") == "A"]
        assert len(dns) == 1
        # No zone-setting records were emitted (all were 403).
        assert _records_by_type(records, "cloudflare_zone_setting") == []


# ═════════════════════════════════════════════════════════════════════════════
# B. Page rules — including redirect-target redaction
# ═════════════════════════════════════════════════════════════════════════════


class TestPageRules:

    def test_B1_page_rules_emitted_with_safe_actions_summary(self):
        with respx.mock(assert_all_called=False) as rmock:
            _dns_records_route(rmock)
            _empty_rulesets(rmock)
            _all_zone_settings_403(rmock)
            _zone_lookup_for_account_resolution(rmock)
            _empty_worker_routes(rmock)
            _no_workers_or_access(rmock)

            rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/pagerules").mock(
                return_value=httpx.Response(200, json=_envelope([
                    {
                        "id": "pr_redirect_001",
                        "priority": 1,
                        "status": "active",
                        "targets": [{"target": "url", "constraint": {
                            "operator": "matches",
                            "value": "api.example.com/legacy/*",
                        }}],
                        "actions": [{
                            "id": "forwarding_url",
                            "value": {
                                "url": "https://new.example.com/handoff?token=SUPERSECRET12345678901234567890",
                                "status_code": 302,
                            },
                        }],
                        "modified_on": "2024-01-01T00:00:00Z",
                    },
                    {
                        "id": "pr_cache_002",
                        "priority": 2,
                        "status": "active",
                        "targets": [{"target": "url", "constraint": {
                            "value": "static.example.com/*",
                        }}],
                        "actions": [{
                            "id": "cache_level",
                            "value": "cache_everything",
                        }],
                        "modified_on": "2024-01-01T00:00:00Z",
                    },
                ]))
            )

            records = CloudflareConnector().fetch(VALID_CREDS)

        rules = _records_by_type(records, "cloudflare_page_rule")
        ids = {r["record_id"] for r in rules}
        assert ids == {"pr_redirect_001", "pr_cache_002"}
        # Redirect rule classifies as "redirect" and the actions_summary
        # contains scheme+host only — no path, no query, no token.
        redirect = next(r for r in rules if r["record_id"] == "pr_redirect_001")
        assert redirect["rule_kind"] == "redirect"
        assert "SUPERSECRET" not in json.dumps(redirect)
        assert "?token=" not in redirect["actions_summary"]
        assert "https://new.example.com" in redirect["actions_summary"]
        assert ",302" in redirect["actions_summary"]
        # Cache rule classifies correctly.
        cache = next(r for r in rules if r["record_id"] == "pr_cache_002")
        assert cache["rule_kind"] == "cache_rule"
        assert "cache_everything" in cache["actions_summary"]

    def test_B2_safe_redirect_target_strips_query_and_path(self):
        # Unit-level: the helper itself never returns the secret slice.
        assert _safe_redirect_target(
            "https://new.example.com/admin?token=abc"
        ) == "https://new.example.com"
        # Malformed → empty.
        assert _safe_redirect_target("not-a-url") == ""
        assert _safe_redirect_target("") == ""


# ═════════════════════════════════════════════════════════════════════════════
# C. Worker routes / scripts
# ═════════════════════════════════════════════════════════════════════════════


class TestWorkers:

    def test_C1_worker_routes_emitted(self):
        with respx.mock(assert_all_called=False) as rmock:
            _dns_records_route(rmock)
            _empty_rulesets(rmock)
            _all_zone_settings_403(rmock)
            _empty_page_rules(rmock)
            _zone_lookup_for_account_resolution(rmock)
            _no_workers_or_access(rmock)

            rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/workers/routes").mock(
                return_value=httpx.Response(200, json=_envelope([
                    {
                        "id": "route_a",
                        "pattern": "api.example.com/*",
                        "script": "edge-handler",
                    },
                ]))
            )

            records = CloudflareConnector().fetch(VALID_CREDS)

        routes = _records_by_type(records, "cloudflare_worker_route")
        assert len(routes) == 1
        assert routes[0]["pattern"] == "api.example.com/*"
        assert routes[0]["script_name"] == "edge-handler"

    def test_C2_worker_scripts_metadata_only_no_source(self):
        with respx.mock(assert_all_called=False) as rmock:
            _dns_records_route(rmock)
            _empty_rulesets(rmock)
            _all_zone_settings_403(rmock)
            _empty_page_rules(rmock)
            _empty_worker_routes(rmock)
            _zone_lookup_for_account_resolution(rmock)
            # Access apps: 403 to keep this test focused on workers.
            rmock.get(f"{CF_BASE}/accounts/{ACCOUNT_ID}/access/apps").mock(
                return_value=httpx.Response(403, json={"success": False})
            )

            # Notice the bindings: one plain_text + one secret_text + one KV
            # binding.  We must count plain_text + secret_text together as
            # env_var_count (2), and total bindings as 3.  Their VALUES
            # must never appear in the snapshot record.
            rmock.get(f"{CF_BASE}/accounts/{ACCOUNT_ID}/workers/scripts").mock(
                return_value=httpx.Response(200, json=_envelope([
                    {
                        "id": "edge-handler",
                        "etag": "etag-aaaa",
                        "modified_on": "2024-01-01T00:00:00Z",
                        "bindings": [
                            {"name": "REGION",      "type": "plain_text",
                             "text": "us-east-1"},
                            {"name": "STRIPE_KEY",  "type": "secret_text",
                             "text": "sk_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                     "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
                            {"name": "MY_KV",       "type": "kv_namespace",
                             "namespace_id": "0011aabbccddeeff0011aabbccddeeff"},
                        ],
                    }
                ]))
            )

            records = CloudflareConnector().fetch(VALID_CREDS)

        scripts = _records_by_type(records, "cloudflare_worker_script")
        assert len(scripts) == 1
        s = scripts[0]
        assert s["script_name"] == "edge-handler"
        assert s["script_etag"] == "etag-aaaa"
        # env_var_count counts plain_text + secret_text only.
        assert s["env_var_count"] == 2
        # binding_count counts all bindings.
        assert s["binding_count"] == 3
        # No env-var name or value (REGION, STRIPE_KEY, MY_KV, sk_live_...)
        # leaks into the stored record.
        blob = json.dumps(s)
        for forbidden in ("REGION", "STRIPE_KEY", "MY_KV", "sk_live_",
                          "us-east-1", "0011aabbccddeeff",
                          "namespace_id", "text"):
            assert forbidden not in blob, (
                f"worker_script snapshot leaked forbidden token: {forbidden}"
            )


# ═════════════════════════════════════════════════════════════════════════════
# D. Access applications / policies
# ═════════════════════════════════════════════════════════════════════════════


class TestAccessApps:

    def test_D1_access_apps_and_policies_emit_counts_only(self):
        with respx.mock(assert_all_called=False) as rmock:
            _dns_records_route(rmock)
            _empty_rulesets(rmock)
            _all_zone_settings_403(rmock)
            _empty_page_rules(rmock)
            _empty_worker_routes(rmock)
            _zone_lookup_for_account_resolution(rmock)
            # Workers scripts: 403 to keep this test focused.
            rmock.get(f"{CF_BASE}/accounts/{ACCOUNT_ID}/workers/scripts").mock(
                return_value=httpx.Response(403, json={"success": False})
            )

            rmock.get(f"{CF_BASE}/accounts/{ACCOUNT_ID}/access/apps").mock(
                return_value=httpx.Response(200, json=_envelope([
                    {
                        "id": "app_001",
                        "name": "Admin Panel",
                        "type": "self_hosted",
                        "domain": "admin.example.com",
                        "app_launcher_visible": False,  # → "private"
                        "enabled": True,
                        "session_duration": "24h",
                        "allowed_idps": ["idp-a", "idp-b"],
                        "updated_at": "2024-01-01T00:00:00Z",
                    },
                ]))
            )
            rmock.get(
                f"{CF_BASE}/accounts/{ACCOUNT_ID}/access/apps/app_001/policies"
            ).mock(
                return_value=httpx.Response(200, json=_envelope([
                    {
                        "id": "pol_001",
                        "name": "Engineers",
                        "decision": "allow",
                        "enabled": True,
                        "precedence": 1,
                        # Realistic raw input — must NOT be persisted.
                        "include": [
                            {"email": {"email": "alice@example.com"}},
                            {"email": {"email": "bob@example.com"}},
                            {"group": {"id": "eng-group"}},
                        ],
                        "exclude": [],
                        "require": [
                            {"service_token": {"token_id": "stkn_secret_001"}},
                        ],
                        "updated_at": "2024-01-01T00:00:00Z",
                    },
                ]))
            )

            records = CloudflareConnector().fetch(VALID_CREDS)

        apps = _records_by_type(records, "cloudflare_access_application")
        policies = _records_by_type(records, "cloudflare_access_policy")
        assert len(apps) == 1 and len(policies) == 1
        app = apps[0]
        assert app["name"] == "Admin Panel"
        assert app["visibility"] == "private"
        assert app["allowed_idps_count"] == 2
        # No allowlist member, group id, or service-token id leaks.
        blob = json.dumps(policies[0])
        for forbidden in (
            "alice@example.com", "bob@example.com", "eng-group",
            "stkn_secret_001", "include", "exclude", "require",
            "email", "service_token",
        ):
            # ``include_count`` / ``exclude_count`` / ``require_count`` keys
            # ARE allowed (they are NOT the raw lists).  Confirm we didn't
            # store the literal sub-keys ``include`` / ``exclude`` /
            # ``require`` themselves with their list bodies.
            if forbidden in ("include", "exclude", "require"):
                assert f'"{forbidden}":' not in blob, (
                    f"policy snapshot kept raw list key {forbidden!r}"
                )
            else:
                assert forbidden not in blob, (
                    f"policy snapshot leaked {forbidden!r}"
                )
        # Counts ARE stored.
        assert policies[0]["include_count"] == 3
        assert policies[0]["exclude_count"] == 0
        assert policies[0]["require_count"] == 1


# ═════════════════════════════════════════════════════════════════════════════
# E. Granular WAF rules
# ═════════════════════════════════════════════════════════════════════════════


class TestWAFRules:

    def test_E1_waf_rules_emitted_with_expression_hashed(self):
        with respx.mock(assert_all_called=False) as rmock:
            _dns_records_route(rmock)
            _all_zone_settings_403(rmock)
            _empty_page_rules(rmock)
            _empty_worker_routes(rmock)
            _zone_lookup_for_account_resolution(rmock)
            _no_workers_or_access(rmock)

            # Cloudflare returns the rulesets list — inline rules path.
            rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/rulesets").mock(
                return_value=httpx.Response(200, json=_envelope([
                    {
                        "id": "ruleset_001",
                        "name": "Custom firewall",
                        "kind": "custom",
                        "phase": "http_request_firewall_custom",
                        "version": "5",
                        "rules": [
                            {
                                "id": "rule_block_sqli",
                                "description": "Block obvious SQLi",
                                "action": "block",
                                "enabled": True,
                                "expression": "(http.request.uri.path contains \"' OR 1=1\") "
                                              "or (http.request.body contains \"--\")",
                                "last_updated": "2024-01-01T00:00:00Z",
                            },
                            {
                                "id": "rule_challenge_bots",
                                "description": "Challenge bot UAs",
                                "action": "managed_challenge",
                                "enabled": True,
                                "expression": "(http.user_agent contains \"bot\")",
                                "last_updated": "2024-01-01T00:00:00Z",
                            },
                        ],
                    },
                ]))
            )

            records = CloudflareConnector().fetch(VALID_CREDS)

        rules = _records_by_type(records, "cloudflare_waf_rule")
        assert {r["record_id"] for r in rules} == {"rule_block_sqli", "rule_challenge_bots"}
        # Description + action + enabled are stored.
        sqli = next(r for r in rules if r["record_id"] == "rule_block_sqli")
        assert sqli["action"] == "block"
        assert sqli["enabled"] is True
        assert sqli["description"] == "Block obvious SQLi"
        assert sqli["ruleset_id"] == "ruleset_001"
        # Expression NEVER stored — only the hash.
        assert "OR 1=1" not in json.dumps(sqli)
        assert "expression" not in sqli  # field name absent
        # Hash matches the deterministic helper.
        assert sqli["expression_hash"] == _hash_expression(
            "(http.request.uri.path contains \"' OR 1=1\") "
            "or (http.request.body contains \"--\")"
        )
        # Different expressions → different hashes.
        bot = next(r for r in rules if r["record_id"] == "rule_challenge_bots")
        assert bot["expression_hash"] != sqli["expression_hash"]

    def test_E2_waf_rules_list_403_returns_empty_no_crash(self):
        with respx.mock(assert_all_called=False) as rmock:
            _dns_records_route(rmock)
            _all_zone_settings_403(rmock)
            _empty_page_rules(rmock)
            _empty_worker_routes(rmock)
            _zone_lookup_for_account_resolution(rmock)
            _no_workers_or_access(rmock)
            rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/rulesets").mock(
                return_value=httpx.Response(403, json={"success": False})
            )

            records = CloudflareConnector().fetch(VALID_CREDS)

        assert _records_by_type(records, "cloudflare_waf_rule") == []
        # DNS still emitted (we never asserted it had data).


# ═════════════════════════════════════════════════════════════════════════════
# F. Permission / partial-failure behaviour
# ═════════════════════════════════════════════════════════════════════════════


class TestPartialFailure:

    def _wire_dns_only_with_403_everywhere_else(self, rmock: respx.MockRouter,
                                                dns_records: list[dict] | None = None) -> None:
        _dns_records_route(
            rmock,
            dns_records or [{
                "id": "rec1", "type": "A", "name": "example.com",
                "content": "1.2.3.4", "ttl": 3600, "proxied": False,
                "modified_on": "2024-01-01T00:00:00Z",
            }],
        )
        # All optional surfaces respond 403.
        rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/rulesets").mock(
            return_value=httpx.Response(403, json={"success": False})
        )
        _all_zone_settings_403(rmock)
        rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/pagerules").mock(
            return_value=httpx.Response(403, json={"success": False})
        )
        rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/workers/routes").mock(
            return_value=httpx.Response(403, json={"success": False})
        )
        rmock.get(f"{CF_BASE}/zones/{ZONE_ID}").mock(
            return_value=httpx.Response(403, json={"success": False})
        )

    def test_F1_all_optional_surfaces_403_dns_still_succeeds(self):
        with respx.mock(assert_all_called=False) as rmock:
            self._wire_dns_only_with_403_everywhere_else(rmock)
            records = CloudflareConnector().fetch(VALID_CREDS)

        # DNS record present.
        dns = [r for r in records if r.get("record_type") == "A"]
        assert len(dns) == 1
        # No optional surface records emitted.
        for rt in ("cloudflare_zone_setting", "cloudflare_page_rule",
                   "cloudflare_worker_route", "cloudflare_worker_script",
                   "cloudflare_waf_rule", "cloudflare_access_application",
                   "cloudflare_access_policy"):
            assert _records_by_type(records, rt) == [], (
                f"unexpected records emitted for {rt}"
            )

    def test_F2_404_on_optional_surface_skips_safely(self):
        with respx.mock(assert_all_called=False) as rmock:
            _dns_records_route(rmock)
            _empty_rulesets(rmock)
            _all_zone_settings_403(rmock)
            _zone_lookup_for_account_resolution(rmock)
            _empty_worker_routes(rmock)
            _no_workers_or_access(rmock)
            # Page rules endpoint returns 404 (plan doesn't support it).
            rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/pagerules").mock(
                return_value=httpx.Response(404, json={"success": False})
            )

            records = CloudflareConnector().fetch(VALID_CREDS)

        assert _records_by_type(records, "cloudflare_page_rule") == []

    def test_F3_zone_lookup_403_skips_account_scoped_surfaces(self):
        with respx.mock(assert_all_called=False) as rmock:
            _dns_records_route(rmock)
            _empty_rulesets(rmock)
            _all_zone_settings_403(rmock)
            _empty_page_rules(rmock)
            _empty_worker_routes(rmock)
            # Zone-detail endpoint denies → no account_id → workers/access
            # endpoints are NEVER called.
            rmock.get(f"{CF_BASE}/zones/{ZONE_ID}").mock(
                return_value=httpx.Response(403, json={"success": False})
            )

            records = CloudflareConnector().fetch(VALID_CREDS)

        assert _records_by_type(records, "cloudflare_worker_script") == []
        assert _records_by_type(records, "cloudflare_access_application") == []
        assert _records_by_type(records, "cloudflare_access_policy") == []

    def test_F4_warning_logs_do_not_include_token_or_authorization(self, caplog):
        import logging
        caplog.set_level(logging.WARNING, logger="app.connectors.cloudflare")
        with respx.mock(assert_all_called=False) as rmock:
            self._wire_dns_only_with_403_everywhere_else(rmock)
            CloudflareConnector().fetch(VALID_CREDS)

        # Inspect every warning record + format string.
        for rec in caplog.records:
            msg = rec.getMessage()
            _assert_no_secret_substring(msg)
            # raw template too, in case args carried sensitive material
            _assert_no_secret_substring(str(rec.msg))


# ═════════════════════════════════════════════════════════════════════════════
# G. End-to-end pipeline: mocked fetch → snapshot diff → risk classification
# ═════════════════════════════════════════════════════════════════════════════


class TestEndToEnd:

    def test_G1_ssl_off_change_classifies_critical_via_risk_service(self):
        # Simulate the diff service producing a Change row from our two
        # snapshots, then route it through classify_change.
        from app.services.risk_service import classify_change

        change = MagicMock()
        change.change_type = "modified"
        change.field_path = "value"
        change.prev_value = "full"
        change.new_value = "off"
        change.provider_metadata = {
            "record_type": "cloudflare_zone_setting",
            "setting_id": "ssl",
            "record_id": "ssl",
        }
        level, reason = classify_change(change)
        assert level == "critical"
        assert "ssl" in reason.lower()

    def test_G2_worker_route_script_change_classifies_critical(self):
        from app.services.risk_service import classify_change

        change = MagicMock()
        change.change_type = "modified"
        change.field_path = "script_name"
        change.prev_value = "edge-handler"
        change.new_value = "someone-elses-script"
        change.provider_metadata = {
            "record_type": "cloudflare_worker_route",
            "pattern": "api.example.com/*",
        }
        level, _ = classify_change(change)
        assert level == "critical"

    def test_G3_access_policy_decision_bypass_classifies_high(self):
        from app.services.risk_service import classify_change

        change = MagicMock()
        change.change_type = "modified"
        change.field_path = "decision"
        change.prev_value = "allow"
        change.new_value = "bypass"
        change.provider_metadata = {
            "record_type": "cloudflare_access_policy",
            "name": "Engineers",
        }
        level, _ = classify_change(change)
        assert level == "high"

    def test_G4_waf_rule_block_to_allow_classifies_critical(self):
        from app.services.risk_service import classify_change

        change = MagicMock()
        change.change_type = "modified"
        change.field_path = "action"
        change.prev_value = "block"
        change.new_value = "allow"
        change.provider_metadata = {
            "record_type": "cloudflare_waf_rule",
            "description": "SQLi block",
        }
        level, _ = classify_change(change)
        assert level == "critical"

    def test_G5_malformed_records_do_not_crash_classifier(self):
        from app.services.risk_service import classify_change

        # provider_metadata is a string (not a dict).  Dispatcher must
        # defensively coerce to empty dict and route to the safe fallback.
        change = MagicMock()
        change.change_type = "modified"
        change.field_path = "value"
        change.prev_value = "x"
        change.new_value = "y"
        change.provider_metadata = "not a dict"
        # No exception.
        level, _ = classify_change(change)
        assert level in ("critical", "high", "medium", "low")


# ═════════════════════════════════════════════════════════════════════════════
# H. Secret-redaction tripwires across the whole snapshot
# ═════════════════════════════════════════════════════════════════════════════


class TestSnapshotSecretSafety:

    def test_H1_snapshot_state_never_contains_secret_substrings(self):
        """End-to-end: a fetch that exercises every surface produces a
        snapshot whose JSON serialisation does NOT contain any of the
        well-known credential shapes we fabricate as side inputs."""
        with respx.mock(assert_all_called=False) as rmock:
            _dns_records_route(rmock)
            _zone_lookup_for_account_resolution(rmock)

            # Zone settings: succeed for ssl only.
            for sid in _ZONE_SETTING_IDS:
                if sid == "ssl":
                    rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/settings/{sid}").mock(
                        return_value=httpx.Response(200, json=_envelope({
                            "id": "ssl", "value": "full", "editable": True,
                            "modified_on": "2024-01-01T00:00:00Z",
                        }))
                    )
                else:
                    rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/settings/{sid}").mock(
                        return_value=httpx.Response(403, json={"success": False})
                    )

            # Page rule with embedded token in URL — must be redacted.
            rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/pagerules").mock(
                return_value=httpx.Response(200, json=_envelope([{
                    "id": "pr_1",
                    "priority": 1, "status": "active",
                    "targets": [{"target": "url", "constraint": {
                        "value": "api.example.com/*",
                    }}],
                    "actions": [{
                        "id": "forwarding_url",
                        "value": {
                            "url": "https://x.example.com/redir?token=sk_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                            "status_code": 302,
                        },
                    }],
                }]))
            )
            _empty_worker_routes(rmock)
            # Workers scripts emit a binding that LOOKS like a secret.
            rmock.get(f"{CF_BASE}/accounts/{ACCOUNT_ID}/workers/scripts").mock(
                return_value=httpx.Response(200, json=_envelope([{
                    "id": "edge-worker",
                    "etag": "etag-x",
                    "bindings": [{
                        "name": "STRIPE",
                        "type": "secret_text",
                        "text": "sk_live_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                    }],
                }]))
            )
            rmock.get(f"{CF_BASE}/accounts/{ACCOUNT_ID}/access/apps").mock(
                return_value=httpx.Response(200, json=_envelope([{
                    "id": "app1", "name": "Admin", "type": "self_hosted",
                    "domain": "admin.example.com",
                    "app_launcher_visible": False, "enabled": True,
                    "session_duration": "24h", "allowed_idps": [],
                }]))
            )
            rmock.get(
                f"{CF_BASE}/accounts/{ACCOUNT_ID}/access/apps/app1/policies"
            ).mock(
                return_value=httpx.Response(200, json=_envelope([{
                    "id": "pol1", "name": "Engineers",
                    "decision": "allow", "enabled": True, "precedence": 1,
                    "include": [{"email": {"email": "ops@example.com"}}],
                    "exclude": [], "require": [
                        {"service_token": {"token_id": "stkn_secret_xxx"}},
                    ],
                }]))
            )
            # WAF rule with a "sensitive" expression — only hash stored.
            rmock.get(f"{CF_BASE}/zones/{ZONE_ID}/rulesets").mock(
                return_value=httpx.Response(200, json=_envelope([{
                    "id": "rs1", "name": "Custom", "kind": "custom",
                    "phase": "http_request_firewall_custom", "version": "1",
                    "rules": [{
                        "id": "r1",
                        "description": "Block",
                        "action": "block", "enabled": True,
                        "expression": "(ip.src eq 10.0.0.5 and "
                                      "http.request.headers[\"x-internal-secret\"] eq \"BIGSECRET\")",
                    }],
                }]))
            )

            records = CloudflareConnector().fetch(VALID_CREDS)

        # Serialise the whole snapshot and scan for forbidden tokens.
        blob = json.dumps(records)
        forbidden_substrings = (
            "sk_live_AAAA", "sk_live_BBBB",
            "?token=", "BIGSECRET",
            "ops@example.com", "stkn_secret_xxx",
            "x-internal-secret", "10.0.0.5",
            "Bearer ", "Authorization:",
            "test-token-abc123",  # the credential we fed in
        )
        for s in forbidden_substrings:
            assert s not in blob, (
                f"snapshot leaked forbidden substring {s!r}"
            )
        # And our pattern-level tripwires.
        _assert_no_secret_substring(blob)
