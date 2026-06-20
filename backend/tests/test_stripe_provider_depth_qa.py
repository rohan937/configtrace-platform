"""Stripe provider depth QA.

Durable guardrails that pin the full Stripe rule taxonomy across every
registration surface and validate the behavioral invariants hardened during the
Stripe QA pass:

  Group 1. Registry / confidence / pack / coverage / frontend-catalog parity
           for all 8 Stripe rule keys.
  Group 2. Backend/frontend severity + category match.
  Group 3. Evidence metadata safety — no forbidden (secret / PII) fields.
  Group 4. No forbidden claim phrases in the Stripe rule module.
  Group 5. Broad-events threshold constant behavior.
  Group 6. Schema Optional import — typing.get_type_hints() works.
  Group 7. Intentional deferred coverage for the payment-method
           configuration / domain record types.
"""

from __future__ import annotations

import re
import typing
from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend" / "app"
FRONTEND = REPO_ROOT / "frontend" / "src"

STRIPE_RULES_FILE = BACKEND / "services" / "security_rules" / "stripe.py"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

# ── Canonical 8-rule set ──────────────────────────────────────────────────────

ALL_STRIPE_RULE_KEYS: frozenset[str] = frozenset({
    "stripe_webhook_http",
    "stripe_webhook_disabled",
    "stripe_webhook_broad_events",
    "stripe_payment_link_tax_disabled",
    "stripe_payment_link_promo_codes_enabled",
    "stripe_portal_subscription_cancel_enabled",
    "stripe_portal_login_enabled",
    "stripe_account_capability_incomplete",
})

EXPECTED_SEVERITY: dict[str, str] = {
    "stripe_webhook_http": "critical",
    "stripe_webhook_disabled": "medium",
    "stripe_webhook_broad_events": "medium",
    "stripe_payment_link_tax_disabled": "medium",
    "stripe_payment_link_promo_codes_enabled": "low",
    "stripe_portal_subscription_cancel_enabled": "low",
    "stripe_portal_login_enabled": "medium",
    "stripe_account_capability_incomplete": "medium",
}

EXPECTED_CATEGORY: dict[str, str] = {
    "stripe_webhook_http": "Webhooks",
    "stripe_webhook_disabled": "Webhooks",
    "stripe_webhook_broad_events": "Webhooks",
    "stripe_payment_link_tax_disabled": "Payment links",
    "stripe_payment_link_promo_codes_enabled": "Payment links",
    "stripe_portal_subscription_cancel_enabled": "Customer portal",
    "stripe_portal_login_enabled": "Customer portal",
    "stripe_account_capability_incomplete": "Account",
}

# Record types intentionally NOT covered by any active rule. These payment-method
# configuration/domain surfaces emit only coarse operational toggles (per-method
# enable flags, Apple/Google Pay status, a domain ``enabled`` boolean that is
# almost always True in production). They are too easily false-positive to back a
# high-signal security finding, so coverage is intentionally deferred — this list
# makes that gap explicit rather than accidental.
DEFERRED_RECORD_TYPES: list[str] = [
    "stripe_payment_method_configuration",
    "stripe_payment_method_domain",
]

# Forbidden claim phrases — never appear in Stripe rule code.
FORBIDDEN_PHRASES = [
    "breach confirmed",
    "compromise confirmed",
    "attacker found",
    "someone has access",
    "data leaked",
    "secret leaked",
    "customer data exposed",
    "card data exposed",
    "unauthorized access confirmed",
    "payment fraud detected",
    "attack detected",
    "fraud confirmed",
]

# Evidence dicts must never carry secret-bearing or PII-bearing keys.
FORBIDDEN_EVIDENCE_KEYS = [
    "secret_key",
    "restricted_key",
    "publishable_key",
    "api_key",
    "token",
    "oauth_token",
    "authorization",
    "payload",
    "request",
    "response",
    "raw",
    "secret",
    "secret_value",
    "webhook_secret",
    "client_secret",
    "checkout_url",
    "portal_url",
    "customer_email",
    "customer_name",
    "phone",
    "address",
    "payment_method",
    "card",
    "card_number",
    "last4",
    "invoice_description",
    "metadata",
    "customer",
]


def _rule_key(f: Any) -> str:
    return f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")


def _severity(f: Any) -> str:
    return f.severity if hasattr(f, "severity") else f.get("severity", "")


def _evidence(f: Any) -> dict:
    ev = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
    return ev if isinstance(ev, dict) else {}


def _description(f: Any) -> str:
    return (f.description if hasattr(f, "description") else f.get("description", "")) or ""


# ── Group 1: Registry / confidence / pack / coverage / catalog parity ─────────

def test_stripe_rule_key_count() -> None:
    assert len(ALL_STRIPE_RULE_KEYS) == 8


def test_all_stripe_rule_keys_in_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    for key in ALL_STRIPE_RULE_KEYS:
        assert key in KNOWN_RULE_KEYS, (
            f"Stripe rule key {key!r} missing from KNOWN_RULE_KEYS"
        )


def test_all_stripe_rule_keys_in_confidence() -> None:
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    for key in ALL_STRIPE_RULE_KEYS:
        assert key in RULE_CONFIDENCE, (
            f"Stripe rule key {key!r} missing from RULE_CONFIDENCE"
        )


def test_all_stripe_rule_keys_in_rule_pack() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_STRIPE_RULE_KEYS:
        assert key in _RULE_META, (
            f"Stripe rule key {key!r} missing from _RULE_META"
        )
        provider, _sev, _cat = _RULE_META[key]
        assert provider == "stripe", (
            f"Rule {key!r} has wrong provider in _RULE_META: {provider!r}"
        )


def test_all_stripe_rule_keys_in_coverage() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    for key in ALL_STRIPE_RULE_KEYS:
        assert key in RULE_RECORD_TYPES, (
            f"Stripe rule key {key!r} missing from coverage RULE_RECORD_TYPES"
        )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_all_stripe_rule_keys_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    missing = [k for k in ALL_STRIPE_RULE_KEYS if k not in text]
    assert not missing, (
        f"Stripe rule keys missing from securityRuleCatalog.ts: {missing}"
    )


# ── Group 2: Severity / category parity (backend pack vs frontend catalog) ────

def test_rule_pack_severity_and_category_match_expected() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_STRIPE_RULE_KEYS:
        _provider, sev, cat = _RULE_META[key]
        assert sev == EXPECTED_SEVERITY[key], (
            f"Rule {key!r}: pack severity {sev!r} != expected {EXPECTED_SEVERITY[key]!r}"
        )
        assert cat == EXPECTED_CATEGORY[key], (
            f"Rule {key!r}: pack category {cat!r} != expected {EXPECTED_CATEGORY[key]!r}"
        )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_severity_matches_backend() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for key, expected_sev in EXPECTED_SEVERITY.items():
        idx = text.find(f'key: "{key}"')
        assert idx != -1, f"Stripe rule {key!r} not found in frontend catalog"
        block = text[idx:idx + 700]
        assert f'severity: "{expected_sev}"' in block, (
            f"Frontend severity for {key!r} does not match backend ({expected_sev!r})"
        )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_category_matches_backend() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for key, expected_cat in EXPECTED_CATEGORY.items():
        idx = text.find(f'key: "{key}"')
        assert idx != -1, f"Stripe rule {key!r} not found in frontend catalog"
        block = text[idx:idx + 700]
        assert f'category: "{expected_cat}"' in block, (
            f"Frontend category for {key!r} does not match backend ({expected_cat!r})"
        )


# ── Group 3: Evidence metadata safety ─────────────────────────────────────────

def _all_stripe_findings() -> list[Any]:
    """Fire every Stripe rule across representative risky records."""
    from app.services.security_rules.stripe import evaluate
    from app.connectors.stripe_schema import (
        STRIPE_ACCOUNT_SETTINGS,
        STRIPE_BILLING_PORTAL_CONFIG,
        STRIPE_PAYMENT_LINK,
        STRIPE_WEBHOOK_ENDPOINT,
    )

    records = [
        {
            "record_type": STRIPE_WEBHOOK_ENDPOINT,
            "record_id": "we_http",
            "url": "http://insecure.example.com/hook",
            "status": "enabled",
            "enabled_events": ["*"],
        },
        {
            "record_type": STRIPE_WEBHOOK_ENDPOINT,
            "record_id": "we_disabled",
            "url": "https://example.com/hook",
            "status": "disabled",
            "enabled_events": ["charge.succeeded"],
        },
        {
            "record_type": STRIPE_PAYMENT_LINK,
            "record_id": "plink_1",
            "active": True,
            "automatic_tax_enabled": False,
            "allow_promotion_codes": True,
        },
        {
            "record_type": STRIPE_BILLING_PORTAL_CONFIG,
            "record_id": "bpc_1",
            "active": True,
            "subscription_cancel_enabled": True,
            "login_page_enabled": True,
        },
        {
            "record_type": STRIPE_ACCOUNT_SETTINGS,
            "record_id": "acct_1",
            "charges_enabled": False,
            "payouts_enabled": False,
            "details_submitted": False,
        },
    ]
    out: list[Any] = []
    for r in records:
        out.extend(evaluate(r))
    return out


def test_all_eight_rules_fire_across_synthetic_records() -> None:
    fired = {_rule_key(f) for f in _all_stripe_findings()}
    missing = ALL_STRIPE_RULE_KEYS - fired
    assert not missing, f"Synthetic records did not fire rules: {sorted(missing)}"


def test_stripe_evidence_has_no_forbidden_keys() -> None:
    findings = _all_stripe_findings()
    assert findings, "expected at least one finding across representative records"
    for f in findings:
        ev_keys = set(_evidence(f))
        for forbidden in FORBIDDEN_EVIDENCE_KEYS:
            assert forbidden not in ev_keys, (
                f"Forbidden evidence key {forbidden!r} in finding "
                f"{_rule_key(f)!r}: {sorted(ev_keys)}"
            )


def test_stripe_evidence_is_flat_safe_scalars() -> None:
    for f in _all_stripe_findings():
        for v in _evidence(f).values():
            assert isinstance(v, (str, int, float, bool, list, type(None))), (
                f"Non-scalar value in evidence of {_rule_key(f)!r}: {type(v).__name__}"
            )
            if isinstance(v, list):
                for item in v:
                    assert isinstance(item, (str, int, float, bool, type(None)))


# ── Group 4: Forbidden wording ────────────────────────────────────────────────

def _strip_docstrings_and_comments(src: str) -> str:
    src = re.sub(r'""".*?"""', "", src, flags=re.DOTALL)
    src = re.sub(r"'''.*?'''", "", src, flags=re.DOTALL)
    src = re.sub(r"#[^\n]*", "", src)
    return src


def test_no_forbidden_phrases_in_stripe_rules_module() -> None:
    src = _strip_docstrings_and_comments(
        STRIPE_RULES_FILE.read_text(encoding="utf-8")
    ).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in src, (
            f"Forbidden phrase {phrase!r} found in stripe rules module code"
        )


def test_no_forbidden_phrases_in_stripe_finding_copy() -> None:
    for f in _all_stripe_findings():
        dl = _description(f).lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase.lower() not in dl, (
                f"Finding {_rule_key(f)!r} description contains forbidden "
                f"phrase {phrase!r}"
            )


# ── Group 5: Broad-events threshold constant ──────────────────────────────────

def test_broad_event_threshold_constant_value() -> None:
    from app.services.security_rules.stripe import BROAD_WEBHOOK_EVENT_THRESHOLD
    assert BROAD_WEBHOOK_EVENT_THRESHOLD == 50


def _webhook_record(record_id: str, events: list[str], status: str = "enabled") -> dict:
    from app.connectors.stripe_schema import STRIPE_WEBHOOK_ENDPOINT
    return {
        "record_type": STRIPE_WEBHOOK_ENDPOINT,
        "record_id": record_id,
        "url": "https://example.com/hook",
        "status": status,
        "enabled_events": events,
    }


def test_wildcard_events_trigger_broad_rule() -> None:
    from app.services.security_rules.stripe import evaluate
    rec = _webhook_record("we_wild", ["*"])
    assert "stripe_webhook_broad_events" in [_rule_key(f) for f in evaluate(rec)]


def test_exactly_threshold_events_triggers_broad_rule() -> None:
    from app.services.security_rules.stripe import (
        BROAD_WEBHOOK_EVENT_THRESHOLD,
        evaluate,
    )
    events = [f"evt.type.{i}" for i in range(BROAD_WEBHOOK_EVENT_THRESHOLD)]
    rec = _webhook_record("we_exact", events)
    assert len(events) == BROAD_WEBHOOK_EVENT_THRESHOLD
    assert "stripe_webhook_broad_events" in [_rule_key(f) for f in evaluate(rec)]


def test_below_threshold_events_does_not_trigger_broad_rule() -> None:
    from app.services.security_rules.stripe import (
        BROAD_WEBHOOK_EVENT_THRESHOLD,
        evaluate,
    )
    events = [f"evt.type.{i}" for i in range(BROAD_WEBHOOK_EVENT_THRESHOLD - 1)]
    rec = _webhook_record("we_below", events, status="enabled")
    assert len(events) == BROAD_WEBHOOK_EVENT_THRESHOLD - 1
    assert "stripe_webhook_broad_events" not in [_rule_key(f) for f in evaluate(rec)]


# ── Group 6: Schema Optional import ───────────────────────────────────────────

def test_schema_get_type_hints_does_not_raise_nameerror() -> None:
    """TypedDicts using Optional[...] must resolve under typing.get_type_hints().

    Before the Optional import fix this raised NameError because the annotation
    name was unresolved at hint-resolution time (PEP 563 lazy annotations hid the
    gap at runtime but not for static hint resolution).
    """
    from app.connectors import stripe_schema

    # StripeProductRecord uses Optional[str] / Optional[int] annotations.
    hints = typing.get_type_hints(stripe_schema.StripeProductRecord)
    assert "default_price" in hints
    # StripePriceRecord also relies on Optional.
    typing.get_type_hints(stripe_schema.StripePriceRecord)


def test_optional_is_imported_in_schema_module() -> None:
    from app.connectors import stripe_schema
    assert hasattr(stripe_schema, "Optional")


# ── Group 7: Deferred coverage documentation ──────────────────────────────────

def test_payment_method_record_types_are_covered_or_deferred() -> None:
    """Each payment-method config/domain record type must be either covered by a
    registered rule or explicitly listed as intentionally deferred."""
    from app.services.security_coverage_service import RULE_RECORD_TYPES

    covered_record_types: set[str] = set()
    for record_types in RULE_RECORD_TYPES.values():
        covered_record_types.update(record_types)

    for rtype in (
        "stripe_payment_method_configuration",
        "stripe_payment_method_domain",
    ):
        assert (rtype in covered_record_types) or (rtype in DEFERRED_RECORD_TYPES), (
            f"Record type {rtype!r} is neither covered by a rule nor documented "
            f"as deferred — coverage gap must be intentional"
        )


def test_deferred_record_types_are_real_schema_constants() -> None:
    """Guard against typos: the deferred record types must match schema constants."""
    from app.connectors.stripe_schema import (
        STRIPE_PAYMENT_METHOD_CONFIGURATION,
        STRIPE_PAYMENT_METHOD_DOMAIN,
        STRIPE_RECORD_TYPES,
    )

    assert STRIPE_PAYMENT_METHOD_CONFIGURATION in DEFERRED_RECORD_TYPES
    assert STRIPE_PAYMENT_METHOD_DOMAIN in DEFERRED_RECORD_TYPES
    for rtype in DEFERRED_RECORD_TYPES:
        assert rtype in STRIPE_RECORD_TYPES, (
            f"Deferred record type {rtype!r} is not a known Stripe record type"
        )
