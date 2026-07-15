"""Cloudflare provider depth QA.

Durable guardrails that pin the full Cloudflare rule taxonomy across every
registration surface and validate key behavioral invariants:

  A. Rule key inventory — all 10 Cloudflare rule keys
  B. Registry parity (KNOWN_RULE_KEYS)
  C. Confidence parity (RULE_CONFIDENCE)
  D. Rule-pack parity (_RULE_META)
  E. Coverage-service parity (RULE_RECORD_TYPES)
  F. Frontend catalog parity (securityRuleCatalog.ts)
  G. Backend/frontend severity match
  H. Backend/frontend category match
  I. Access-policy rules present on all 5 surfaces
  J. Access-policy bypass rule fires on risky record
  K. Access-policy bypass rule does not fire on safe record
  L. Access-policy disabled rule fires on risky record
  M. Access-policy disabled rule does not fire on safe record
  N. Evidence metadata safety — no forbidden fields
  O. No forbidden claim phrases in Cloudflare rule module
  P. Capability matrix — Cloudflare entry correct
  Q. Provider expansion framework — roadmap still points to M89A/Kubernetes
  R. No unintentional Terraform/Kubernetes changes staged
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend" / "app"
FRONTEND = REPO_ROOT / "frontend" / "src"

CLOUDFLARE_RULES_FILE = BACKEND / "services" / "security_rules" / "cloudflare.py"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

# ── Canonical 10-rule set ─────────────────────────────────────────────────────

ALL_CLOUDFLARE_RULE_KEYS: frozenset[str] = frozenset({
    # Zone-setting rules (M60.4.3)
    "cloudflare_ssl_mode_weak",
    "cloudflare_always_https_off",
    "cloudflare_min_tls_weak",
    "cloudflare_security_level_low",
    "cloudflare_development_mode_on",
    "cloudflare_hsts_disabled",
    # WAF rule (M57.7)
    "cloudflare_waf_rule_disabled",
    # DNS rule
    "cloudflare_dns_private_origin",
    # Access-policy rules (M68.3) — the two previously missing registrations
    "cloudflare_access_policy_bypass",
    "cloudflare_access_policy_disabled",
    # Change-classification-QA pass — two new high-signal, low-noise rules
    "cloudflare_page_rule_http_forward",
    "cloudflare_access_application_disabled",
})

# Severity expected per rule (matches security_rules/cloudflare.py)
EXPECTED_SEVERITY: dict[str, str] = {
    "cloudflare_ssl_mode_weak": "high",
    "cloudflare_always_https_off": "medium",
    "cloudflare_min_tls_weak": "medium",
    "cloudflare_security_level_low": "medium",
    "cloudflare_development_mode_on": "medium",
    "cloudflare_hsts_disabled": "medium",
    "cloudflare_waf_rule_disabled": "high",
    "cloudflare_dns_private_origin": "high",
    "cloudflare_access_policy_bypass": "high",
    "cloudflare_access_policy_disabled": "medium",
    "cloudflare_page_rule_http_forward": "medium",
    "cloudflare_access_application_disabled": "high",
}

# Category expected per rule (matches rule pack)
EXPECTED_CATEGORY: dict[str, str] = {
    "cloudflare_ssl_mode_weak": "SSL/TLS",
    "cloudflare_always_https_off": "HTTPS",
    "cloudflare_min_tls_weak": "SSL/TLS",
    "cloudflare_security_level_low": "WAF / security",
    "cloudflare_development_mode_on": "WAF / security",
    "cloudflare_hsts_disabled": "HTTPS",
    "cloudflare_waf_rule_disabled": "WAF / security",
    "cloudflare_dns_private_origin": "DNS",
    "cloudflare_access_policy_bypass": "Access control",
    "cloudflare_access_policy_disabled": "Access control",
    "cloudflare_page_rule_http_forward": "Page Rules",
    "cloudflare_access_application_disabled": "Access control",
}

FORBIDDEN_PHRASES = [
    "breach confirmed",
    "compromise confirmed",
    "attacker found",
    "someone has access",
    "data leaked",
    "secret leaked",
    "customer data exposed",
    "unauthorized access confirmed",
    "payment fraud detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
]

FORBIDDEN_EVIDENCE_KEYS = [
    "api_token",
    "access_token",
    "authorization",
    "raw_expression",
    "expression",
    "email",
    "ip_address",
    "password",
    "secret",
    "credential",
]


# ── Section A: Rule key inventory ─────────────────────────────────────────────

def test_cloudflare_rule_key_count() -> None:
    assert len(ALL_CLOUDFLARE_RULE_KEYS) == 12


def test_all_cloudflare_rule_keys_are_strings() -> None:
    for key in ALL_CLOUDFLARE_RULE_KEYS:
        assert isinstance(key, str)
        assert key.startswith("cloudflare_")


def test_access_policy_rules_in_canonical_set() -> None:
    assert "cloudflare_access_policy_bypass" in ALL_CLOUDFLARE_RULE_KEYS
    assert "cloudflare_access_policy_disabled" in ALL_CLOUDFLARE_RULE_KEYS


# ── Section B: Registry parity ────────────────────────────────────────────────

def test_all_cloudflare_rule_keys_in_rule_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    for key in ALL_CLOUDFLARE_RULE_KEYS:
        assert key in KNOWN_RULE_KEYS, (
            f"Cloudflare rule key {key!r} missing from KNOWN_RULE_KEYS"
        )


def test_access_policy_bypass_in_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    assert "cloudflare_access_policy_bypass" in KNOWN_RULE_KEYS


def test_access_policy_disabled_in_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    assert "cloudflare_access_policy_disabled" in KNOWN_RULE_KEYS


# ── Section C: Confidence parity ──────────────────────────────────────────────

def test_all_cloudflare_rule_keys_in_confidence() -> None:
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    for key in ALL_CLOUDFLARE_RULE_KEYS:
        assert key in RULE_CONFIDENCE, (
            f"Cloudflare rule key {key!r} missing from RULE_CONFIDENCE"
        )


def test_access_policy_rules_have_high_confidence() -> None:
    from app.services.security_rule_confidence import RULE_CONFIDENCE, HIGH
    assert RULE_CONFIDENCE.get("cloudflare_access_policy_bypass", (None,))[0] == HIGH
    assert RULE_CONFIDENCE.get("cloudflare_access_policy_disabled", (None,))[0] == HIGH


# ── Section D: Rule-pack parity ───────────────────────────────────────────────

def test_all_cloudflare_rule_keys_in_rule_pack() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_CLOUDFLARE_RULE_KEYS:
        assert key in _RULE_META, (
            f"Cloudflare rule key {key!r} missing from _RULE_META"
        )


def test_rule_pack_cloudflare_provider() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_CLOUDFLARE_RULE_KEYS:
        provider, _sev, _cat = _RULE_META[key]
        assert provider == "cloudflare", (
            f"Rule {key!r} has wrong provider in _RULE_META: {provider!r}"
        )


def test_rule_pack_severity_matches_expected() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_CLOUDFLARE_RULE_KEYS:
        _provider, sev, _cat = _RULE_META[key]
        expected = EXPECTED_SEVERITY[key]
        assert sev == expected, (
            f"Rule {key!r}: pack severity {sev!r} != expected {expected!r}"
        )


def test_rule_pack_category_matches_expected() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_CLOUDFLARE_RULE_KEYS:
        _provider, _sev, cat = _RULE_META[key]
        expected = EXPECTED_CATEGORY[key]
        assert cat == expected, (
            f"Rule {key!r}: pack category {cat!r} != expected {expected!r}"
        )


def test_access_policy_bypass_is_high_in_pack() -> None:
    from app.services.security_rule_pack import _RULE_META
    _provider, sev, cat = _RULE_META["cloudflare_access_policy_bypass"]
    assert sev == "high"
    assert cat == "Access control"


def test_access_policy_disabled_is_medium_in_pack() -> None:
    from app.services.security_rule_pack import _RULE_META
    _provider, sev, cat = _RULE_META["cloudflare_access_policy_disabled"]
    assert sev == "medium"
    assert cat == "Access control"


# ── Section E: Coverage-service parity ────────────────────────────────────────

def test_all_cloudflare_rule_keys_in_coverage() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    for key in ALL_CLOUDFLARE_RULE_KEYS:
        assert key in RULE_RECORD_TYPES, (
            f"Cloudflare rule key {key!r} missing from RULE_RECORD_TYPES"
        )


def test_access_policy_rules_map_to_correct_record_type() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    assert "cloudflare_access_policy" in RULE_RECORD_TYPES[
        "cloudflare_access_policy_bypass"
    ]
    assert "cloudflare_access_policy" in RULE_RECORD_TYPES[
        "cloudflare_access_policy_disabled"
    ]


# ── Section F: Frontend catalog parity ────────────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_all_cloudflare_rule_keys_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    missing = [k for k in ALL_CLOUDFLARE_RULE_KEYS if k not in text]
    assert not missing, (
        f"Cloudflare rule keys missing from securityRuleCatalog.ts: {missing}"
    )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_access_policy_bypass_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    assert "cloudflare_access_policy_bypass" in text


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_access_policy_disabled_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    assert "cloudflare_access_policy_disabled" in text


# ── Section G: Backend/frontend severity match ────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_severity_matches_backend() -> None:
    """Every Cloudflare rule key in the frontend catalog has the expected severity."""
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for key, expected_sev in EXPECTED_SEVERITY.items():
        # Find the entry block for this key
        idx = text.find(f'key: "{key}"')
        if idx == -1:
            continue  # covered by catalog-presence test above
        block = text[idx:idx + 500]
        assert f'severity: "{expected_sev}"' in block, (
            f"Frontend severity for {key!r} does not match backend ({expected_sev!r})"
        )


# ── Section H: Backend/frontend category match ────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_category_matches_backend() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for key, expected_cat in EXPECTED_CATEGORY.items():
        idx = text.find(f'key: "{key}"')
        if idx == -1:
            continue
        block = text[idx:idx + 500]
        assert f'category: "{expected_cat}"' in block, (
            f"Frontend category for {key!r} does not match backend ({expected_cat!r})"
        )


# ── Section I: Access-policy rules present on all 5 surfaces ──────────────────

def test_access_policy_bypass_on_all_5_surfaces() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    from app.services.security_rule_pack import _RULE_META
    from app.services.security_coverage_service import RULE_RECORD_TYPES

    key = "cloudflare_access_policy_bypass"
    assert key in KNOWN_RULE_KEYS
    assert key in RULE_CONFIDENCE
    assert key in _RULE_META
    assert key in RULE_RECORD_TYPES

    if FE_RULE_CATALOG.exists():
        assert key in FE_RULE_CATALOG.read_text(encoding="utf-8")


def test_access_policy_disabled_on_all_5_surfaces() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    from app.services.security_rule_pack import _RULE_META
    from app.services.security_coverage_service import RULE_RECORD_TYPES

    key = "cloudflare_access_policy_disabled"
    assert key in KNOWN_RULE_KEYS
    assert key in RULE_CONFIDENCE
    assert key in _RULE_META
    assert key in RULE_RECORD_TYPES

    if FE_RULE_CATALOG.exists():
        assert key in FE_RULE_CATALOG.read_text(encoding="utf-8")


# ── Section J: bypass rule fires on risky record ──────────────────────────────

def test_access_policy_bypass_fires_on_bypass_decision() -> None:
    from app.services.security_rules.cloudflare import evaluate
    from app.connectors.cloudflare_schema import CLOUDFLARE_ACCESS_POLICY

    record = {
        "record_type": CLOUDFLARE_ACCESS_POLICY,
        "record_id": "pol-bypass-001",
        "name": "Bypass all",
        "decision": "bypass",
        "enabled": True,
        "application_id": "app-001",
    }
    findings = evaluate(record)
    rule_keys = [
        f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")
        for f in findings
    ]
    assert "cloudflare_access_policy_bypass" in rule_keys


def test_access_policy_bypass_severity_is_high() -> None:
    from app.services.security_rules.cloudflare import evaluate
    from app.connectors.cloudflare_schema import CLOUDFLARE_ACCESS_POLICY

    record = {
        "record_type": CLOUDFLARE_ACCESS_POLICY,
        "record_id": "pol-bypass-002",
        "name": "Bypass all",
        "decision": "bypass",
        "enabled": True,
        "application_id": "app-002",
    }
    findings = evaluate(record)
    bypass_findings = [
        f for f in findings
        if (f.rule_key if hasattr(f, "rule_key") else f.get("rule_key")) == "cloudflare_access_policy_bypass"
    ]
    assert bypass_findings, "cloudflare_access_policy_bypass did not fire"
    f = bypass_findings[0]
    sev = f.severity if hasattr(f, "severity") else f.get("severity")
    assert sev == "high"


# ── Section K: bypass rule safe on non-bypass decisions ───────────────────────

@pytest.mark.parametrize("decision", ["allow", "deny", "non_identity", ""])
def test_access_policy_bypass_does_not_fire_on_safe_decisions(decision: str) -> None:
    from app.services.security_rules.cloudflare import evaluate
    from app.connectors.cloudflare_schema import CLOUDFLARE_ACCESS_POLICY

    record = {
        "record_type": CLOUDFLARE_ACCESS_POLICY,
        "record_id": f"pol-safe-{decision}",
        "name": "Safe policy",
        "decision": decision,
        "enabled": True,
        "application_id": "app-safe",
    }
    findings = evaluate(record)
    rule_keys = [
        f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")
        for f in findings
    ]
    assert "cloudflare_access_policy_bypass" not in rule_keys, (
        f"cloudflare_access_policy_bypass fired on safe decision {decision!r}"
    )


# ── Section L: disabled rule fires on explicitly-disabled policy ───────────────

def test_access_policy_disabled_fires_when_enabled_is_false() -> None:
    from app.services.security_rules.cloudflare import evaluate
    from app.connectors.cloudflare_schema import CLOUDFLARE_ACCESS_POLICY

    record = {
        "record_type": CLOUDFLARE_ACCESS_POLICY,
        "record_id": "pol-disabled-001",
        "name": "Disabled policy",
        "decision": "allow",
        "enabled": False,
        "application_id": "app-disabled",
    }
    findings = evaluate(record)
    rule_keys = [
        f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")
        for f in findings
    ]
    assert "cloudflare_access_policy_disabled" in rule_keys


def test_access_policy_disabled_severity_is_medium() -> None:
    from app.services.security_rules.cloudflare import evaluate
    from app.connectors.cloudflare_schema import CLOUDFLARE_ACCESS_POLICY

    record = {
        "record_type": CLOUDFLARE_ACCESS_POLICY,
        "record_id": "pol-disabled-002",
        "name": "Disabled policy",
        "decision": "allow",
        "enabled": False,
        "application_id": "app-disabled-2",
    }
    findings = evaluate(record)
    disabled_findings = [
        f for f in findings
        if (f.rule_key if hasattr(f, "rule_key") else f.get("rule_key")) == "cloudflare_access_policy_disabled"
    ]
    assert disabled_findings, "cloudflare_access_policy_disabled did not fire"
    f = disabled_findings[0]
    sev = f.severity if hasattr(f, "severity") else f.get("severity")
    assert sev == "medium"


# ── Section M: disabled rule safe on enabled policies ─────────────────────────

def test_access_policy_disabled_does_not_fire_on_enabled_policy() -> None:
    from app.services.security_rules.cloudflare import evaluate
    from app.connectors.cloudflare_schema import CLOUDFLARE_ACCESS_POLICY

    record = {
        "record_type": CLOUDFLARE_ACCESS_POLICY,
        "record_id": "pol-active-001",
        "name": "Active policy",
        "decision": "allow",
        "enabled": True,
        "application_id": "app-active",
    }
    findings = evaluate(record)
    rule_keys = [
        f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")
        for f in findings
    ]
    assert "cloudflare_access_policy_disabled" not in rule_keys


def test_access_policy_disabled_does_not_fire_when_enabled_absent() -> None:
    """When 'enabled' is absent the rule must not fire (avoid false positives)."""
    from app.services.security_rules.cloudflare import evaluate
    from app.connectors.cloudflare_schema import CLOUDFLARE_ACCESS_POLICY

    record = {
        "record_type": CLOUDFLARE_ACCESS_POLICY,
        "record_id": "pol-no-enabled",
        "name": "Policy without enabled field",
        "decision": "allow",
        "application_id": "app-no-enabled",
    }
    findings = evaluate(record)
    rule_keys = [
        f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")
        for f in findings
    ]
    assert "cloudflare_access_policy_disabled" not in rule_keys, (
        "cloudflare_access_policy_disabled fired when 'enabled' field was absent"
    )


# ── Section N: Evidence metadata safety ───────────────────────────────────────

def test_access_policy_evidence_has_no_forbidden_keys() -> None:
    from app.services.security_rules.cloudflare import evaluate
    from app.connectors.cloudflare_schema import CLOUDFLARE_ACCESS_POLICY

    record = {
        "record_type": CLOUDFLARE_ACCESS_POLICY,
        "record_id": "pol-evidence-check",
        "name": "Test policy",
        "decision": "bypass",
        "enabled": False,
        "application_id": "app-evidence",
    }
    findings = evaluate(record)
    for f in findings:
        evidence = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
        if isinstance(evidence, dict):
            for forbidden_key in FORBIDDEN_EVIDENCE_KEYS:
                assert forbidden_key not in evidence, (
                    f"Forbidden key {forbidden_key!r} found in finding evidence: "
                    f"{list(evidence.keys())}"
                )


def test_access_policy_evidence_is_flat_safe_scalars() -> None:
    from app.services.security_rules.cloudflare import evaluate
    from app.connectors.cloudflare_schema import CLOUDFLARE_ACCESS_POLICY

    record = {
        "record_type": CLOUDFLARE_ACCESS_POLICY,
        "record_id": "pol-flat-check",
        "name": "Flat check policy",
        "decision": "bypass",
        "enabled": True,
        "application_id": "app-flat",
    }
    findings = evaluate(record)
    for f in findings:
        evidence = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
        if isinstance(evidence, dict):
            for v in evidence.values():
                assert isinstance(v, (str, int, float, bool, type(None))), (
                    f"Non-scalar value in evidence: {type(v).__name__}"
                )


# ── Section O: No forbidden claim phrases in rule module ──────────────────────

def _strip_docstrings_and_comments(src: str) -> str:
    src = re.sub(r'""".*?"""', "", src, flags=re.DOTALL)
    src = re.sub(r"'''.*?'''", "", src, flags=re.DOTALL)
    src = re.sub(r"#[^\n]*", "", src)
    return src


def test_no_forbidden_phrases_in_cloudflare_rules_module() -> None:
    src = _strip_docstrings_and_comments(
        CLOUDFLARE_RULES_FILE.read_text(encoding="utf-8")
    ).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in src, (
            f"Forbidden phrase {phrase!r} found in cloudflare rules module code"
        )


# ── Section P: Capability matrix ──────────────────────────────────────────────

def test_capability_matrix_cloudflare_entry_exists() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("cloudflare")
    assert cap is not None
    assert cap.provider == "cloudflare"


def test_capability_matrix_cloudflare_drift_snapshots() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("cloudflare")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_risk_classification is True


def test_capability_matrix_cloudflare_security_rules() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("cloudflare")
    assert cap is not None
    assert cap.security.security_rules is True


# ── Section Q: Provider expansion framework ───────────────────────────────────

def test_expansion_framework_planned_next_stage_is_m89a() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert "M89A" in planned or "Kubernetes" in planned, (
        f"planned_next_stage should point to M89A/Kubernetes; got: {planned!r}"
    )


def test_expansion_framework_terraform_cloud_arc_complete() -> None:
    """Terraform Cloud is no longer in the recommended queue (arc M88A-M88I complete)."""
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    queue = fw.get("recommended_next_providers", [])
    providers = [p.get("provider", "") for p in queue]
    assert "terraform_cloud" not in providers, (
        "terraform_cloud should be removed from recommended queue after M88I"
    )


def test_expansion_framework_kubernetes_is_in_queue() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    queue = fw.get("recommended_next_providers", [])
    providers = [p.get("provider", "") for p in queue]
    assert "kubernetes" in providers


# ── Section R: Safety check — Cloudflare evaluator dispatch ───────────────────

def test_cloudflare_evaluator_dispatches_correctly() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    from app.connectors.cloudflare_schema import CLOUDFLARE_ACCESS_POLICY

    record = {
        "record_type": CLOUDFLARE_ACCESS_POLICY,
        "record_id": "pol-dispatch-test",
        "name": "Dispatch test",
        "decision": "bypass",
        "enabled": False,
        "application_id": "app-dispatch",
    }
    findings = evaluate_record(record, "cloudflare")
    assert isinstance(findings, list)
    # Both bypass AND disabled rules should fire
    rule_keys = [
        f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")
        for f in findings
    ]
    assert "cloudflare_access_policy_bypass" in rule_keys
    assert "cloudflare_access_policy_disabled" in rule_keys


def test_cloudflare_page_rule_http_forward_dispatches_via_evaluator() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    from app.connectors.cloudflare_schema import CLOUDFLARE_PAGE_RULE

    record = {
        "record_type": CLOUDFLARE_PAGE_RULE,
        "record_id": "pr-dispatch-test",
        "target_url_pattern": "example.com/*",
        "actions_summary": "forwarding_url:to=http://insecure.example.com,301",
        "rule_kind": "redirect",
        "priority": 1,
        "status": "active",
    }
    findings = evaluate_record(record, "cloudflare")
    rule_keys = [
        f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")
        for f in findings
    ]
    assert "cloudflare_page_rule_http_forward" in rule_keys


def test_cloudflare_page_rule_https_forward_does_not_fire() -> None:
    from app.services.security_rules.cloudflare import evaluate
    record = {
        "record_type": "cloudflare_page_rule",
        "record_id": "pr-safe",
        "target_url_pattern": "example.com/*",
        "actions_summary": "forwarding_url:to=https://secure.example.com,301",
        "rule_kind": "redirect",
    }
    assert evaluate(record) == []


def test_cloudflare_page_rule_non_forwarding_does_not_fire() -> None:
    from app.services.security_rules.cloudflare import evaluate
    record = {
        "record_type": "cloudflare_page_rule",
        "record_id": "pr-cache",
        "target_url_pattern": "example.com/*",
        "actions_summary": "cache_level:cache_everything",
        "rule_kind": "cache_rule",
    }
    assert evaluate(record) == []


def test_cloudflare_access_application_disabled_dispatches_via_evaluator() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    from app.connectors.cloudflare_schema import CLOUDFLARE_ACCESS_APPLICATION

    record = {
        "record_type": CLOUDFLARE_ACCESS_APPLICATION,
        "record_id": "app-dispatch-test",
        "name": "Internal Admin",
        "type": "self_hosted",
        "domain": "admin.example.com",
        "visibility": "private",
        "enabled": False,
        "session_duration": "24h",
        "allowed_idps_count": 1,
    }
    findings = evaluate_record(record, "cloudflare")
    rule_keys = [
        f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")
        for f in findings
    ]
    assert "cloudflare_access_application_disabled" in rule_keys


def test_cloudflare_access_application_enabled_does_not_fire() -> None:
    from app.services.security_rules.cloudflare import evaluate
    record = {
        "record_type": "cloudflare_access_application",
        "record_id": "app-safe",
        "name": "Internal Admin",
        "enabled": True,
    }
    assert evaluate(record) == []


def test_cloudflare_access_application_enabled_absent_does_not_fire() -> None:
    """Unknown/missing 'enabled' must never be treated as an explicit False."""
    from app.services.security_rules.cloudflare import evaluate
    record = {
        "record_type": "cloudflare_access_application",
        "record_id": "app-unknown",
        "name": "Internal Admin",
    }
    assert evaluate(record) == []


def test_cloudflare_evaluate_returns_empty_for_unknown_type() -> None:
    from app.services.security_rules.cloudflare import evaluate
    result = evaluate({"record_type": "unknown_type_xyz"})
    assert result == []


def test_cloudflare_evaluate_returns_empty_for_non_dict() -> None:
    from app.services.security_rules.cloudflare import evaluate
    assert evaluate(None) == []  # type: ignore[arg-type]
    assert evaluate("string") == []  # type: ignore[arg-type]
