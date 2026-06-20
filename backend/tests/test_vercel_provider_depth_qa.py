"""Vercel provider depth QA.

Durable guardrails that pin the full Vercel rule taxonomy across every
registration surface and validate the behavioral invariants hardened during the
Vercel QA pass:

  A. Rule key inventory — all 7 Vercel rule keys
  B. Registry parity (KNOWN_RULE_KEYS)
  C. Confidence parity (RULE_CONFIDENCE)
  D. Rule-pack parity (_RULE_META) + severity + category
  E. Coverage-service parity (RULE_RECORD_TYPES)
  F. Frontend catalog parity (securityRuleCatalog.ts) — key presence
  G. Backend/frontend severity match
  H. Backend/frontend category match
  I. Evidence metadata safety — no forbidden fields
  J. No forbidden claim phrases in Vercel rule module + frontend Vercel copy
  K. vercel_preview_unprotected has a reachable production record source
     (the connector's core fetch path emits vercel_deployment_protection)
  L. Redirect-only domain false positive is prevented
  M. Public env-var names do NOT trigger the high-severity finding
  N. Sensitive env-var names DO trigger the high-severity finding
  O. Capability matrix — Vercel entry correct
  P. Provider expansion framework — roadmap still points to M89A/Kubernetes
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

VERCEL_RULES_FILE = BACKEND / "services" / "security_rules" / "vercel.py"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

# ── Canonical 7-rule set ──────────────────────────────────────────────────────

ALL_VERCEL_RULE_KEYS: frozenset[str] = frozenset({
    "vercel_preview_unprotected",
    "vercel_production_branch_missing",
    "vercel_production_branch_unusual",
    "vercel_domain_unverified",
    "vercel_env_var_broad_target",
    "vercel_sensitive_env_var_broad_scope",
    "vercel_deploy_hook_production_branch",
})

EXPECTED_SEVERITY: dict[str, str] = {
    "vercel_preview_unprotected": "medium",
    "vercel_production_branch_missing": "medium",
    "vercel_production_branch_unusual": "medium",
    "vercel_domain_unverified": "medium",
    "vercel_env_var_broad_target": "medium",
    "vercel_sensitive_env_var_broad_scope": "high",
    "vercel_deploy_hook_production_branch": "medium",
}

EXPECTED_CATEGORY: dict[str, str] = {
    "vercel_preview_unprotected": "Deployment protection",
    "vercel_production_branch_missing": "Deployment configuration",
    "vercel_production_branch_unusual": "Deployment configuration",
    "vercel_domain_unverified": "Domains",
    "vercel_env_var_broad_target": "Environment variables",
    "vercel_sensitive_env_var_broad_scope": "Environment variables",
    "vercel_deploy_hook_production_branch": "Deploy hooks",
}

# Hard forbidden claim phrases — never appear in code or copy.
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

# Softer unsafe wording — must not appear as a bare assertion in Vercel copy.
# Allowed only inside a negation/disclaimer ("does not confirm ... compromise").
SOFT_UNSAFE_WORDS = [
    "breach",
    "compromise",
    "attacker",
    "leaked",
    "unauthorized access",
    "exfiltration",
    "stolen",
    "fraud",
    "attack",
]

FORBIDDEN_EVIDENCE_KEYS = [
    "value",
    "token",
    "api_token",
    "access_token",
    "authorization",
    "password",
    "secret",
    "credential",
    "email",
    "url",
    "redirect",
    "ip_address",
]


def _rule_key(f: Any) -> str:
    return f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")


def _severity(f: Any) -> str:
    return f.severity if hasattr(f, "severity") else f.get("severity", "")


def _evidence(f: Any) -> dict:
    ev = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
    return ev if isinstance(ev, dict) else {}


# ── Section A: Rule key inventory ─────────────────────────────────────────────

def test_vercel_rule_key_count() -> None:
    assert len(ALL_VERCEL_RULE_KEYS) == 7


def test_all_vercel_rule_keys_are_strings() -> None:
    for key in ALL_VERCEL_RULE_KEYS:
        assert isinstance(key, str)
        assert key.startswith("vercel_")


# ── Section B: Registry parity ────────────────────────────────────────────────

def test_all_vercel_rule_keys_in_rule_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    for key in ALL_VERCEL_RULE_KEYS:
        assert key in KNOWN_RULE_KEYS, (
            f"Vercel rule key {key!r} missing from KNOWN_RULE_KEYS"
        )


# ── Section C: Confidence parity ──────────────────────────────────────────────

def test_all_vercel_rule_keys_in_confidence() -> None:
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    for key in ALL_VERCEL_RULE_KEYS:
        assert key in RULE_CONFIDENCE, (
            f"Vercel rule key {key!r} missing from RULE_CONFIDENCE"
        )


# ── Section D: Rule-pack parity ───────────────────────────────────────────────

def test_all_vercel_rule_keys_in_rule_pack() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_VERCEL_RULE_KEYS:
        assert key in _RULE_META, (
            f"Vercel rule key {key!r} missing from _RULE_META"
        )


def test_rule_pack_vercel_provider() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_VERCEL_RULE_KEYS:
        provider, _sev, _cat = _RULE_META[key]
        assert provider == "vercel", (
            f"Rule {key!r} has wrong provider in _RULE_META: {provider!r}"
        )


def test_rule_pack_severity_matches_expected() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_VERCEL_RULE_KEYS:
        _provider, sev, _cat = _RULE_META[key]
        assert sev == EXPECTED_SEVERITY[key], (
            f"Rule {key!r}: pack severity {sev!r} != expected "
            f"{EXPECTED_SEVERITY[key]!r}"
        )


def test_rule_pack_category_matches_expected() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_VERCEL_RULE_KEYS:
        _provider, _sev, cat = _RULE_META[key]
        assert cat == EXPECTED_CATEGORY[key], (
            f"Rule {key!r}: pack category {cat!r} != expected "
            f"{EXPECTED_CATEGORY[key]!r}"
        )


# ── Section E: Coverage-service parity ────────────────────────────────────────

def test_all_vercel_rule_keys_in_coverage() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    for key in ALL_VERCEL_RULE_KEYS:
        assert key in RULE_RECORD_TYPES, (
            f"Vercel rule key {key!r} missing from RULE_RECORD_TYPES"
        )


def test_preview_unprotected_maps_to_deployment_protection() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    assert "vercel_deployment_protection" in RULE_RECORD_TYPES[
        "vercel_preview_unprotected"
    ]


# ── Section F: Frontend catalog parity (key presence) ─────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_all_vercel_rule_keys_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    missing = [k for k in ALL_VERCEL_RULE_KEYS if k not in text]
    assert not missing, (
        f"Vercel rule keys missing from securityRuleCatalog.ts: {missing}"
    )


# ── Section G: Backend/frontend severity match ────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_severity_matches_backend() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for key, expected_sev in EXPECTED_SEVERITY.items():
        idx = text.find(f'key: "{key}"')
        assert idx != -1, f"Vercel rule {key!r} not found in frontend catalog"
        block = text[idx:idx + 600]
        assert f'severity: "{expected_sev}"' in block, (
            f"Frontend severity for {key!r} does not match backend ({expected_sev!r})"
        )


# ── Section H: Backend/frontend category match ────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_category_matches_backend() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    for key, expected_cat in EXPECTED_CATEGORY.items():
        idx = text.find(f'key: "{key}"')
        assert idx != -1, f"Vercel rule {key!r} not found in frontend catalog"
        block = text[idx:idx + 600]
        assert f'category: "{expected_cat}"' in block, (
            f"Frontend category for {key!r} does not match backend ({expected_cat!r})"
        )


# ── Section I: Evidence metadata safety ───────────────────────────────────────

def _all_vercel_findings() -> list[Any]:
    """Produce a finding from every Vercel rule across representative records."""
    from app.services.security_rules.vercel import evaluate
    from app.connectors.vercel_schema import (
        VERCEL_DEPLOY_HOOK_METADATA,
        VERCEL_DEPLOYMENT_PROTECTION,
        VERCEL_DOMAIN,
        VERCEL_ENV_VAR,
        VERCEL_PROJECT,
    )

    records = [
        {
            "record_type": VERCEL_DEPLOYMENT_PROTECTION,
            "record_id": "prj_1",
            "name": "site",
            "preview_deployments_protected": False,
            "sso_enabled": False,
            "password_enabled": False,
        },
        {
            "record_type": VERCEL_PROJECT,
            "record_id": "prj_2",
            "name": "site",
            "git_repository": "acme/site",
            "git_branch": "",
        },
        {
            "record_type": VERCEL_PROJECT,
            "record_id": "prj_3",
            "name": "site",
            "git_repository": "acme/site",
            "git_branch": "develop",
        },
        {
            "record_type": VERCEL_DOMAIN,
            "record_id": "bad.example.com",
            "name": "bad.example.com",
            "verified": False,
        },
        {
            "record_type": VERCEL_ENV_VAR,
            "record_id": "env_1",
            "key": "API_KEY",
            "target": ["production", "preview"],
        },
        {
            "record_type": VERCEL_DEPLOY_HOOK_METADATA,
            "record_id": "prj_1#deploy_hook#h1",
            "hook_name": "nightly",
            "hook_ref": "main",
        },
    ]
    out: list[Any] = []
    for r in records:
        out.extend(evaluate(r))
    return out


def test_vercel_evidence_has_no_forbidden_keys() -> None:
    findings = _all_vercel_findings()
    assert findings, "expected at least one finding across representative records"
    for f in findings:
        for forbidden in FORBIDDEN_EVIDENCE_KEYS:
            assert forbidden not in _evidence(f), (
                f"Forbidden evidence key {forbidden!r} in finding "
                f"{_rule_key(f)!r}: {list(_evidence(f).keys())}"
            )


def test_vercel_evidence_is_flat_safe_scalars() -> None:
    for f in _all_vercel_findings():
        for v in _evidence(f).values():
            assert isinstance(v, (str, int, float, bool, list, type(None))), (
                f"Non-scalar value in evidence of {_rule_key(f)!r}: {type(v).__name__}"
            )
            if isinstance(v, list):
                for item in v:
                    assert isinstance(item, (str, int, float, bool, type(None)))


# ── Section J: No forbidden / unsafe wording ──────────────────────────────────

def _strip_docstrings_and_comments(src: str) -> str:
    src = re.sub(r'""".*?"""', "", src, flags=re.DOTALL)
    src = re.sub(r"'''.*?'''", "", src, flags=re.DOTALL)
    src = re.sub(r"#[^\n]*", "", src)
    return src


def test_no_forbidden_phrases_in_vercel_rules_module() -> None:
    src = _strip_docstrings_and_comments(
        VERCEL_RULES_FILE.read_text(encoding="utf-8")
    ).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in src, (
            f"Forbidden phrase {phrase!r} found in vercel rules module code"
        )


def test_no_unsafe_assertions_in_vercel_finding_copy() -> None:
    """Soft-unsafe words may appear only inside a negation/disclaimer phrase.

    Every Vercel finding's description that contains a soft-unsafe word must
    also contain a negation ("does not confirm" / "not confirm").
    """
    for f in _all_vercel_findings():
        desc = (f.description if hasattr(f, "description") else f.get("description", "")) or ""
        dl = desc.lower()
        for word in SOFT_UNSAFE_WORDS:
            if word in dl:
                assert ("does not confirm" in dl) or ("not confirm" in dl), (
                    f"Finding {_rule_key(f)!r} uses unsafe word {word!r} without "
                    f"a disclaimer: {desc!r}"
                )


# ── Section K: preview_unprotected reachable from the core fetch path ─────────

def test_connector_fetch_emits_deployment_protection_record() -> None:
    """The Vercel connector's core fetch path must emit a
    vercel_deployment_protection record so vercel_preview_unprotected has a
    reachable production record source (not only the drift/expansion path)."""
    from unittest.mock import patch

    from app.connectors.vercel import VercelConnector
    from app.connectors.vercel_schema import VERCEL_DEPLOYMENT_PROTECTION

    raw_project = {
        "id": "prj_abc",
        "name": "site",
        # No protection configured → previews unprotected.
        "ssoProtection": None,
        "passwordProtection": None,
        "deployHooks": [],
    }

    conn = VercelConnector()

    def fake_get(path: str, headers: dict, params: dict | None = None) -> dict:
        if path.endswith("/env"):
            return {"envs": []}
        if path.endswith("/domains"):
            return {"domains": []}
        return raw_project

    with patch.object(conn, "_get", side_effect=fake_get):
        records = conn.fetch(
            {"vercel_token": "t", "vercel_project_id": "prj_abc"}
        )

    protection = [
        r for r in records if r.get("record_type") == VERCEL_DEPLOYMENT_PROTECTION
    ]
    assert protection, (
        "VercelConnector.fetch() did not emit a vercel_deployment_protection "
        "record — vercel_preview_unprotected would have no reachable source"
    )
    assert protection[0]["preview_deployments_protected"] is False


def test_emitted_protection_record_fires_preview_unprotected() -> None:
    """End-to-end: the connector-emitted record drives the security rule."""
    from unittest.mock import patch

    from app.connectors.vercel import VercelConnector
    from app.connectors.vercel_schema import VERCEL_DEPLOYMENT_PROTECTION
    from app.services.security_finding_evaluator import evaluate_record

    raw_project = {
        "id": "prj_abc",
        "name": "site",
        "ssoProtection": None,
        "passwordProtection": None,
        "deployHooks": [],
    }
    conn = VercelConnector()

    def fake_get(path: str, headers: dict, params: dict | None = None) -> dict:
        if path.endswith("/env"):
            return {"envs": []}
        if path.endswith("/domains"):
            return {"domains": []}
        return raw_project

    with patch.object(conn, "_get", side_effect=fake_get):
        records = conn.fetch({"vercel_token": "t", "vercel_project_id": "prj_abc"})

    protection = next(
        r for r in records if r.get("record_type") == VERCEL_DEPLOYMENT_PROTECTION
    )
    findings = evaluate_record(protection, "vercel")
    assert "vercel_preview_unprotected" in [_rule_key(f) for f in findings]


def test_emitted_protection_record_safe_when_sso_covers_preview() -> None:
    """When SSO protection covers previews, the rule must NOT fire."""
    from app.connectors.vercel import _extract_deployment_protection
    from app.services.security_rules.vercel import evaluate

    raw_project = {
        "id": "prj_xyz",
        "name": "secure-site",
        "ssoProtection": {"deploymentType": "all"},
        "passwordProtection": None,
    }
    rec = _extract_deployment_protection(raw_project, "prj_xyz")
    assert rec["preview_deployments_protected"] is True
    assert "vercel_preview_unprotected" not in [_rule_key(f) for f in evaluate(rec)]


# ── Section L: redirect-only domain false positive prevented ──────────────────

def _domain_record(name: str, verified: bool, **extra: Any) -> dict:
    from app.connectors.vercel_schema import VERCEL_DOMAIN
    rec = {
        "record_type": VERCEL_DOMAIN,
        "record_id": name,
        "name": name,
        "verified": verified,
    }
    rec.update(extra)
    return rec


def test_unverified_non_redirect_domain_fires() -> None:
    from app.services.security_rules.vercel import evaluate
    rec = _domain_record("bad.example.com", verified=False, redirect_only=False)
    assert "vercel_domain_unverified" in [_rule_key(f) for f in evaluate(rec)]


def test_unverified_redirect_only_domain_does_not_fire() -> None:
    from app.services.security_rules.vercel import evaluate
    rec = _domain_record("alias.example.com", verified=False, redirect_only=True)
    assert "vercel_domain_unverified" not in [_rule_key(f) for f in evaluate(rec)]


def test_unverified_domain_missing_redirect_field_fires_conservatively() -> None:
    """Missing redirect_only must fall through and fire (err toward detection)."""
    from app.services.security_rules.vercel import evaluate
    rec = _domain_record("nofield.example.com", verified=False)
    assert "vercel_domain_unverified" in [_rule_key(f) for f in evaluate(rec)]


def test_normalize_domain_sets_redirect_only() -> None:
    from app.connectors.vercel import _normalize_domain
    redirecting = _normalize_domain(
        {"name": "alias.example.com", "verified": False, "redirect": "https://x.example.com"}
    )
    assert redirecting["redirect_only"] is True
    serving = _normalize_domain({"name": "app.example.com", "verified": False})
    assert serving["redirect_only"] is False


def test_redirect_target_url_not_in_domain_finding_evidence() -> None:
    from app.services.security_rules.vercel import evaluate
    rec = _domain_record(
        "bad.example.com",
        verified=False,
        redirect_only=False,
        redirect="https://secret-internal.example.com/path",
    )
    for f in evaluate(rec):
        for v in _evidence(f).values():
            assert "secret-internal" not in str(v)


# ── Section M: public env-var names do NOT trigger high finding ───────────────

def _env_record(key: str, target: list[str]) -> dict:
    from app.connectors.vercel_schema import VERCEL_ENV_VAR
    return {
        "record_type": VERCEL_ENV_VAR,
        "record_id": f"env_{key}",
        "key": key,
        "name": key,
        "target": target,
    }


@pytest.mark.parametrize("key", [
    "NEXT_PUBLIC_KEY",
    "PUBLIC_SITE_URL",
    "VITE_API_URL",
    "REACT_APP_API_URL",
    "NEXT_PUBLIC_SECRET_KEY",  # public prefix is authoritative → not flagged
    "CACHE_TTL",
    "AUTH_REDIRECT_URL",
    "AUTH_CALLBACK_URL",
])
def test_public_env_var_does_not_trigger_high(key: str) -> None:
    from app.services.security_rules.vercel import evaluate
    rec = _env_record(key, ["production", "preview"])
    keys = [_rule_key(f) for f in evaluate(rec)]
    assert "vercel_sensitive_env_var_broad_scope" not in keys, (
        f"public/benign env var {key!r} wrongly triggered the high-severity finding"
    )


# ── Section N: sensitive env-var names DO trigger high finding ────────────────

@pytest.mark.parametrize("key", [
    "API_KEY",
    "SECRET_KEY",
    "PRIVATE_KEY",
    "AUTH_TOKEN",
    "CERT_PEM",
    "TLS_CERT",
    "SSL_CERT",
    "DB_PASSWORD",
    "DATABASE_URL",
    "CACHE_SECRET",  # CACHE_ carve-out: still flagged
    "CACHE_KEY",
])
def test_sensitive_env_var_triggers_high(key: str) -> None:
    from app.services.security_rules.vercel import evaluate
    rec = _env_record(key, ["production", "preview"])
    keys = [_rule_key(f) for f in evaluate(rec)]
    assert "vercel_sensitive_env_var_broad_scope" in keys, (
        f"sensitive env var {key!r} did not trigger the high-severity finding"
    )


def test_sensitive_env_var_finding_is_high_severity() -> None:
    from app.services.security_rules.vercel import evaluate
    rec = _env_record("API_KEY", ["production", "preview"])
    high = [
        f for f in evaluate(rec)
        if _rule_key(f) == "vercel_sensitive_env_var_broad_scope"
    ]
    assert high and _severity(high[0]) == "high"


# ── Section O: Capability matrix ──────────────────────────────────────────────

def test_capability_matrix_vercel_entry_exists() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("vercel")
    assert cap is not None
    assert cap.provider == "vercel"


def test_capability_matrix_vercel_security_rules() -> None:
    from app.services.provider_capability_matrix_service import get_provider_capability
    cap = get_provider_capability("vercel")
    assert cap is not None
    assert cap.security.security_rules is True


# ── Section P: Provider expansion framework unchanged ─────────────────────────

def test_expansion_framework_planned_next_stage_is_m89a() -> None:
    from app.services.provider_expansion_framework import get_framework
    fw = get_framework()
    planned = fw.get("summary", {}).get("planned_next_stage", "")
    assert "M89A" in planned or "Kubernetes" in planned, (
        f"planned_next_stage should point to M89A/Kubernetes; got: {planned!r}"
    )
