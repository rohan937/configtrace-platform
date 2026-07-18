"""Supabase provider depth QA.

Durable guardrails that pin the full Supabase rule taxonomy across every
registration surface and validate the behavioral / claim-discipline invariants
hardened during the Supabase QA pass:

  Group 1. Registry / confidence / pack / coverage / frontend-catalog parity
           for all Supabase rule keys.
  Group 2. Backend pack severity == frontend catalog severity for each key.
  Group 3. Evidence metadata is flat and carries no secret / PII / raw keys.
  Group 4. Supabase rule copy carries no forbidden (breach-style) wording.
  Group 5. RLS-off vs RLS-on behavior for supabase_public_write_policy.
  Group 6. Steady-state auth-hardening rules fire only on an explicit False.
  Group 7. supabase_edge_function_jwt_disabled dynamic severity + worst-case
           pack/catalog label is "high".
  Group 8. Provider capability matrix marks Supabase complete; expansion
           framework still points at M89A Kubernetes; Kubernetes is NOT built.

Pure unit tests: the parity / copy / registry / catalog checks read Python dicts
and the TypeScript catalog as text and require no database connection.
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

SUPABASE_RULES_FILE = BACKEND / "services" / "security_rules" / "supabase.py"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

# ── Canonical Supabase rule set ───────────────────────────────────────────────

ALL_SUPABASE_RULE_KEYS: frozenset[str] = frozenset({
    "supabase_rls_disabled",
    "supabase_anonymous_access_enabled",
    "supabase_jwt_expiry_long",
    "supabase_public_select_sensitive_table",
    "supabase_public_write_policy",
    "supabase_edge_function_jwt_disabled",
    "supabase_auth_protection_missing",
    # auth-hardening QA additions
    "supabase_refresh_token_rotation_disabled",
    "supabase_captcha_disabled",
    "supabase_password_update_reauth_disabled",
})

# Backend pack severity (headline / worst-case). Must match the frontend catalog.
EXPECTED_SEVERITY: dict[str, str] = {
    "supabase_rls_disabled": "high",
    "supabase_anonymous_access_enabled": "medium",
    "supabase_jwt_expiry_long": "medium",
    "supabase_public_select_sensitive_table": "high",
    "supabase_public_write_policy": "high",
    "supabase_edge_function_jwt_disabled": "high",
    "supabase_auth_protection_missing": "medium",
    "supabase_refresh_token_rotation_disabled": "medium",
    "supabase_captcha_disabled": "low",
    "supabase_password_update_reauth_disabled": "medium",
}

# Forbidden claim phrases — never in Supabase rule code or user-facing copy.
FORBIDDEN_PHRASES = [
    "breach",
    "compromise",
    "attacker",
    "leaked",
    "unauthorized access confirmed",
    "exfiltration",
    "stolen",
    "fraud",
    "attack",
    "data leaked",
    "database exposed",
    "storage exposed",
    "data exposure",
]

# Phrases that legitimately negate a claim — a forbidden token inside one of
# these disclaimer windows is allowed (it is making the opposite assertion).
_DISCLAIMER_MARKERS = ("does not confirm", "not confirm", "does not assert")

# Supabase's "leaked-password protection" (Have I Been Pwned integration) is a
# real product feature name and a normalized field name. A "leaked" token that
# is part of this exact feature-name phrase is not a breach claim and is allowed.
_ALLOWED_FEATURE_PHRASES = (
    "leaked-password",
    "leaked password",
    "leaked_password",
)

# Evidence dicts must never carry secret-bearing / PII-bearing / raw keys.
FORBIDDEN_EVIDENCE_KEYS = [
    "service_role_key",
    "anon_key",
    "jwt_secret",
    "password",
    "connection_string",
    "api_key",
    "token",
    "bearer",
    "email",
    "phone",
    "uid",
    "sql",
    "policy_sql",
    "with_check",
    "source",
    "log",
    "customer",
    "raw",
]


def _rule_key(f: Any) -> str:
    return f.rule_key if hasattr(f, "rule_key") else f.get("rule_key", "")


def _severity(f: Any) -> str:
    return f.severity if hasattr(f, "severity") else f.get("severity", "")


def _evidence(f: Any) -> dict:
    ev = f.evidence if hasattr(f, "evidence") else f.get("evidence", {})
    return ev if isinstance(ev, dict) else {}


def _title(f: Any) -> str:
    return (f.title if hasattr(f, "title") else f.get("title", "")) or ""


def _description(f: Any) -> str:
    return (f.description if hasattr(f, "description") else f.get("description", "")) or ""


def _strip_docstrings_and_comments(src: str) -> str:
    src = re.sub(r'""".*?"""', "", src, flags=re.DOTALL)
    src = re.sub(r"'''.*?'''", "", src, flags=re.DOTALL)
    src = re.sub(r"#[^\n]*", "", src)
    return src


def _phrase_violations(text: str) -> list[str]:
    """Return forbidden phrases present in ``text`` outside a disclaimer window."""
    low = text.lower()
    violations: list[str] = []
    for phrase in FORBIDDEN_PHRASES:
        start = 0
        while True:
            idx = low.find(phrase, start)
            if idx == -1:
                break
            window = low[max(0, idx - 130):idx]
            # Allow the exact "leaked-password protection" product-feature name.
            feature_window = low[max(0, idx - 8):idx + 40]
            if any(fp in feature_window for fp in _ALLOWED_FEATURE_PHRASES):
                start = idx + len(phrase)
                continue
            if not any(marker in window for marker in _DISCLAIMER_MARKERS):
                violations.append(phrase)
                break
            start = idx + len(phrase)
    return violations


# ── Synthetic risky records firing every Supabase rule ────────────────────────

def _all_supabase_findings() -> list[Any]:
    from app.connectors.supabase_schema import (
        SUPABASE_AUTH_CONFIG,
        SUPABASE_EDGE_FUNCTION,
        SUPABASE_RLS_STATUS,
    )
    from app.services.security_rules.supabase import evaluate

    records = [
        # RLS disabled.
        {
            "record_type": SUPABASE_RLS_STATUS,
            "record_id": "p/rls/off",
            "schema_name": "public",
            "table_name": "logs",
            "rls_enabled": False,
        },
        # RLS enabled + public SELECT on a sensitive table + public write.
        {
            "record_type": SUPABASE_RLS_STATUS,
            "record_id": "p/rls/users",
            "schema_name": "public",
            "table_name": "users",
            "rls_enabled": True,
            "has_public_select_policy": True,
            "has_public_insert_policy": True,
            "has_public_update_policy": True,
            "has_public_delete_policy": True,
            "policy_count": 3,
        },
        # Auth config firing every auth rule.
        {
            "record_type": SUPABASE_AUTH_CONFIG,
            "record_id": "p/auth_config",
            "anonymous_enabled": True,
            "jwt_exp": 200_000,
            "leaked_password_protection_enabled": False,
            "mfa_totp_enabled": False,
            "refresh_token_rotation_enabled": False,
            "captcha_enabled": False,
            "require_reauthentication_for_password_update": False,
        },
        # Edge function with JWT disabled on a sensitive name → high.
        {
            "record_type": SUPABASE_EDGE_FUNCTION,
            "record_id": "p/fn/process-payment",
            "function_name": "process-payment",
            "verify_jwt": False,
        },
    ]
    out: list[Any] = []
    for r in records:
        out.extend(evaluate(r))
    return out


def _eval(record: dict) -> list[Any]:
    from app.services.security_rules.supabase import evaluate
    return evaluate(record)


# ── Group 1: Registry / confidence / pack / coverage / catalog parity ─────────

def test_supabase_rule_key_count() -> None:
    assert len(ALL_SUPABASE_RULE_KEYS) == 10


def test_all_supabase_rule_keys_in_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    for key in ALL_SUPABASE_RULE_KEYS:
        assert key in KNOWN_RULE_KEYS, f"{key!r} missing from KNOWN_RULE_KEYS"


def test_all_supabase_rule_keys_in_confidence() -> None:
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    for key in ALL_SUPABASE_RULE_KEYS:
        assert key in RULE_CONFIDENCE, f"{key!r} missing from RULE_CONFIDENCE"


def test_all_supabase_rule_keys_in_rule_pack() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_SUPABASE_RULE_KEYS:
        assert key in _RULE_META, f"{key!r} missing from _RULE_META"
        provider, _sev, _cat = _RULE_META[key]
        assert provider == "supabase", f"{key!r} wrong provider: {provider!r}"


def test_all_supabase_rule_keys_in_coverage() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    for key in ALL_SUPABASE_RULE_KEYS:
        assert key in RULE_RECORD_TYPES, f"{key!r} missing from RULE_RECORD_TYPES"
        assert RULE_RECORD_TYPES[key], f"{key!r} has empty record-type tuple"


def test_new_auth_rules_map_to_auth_config_record() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    for key in (
        "supabase_refresh_token_rotation_disabled",
        "supabase_captcha_disabled",
        "supabase_password_update_reauth_disabled",
    ):
        assert RULE_RECORD_TYPES[key] == ("supabase_auth_config",), (
            f"{key!r} should map to supabase_auth_config"
        )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_all_supabase_rule_keys_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    missing = [k for k in ALL_SUPABASE_RULE_KEYS if f'key: "{k}"' not in text]
    assert not missing, f"Supabase rule keys missing from catalog: {missing}"


# ── Group 2: Severity parity (backend pack vs frontend catalog) ───────────────

def test_rule_pack_severity_matches_expected() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_SUPABASE_RULE_KEYS:
        _provider, sev, _cat = _RULE_META[key]
        assert sev == EXPECTED_SEVERITY[key], (
            f"{key!r}: pack severity {sev!r} != expected {EXPECTED_SEVERITY[key]!r}"
        )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_severity_matches_backend() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_SUPABASE_RULE_KEYS:
        idx = text.find(f'key: "{key}"')
        assert idx != -1, f"Supabase rule {key!r} not found in frontend catalog"
        block = text[idx:idx + 900]
        _provider, expected_sev, _cat = _RULE_META[key]
        assert f'severity: "{expected_sev}"' in block, (
            f"Frontend severity for {key!r} does not match backend "
            f"({expected_sev!r})"
        )


# ── Group 3: Evidence metadata safety ─────────────────────────────────────────

def test_all_supabase_rules_fire_across_synthetic_records() -> None:
    fired = {_rule_key(f) for f in _all_supabase_findings()}
    missing = ALL_SUPABASE_RULE_KEYS - fired
    assert not missing, f"Synthetic records did not fire rules: {sorted(missing)}"


def test_supabase_evidence_has_no_forbidden_keys() -> None:
    findings = _all_supabase_findings()
    assert findings, "expected at least one finding across representative records"
    for f in findings:
        ev_keys = {k.lower() for k in _evidence(f)}
        for forbidden in FORBIDDEN_EVIDENCE_KEYS:
            assert forbidden not in ev_keys, (
                f"Forbidden evidence key {forbidden!r} in finding "
                f"{_rule_key(f)!r}: {sorted(ev_keys)}"
            )


def test_supabase_evidence_is_flat_safe_scalars() -> None:
    for f in _all_supabase_findings():
        for v in _evidence(f).values():
            assert isinstance(v, (str, int, float, bool, list, type(None))), (
                f"Non-scalar evidence value in {_rule_key(f)!r}: {type(v).__name__}"
            )
            if isinstance(v, list):
                for item in v:
                    assert isinstance(item, (str, int, float, bool, type(None)))


# ── Group 4: Forbidden wording ────────────────────────────────────────────────

def test_no_forbidden_wording_in_supabase_rules_module() -> None:
    src = _strip_docstrings_and_comments(
        SUPABASE_RULES_FILE.read_text(encoding="utf-8")
    )
    # Collapse Python f-string concatenation artifacts ("does not "\n f"confirm")
    # so multi-line disclaimer prose reads continuously before phrase scanning.
    src = re.sub(r'"\s*\+?\s*f?"', "", src)
    src = re.sub(r"\s+", " ", src)
    violations = _phrase_violations(src)
    assert not violations, (
        f"Forbidden wording in supabase rules module code: {violations}"
    )


def test_no_forbidden_wording_in_supabase_finding_copy() -> None:
    for f in _all_supabase_findings():
        blob = f"{_title(f)}\n{_description(f)}"
        violations = _phrase_violations(blob)
        assert not violations, (
            f"Finding {_rule_key(f)!r} copy contains forbidden wording: "
            f"{violations}"
        )


# ── Group 5: Public-write policy RLS-off vs RLS-on behavior ────────────────────

def test_public_write_does_not_fire_when_rls_disabled() -> None:
    """RLS disabled = supabase_rls_disabled fires, NOT public_write. The M71A
    public-policy rules only apply when RLS is enabled (policies are active)."""
    from app.connectors.supabase_schema import SUPABASE_RLS_STATUS
    record = {
        "record_type": SUPABASE_RLS_STATUS,
        "record_id": "p/rls/off-with-policy",
        "schema_name": "public",
        "table_name": "orders",
        "rls_enabled": False,
        # Even with a public write policy flag present, RLS-off suppresses it.
        "has_public_insert_policy": True,
        "has_public_update_policy": True,
        "has_public_delete_policy": True,
        "policy_count": 2,
    }
    fired = {_rule_key(f) for f in _eval(record)}
    assert "supabase_public_write_policy" not in fired, (
        "public_write must NOT fire when RLS is disabled"
    )
    assert "supabase_rls_disabled" in fired, (
        "supabase_rls_disabled should fire when RLS is disabled"
    )


def test_public_write_fires_when_rls_enabled_with_public_policy() -> None:
    from app.connectors.supabase_schema import SUPABASE_RLS_STATUS
    record = {
        "record_type": SUPABASE_RLS_STATUS,
        "record_id": "p/rls/on-with-policy",
        "schema_name": "public",
        "table_name": "orders",
        "rls_enabled": True,
        "has_public_insert_policy": True,
        "policy_count": 1,
    }
    findings = _eval(record)
    fired = {_rule_key(f) for f in findings}
    assert "supabase_public_write_policy" in fired, (
        "public_write should fire when RLS enabled and a public write policy exists"
    )
    assert "supabase_rls_disabled" not in fired


# ── Group 6: Steady-state auth-hardening rules — explicit False only ──────────

_NEW_AUTH_RULES = {
    "supabase_refresh_token_rotation_disabled": "refresh_token_rotation_enabled",
    "supabase_captcha_disabled": "captcha_enabled",
    "supabase_password_update_reauth_disabled": "require_reauthentication_for_password_update",
}


def _auth_record(**overrides: Any) -> dict:
    from app.connectors.supabase_schema import SUPABASE_AUTH_CONFIG
    rec = {"record_type": SUPABASE_AUTH_CONFIG, "record_id": "p/auth_config"}
    rec.update(overrides)
    return rec


@pytest.mark.parametrize("rule_key,field", sorted(_NEW_AUTH_RULES.items()))
def test_new_auth_rule_fires_on_explicit_false(rule_key: str, field: str) -> None:
    fired = {_rule_key(f) for f in _eval(_auth_record(**{field: False}))}
    assert rule_key in fired, f"{rule_key} should fire when {field} is False"


@pytest.mark.parametrize("rule_key,field", sorted(_NEW_AUTH_RULES.items()))
@pytest.mark.parametrize("value", [True, None, "false", 0])
def test_new_auth_rule_does_not_fire_on_non_false(
    rule_key: str, field: str, value: Any
) -> None:
    fired = {_rule_key(f) for f in _eval(_auth_record(**{field: value}))}
    assert rule_key not in fired, (
        f"{rule_key} must NOT fire when {field} is {value!r}"
    )


@pytest.mark.parametrize("rule_key,field", sorted(_NEW_AUTH_RULES.items()))
def test_new_auth_rule_does_not_fire_when_field_missing(
    rule_key: str, field: str
) -> None:
    fired = {_rule_key(f) for f in _eval(_auth_record())}
    assert rule_key not in fired, (
        f"{rule_key} must NOT fire when {field} is absent"
    )


def test_new_auth_rule_severities() -> None:
    findings = {_rule_key(f): f for f in _eval(_auth_record(
        refresh_token_rotation_enabled=False,
        captcha_enabled=False,
        require_reauthentication_for_password_update=False,
    ))}
    assert _severity(findings["supabase_refresh_token_rotation_disabled"]) == "medium"
    assert _severity(findings["supabase_captcha_disabled"]) == "low"
    assert _severity(findings["supabase_password_update_reauth_disabled"]) == "medium"


# ── Group 7: Edge-function dynamic severity + worst-case label ─────────────────

def test_edge_function_sensitive_name_is_high() -> None:
    from app.connectors.supabase_schema import SUPABASE_EDGE_FUNCTION
    findings = _eval({
        "record_type": SUPABASE_EDGE_FUNCTION,
        "record_id": "p/fn/admin",
        "function_name": "admin-delete-user",
        "verify_jwt": False,
    })
    f = next(f for f in findings if _rule_key(f) == "supabase_edge_function_jwt_disabled")
    assert _severity(f) == "high"


def test_edge_function_non_sensitive_name_is_medium() -> None:
    from app.connectors.supabase_schema import SUPABASE_EDGE_FUNCTION
    findings = _eval({
        "record_type": SUPABASE_EDGE_FUNCTION,
        "record_id": "p/fn/hello",
        "function_name": "hello-world",
        "verify_jwt": False,
    })
    f = next(f for f in findings if _rule_key(f) == "supabase_edge_function_jwt_disabled")
    assert _severity(f) == "medium"


def test_edge_function_pack_label_is_worst_case_high() -> None:
    from app.services.security_rule_pack import _RULE_META
    _provider, sev, _cat = _RULE_META["supabase_edge_function_jwt_disabled"]
    assert sev == "high", "pack headline severity should be worst-case 'high'"


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_edge_function_catalog_label_is_high_with_dynamic_note() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    idx = text.find('key: "supabase_edge_function_jwt_disabled"')
    assert idx != -1
    block = text[idx:idx + 900]
    assert 'severity: "high"' in block
    assert "severityNote" in block
    low = block.lower()
    assert "high" in low and "medium" in low, (
        "catalog should note dynamic high/medium severity"
    )


# ── Group 8: Capability matrix / expansion framework / no Kubernetes ──────────

def test_supabase_capability_is_complete() -> None:
    from app.services.provider_capability_matrix_service import (
        get_provider_capability,
    )
    cap = get_provider_capability("supabase")
    assert cap is not None, "Supabase missing from provider capability matrix"
    assert cap.provider == "supabase"
    assert cap.maturity == "complete"
    assert cap.security.security_rules is True


def test_expansion_framework_points_at_kubernetes() -> None:
    """Regression note: Kubernetes launched its provider architecture
    foundation (Kubernetes message 1 / M89A) and was removed from the
    recommended queue — Sentry (M90A) is now the head."""
    from app.services.provider_expansion_framework import (
        RECOMMENDED_NEXT_PROVIDERS,
    )
    providers = {p.provider for p in RECOMMENDED_NEXT_PROVIDERS}
    assert "kubernetes" not in providers
    head = RECOMMENDED_NEXT_PROVIDERS[0]
    assert head.provider == "sentry"
    assert "M90" in (head.first_milestone_name or "")


def test_kubernetes_is_not_implemented() -> None:
    """Regression note: the Kubernetes connector and Security Findings
    module now exist (Kubernetes message 6 — static Security Finding
    taxonomy)."""
    assert (BACKEND / "connectors" / "kubernetes.py").exists()
    assert (BACKEND / "services" / "security_rules" / "kubernetes.py").exists()
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    assert any("kubernetes" in k.lower() or k.lower().startswith("k8s")
               for k in KNOWN_RULE_KEYS)
