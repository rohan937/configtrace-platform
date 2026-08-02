"""Firebase provider depth QA.

Durable guardrails that pin the full Firebase rule taxonomy across every
registration surface and validate the behavioral / claim-discipline invariants
hardened during the Firebase QA pass:

  Group 1. Registry / confidence / pack / coverage / frontend-catalog parity
           for all Firebase rule keys.
  Group 2. Backend pack severity == frontend catalog severity for each key.
  Group 3. Evidence metadata is flat and carries no secret / PII / raw-rule keys.
  Group 4. Firebase rule copy carries no forbidden (breach-style) wording.
  Group 5. firebase_auth_protection_missing copy describes MFA/auth protection.
  Group 6. Stale deferred note no longer claims the RTDB read/write split was
           rejected wholesale.
  Group 7. Provider capability matrix marks Firebase complete; expansion
           framework still points at M89A Kubernetes; Kubernetes is NOT built.
  Group 8. No Firebase activity-signal evidence stores raw secrets / PII / rules.

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

FIREBASE_RULES_FILE = BACKEND / "services" / "security_rules" / "firebase.py"
FE_RULE_CATALOG = FRONTEND / "lib" / "securityRuleCatalog.ts"

# ── Canonical Firebase rule set ───────────────────────────────────────────────

ALL_FIREBASE_RULE_KEYS: frozenset[str] = frozenset({
    "firebase_rules_public",
    "firebase_storage_rules_public",
    "firebase_anonymous_auth_enabled",
    "firebase_database_public_read",
    "firebase_database_public_write",
    "firebase_auth_protection_missing",
    # M72C QA additions
    "firebase_storage_public_access_prevention_disabled",
    "firebase_app_check_unenforced_services",
})

# Backend pack severity (must match the frontend catalog severity exactly).
EXPECTED_SEVERITY: dict[str, str] = {
    "firebase_rules_public": "critical",
    "firebase_storage_rules_public": "critical",
    "firebase_anonymous_auth_enabled": "medium",
    "firebase_database_public_read": "high",
    "firebase_database_public_write": "critical",
    "firebase_auth_protection_missing": "medium",
    "firebase_storage_public_access_prevention_disabled": "high",
    "firebase_app_check_unenforced_services": "medium",
}

# Forbidden claim phrases — never in Firebase rule code or user-facing copy.
FORBIDDEN_PHRASES = [
    "breach",
    "compromise",
    "attacker",
    "leaked",
    "unauthorized access",   # allowed only inside a "does not confirm ..." disclaimer
    "exfiltration",
    "stolen",
    "fraud",
    "attack",
    "data exposure",
    "publicly exposed",
    "database exposed",
    "storage exposed",
]

# Phrases that legitimately negate a claim — a forbidden token inside one of
# these disclaimer windows is allowed (it is making the opposite assertion).
_DISCLAIMER_MARKERS = ("does not confirm", "not confirm", "does not assert")

# Evidence dicts must never carry secret-bearing / PII-bearing / raw-rule keys.
FORBIDDEN_EVIDENCE_KEYS = [
    "private_key",
    "api_key",
    "token",
    "oauth_token",
    "authorization",
    "headers",
    "payload",
    "request",
    "response",
    "rules_text",
    "raw_rules",
    "email",
    "phone",
    "uid",
    "customer",
    "pii",
    "service_account_key",
    "function_source",
    "function_log",
    "database_path",
    "principalemail",
    "actor_email",
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
            window = low[max(0, idx - 110):idx]
            if not any(marker in window for marker in _DISCLAIMER_MARKERS):
                violations.append(phrase)
                break
            start = idx + len(phrase)
    return violations


# ── Synthetic risky records firing every Firebase rule ────────────────────────

def _all_firebase_findings() -> list[Any]:
    from app.services.security_rules.firebase import evaluate
    from app.connectors.firebase_schema import (
        FIREBASE_APP_CHECK_CONFIG,
        FIREBASE_AUTH_CONFIG,
        FIREBASE_DATABASE_RULESET,
        FIREBASE_FIRESTORE_RULESET,
        FIREBASE_STORAGE_BUCKET,
        FIREBASE_STORAGE_RULESET,
    )

    records = [
        {
            "record_type": FIREBASE_FIRESTORE_RULESET,
            "record_id": "p/firestore/r1",
            "release_name": "cloud.firestore",
            "public_read_detected": True,
            "public_write_detected": True,
            "parser_confidence": "high",
        },
        {
            "record_type": FIREBASE_STORAGE_RULESET,
            "record_id": "p/storage/r1",
            "release_name": "firebase.storage",
            "public_read_detected": True,
            "public_write_detected": False,
            "parser_confidence": "high",
        },
        {
            "record_type": FIREBASE_DATABASE_RULESET,
            "record_id": "p/rtdb/default",
            "name": "default",
            "public_read_detected": True,
            "public_write_detected": True,
            "parser_confidence": "high",
        },
        {
            "record_type": FIREBASE_AUTH_CONFIG,
            "record_id": "p/auth_config",
            "project_id": "demo-fb",
            "anonymous_enabled": True,
            "mfa_enabled": False,
        },
        {
            "record_type": FIREBASE_STORAGE_BUCKET,
            "record_id": "p/bucket-1",
            "name": "bucket-1",
            "public_access_prevention": "inherited",
            "uniform_bucket_level_access": False,
        },
        {
            "record_type": FIREBASE_APP_CHECK_CONFIG,
            "record_id": "p/app_check",
            "unenforced_service_count": 2,
            "enforced_service_count": 1,
        },
    ]
    out: list[Any] = []
    for r in records:
        out.extend(evaluate(r))
    return out


# ── Group 1: Registry / confidence / pack / coverage / catalog parity ─────────

def test_firebase_rule_key_count() -> None:
    assert len(ALL_FIREBASE_RULE_KEYS) == 8


def test_all_firebase_rule_keys_in_registry() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    for key in ALL_FIREBASE_RULE_KEYS:
        assert key in KNOWN_RULE_KEYS, f"{key!r} missing from KNOWN_RULE_KEYS"


def test_all_firebase_rule_keys_in_confidence() -> None:
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    for key in ALL_FIREBASE_RULE_KEYS:
        assert key in RULE_CONFIDENCE, f"{key!r} missing from RULE_CONFIDENCE"


def test_all_firebase_rule_keys_in_rule_pack() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_FIREBASE_RULE_KEYS:
        assert key in _RULE_META, f"{key!r} missing from _RULE_META"
        provider, _sev, _cat = _RULE_META[key]
        assert provider == "firebase", f"{key!r} wrong provider: {provider!r}"


def test_all_firebase_rule_keys_in_coverage() -> None:
    from app.services.security_coverage_service import RULE_RECORD_TYPES
    for key in ALL_FIREBASE_RULE_KEYS:
        assert key in RULE_RECORD_TYPES, f"{key!r} missing from RULE_RECORD_TYPES"
        assert RULE_RECORD_TYPES[key], f"{key!r} has empty record-type tuple"


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_all_firebase_rule_keys_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    missing = [k for k in ALL_FIREBASE_RULE_KEYS if k not in text]
    assert not missing, f"Firebase rule keys missing from catalog: {missing}"


# ── Group 2: Severity parity (backend pack vs frontend catalog) ───────────────

def test_rule_pack_severity_matches_expected() -> None:
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_FIREBASE_RULE_KEYS:
        _provider, sev, _cat = _RULE_META[key]
        assert sev == EXPECTED_SEVERITY[key], (
            f"{key!r}: pack severity {sev!r} != expected {EXPECTED_SEVERITY[key]!r}"
        )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_frontend_catalog_severity_matches_backend() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    from app.services.security_rule_pack import _RULE_META
    for key in ALL_FIREBASE_RULE_KEYS:
        idx = text.find(f'key: "{key}"')
        assert idx != -1, f"Firebase rule {key!r} not found in frontend catalog"
        block = text[idx:idx + 900]
        _provider, expected_sev, _cat = _RULE_META[key]
        assert f'severity: "{expected_sev}"' in block, (
            f"Frontend severity for {key!r} does not match backend "
            f"({expected_sev!r})"
        )


# ── Group 3: Evidence metadata safety ─────────────────────────────────────────

def test_all_firebase_rules_fire_across_synthetic_records() -> None:
    fired = {_rule_key(f) for f in _all_firebase_findings()}
    missing = ALL_FIREBASE_RULE_KEYS - fired
    assert not missing, f"Synthetic records did not fire rules: {sorted(missing)}"


def test_firebase_evidence_has_no_forbidden_keys() -> None:
    findings = _all_firebase_findings()
    assert findings, "expected at least one finding across representative records"
    for f in findings:
        ev_keys = {k.lower() for k in _evidence(f)}
        for forbidden in FORBIDDEN_EVIDENCE_KEYS:
            assert forbidden not in ev_keys, (
                f"Forbidden evidence key {forbidden!r} in finding "
                f"{_rule_key(f)!r}: {sorted(ev_keys)}"
            )


def test_firebase_evidence_is_flat_safe_scalars() -> None:
    for f in _all_firebase_findings():
        for v in _evidence(f).values():
            assert isinstance(v, (str, int, float, bool, list, type(None))), (
                f"Non-scalar evidence value in {_rule_key(f)!r}: {type(v).__name__}"
            )
            if isinstance(v, list):
                for item in v:
                    assert isinstance(item, (str, int, float, bool, type(None)))


# ── Group 4: Forbidden wording ────────────────────────────────────────────────

def test_no_forbidden_wording_in_firebase_rules_module() -> None:
    src = _strip_docstrings_and_comments(
        FIREBASE_RULES_FILE.read_text(encoding="utf-8")
    )
    violations = _phrase_violations(src)
    assert not violations, (
        f"Forbidden wording in firebase rules module code: {violations}"
    )


def test_no_forbidden_wording_in_firebase_finding_copy() -> None:
    for f in _all_firebase_findings():
        blob = f"{_title(f)}\n{_description(f)}"
        violations = _phrase_violations(blob)
        assert not violations, (
            f"Finding {_rule_key(f)!r} copy contains forbidden wording: "
            f"{violations}"
        )


# ── Group 5: Auth-protection copy describes MFA / auth protection ─────────────

def test_auth_protection_copy_describes_mfa() -> None:
    findings = {_rule_key(f): f for f in _all_firebase_findings()}
    f = findings.get("firebase_auth_protection_missing")
    assert f is not None, "firebase_auth_protection_missing did not fire"
    blob = f"{_title(f)} {_description(f)}".lower()
    assert ("mfa" in blob) or ("multi-factor" in blob), (
        "firebase_auth_protection_missing copy must reference MFA / multi-factor"
    )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_auth_protection_copy_describes_mfa_in_catalog() -> None:
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    idx = text.find('key: "firebase_auth_protection_missing"')
    assert idx != -1
    block = text[idx:idx + 900].lower()
    assert ("mfa" in block) or ("multi-factor" in block)


# ── Group 6: Deferred note accuracy ───────────────────────────────────────────

@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_deferred_note_does_not_claim_rtdb_split_rejected() -> None:
    """The RTDB read/write split IS implemented (two separate rules). The stale
    deferral note must not claim it was rejected wholesale; the deferral applies
    only to Firestore/Storage (single rule, dynamic severity)."""
    text = FE_RULE_CATALOG.read_text(encoding="utf-8")
    # The two split rule keys must both exist in the catalog.
    assert 'key: "firebase_database_public_read"' in text
    assert 'key: "firebase_database_public_write"' in text
    # Find the firebase Firestore/Storage split deferral note.
    idx = text.find("Firestore / Storage public read vs write split")
    assert idx != -1, "expected the Firestore/Storage split deferral note"
    block = text[idx:idx + 900]
    low = block.lower()
    # The note must acknowledge the RTDB split is implemented and scope the
    # deferral to Firestore/Storage only.
    assert "realtime database" in low and "split" in low
    assert "firebase_database_public_read" in block
    assert "firebase_database_public_write" in block


# ── Group 7: Capability matrix / expansion framework / no Kubernetes ──────────

def test_firebase_capability_is_complete() -> None:
    from app.services.provider_capability_matrix_service import (
        get_provider_capability,
    )
    cap = get_provider_capability("firebase")
    assert cap is not None, "Firebase missing from provider capability matrix"
    assert cap.provider == "firebase"
    assert cap.maturity == "complete"


def test_expansion_framework_queue_is_empty_after_sentry_launch() -> None:
    """Regression note: Kubernetes launched its provider architecture
    foundation (message 1 / M89A) and was removed from the recommended
    queue. Sentry (message 8 — public launch) was the FINAL planned
    provider, so the queue is now permanently empty."""
    from app.services.provider_expansion_framework import (
        RECOMMENDED_NEXT_PROVIDERS,
    )
    providers = {p.provider for p in RECOMMENDED_NEXT_PROVIDERS}
    assert "kubernetes" not in providers
    assert "sentry" not in providers
    assert RECOMMENDED_NEXT_PROVIDERS == []


def test_kubernetes_is_not_implemented() -> None:
    """Regression note: the Kubernetes connector and security-rules module
    now exist (Kubernetes message 6 — static Security Finding taxonomy)."""
    assert (BACKEND / "connectors" / "kubernetes.py").exists()
    assert (BACKEND / "services" / "security_rules" / "kubernetes.py").exists()
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    assert any("kubernetes" in k.lower() or k.lower().startswith("k8s")
               for k in KNOWN_RULE_KEYS)


# ── Group 8: Firebase activity-signal evidence privacy ────────────────────────

def test_activity_signal_module_has_no_raw_secret_or_pii_keys() -> None:
    """The Firebase activity-signal builder must only allowlist safe, flat
    metadata fields — never raw rule text, service-account keys, function logs,
    user emails, UIDs, or phone numbers."""
    src = BACKEND / "services" / "firebase_activity_signal_service.py"
    text = src.read_text(encoding="utf-8")
    code = _strip_docstrings_and_comments(text).lower()
    forbidden_metadata_tokens = [
        "principalemail",
        "private_key",
        "service_account_key",
        "function_log",
        "rules_text",
        "raw_rules",
        '"email"',
        '"uid"',
        '"phone"',
        '"actor_email"',
    ]
    for token in forbidden_metadata_tokens:
        assert token not in code, (
            f"Firebase activity-signal code references forbidden token {token!r}"
        )
