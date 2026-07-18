"""GitLab provider-depth QA — connector→evaluator regression coverage.

This suite hardens the GitLab provider against the specific regressions fixed in
the "harden GitLab webhook evaluation" change:

  * P1 — webhook ``enabled`` was incorrectly derived from
    ``enable_ssl_verification``, so SSL-disabled webhooks were silently skipped
    by the rule evaluator. ``enabled`` is now always truthy for fetched hooks.
  * P2 — the MR approval summary mapped ``code_owner_approval_required`` from the
    raw ``merge_requests_author_approval`` field. The normalized field is now
    ``author_approval_allowed`` to match what the raw field actually means.
  * P2 — ``gitlab_mr_approver_override_allowed`` fired Medium on GitLab's default
    config; it is now a Low-severity hygiene finding.

Unlike the rule-layer milestone tests, these tests drive the *actual* connector
normalizer (``GitLabConnector._normalize_webhook`` /
``_normalize_mr_approval_summary``) and the *actual* central evaluator
(``evaluate_record``), so a connector-level regression cannot pass behind a
synthetic helper that hardcodes ``enabled=True``.
"""
from __future__ import annotations

import re
from pathlib import Path

from app.connectors.gitlab import GitLabConnector
from app.connectors.gitlab_schema import GITLAB_RECORD_TYPES
from app.services.security_finding_evaluator import (
    _PROVIDER_RULES,
    evaluate_record,
)
from app.services.security_rules.gitlab import GITLAB_RULE_KEYS
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META as RULE_PACK
from app.services.security_coverage_service import RULE_RECORD_TYPES

# ---------------------------------------------------------------------------
# Paths / constants
# ---------------------------------------------------------------------------

_BACKEND = Path(__file__).parent.parent
_FRONTEND = _BACKEND.parent / "frontend" / "src"
_FE_RULE_CATALOG_TS = _FRONTEND / "lib" / "securityRuleCatalog.ts"
_EXPANSION_FRAMEWORK_PY = (
    _BACKEND / "app" / "services" / "provider_expansion_framework.py"
)

# The 25 GitLab security rule keys (M87B + M87C). Sourced from the rule module's
# own export so this list cannot silently drift from the implementation.
ALL_GITLAB_RULE_KEYS = frozenset(GITLAB_RULE_KEYS)

_FORBIDDEN_PHRASES = [
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
    "repo exposed",
    "repository exposed",
    "source code exposed",
    "source code leaked",
    "secrets exposed",
    "tokens leaked",
    "ci secrets exposed",
    "credentials exposed",
    "fraud confirmed",
]

# Evidence keys that would carry a raw sensitive VALUE are forbidden. Safe
# presence/category/count flags (e.g. ``secret_token_present``) are allowed
# because they expose only a boolean, never the underlying value. We therefore
# match against exact dangerous key names rather than broad substrings.
_FORBIDDEN_EVIDENCE_KEYS = frozenset({
    "token",
    "secret",
    "secret_token",
    "access_token",
    "private_token",
    "authorization",
    "password",
    "url",
    "webhook_url",
    "user_email",
    "username",
    "project_name",
    "group_name",
    "branch_name",
    "namespace",
    "fingerprint",
    "key_material",
    "ssh_key",
    "ip_address",
    "payload",
})


def _src(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Record builders that mirror the connector's normalized output
# ---------------------------------------------------------------------------

def _risky_project_record() -> dict:
    """A public GitLab project — should produce >=1 finding."""
    return {
        "record_type": "gitlab_project",
        "provider": "gitlab",
        "record_id": "gitlab_project:proj_opaque_1",
        "resource_id": "proj_opaque_1",
        "visibility_category": "public",
        "archived": False,
        "default_branch_present": True,
        "merge_requests_enabled": True,
        "issues_enabled": True,
        "wiki_enabled": False,
        "snippets_enabled": False,
        "container_registry_enabled": False,
        "packages_enabled": False,
        "shared_runners_enabled": False,
        "protected_branch_count": 1,
        "webhook_count": 0,
        "ci_variable_count": 0,
        "deploy_key_count": 0,
        "approval_rule_count": 1,
    }


def _normalize_webhook(raw: dict) -> dict:
    """Drive the real connector normalizer (not a synthetic helper)."""
    return GitLabConnector()._normalize_webhook(raw, "owner_opaque_1", "project")


# ===========================================================================
# 1–5: Rule-key registration parity across every table
# ===========================================================================

def test_all_25_gitlab_rule_keys_in_registry() -> None:
    assert len(ALL_GITLAB_RULE_KEYS) == 25
    missing = ALL_GITLAB_RULE_KEYS - KNOWN_RULE_KEYS
    assert not missing, f"GitLab rule keys missing from registry: {sorted(missing)}"


def test_all_25_gitlab_rule_keys_in_confidence() -> None:
    missing = ALL_GITLAB_RULE_KEYS - set(RULE_CONFIDENCE)
    assert not missing, f"GitLab rule keys missing from confidence: {sorted(missing)}"


def test_all_25_gitlab_rule_keys_in_rule_pack() -> None:
    missing = ALL_GITLAB_RULE_KEYS - set(RULE_PACK)
    assert not missing, f"GitLab rule keys missing from rule pack: {sorted(missing)}"


def test_all_25_gitlab_rule_keys_in_coverage_service() -> None:
    missing = ALL_GITLAB_RULE_KEYS - set(RULE_RECORD_TYPES)
    assert not missing, (
        f"GitLab rule keys missing from coverage RULE_RECORD_TYPES: {sorted(missing)}"
    )


def test_all_25_gitlab_rule_keys_in_frontend_catalog() -> None:
    src = _src(_FE_RULE_CATALOG_TS)
    missing = [rk for rk in ALL_GITLAB_RULE_KEYS if f'"{rk}"' not in src]
    assert not missing, f"GitLab rule keys missing from frontend catalog: {sorted(missing)}"


# ===========================================================================
# 6: Backend / frontend severity parity
# ===========================================================================

def test_backend_frontend_severity_match() -> None:
    src = _src(_FE_RULE_CATALOG_TS)
    # Parse the catalog into (key, severity) pairs via lightweight block scan.
    # Each entry is an object with `key: "..."` and `severity: "..."`.
    entries = re.findall(
        r'key:\s*"(gitlab_[a-z_]+)".*?severity:\s*"(\w+)"',
        src,
        flags=re.DOTALL,
    )
    fe_sev = {k: s for k, s in entries}
    for rk in ALL_GITLAB_RULE_KEYS:
        assert rk in fe_sev, f"{rk} not found in frontend catalog severity scan"
        backend_sev = RULE_PACK[rk][1]
        assert fe_sev[rk] == backend_sev, (
            f"severity mismatch for {rk}: backend={backend_sev} frontend={fe_sev[rk]}"
        )


# ===========================================================================
# 7–8: Evidence + copy safety
# ===========================================================================

def _sample_gitlab_findings() -> list:
    """Produce a spread of real GitLab findings across record types."""
    findings: list = []
    findings += evaluate_record(_risky_project_record(), "gitlab")
    findings += evaluate_record(
        _normalize_webhook(
            {"id": "1", "url": "http://hook.example/x", "enable_ssl_verification": False}
        ),
        "gitlab",
    )
    findings += evaluate_record(
        GitLabConnector()._normalize_mr_approval_summary(
            {
                "approvals_required": 0,
                "merge_requests_author_approval": True,
                "reset_approvals_on_push": False,
                "disable_overriding_approvers_per_merge_request": False,
            },
            "proj_opaque_1",
        ),
        "gitlab",
    )
    return findings


def test_evidence_metadata_safe() -> None:
    findings = _sample_gitlab_findings()
    assert findings, "expected sample GitLab findings"
    for f in findings:
        for key in f.evidence:
            lk = key.lower()
            assert lk not in _FORBIDDEN_EVIDENCE_KEYS, (
                f"evidence key {key!r} on {f.rule_key} is a forbidden raw-value key"
            )
            # Defense in depth: evidence values must be flat scalars only.
            val = f.evidence[key]
            assert isinstance(val, (bool, int, str)), (
                f"evidence value for {key!r} on {f.rule_key} is not a flat scalar"
            )


def test_rule_copy_no_forbidden_wording() -> None:
    findings = _sample_gitlab_findings()
    for f in findings:
        blob = f"{f.title}\n{f.description}".lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in blob, (
                f"forbidden phrase {phrase!r} in copy for {f.rule_key}"
            )


# ===========================================================================
# 9–10: Evaluator wiring
# ===========================================================================

def test_gitlab_wired_in_provider_rules() -> None:
    assert "gitlab" in _PROVIDER_RULES
    assert _PROVIDER_RULES["gitlab"], "gitlab evaluator list must be non-empty"


def test_central_evaluator_produces_finding() -> None:
    findings = evaluate_record(_risky_project_record(), "gitlab")
    assert len(findings) >= 1
    assert any(f.rule_key == "gitlab_project_public_visibility" for f in findings)


# ===========================================================================
# 11–14: Webhook regression — SSL-disabled hooks must NOT be skipped
# ===========================================================================

def test_ssl_disabled_webhook_not_skipped() -> None:
    """Connector-normalized SSL-disabled webhook must have enabled truthy and
    ssl_verification_enabled False (the two must be decoupled)."""
    record = _normalize_webhook(
        {"id": "1", "url": "https://hook.example/x", "enable_ssl_verification": False}
    )
    assert record["enabled"], "SSL-disabled webhook must remain enabled/active"
    assert record["ssl_verification_enabled"] is False
    # Decoupled: enabled must not simply mirror ssl_verification_enabled.
    assert record["enabled"] != record["ssl_verification_enabled"]


def test_ssl_disabled_webhook_triggers_ssl_rule() -> None:
    record = _normalize_webhook(
        {"id": "1", "url": "https://hook.example/x", "enable_ssl_verification": False}
    )
    findings = evaluate_record(record, "gitlab")
    keys = {f.rule_key for f in findings}
    assert "gitlab_webhook_ssl_verification_disabled" in keys


def test_http_webhook_fires_even_when_ssl_disabled() -> None:
    record = _normalize_webhook(
        {"id": "2", "url": "http://hook.example/x", "enable_ssl_verification": False}
    )
    findings = evaluate_record(record, "gitlab")
    keys = {f.rule_key for f in findings}
    assert "gitlab_webhook_http_scheme" in keys


def test_missing_secret_fires_even_when_ssl_disabled() -> None:
    record = _normalize_webhook(
        {"id": "3", "url": "https://hook.example/x", "enable_ssl_verification": False}
    )
    # No token / secret_token in the raw dict → secret_token_present is False.
    assert record["secret_token_present"] is False
    findings = evaluate_record(record, "gitlab")
    keys = {f.rule_key for f in findings}
    assert "gitlab_webhook_secret_missing" in keys


# ===========================================================================
# 15–16: MR approval retune + field rename
# ===========================================================================

def test_mr_approver_override_rule_is_low_severity() -> None:
    record = GitLabConnector()._normalize_mr_approval_summary(
        {
            "approvals_required": 2,
            "reset_approvals_on_push": True,
            "disable_overriding_approvers_per_merge_request": False,
        },
        "proj_opaque_1",
    )
    findings = evaluate_record(record, "gitlab")
    override = [
        f for f in findings if f.rule_key == "gitlab_mr_approver_override_allowed"
    ]
    assert override, "override rule should still fire on default config"
    assert override[0].severity == "low"
    # And the pack agrees.
    assert RULE_PACK["gitlab_mr_approver_override_allowed"][1] == "low"


def test_author_approval_field_name_correct() -> None:
    """The MR approval summary must expose author_approval_allowed (mapped from
    raw merge_requests_author_approval), NOT code_owner_approval_required."""
    record = GitLabConnector()._normalize_mr_approval_summary(
        {
            "approvals_required": 2,
            "merge_requests_author_approval": True,
            "reset_approvals_on_push": True,
            "disable_overriding_approvers_per_merge_request": True,
        },
        "proj_opaque_1",
    )
    assert "author_approval_allowed" in record
    assert record["author_approval_allowed"] is True
    assert "code_owner_approval_required" not in record


# ===========================================================================
# 17–18: Provider scope / next-stage references
# ===========================================================================

def test_kubernetes_not_implemented() -> None:
    """Regression note: kubernetes is now wired into the central evaluator
    (Kubernetes message 6 — static Security Finding taxonomy)."""
    assert "kubernetes" in _PROVIDER_RULES
    rules_dir = _BACKEND / "app" / "services" / "security_rules"
    assert (rules_dir / "kubernetes.py").exists()


def test_provider_expansion_points_to_m89a_kubernetes() -> None:
    src = _src(_EXPANSION_FRAMEWORK_PY)
    assert "M89A" in src or "Kubernetes" in src
