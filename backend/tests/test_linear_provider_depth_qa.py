"""
Linear provider depth QA — post-audit regression suite.

Covers:
- All 39 Linear rule keys present in registry, confidence, pack, coverage, frontend catalog
- Backend/frontend severity parity for all 39 rules
- Evidence metadata safety (flat, no forbidden fields)
- Linear rule copy has no forbidden wording
- Linear wired into _PROVIDER_RULES (evaluator dispatch)
- central evaluate_record(record, "linear") dispatch produces findings
- Workflow-hygiene rules have calibrated severity (not inflated)
- linear_team_no_completed_state is medium (not high)
- linear_team_private copy does NOT frame private as a risk
- planned_next_stage structural invariant (M89A Kubernetes)
- provider capability matrix correct for Linear
- Kubernetes is not yet implemented
- Targeted Linear token grep is clean

This suite does NOT confirm breaches, compromise, unauthorized access, data exposure,
or any security event. Linear findings are configuration evidence for review only.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from app.connectors.linear_schema import (
    LINEAR_CYCLE,
    LINEAR_INTEGRATION,
    LINEAR_LABEL,
    LINEAR_PROJECT,
    LINEAR_TEAM,
    LINEAR_VIEW,
    LINEAR_WEBHOOK,
    LINEAR_WORKFLOW_STATE,
    LINEAR_WORKSPACE,
)
from app.services.security_rules.linear import LINEAR_RULE_KEYS, evaluate
from app.services.security_finding_evaluator import _PROVIDER_RULES, evaluate_record
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_coverage_service import RULE_RECORD_TYPES, PROVIDERS
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

# ── constants ──────────────────────────────────────────────────────────────────

BASE = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[2]
_CATALOG_PATH = _REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"
_LINEAR_RULES_PATH = (
    _REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "linear.py"
)

EXPECTED_LINEAR_RULE_COUNT = 39

# The 39 Linear rule keys — extracted from security_rule_registry.py.
EXPECTED_LINEAR_RULE_KEYS: frozenset[str] = frozenset({
    # Workspace (5)
    "linear_workspace_missing_url_key",
    "linear_workspace_missing_logo",
    "linear_workspace_low_team_count",
    "linear_workspace_no_webhooks",
    "linear_workspace_no_integrations",
    # Team (13)
    "linear_team_private",
    "linear_team_low_member_count",
    "linear_team_no_projects",
    "linear_team_auto_archive_disabled",
    "linear_team_cycles_disabled",
    "linear_team_long_cycle_duration",
    "linear_team_no_backlog_state",
    "linear_team_no_started_state",
    "linear_team_no_completed_state",
    "linear_team_no_canceled_state",
    "linear_team_low_workflow_state_count",
    "linear_team_no_labels",
    "linear_team_no_webhooks",
    # Project (6)
    "linear_project_no_lead",
    "linear_project_no_members",
    "linear_project_high_issue_count",
    "linear_project_unhealthy",
    "linear_project_unknown_status",
    "linear_project_no_team_scope",
    # Workflow state (1)
    "linear_workflow_state_unknown_type",
    # Label (1)
    "linear_label_missing_team_scope",
    # Webhook (7)
    "linear_webhook_disabled",
    "linear_webhook_no_secret_indicator",
    "linear_webhook_non_https",
    "linear_webhook_no_events",
    "linear_webhook_broad_resource_scope",
    "linear_webhook_issue_comment_scope",
    "linear_webhook_attachment_scope",
    # View (2)
    "linear_view_shared",
    "linear_view_shared_without_team_scope",
    # Cycle (1)
    "linear_cycle_high_issue_count",
    # Integration (3)
    "linear_integration_disabled",
    "linear_integration_unknown_type",
    "linear_integration_workspace_scoped",
})

# Rules that should be HIGH severity (webhook transport / signing posture).
HIGH_SEVERITY_RULES = {
    "linear_webhook_no_secret_indicator",
    "linear_webhook_non_https",
}

# Rules that should be LOW severity (recalibrated down in this QA pass).
LOW_SEVERITY_RULES_EXPECTED = {
    "linear_team_cycles_disabled",          # recalibrated from medium
    "linear_team_auto_archive_disabled",    # recalibrated from medium
    "linear_team_no_backlog_state",         # recalibrated from medium
    "linear_team_no_started_state",         # recalibrated from medium
    "linear_team_low_workflow_state_count",  # recalibrated from medium
    "linear_workspace_no_webhooks",         # recalibrated from medium
    "linear_team_no_webhooks",              # recalibrated from medium
    "linear_team_private",
}

FORBIDDEN_COPY_PHRASES = [
    "breach confirmed", "compromise confirmed", "attacker found",
    "someone has access", "data leaked", "secret leaked",
    "customer data exposed", "unauthorized access confirmed",
    "payment fraud detected", "attack detected", "orders exposed",
    "card data exposed", "issues exposed", "project data exposed",
    "workspace exposed", "tokens leaked", "secrets exposed",
    "fraud confirmed",
]

FORBIDDEN_EVIDENCE_KEYS = {
    "api_token", "oauth_token", "integration_token", "authorization",
    "headers", "payload", "request", "response", "raw", "secret_value",
    "webhook_secret", "issue_title", "issue_description",
    "user_email", "user_name", "assignee", "creator", "customer", "comment",
}


# ── record builders ────────────────────────────────────────────────────────────


def _team(**kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "record_type": LINEAR_TEAM,
        "provider": "linear",
        "record_id": "linear_team_qa001",
        "private_team": False,
        "member_count_category": "several",
        "project_count": 2,
        "auto_archive_enabled": True,
        "cycle_enabled": True,
        "cycle_duration_category": "standard",
        "has_backlog_state": True,
        "has_started_state": True,
        "has_completed_state": True,
        "has_canceled_state": True,
        "workflow_state_count": 5,
        "label_count": 3,
        "webhook_count": 1,
    }
    d.update(kw)
    return d


def _webhook(**kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "record_type": LINEAR_WEBHOOK,
        "provider": "linear",
        "record_id": "linear_webhook_qa001",
        "webhook_enabled": True,
        "webhook_secret_present": True,
        "webhook_url_scheme_category": "https",
        "webhook_resource_types_count": 2,
        "webhook_has_comment_type": False,
        "webhook_has_attachment_type": False,
    }
    d.update(kw)
    return d


def _rule_keys(findings: list) -> set[str]:
    return {f.rule_key for f in findings}


def _catalog_severities() -> dict[str, str]:
    """Return {rule_key: severity} for linear rules in the frontend catalog."""
    text = _CATALOG_PATH.read_text(encoding="utf-8")
    result: dict[str, str] = {}
    pattern = re.compile(
        r'key:\s*"(linear_[^"]+)"[^}]*?severity:\s*"([^"]+)"',
        re.DOTALL,
    )
    for m in pattern.finditer(text):
        result[m.group(1)] = m.group(2)
    return result


def _backend_pack_severity(key: str) -> str | None:
    meta = _RULE_META.get(key)
    if not meta:
        return None
    return meta[1]


# ═════════════════════════════════════════════════════════════════════════════
# 1–4. Taxonomy parity across registry / confidence / pack / coverage
# ═════════════════════════════════════════════════════════════════════════════


def test_linear_rule_count_in_registry() -> None:
    assert len(EXPECTED_LINEAR_RULE_KEYS) == EXPECTED_LINEAR_RULE_COUNT
    registry_linear = {k for k in KNOWN_RULE_KEYS if k.startswith("linear_")}
    assert len(registry_linear) == EXPECTED_LINEAR_RULE_COUNT, (
        f"Expected {EXPECTED_LINEAR_RULE_COUNT} linear keys in registry, "
        f"got {len(registry_linear)}: extra={sorted(registry_linear - EXPECTED_LINEAR_RULE_KEYS)} "
        f"missing={sorted(EXPECTED_LINEAR_RULE_KEYS - registry_linear)}"
    )
    assert len(LINEAR_RULE_KEYS) == EXPECTED_LINEAR_RULE_COUNT


def test_linear_rule_keys_in_confidence() -> None:
    missing = EXPECTED_LINEAR_RULE_KEYS - set(RULE_CONFIDENCE.keys())
    assert not missing, f"Linear rules missing from confidence: {sorted(missing)}"


def test_linear_rule_keys_in_pack() -> None:
    missing = EXPECTED_LINEAR_RULE_KEYS - set(_RULE_META.keys())
    assert not missing, f"Linear rules missing from rule pack: {sorted(missing)}"


def test_linear_rule_keys_in_coverage() -> None:
    missing = EXPECTED_LINEAR_RULE_KEYS - set(RULE_RECORD_TYPES.keys())
    assert not missing, f"Linear rules missing from coverage service: {sorted(missing)}"
    assert "linear" in PROVIDERS, "linear missing from coverage PROVIDERS set"


# ═════════════════════════════════════════════════════════════════════════════
# 5–6. Frontend catalog parity
# ═════════════════════════════════════════════════════════════════════════════


def test_linear_frontend_catalog_has_all_rule_keys() -> None:
    if not _CATALOG_PATH.exists():
        pytest.skip("securityRuleCatalog.ts not found")
    catalog_text = _CATALOG_PATH.read_text(encoding="utf-8")
    missing = [k for k in EXPECTED_LINEAR_RULE_KEYS if k not in catalog_text]
    assert not missing, f"Linear rules missing from frontend catalog: {sorted(missing)}"


def test_linear_backend_frontend_severity_parity() -> None:
    if not _CATALOG_PATH.exists():
        pytest.skip("securityRuleCatalog.ts not found")
    catalog = _catalog_severities()
    mismatches = []
    for key in EXPECTED_LINEAR_RULE_KEYS:
        backend_sev = _backend_pack_severity(key)
        frontend_sev = catalog.get(key)
        if frontend_sev is None:
            mismatches.append(f"{key}: missing from catalog")
        elif backend_sev != frontend_sev:
            mismatches.append(
                f"{key}: backend={backend_sev!r} frontend={frontend_sev!r}"
            )
    assert not mismatches, "Backend/frontend severity mismatches:\n" + "\n".join(mismatches)


# ═════════════════════════════════════════════════════════════════════════════
# 7–9. Severity calibration
# ═════════════════════════════════════════════════════════════════════════════


def test_linear_no_completed_state_is_medium_not_high() -> None:
    """linear_team_no_completed_state must be medium (recalibrated from high)."""
    assert _backend_pack_severity("linear_team_no_completed_state") == "medium"
    catalog = _catalog_severities()
    assert catalog.get("linear_team_no_completed_state") == "medium"
    # rule body severity (runtime)
    findings = evaluate(_team(has_completed_state=False))
    fired = [f for f in findings if f.rule_key == "linear_team_no_completed_state"]
    assert fired, "linear_team_no_completed_state did not fire"
    assert fired[0].severity == "medium", (
        f"runtime severity is {fired[0].severity!r}, expected medium"
    )


def test_linear_workflow_hygiene_rules_are_low() -> None:
    """The recalibrated workflow-hygiene rules must be low in pack AND catalog."""
    catalog = _catalog_severities()
    violations = []
    for key in LOW_SEVERITY_RULES_EXPECTED:
        backend_sev = _backend_pack_severity(key)
        if backend_sev != "low":
            violations.append(f"{key}: pack severity={backend_sev!r} (expected low)")
        frontend_sev = catalog.get(key)
        if frontend_sev != "low":
            violations.append(f"{key}: catalog severity={frontend_sev!r} (expected low)")
    assert not violations, "Workflow-hygiene rules not low:\n" + "\n".join(violations)


def test_linear_high_severity_rules_remain_high() -> None:
    """Webhook signing/transport rules must remain high."""
    catalog = _catalog_severities()
    for key in HIGH_SEVERITY_RULES:
        assert _backend_pack_severity(key) == "high", (
            f"{key}: pack severity is {_backend_pack_severity(key)!r}, expected high"
        )
        assert catalog.get(key) == "high", (
            f"{key}: catalog severity is {catalog.get(key)!r}, expected high"
        )


# ═════════════════════════════════════════════════════════════════════════════
# 10. Private team copy is not risk-framed
# ═════════════════════════════════════════════════════════════════════════════


def test_linear_private_team_copy_not_risk_framing() -> None:
    """linear_team_private copy must NOT frame private visibility as a risk/threat."""
    findings = evaluate(_team(private_team=True))
    fired = [f for f in findings if f.rule_key == "linear_team_private"]
    assert fired, "linear_team_private did not fire on a private team"
    f = fired[0]
    combined = (f.title + " " + f.description).lower()
    forbidden_framing = ["attacker", "exposed", "breach", "compromise", "leaked", "unauthorized"]
    bad = [w for w in forbidden_framing if w in combined]
    assert not bad, f"linear_team_private copy contains risk framing {bad}: {combined!r}"
    # Should explicitly acknowledge the configuration may be intentional.
    assert "intentional" in combined or "common" in combined, (
        f"linear_team_private copy should acknowledge benign/intentional use: {combined!r}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# 11. Evaluator dispatch wiring
# ═════════════════════════════════════════════════════════════════════════════


def test_linear_wired_in_provider_rules() -> None:
    assert "linear" in _PROVIDER_RULES, (
        "linear missing from _PROVIDER_RULES in security_finding_evaluator.py"
    )
    rules = _PROVIDER_RULES["linear"]
    assert rules and all(callable(fn) for fn in rules)


# ═════════════════════════════════════════════════════════════════════════════
# 12–15. Central evaluate_record dispatch
# ═════════════════════════════════════════════════════════════════════════════


def test_central_evaluate_record_dispatch_webhook_no_secret() -> None:
    rec = _webhook(webhook_secret_present=False)
    findings = evaluate_record(rec, "linear")
    assert "linear_webhook_no_secret_indicator" in _rule_keys(findings)


def test_central_evaluate_record_dispatch_non_https() -> None:
    rec = _webhook(webhook_url_scheme_category="non_https")
    findings = evaluate_record(rec, "linear")
    assert "linear_webhook_non_https" in _rule_keys(findings)


def test_central_evaluate_record_dispatch_team_rule() -> None:
    rec = _team(has_completed_state=False)
    findings = evaluate_record(rec, "linear")
    keys = _rule_keys(findings)
    assert any(k.startswith("linear_") for k in keys), (
        f"No linear findings from risky team record: {keys}"
    )
    assert "linear_team_no_completed_state" in keys


def test_evaluate_record_argument_order_is_correct() -> None:
    """Guard against reversed-argument false passes: (record, 'linear') is correct."""
    rec = _webhook(webhook_secret_present=False)
    correct = evaluate_record(rec, "linear")
    assert correct, "Correct argument order produced no findings"
    # Reversed order must NOT produce linear findings (would raise or be empty).
    try:
        reversed_result = evaluate_record("linear", rec)  # type: ignore[arg-type]
    except Exception:
        reversed_result = []
    reversed_keys = {
        getattr(f, "rule_key", None) for f in reversed_result
    } if reversed_result else set()
    assert "linear_webhook_no_secret_indicator" not in reversed_keys, (
        "Reversed argument order unexpectedly produced linear findings"
    )


# ═════════════════════════════════════════════════════════════════════════════
# 16. Evidence safety
# ═════════════════════════════════════════════════════════════════════════════


def _all_risky_findings() -> list:
    records = [
        _team(
            private_team=True,
            member_count_category="none",
            project_count=0,
            auto_archive_enabled=False,
            cycle_enabled=False,
            cycle_duration_category="long",
            has_backlog_state=False,
            has_started_state=False,
            has_completed_state=False,
            has_canceled_state=False,
            workflow_state_count=1,
            label_count=0,
            webhook_count=0,
        ),
        _webhook(
            webhook_enabled=False,
            webhook_secret_present=False,
            webhook_url_scheme_category="non_https",
            webhook_resource_types_count=8,
            webhook_has_comment_type=True,
            webhook_has_attachment_type=True,
        ),
        {
            "record_type": LINEAR_WORKSPACE, "provider": "linear",
            "record_id": "linear_workspace_qa001",
            "url_key_present": False, "logo_present": False,
            "team_count": 1, "webhook_count": 0, "integration_count": 0,
        },
        {
            "record_type": LINEAR_PROJECT, "provider": "linear",
            "record_id": "linear_project_qa001",
            "lead_present": False, "member_count_category": "none",
            "issue_count_category": "many", "project_health_category": "atrisk",
            "project_status_category": "unknown", "team_count": 0,
        },
        {
            "record_type": LINEAR_WORKFLOW_STATE, "provider": "linear",
            "record_id": "linear_wfs_qa001", "state_type_category": "unknown",
        },
        {
            "record_type": LINEAR_LABEL, "provider": "linear",
            "record_id": "linear_label_qa001", "team_id": None,
        },
        {
            "record_type": LINEAR_VIEW, "provider": "linear",
            "record_id": "linear_view_qa001", "view_shared": True, "team_id": None,
        },
        {
            "record_type": LINEAR_CYCLE, "provider": "linear",
            "record_id": "linear_cycle_qa001", "issue_count_category": "many",
        },
        {
            "record_type": LINEAR_INTEGRATION, "provider": "linear",
            "record_id": "linear_integration_qa001",
            "integration_enabled": False, "integration_type_category": "unknown",
            "team_id": None,
        },
        {
            "record_type": LINEAR_INTEGRATION, "provider": "linear",
            "record_id": "linear_integration_qa002",
            "integration_enabled": True, "integration_type_category": "github",
            "team_id": None,
        },
    ]
    out: list = []
    for rec in records:
        out.extend(evaluate(rec))
    return out


def test_linear_evidence_no_forbidden_keys() -> None:
    findings = _all_risky_findings()
    assert findings, "No findings produced for evidence-safety scan"
    violations = []
    for f in findings:
        if not f.evidence:
            continue
        bad = set(f.evidence.keys()) & FORBIDDEN_EVIDENCE_KEYS
        if bad:
            violations.append(f"{f.rule_key}: {sorted(bad)}")
        # Evidence values must be flat scalars.
        for k, v in f.evidence.items():
            if not isinstance(v, (bool, int, float, str, type(None))):
                violations.append(f"{f.rule_key}.{k}: non-scalar type {type(v).__name__}")
    assert not violations, "Evidence safety violations:\n" + "\n".join(violations)


# ═════════════════════════════════════════════════════════════════════════════
# 17. Forbidden wording in rule source
# ═════════════════════════════════════════════════════════════════════════════


def test_linear_rule_copy_no_forbidden_phrases() -> None:
    text = _LINEAR_RULES_PATH.read_text(encoding="utf-8").lower()
    violations = [p for p in FORBIDDEN_COPY_PHRASES if p in text]
    assert not violations, f"Forbidden phrases in linear.py: {violations}"
    # Also scan produced finding copy.
    findings = _all_risky_findings()
    for f in findings:
        blob = ((f.title or "") + " " + (f.description or "")).lower()
        bad = [p for p in FORBIDDEN_COPY_PHRASES if p in blob]
        assert not bad, f"{f.rule_key}: forbidden phrase {bad}"


# ═════════════════════════════════════════════════════════════════════════════
# 18–19. Roadmap / framework invariants
# ═════════════════════════════════════════════════════════════════════════════


def test_planned_next_stage_structural_invariant() -> None:
    """Regression note: Kubernetes launched (message 1 / M89A), then
    Sentry (message 8 — public launch) was the FINAL planned provider.
    Provider expansion is now frozen."""
    fw = get_framework()
    planned = fw["summary"]["planned_next_stage"]
    assert isinstance(planned, str) and planned, "planned_next_stage must be a non-empty string"
    assert "frozen" in planned.lower(), f"planned_next_stage should say frozen, got {planned!r}"


def test_kubernetes_not_yet_implemented() -> None:
    """Regression note: the Kubernetes connector and security-rules module
    now exist (Kubernetes message 6 — static Security Finding taxonomy). It
    has been removed from the recommended-next queue since it has launched."""
    assert (_REPO_ROOT / "backend" / "app" / "connectors" / "kubernetes.py").exists()
    assert (
        _REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "kubernetes.py"
    ).exists()
    assert "kubernetes" in _PROVIDER_RULES
    cap = get_provider_capability("kubernetes")
    assert cap is not None
    assert cap.maturity == "partial"
    fw = get_framework()
    recommended = [
        r.get("provider", "").lower()
        for r in fw.get("recommended_next_providers", [])
        if isinstance(r, dict)
    ]
    assert "kubernetes" not in recommended, "Kubernetes has launched and should not be recommended-next"


# ═════════════════════════════════════════════════════════════════════════════
# Provider capability matrix correctness for Linear
# ═════════════════════════════════════════════════════════════════════════════


def test_linear_capability_matrix_correct() -> None:
    cap = get_provider_capability("linear")
    assert cap is not None, "Linear must have a capability matrix entry"
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.demo_seed_clear is True


# ═════════════════════════════════════════════════════════════════════════════
# 20. Targeted Linear token grep
# ═════════════════════════════════════════════════════════════════════════════


def test_linear_token_grep_clean() -> None:
    """No real lin_api_ token-shaped strings in Linear backend modules.

    Placeholder text ('lin_api_...') and documentation comments are allowed;
    a real token would have additional secret-shaped characters after the prefix.
    """
    real_token = re.compile(r"lin_api_[A-Za-z0-9]{16,}")
    linear_modules = [
        _REPO_ROOT / "backend" / "app" / "connectors" / "linear.py",
        _REPO_ROOT / "backend" / "app" / "connectors" / "linear_schema.py",
        _REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "linear.py",
    ]
    violations = []
    for path in linear_modules:
        if not path.exists():
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if real_token.search(line):
                violations.append(f"{path.name}:{i}: {line.strip()[:80]!r}")
    assert not violations, "Token-shaped strings in Linear modules:\n" + "\n".join(violations)
