"""
Terraform Cloud Provider-Depth QA Tests

Covers dispatch wiring, rule/registry/catalog parity, evidence safety,
forbidden wording, phantom-field detection, orphaned-field detection,
plan_access_count correctness, env-var rule status, next-stage planning.

These tests are adapted to the actual ConfigTrace codebase:
  - Terraform Cloud rules are emitted by ``terraform_cloud.evaluate(record)``,
    which returns a list of ``FindingCandidate`` dataclass instances
    (attributes: ``rule_key``, ``severity``, ``title``, ``description``,
    ``evidence``), NOT a list of rule dicts.
  - The exported set of rule keys is ``TERRAFORM_CLOUD_RULE_KEYS``.
  - Records are dispatched by ``record_type`` (schema string constants).
  - Cross-module parity targets:
        registry   -> security_rule_registry.KNOWN_RULE_KEYS
        confidence -> security_rule_confidence.RULE_CONFIDENCE
        pack       -> security_rule_pack._RULE_META
        coverage   -> security_coverage_service.RULE_RECORD_TYPES
"""
import inspect
import os
import sys

import pytest

BACKEND_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FRONTEND_CATALOG_PATH = os.path.abspath(
    os.path.join(BACKEND_ROOT, "../frontend/src/lib/securityRuleCatalog.ts")
)
PROVIDER_EXPANSION_PATH = os.path.join(
    BACKEND_ROOT, "app/services/provider_expansion_framework.py"
)
KUBERNETES_CONNECTOR_PATH = os.path.join(
    BACKEND_ROOT, "app/connectors/kubernetes.py"
)

sys.path.insert(0, BACKEND_ROOT)


def _get_rule_keys():
    """Return the exported frozenset of Terraform Cloud rule keys as a sorted list."""
    from app.services.security_rules.terraform_cloud import TERRAFORM_CLOUD_RULE_KEYS

    return sorted(TERRAFORM_CLOUD_RULE_KEYS)


def _team_access(overrides: dict) -> dict:
    """Build a terraform_cloud_team_access_summary record with safe defaults."""
    base = {
        "record_type": "terraform_cloud_team_access_summary",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_team_access_summary:depth_qa",
        "resource_id": "depth_qa",
        "workspace_resource_id": "ws_opaque_depth",
        "team_access_count": 2,
        "admin_access_count": 0,
        "write_access_count": 0,
        "read_access_count": 0,
        "plan_access_count": 0,
        "custom_permission_count": 0,
    }
    base.update(overrides)
    return base


def _rule_keys_from_findings(findings) -> set:
    """Extract rule keys from FindingCandidate instances (or dicts, defensively)."""
    keys = set()
    for f in findings:
        rk = getattr(f, "rule_key", None)
        if rk is None and isinstance(f, dict):
            rk = f.get("rule_key") or f.get("finding_key") or f.get("key")
        if rk is not None:
            keys.add(rk)
    return keys


# ── A. Dispatch wiring ───────────────────────────────────────────────────────


def test_terraform_cloud_in_provider_rules():
    from app.services.security_finding_evaluator import _PROVIDER_RULES

    assert "terraform_cloud" in _PROVIDER_RULES


def test_evaluate_record_produces_finding_for_risky_workspace():
    from app.services.security_finding_evaluator import evaluate_record

    # auto_apply=True should reliably fire on a workspace record.
    record = {
        "record_type": "terraform_cloud_workspace",
        "provider": "terraform_cloud",
        "record_id": "terraform_cloud_workspace:depth_qa_ws",
        "resource_id": "ws-depth-qa-001",
        "workspace_resource_id": "ws_opaque_depth",
        "auto_apply": True,
        "global_remote_state": True,
        "execution_mode_category": "remote",
        "vcs_connected": True,
    }
    findings = evaluate_record(record, "terraform_cloud")
    assert len(findings) >= 1


def test_evaluate_record_dispatches_via_provider_key():
    """evaluate_record routes terraform_cloud records through tc evaluate()."""
    from app.services.security_finding_evaluator import evaluate_record

    findings = evaluate_record(_team_access({"plan_access_count": 3}), "terraform_cloud")
    assert "terraform_cloud_team_plan_access" in _rule_keys_from_findings(findings)


# ── B. Rule / registry / catalog parity ──────────────────────────────────────


def test_all_rule_keys_in_registry():
    from app.services.security_rule_registry import KNOWN_RULE_KEYS

    missing = [k for k in _get_rule_keys() if k not in KNOWN_RULE_KEYS]
    assert not missing, f"Missing from registry KNOWN_RULE_KEYS: {missing}"


def test_all_rule_keys_in_confidence():
    from app.services.security_rule_confidence import RULE_CONFIDENCE

    missing = [k for k in _get_rule_keys() if k not in RULE_CONFIDENCE]
    assert not missing, f"Missing from RULE_CONFIDENCE: {missing}"


def test_all_rule_keys_in_pack():
    from app.services.security_rule_pack import _RULE_META

    missing = [k for k in _get_rule_keys() if k not in _RULE_META]
    assert not missing, f"Missing from rule pack _RULE_META: {missing}"


def test_all_rule_keys_in_coverage():
    from app.services.security_coverage_service import RULE_RECORD_TYPES

    missing = [k for k in _get_rule_keys() if k not in RULE_RECORD_TYPES]
    assert not missing, f"Missing from coverage RULE_RECORD_TYPES: {missing}"


def test_all_rule_keys_in_frontend_catalog():
    if not os.path.exists(FRONTEND_CATALOG_PATH):
        pytest.skip(f"Frontend catalog not found at {FRONTEND_CATALOG_PATH}")
    with open(FRONTEND_CATALOG_PATH) as fh:
        catalog = fh.read()
    missing = [k for k in _get_rule_keys() if k not in catalog]
    assert not missing, f"Missing from frontend catalog: {missing}"


# ── C. Phantom-field detection: no rule reads apply_access_count ──────────────


def test_no_rule_reads_apply_access_count():
    from app.services.security_rules import terraform_cloud as tc_module

    source = inspect.getsource(tc_module)
    bad_lines = [
        line
        for line in source.splitlines()
        if "apply_access_count" in line and not line.strip().startswith("#")
    ]
    assert not bad_lines, (
        "apply_access_count (phantom field — never emitted by the connector) appears "
        "in non-comment lines:\n" + "\n".join(bad_lines)
    )


def test_stale_rule_key_absent():
    assert "terraform_cloud_team_apply_access" not in _get_rule_keys()


def test_stale_rule_key_absent_everywhere():
    """The renamed-away key must not survive in any parity surface."""
    from app.services.security_rule_confidence import RULE_CONFIDENCE
    from app.services.security_rule_pack import _RULE_META
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    from app.services.security_coverage_service import RULE_RECORD_TYPES

    stale = "terraform_cloud_team_apply_access"
    assert stale not in KNOWN_RULE_KEYS
    assert stale not in RULE_CONFIDENCE
    assert stale not in _RULE_META
    assert stale not in RULE_RECORD_TYPES


def test_no_stale_apply_access_wording():
    from app.services.security_rules.terraform_cloud import evaluate

    findings = evaluate(_team_access({"plan_access_count": 2}))
    violations = []
    for f in findings:
        for field in ("title", "description"):
            val = (getattr(f, field, "") or "").lower()
            if "apply access" in val or "apply-level access" in val:
                violations.append(f"{f.rule_key}.{field}")
    assert not violations, f"Stale 'apply access' wording: {violations}"


# ── D. plan_access_count is consumed (not orphaned) ──────────────────────────


def test_plan_access_count_consumed():
    from app.services.security_rules import terraform_cloud as tc_module

    source = inspect.getsource(tc_module)
    lines = [
        l
        for l in source.splitlines()
        if "plan_access_count" in l and not l.strip().startswith("#")
    ]
    assert lines, (
        "plan_access_count emitted by connector but consumed by no rule (orphaned field)"
    )


# ── E. Team plan access rule functional tests ────────────────────────────────


def test_team_plan_access_rule_key_exists():
    assert "terraform_cloud_team_plan_access" in _get_rule_keys()


def test_team_plan_access_fires():
    from app.services.security_rules.terraform_cloud import evaluate

    findings = evaluate(_team_access({"plan_access_count": 2}))
    keys = _rule_keys_from_findings(findings)
    assert "terraform_cloud_team_plan_access" in keys, (
        f"terraform_cloud_team_plan_access did not fire on plan_access_count=2. "
        f"Got: {keys}"
    )


def test_team_plan_access_no_fire_when_zero():
    from app.services.security_rules.terraform_cloud import evaluate

    findings = evaluate(_team_access({"plan_access_count": 0}))
    keys = _rule_keys_from_findings(findings)
    assert "terraform_cloud_team_plan_access" not in keys, (
        "terraform_cloud_team_plan_access incorrectly fired when plan_access_count=0"
    )


def test_team_plan_access_no_fire_when_missing():
    """Absent plan_access_count (None) must not fire the rule."""
    from app.services.security_rules.terraform_cloud import evaluate

    rec = _team_access({})
    rec.pop("plan_access_count", None)
    findings = evaluate(rec)
    assert "terraform_cloud_team_plan_access" not in _rule_keys_from_findings(findings)


def test_team_plan_access_title_references_plan():
    from app.services.security_rules.terraform_cloud import evaluate

    findings = evaluate(_team_access({"plan_access_count": 1}))
    plan_findings = [
        f for f in findings if f.rule_key == "terraform_cloud_team_plan_access"
    ]
    assert plan_findings, "plan-access finding not produced"
    title = plan_findings[0].title.lower()
    assert "plan" in title and "apply" not in title


# ── F. Evidence safety ───────────────────────────────────────────────────────


FORBIDDEN_EVIDENCE_KEYS = {
    "api_token", "team_token", "user_token", "organization_token", "oauth_token",
    "vcs_token", "run_token", "token", "authorization", "headers", "payload",
    "request", "response", "raw", "secret", "secret_value", "variable_value",
    "env_value", "terraform_variable_value", "tfstate", "state", "state_output",
    "state_version", "plan_json", "plan_log", "apply_log", "run_log",
    "configuration", "provider_credentials", "cloud_credentials", "private_key",
    "database_url", "user_email", "user_name", "customer",
}


def _all_findings_across_surfaces():
    """Drive evaluate() across every record type to collect all emitted findings."""
    from app.services.security_rules.terraform_cloud import evaluate

    records = [
        {
            "record_type": "terraform_cloud_organization",
            "record_id": "terraform_cloud_organization:o",
            "resource_id": "o", "two_factor_requirement_enabled": False,
            "sso_enabled": False, "workspace_count": 3,
        },
        {
            "record_type": "terraform_cloud_workspace",
            "record_id": "terraform_cloud_workspace:w", "resource_id": "w",
            "workspace_resource_id": "ws_o", "auto_apply": True,
            "global_remote_state": True, "execution_mode_category": "local",
            "vcs_connected": False, "queue_all_runs": False,
            "terraform_version_category": "latest", "file_triggers_enabled": False,
            "speculative_enabled": False, "run_trigger_count": 2,
            "trigger_prefix_count": 9, "latest_run_status_category": "errored",
        },
        {
            "record_type": "terraform_cloud_workspace_variable_summary",
            "record_id": "terraform_cloud_workspace_variable_summary:v",
            "workspace_resource_id": "ws_o", "variable_count": 4,
            "sensitive_variable_count": 0, "non_sensitive_variable_count": 4,
            "environment_variable_count": 2, "terraform_variable_count": 2,
            "unprotected_non_sensitive_count": 2, "raw_value_never_read": True,
        },
        {
            "record_type": "terraform_cloud_notification_configuration",
            "record_id": "terraform_cloud_notification_configuration:n",
            "notification_resource_id": "n_o", "workspace_resource_id": "ws_o",
            "enabled": True, "destination_type_category": "webhook",
            "webhook_url_scheme_category": "http", "token_present": False,
            "trigger_count": 7,
        },
        {
            "record_type": "terraform_cloud_policy_set",
            "record_id": "terraform_cloud_policy_set:p", "policy_set_resource_id": "p_o",
            "enforcement_level_category": "advisory", "policy_count": 0,
            "global_scope": True, "workspace_count": 0, "project_count": 0,
        },
        _team_access({"admin_access_count": 2, "write_access_count": 1,
                      "plan_access_count": 2, "custom_permission_count": 1}),
        {
            "record_type": "terraform_cloud_variable_set",
            "record_id": "terraform_cloud_variable_set:vs",
            "variable_set_resource_id": "vs_o", "global_scope": True,
            "variable_count": 8, "sensitive_variable_count": 0,
            "non_sensitive_variable_count": 8, "workspace_count": 0,
            "project_count": 0,
        },
        {
            "record_type": "terraform_cloud_state_version_summary",
            "record_id": "terraform_cloud_state_version_summary:s",
            "workspace_resource_id": "ws_o", "state_version_present": True,
            "raw_state_never_fetched": True,
        },
        {
            "record_type": "terraform_cloud_run_trigger",
            "record_id": "terraform_cloud_run_trigger:rt",
            "run_trigger_resource_id": "rt_o", "workspace_resource_id": "ws_o",
            "sourceable_type_category": "workspace",
        },
    ]
    findings = []
    for rec in records:
        findings.extend(evaluate(rec))
    return findings


def test_evidence_keys_safe():
    violations = []
    for f in _all_findings_across_surfaces():
        evidence = getattr(f, "evidence", {}) or {}
        if isinstance(evidence, dict):
            bad = set(evidence.keys()) & FORBIDDEN_EVIDENCE_KEYS
            if bad:
                violations.append(f"{f.rule_key}: {bad}")
    assert not violations, f"Forbidden evidence keys: {violations}"


def test_evidence_values_are_scalars():
    """Evidence must contain only bools, ints, or short strings — never dicts/lists."""
    violations = []
    for f in _all_findings_across_surfaces():
        evidence = getattr(f, "evidence", {}) or {}
        for k, v in evidence.items():
            if not isinstance(v, (bool, int, str)):
                violations.append(f"{f.rule_key}.{k}={type(v).__name__}")
    assert not violations, f"Non-scalar evidence values: {violations}"


# ── G. Forbidden wording ─────────────────────────────────────────────────────


FORBIDDEN_PHRASES = [
    "breach confirmed", "compromise confirmed", "attacker found", "someone has access",
    "data leaked", "secret leaked", "customer data exposed", "unauthorized access confirmed",
    "payment fraud detected", "attack detected", "state leaked", "tfstate leaked",
    "state exposed", "tfstate exposed", "infrastructure exposed", "secrets exposed",
    "tokens leaked", "credentials exposed", "credential exposure confirmed", "fraud confirmed",
]


def test_no_forbidden_wording():
    violations = []
    for f in _all_findings_across_surfaces():
        text = " ".join(
            [
                getattr(f, "title", "") or "",
                getattr(f, "description", "") or "",
            ]
        ).lower()
        for phrase in FORBIDDEN_PHRASES:
            if phrase in text:
                violations.append(f"{f.rule_key}: '{phrase}'")
    assert not violations, f"Forbidden wording: {violations}"


def test_disclaimer_present_on_all_findings():
    """Every finding description carries the non-confirmation disclaimer."""
    violations = []
    for f in _all_findings_across_surfaces():
        desc = (getattr(f, "description", "") or "").lower()
        if "does not confirm" not in desc:
            violations.append(f.rule_key)
    assert not violations, f"Findings missing disclaimer: {violations}"


# ── H. Next stage planning ───────────────────────────────────────────────────


def test_kubernetes_not_implemented():
    assert not os.path.exists(KUBERNETES_CONNECTOR_PATH), (
        "Kubernetes connector exists — should not be implemented yet"
    )


def test_provider_expansion_references_kubernetes():
    if not os.path.exists(PROVIDER_EXPANSION_PATH):
        pytest.skip("provider_expansion_framework.py not found")
    with open(PROVIDER_EXPANSION_PATH) as fh:
        content = fh.read().lower()
    assert any(kw in content for kw in ("kubernetes", "m89a", "k8s")), (
        "provider_expansion_framework.py does not reference Kubernetes/M89A as next stage"
    )


# ── I. Rule count ────────────────────────────────────────────────────────────


def test_rule_count_is_36():
    keys = _get_rule_keys()
    assert len(keys) == 36, f"Expected 36 rules, got {len(keys)}: {keys}"
