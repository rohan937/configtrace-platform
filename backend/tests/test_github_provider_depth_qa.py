"""GitHub provider depth QA.

Durable guardrails that pin the full GitHub rule taxonomy across every
registration surface and validate key behavioral invariants:

  A. Rule key inventory — all expected GitHub rule keys
  B. Registry parity (KNOWN_RULE_KEYS)
  C. Confidence parity (RULE_CONFIDENCE)
  D. Rule-pack parity (_RULE_META)
  E. Coverage-service parity (RULE_RECORD_TYPES)
  F. Provider surfaces completeness (PROVIDER_SURFACES)
  G. Record-type diagnostics completeness (RECORD_TYPE_DIAGNOSTICS)
  H. Webhook HTTP evidence does not store raw URL
  I. Deploy key finding wording is safe
  J. GitHub rule copy has no forbidden words
  K. Actions broad-permissions evaluator dispatches correctly
  L. Branch admin bypass evaluator dispatches correctly
  M. Severity calibration — webhook_http=high, webhook_secret_missing=high
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend" / "app"

GITHUB_RULES_FILE = BACKEND / "services" / "security_rules" / "github.py"

# ── Canonical GitHub rule key set ─────────────────────────────────────────────

EXPECTED_GITHUB_RULE_KEYS: frozenset[str] = frozenset({
    # Webhook rules
    "github_webhook_http",
    "github_webhook_secret_missing",
    "github_webhook_ssl_verification_disabled",
    # Branch protection rules
    "github_branch_protection_missing",
    "github_force_pushes_allowed",
    "github_branch_deletion_allowed",
    "github_pr_review_not_required",
    "github_status_checks_not_required",
    "github_branch_admin_bypass_allowed",
    # Deploy key rules
    "github_deploy_key_write_access",
    # Environment rules
    "github_env_protection_missing",
    # Ruleset rules (M69.5A)
    "github_ruleset_not_enforced",
    "github_ruleset_force_push_allowed",
    "github_ruleset_pr_review_missing",
    "github_ruleset_status_checks_missing",
    "github_ruleset_bypass_actors_present",
    "github_ruleset_weak_target_coverage",
    # Automation credential / token rules (M69.5B)
    "github_automation_admin_permission",
    "github_automation_write_permission",
    "github_token_broad_scopes",
    # Actions permissions rule (new QA rule)
    "github_actions_broad_permissions",
    "github_actions_workflow_token_write_permission",
    "github_actions_can_approve_pull_requests",
})

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


def test_A_all_expected_github_rule_keys_defined():
    """Every expected GitHub rule key appears in EXPECTED_GITHUB_RULE_KEYS."""
    # The set is defined at module level; just confirm it has entries.
    assert len(EXPECTED_GITHUB_RULE_KEYS) >= 20, (
        f"Expected at least 20 GitHub rule keys; got {len(EXPECTED_GITHUB_RULE_KEYS)}"
    )
    # Spot-check the two new QA rules
    assert "github_actions_broad_permissions" in EXPECTED_GITHUB_RULE_KEYS
    assert "github_branch_admin_bypass_allowed" in EXPECTED_GITHUB_RULE_KEYS


# ── Section B: Registry parity ────────────────────────────────────────────────


def test_B_all_github_rule_keys_in_registry():
    """All expected GitHub rule keys are registered in KNOWN_RULE_KEYS."""
    from app.services.security_rule_registry import KNOWN_RULE_KEYS

    missing = [k for k in EXPECTED_GITHUB_RULE_KEYS if k not in KNOWN_RULE_KEYS]
    assert not missing, (
        f"These GitHub rule keys are missing from KNOWN_RULE_KEYS: {sorted(missing)}"
    )


# ── Section C: Confidence parity ──────────────────────────────────────────────


def test_C_all_github_rule_keys_in_confidence():
    """All expected GitHub rule keys have a confidence entry in RULE_CONFIDENCE."""
    from app.services.security_rule_confidence import RULE_CONFIDENCE

    missing = [k for k in EXPECTED_GITHUB_RULE_KEYS if k not in RULE_CONFIDENCE]
    assert not missing, (
        f"These GitHub rule keys are missing from RULE_CONFIDENCE: {sorted(missing)}"
    )


# ── Section D: Rule-pack parity ───────────────────────────────────────────────


def test_D_all_github_rule_keys_in_pack():
    """All expected GitHub rule keys are present in _RULE_META."""
    from app.services.security_rule_pack import _RULE_META

    missing = [k for k in EXPECTED_GITHUB_RULE_KEYS if k not in _RULE_META]
    assert not missing, (
        f"These GitHub rule keys are missing from _RULE_META: {sorted(missing)}"
    )


# ── Section E: Coverage-service parity ────────────────────────────────────────


def test_E_all_github_rule_keys_in_coverage():
    """All expected GitHub rule keys map to at least one record type in RULE_RECORD_TYPES."""
    from app.services.security_coverage_service import RULE_RECORD_TYPES

    missing = [k for k in EXPECTED_GITHUB_RULE_KEYS if k not in RULE_RECORD_TYPES]
    assert not missing, (
        f"These GitHub rule keys are missing from RULE_RECORD_TYPES: {sorted(missing)}"
    )


# ── Section F: Provider surfaces completeness ─────────────────────────────────


def test_F_github_provider_surfaces_complete():
    """PROVIDER_SURFACES['github'] lists the expected monitoring surfaces."""
    from app.services.security_coverage_service import PROVIDER_SURFACES

    surfaces = PROVIDER_SURFACES.get("github", [])
    assert surfaces, "PROVIDER_SURFACES must have a 'github' entry"
    for expected in ("Webhooks", "Branch protection", "Rulesets", "Automation permissions"):
        assert expected in surfaces, (
            f"Expected surface {expected!r} missing from GitHub surfaces: {surfaces}"
        )


# ── Section G: Record-type diagnostics completeness ───────────────────────────


def test_G_record_type_diagnostics_complete():
    """Key GitHub record types are present in RECORD_TYPE_DIAGNOSTICS."""
    from app.services.security_coverage_service import RECORD_TYPE_DIAGNOSTICS

    for rt in ("github_ruleset", "github_automation_permissions", "github_webhook",
               "github_branch_protection"):
        assert rt in RECORD_TYPE_DIAGNOSTICS, (
            f"Record type {rt!r} missing from RECORD_TYPE_DIAGNOSTICS"
        )


# ── Section H: Webhook HTTP evidence safety ───────────────────────────────────


def test_H_webhook_http_evidence_does_not_store_raw_url():
    """Evidence for github_webhook_http must not contain the raw URL or query params."""
    from app.services.security_rules import github as gh

    record = {
        "record_id": "acme/qa-repo#webhook#1",
        "record_type": "github_webhook",
        "active": True,
        "url": "http://hooks.example.com/intake?token=secret_abc123&api_key=xyz_secret",
    }
    findings = gh.evaluate(record)
    http_f = next((f for f in findings if f.rule_key == "github_webhook_http"), None)
    assert http_f is not None, "github_webhook_http should fire for http:// URL"

    ev = http_f.evidence
    ev_str = str(ev)
    assert "url" not in ev, f"Raw 'url' key must not be in evidence: {ev}"
    assert "secret_abc123" not in ev_str, "Embedded token must not appear in evidence"
    assert "api_key" not in ev_str, "Query param keys must not appear in evidence"
    assert "xyz_secret" not in ev_str, "Query param values must not appear in evidence"
    assert ev.get("url_scheme") == "http"
    assert ev.get("url_host") == "hooks.example.com"
    assert ev.get("uses_http") is True
    # url_host must be just the hostname — no path or query string
    host = ev.get("url_host", "")
    assert "?" not in host, f"url_host must not contain query string: {host!r}"
    assert "/" not in host, f"url_host must not contain path: {host!r}"


# ── Section I: Deploy key wording safety ──────────────────────────────────────


def test_I_deploy_key_wording_safe():
    """Deploy key findings must not contain forbidden claim wording."""
    from app.services.security_rules import github as gh

    record = {
        "record_id": "acme/qa-repo#deploy_key#5",
        "record_type": "github_deploy_key",
        "name": "ci-deploy",
        "key_id": 5,
        "title": "ci-deploy",
        "read_only": False,
        "verified": True,
    }
    findings = gh.evaluate(record)
    write_key_f = next((f for f in findings if f.rule_key == "github_deploy_key_write_access"), None)
    assert write_key_f is not None, "github_deploy_key_write_access should fire for read_only=False"

    finding_text = (
        (write_key_f.title or "") + " " + (write_key_f.description or "")
    ).lower()
    # Must not assert breach/compromise
    for phrase in FORBIDDEN_PHRASES:
        assert phrase.lower() not in finding_text, (
            f"Forbidden phrase {phrase!r} found in deploy key finding copy: {finding_text!r}"
        )


# ── Section J: No forbidden words in GitHub rule copy ────────────────────────


def test_J_github_rule_copy_no_forbidden_words():
    """Risky GitHub records must not produce findings with forbidden claim wording."""
    from app.services.security_rules import github as gh

    risky_records: list[dict[str, Any]] = [
        # Webhook over HTTP
        {
            "record_id": "acme/qa-repo#webhook#1",
            "record_type": "github_webhook",
            "active": True,
            "url": "http://hooks.example.com/hook",
        },
        # Webhook without secret
        {
            "record_id": "acme/qa-repo#webhook#2",
            "record_type": "github_webhook",
            "active": True,
            "url": "https://hooks.example.com/hook",
            "webhook_secret_configured": False,
        },
        # Webhook with SSL verification disabled
        {
            "record_id": "acme/qa-repo#webhook#3",
            "record_type": "github_webhook",
            "active": True,
            "url": "https://hooks.example.com/hook",
            "insecure_ssl_enabled": True,
        },
        # Branch protection missing
        {
            "record_id": "acme/qa-repo#branch_protection#main",
            "record_type": "github_branch_protection",
            "branch": "main",
            "protection_enabled": False,
        },
        # Deploy key with write access
        {
            "record_id": "acme/qa-repo#deploy_key#1",
            "record_type": "github_deploy_key",
            "title": "ci-key",
            "key_id": 1,
            "read_only": False,
            "verified": True,
        },
        # Environment without protection
        {
            "record_id": "acme/qa-repo#environment#production",
            "record_type": "github_environment_protection",
            "environment_name": "production",
            "name": "production",
            "wait_timer": 0,
            "reviewers_count": 0,
            "prevent_self_review": False,
        },
        # Actions broad permissions
        {
            "record_id": "acme/qa-repo#actions_permissions",
            "record_type": "github_actions_permissions",
            "enabled": True,
            "allowed_actions": "all",
        },
        # Actions workflow token write + PR approval
        {
            "record_id": "acme/qa-repo#actions_permissions",
            "record_type": "github_actions_permissions",
            "enabled": True,
            "allowed_actions": "selected",
            "default_workflow_permissions": "write",
            "can_approve_pull_request_reviews": True,
        },
    ]

    all_findings = []
    for record in risky_records:
        all_findings.extend(gh.evaluate(record))

    for finding in all_findings:
        title = (finding.title or "").lower()
        description = (finding.description or "").lower()
        combined = title + " " + description
        for phrase in FORBIDDEN_PHRASES:
            assert phrase.lower() not in combined, (
                f"Forbidden phrase {phrase!r} found in finding {finding.rule_key!r} copy: "
                f"title={finding.title!r}, description={finding.description!r}"
            )


# ── Section K: Actions broad permissions evaluator ────────────────────────────


def test_K_actions_broad_permissions_fires_on_all():
    """github_actions_broad_permissions fires when allowed_actions == 'all'."""
    from app.services.security_rules import github as gh

    risky = {
        "record_id": "acme/qa-repo#actions_permissions",
        "record_type": "github_actions_permissions",
        "enabled": True,
        "allowed_actions": "all",
    }
    findings = gh.evaluate(risky)
    assert any(f.rule_key == "github_actions_broad_permissions" for f in findings), (
        f"github_actions_broad_permissions should fire for allowed_actions='all'; got: "
        f"{[f.rule_key for f in findings]}"
    )


def test_K_actions_broad_permissions_does_not_fire_for_local_only():
    """github_actions_broad_permissions does not fire when allowed_actions is restrictive."""
    from app.services.security_rules import github as gh

    for safe_value in ("local_only", "selected", None):
        record: dict[str, Any] = {
            "record_id": "acme/qa-repo#actions_permissions",
            "record_type": "github_actions_permissions",
            "enabled": True,
        }
        if safe_value is not None:
            record["allowed_actions"] = safe_value
        findings = gh.evaluate(record)
        broad = [f for f in findings if f.rule_key == "github_actions_broad_permissions"]
        assert not broad, (
            f"github_actions_broad_permissions must not fire for allowed_actions={safe_value!r}"
        )


def test_K_workflow_token_write_fires_on_write():
    """github_actions_workflow_token_write_permission fires when the token permission is 'write'."""
    from app.services.security_rules import github as gh

    record = {
        "record_id": "acme/qa-repo#actions_permissions",
        "record_type": "github_actions_permissions",
        "enabled": True,
        "allowed_actions": "selected",
        "default_workflow_permissions": "write",
    }
    findings = gh.evaluate(record)
    assert any(f.rule_key == "github_actions_workflow_token_write_permission" for f in findings)


def test_K_workflow_token_write_does_not_fire_on_read_or_unknown():
    """github_actions_workflow_token_write_permission must not fire for 'read' or unknown (None)."""
    from app.services.security_rules import github as gh

    for safe_value in ("read", None):
        record: dict[str, Any] = {
            "record_id": "acme/qa-repo#actions_permissions",
            "record_type": "github_actions_permissions",
            "enabled": True,
            "allowed_actions": "selected",
            "default_workflow_permissions": safe_value,
        }
        findings = gh.evaluate(record)
        write_findings = [
            f for f in findings if f.rule_key == "github_actions_workflow_token_write_permission"
        ]
        assert not write_findings, (
            f"github_actions_workflow_token_write_permission must not fire for "
            f"default_workflow_permissions={safe_value!r}"
        )


def test_K_actions_can_approve_prs_fires_on_true():
    """github_actions_can_approve_pull_requests fires when the flag is explicitly True."""
    from app.services.security_rules import github as gh

    record = {
        "record_id": "acme/qa-repo#actions_permissions",
        "record_type": "github_actions_permissions",
        "enabled": True,
        "allowed_actions": "selected",
        "can_approve_pull_request_reviews": True,
    }
    findings = gh.evaluate(record)
    assert any(f.rule_key == "github_actions_can_approve_pull_requests" for f in findings)


def test_K_actions_can_approve_prs_does_not_fire_on_false_or_unknown():
    """github_actions_can_approve_pull_requests must not fire for False or unknown (None)."""
    from app.services.security_rules import github as gh

    for safe_value in (False, None):
        record: dict[str, Any] = {
            "record_id": "acme/qa-repo#actions_permissions",
            "record_type": "github_actions_permissions",
            "enabled": True,
            "allowed_actions": "selected",
            "can_approve_pull_request_reviews": safe_value,
        }
        findings = gh.evaluate(record)
        approve_findings = [
            f for f in findings if f.rule_key == "github_actions_can_approve_pull_requests"
        ]
        assert not approve_findings, (
            f"github_actions_can_approve_pull_requests must not fire for "
            f"can_approve_pull_request_reviews={safe_value!r}"
        )


# ── Section L: Branch admin bypass evaluator ──────────────────────────────────


def test_L_branch_admin_bypass_fires_when_enforce_admins_false():
    """github_branch_admin_bypass_allowed fires when protection is enabled but enforce_admins=False."""
    from app.services.security_rules import github as gh

    record = {
        "record_id": "acme/qa-repo#branch_protection#main",
        "record_type": "github_branch_protection",
        "branch": "main",
        "protection_enabled": True,
        "enforce_admins": False,
        "required_pull_request_reviews_enabled": True,
        "required_approving_review_count": 1,
        "required_status_checks_enabled": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "dismiss_stale_reviews": True,
        "required_linear_history": True,
    }
    findings = gh.evaluate(record)
    bypass_f = next(
        (f for f in findings if f.rule_key == "github_branch_admin_bypass_allowed"), None
    )
    assert bypass_f is not None, (
        f"github_branch_admin_bypass_allowed should fire when enforce_admins=False; "
        f"got findings: {[f.rule_key for f in findings]}"
    )


def test_L_branch_admin_bypass_does_not_fire_when_enforce_admins_true():
    """github_branch_admin_bypass_allowed does not fire when enforce_admins=True."""
    from app.services.security_rules import github as gh

    record = {
        "record_id": "acme/qa-repo#branch_protection#main",
        "record_type": "github_branch_protection",
        "branch": "main",
        "protection_enabled": True,
        "enforce_admins": True,
        "required_pull_request_reviews_enabled": True,
        "required_approving_review_count": 1,
        "required_status_checks_enabled": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "dismiss_stale_reviews": True,
        "required_linear_history": True,
    }
    findings = gh.evaluate(record)
    bypass_findings = [f for f in findings if f.rule_key == "github_branch_admin_bypass_allowed"]
    assert not bypass_findings, (
        "github_branch_admin_bypass_allowed must not fire when enforce_admins=True"
    )


# ── Section M: Severity calibration ───────────────────────────────────────────


def test_M_severity_calibration_webhook_http_is_high():
    """github_webhook_http was calibrated from 'critical' to 'high'."""
    from app.services.security_rules import github as gh

    record = {
        "record_id": "acme/qa-repo#webhook#cal",
        "record_type": "github_webhook",
        "active": True,
        "url": "http://hooks.example.com/hook",
    }
    findings = gh.evaluate(record)
    http_f = next((f for f in findings if f.rule_key == "github_webhook_http"), None)
    assert http_f is not None
    assert http_f.severity == "high", (
        f"github_webhook_http must be 'high' after calibration; got {http_f.severity!r}"
    )


def test_M_severity_calibration_webhook_secret_missing_is_high():
    """github_webhook_secret_missing was calibrated from 'medium' to 'high'."""
    from app.services.security_rules import github as gh

    record = {
        "record_id": "acme/qa-repo#webhook#sec",
        "record_type": "github_webhook",
        "active": True,
        "url": "https://hooks.example.com/hook",
        "webhook_secret_configured": False,
    }
    findings = gh.evaluate(record)
    secret_f = next((f for f in findings if f.rule_key == "github_webhook_secret_missing"), None)
    assert secret_f is not None
    assert secret_f.severity == "high", (
        f"github_webhook_secret_missing must be 'high' after calibration; got {secret_f.severity!r}"
    )


def test_M_rule_pack_severity_github_webhook_http_is_high():
    """_RULE_META confirms github_webhook_http severity as 'high'."""
    from app.services.security_rule_pack import _RULE_META

    provider, severity, category = _RULE_META["github_webhook_http"]
    assert severity == "high", (
        f"_RULE_META['github_webhook_http'] severity must be 'high'; got {severity!r}"
    )


def test_M_rule_pack_severity_github_webhook_secret_missing_is_high():
    """_RULE_META confirms github_webhook_secret_missing severity as 'high'."""
    from app.services.security_rule_pack import _RULE_META

    provider, severity, category = _RULE_META["github_webhook_secret_missing"]
    assert severity == "high", (
        f"_RULE_META['github_webhook_secret_missing'] severity must be 'high'; got {severity!r}"
    )


def test_M_severity_github_webhook_ssl_verification_disabled_is_high():
    """github_webhook_ssl_verification_disabled fires 'high' when insecure_ssl_enabled is True."""
    from app.services.security_rules import github as gh

    record = {
        "record_id": "acme/qa-repo#webhook#ssl",
        "record_type": "github_webhook",
        "active": True,
        "url": "https://hooks.example.com/hook",
        "insecure_ssl_enabled": True,
    }
    findings = gh.evaluate(record)
    ssl_f = next(
        (f for f in findings if f.rule_key == "github_webhook_ssl_verification_disabled"),
        None,
    )
    assert ssl_f is not None
    assert ssl_f.severity == "high", (
        f"github_webhook_ssl_verification_disabled must be 'high'; got {ssl_f.severity!r}"
    )


def test_M_no_finding_when_ssl_verification_enabled():
    """No finding fires when insecure_ssl_enabled is explicitly False."""
    from app.services.security_rules import github as gh

    record = {
        "record_id": "acme/qa-repo#webhook#ssl-ok",
        "record_type": "github_webhook",
        "active": True,
        "url": "https://hooks.example.com/hook",
        "insecure_ssl_enabled": False,
    }
    findings = gh.evaluate(record)
    ssl_findings = [f for f in findings if f.rule_key == "github_webhook_ssl_verification_disabled"]
    assert not ssl_findings, "No finding should fire when insecure_ssl_enabled is False"


def test_M_no_finding_when_ssl_verification_unknown():
    """No finding fires when insecure_ssl_enabled is unknown (None / absent)."""
    from app.services.security_rules import github as gh

    record = {
        "record_id": "acme/qa-repo#webhook#ssl-unknown",
        "record_type": "github_webhook",
        "active": True,
        "url": "https://hooks.example.com/hook",
    }
    findings = gh.evaluate(record)
    ssl_findings = [f for f in findings if f.rule_key == "github_webhook_ssl_verification_disabled"]
    assert not ssl_findings, "No finding should fire when insecure_ssl_enabled is unknown/absent"


def test_M_rule_pack_severity_github_webhook_ssl_verification_disabled_is_high():
    """_RULE_META confirms github_webhook_ssl_verification_disabled severity as 'high'."""
    from app.services.security_rule_pack import _RULE_META

    provider, severity, category = _RULE_META["github_webhook_ssl_verification_disabled"]
    assert severity == "high", (
        f"_RULE_META['github_webhook_ssl_verification_disabled'] severity must be 'high'; got {severity!r}"
    )


def test_M_rule_pack_severity_github_actions_workflow_token_write_permission_is_high():
    """_RULE_META confirms github_actions_workflow_token_write_permission severity as 'high'."""
    from app.services.security_rule_pack import _RULE_META

    provider, severity, category = _RULE_META["github_actions_workflow_token_write_permission"]
    assert severity == "high", (
        f"_RULE_META['github_actions_workflow_token_write_permission'] severity must be 'high'; got {severity!r}"
    )


def test_M_rule_pack_severity_github_actions_can_approve_pull_requests_is_high():
    """_RULE_META confirms github_actions_can_approve_pull_requests severity as 'high'."""
    from app.services.security_rule_pack import _RULE_META

    provider, severity, category = _RULE_META["github_actions_can_approve_pull_requests"]
    assert severity == "high", (
        f"_RULE_META['github_actions_can_approve_pull_requests'] severity must be 'high'; got {severity!r}"
    )
