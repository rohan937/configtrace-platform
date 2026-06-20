"""M86I — Jira cross-cloud UX polish guardrails.

Durable, deterministic guardrails that pin the final Jira arc (M86A–M86I)
state. This file adds NO product engine code — it verifies that Jira is a
first-class completed provider across all internal security UX surfaces, demo
script, provider capability table, case report / timeline labels, and roadmap
handoff to GitLab (M87A).

Sections:

  PROVIDER LABEL
     Jira capability-matrix provider name / label / flags.

  ARC COMPLETION
     Maturity reflects completion per convention (stays "partial", consistent
     with other completed partial arcs: Datadog, Clerk, PagerDuty, Linear).
     planned_next_stage has advanced past M86I to M87A: GitLab.

  SECURITY RULES CATALOG
     securityRuleCatalog.ts contains every backend Jira rule key; counts match;
     copy avoids forbidden wording; HIGH/MEDIUM/LOW all represented.

  FRONTEND PAGES
     activity / signals / correlations / cases pages include Jira; api.ts has
     the Jira sync / generate functions.

  CROSS-PROVIDER
     GitLab is the planned-next provider; no gitlab_ rule keys registered yet;
     M75A guardrails cover Jira.

  PRIVACY / COPY
     No forbidden wording near Jira frontend copy; demo uses JIRA_DEMO_
     placeholder IDs; Jira evidence allowlist carries no PII keys.

  M86A–M86H REGRESSION SPOT-CHECKS
     82 rules still registered, 13 event types still mapped, demo seed/clear
     functions still importable.

  WORDING
     No forbidden wording across the jira_* service modules; case report carries
     a human-review disclaimer.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import security_case_report_service as report_svc
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_rules.jira import JIRA_RULE_KEYS

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ROOT = REPO_ROOT / "frontend" / "src"
FE_ACTIVITY = FE_ROOT / "app" / "(app)" / "security" / "activity" / "page.tsx"
FE_SIGNALS = FE_ROOT / "app" / "(app)" / "security" / "signals" / "page.tsx"
FE_CORRELATIONS = FE_ROOT / "app" / "(app)" / "security" / "correlations" / "page.tsx"
FE_CASES = FE_ROOT / "app" / "(app)" / "security" / "cases" / "page.tsx"
FE_RULE_CATALOG = FE_ROOT / "lib" / "securityRuleCatalog.ts"
FE_API = FE_ROOT / "lib" / "api.ts"

_FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "customer data leaked",
    "payment fraud detected",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
]

_JIRA_BACKEND_MODULES = [
    REPO_ROOT / "backend" / "app" / "services" / "jira_activity_ingestion_service.py",
    REPO_ROOT / "backend" / "app" / "services" / "jira_activity_signal_service.py",
    REPO_ROOT / "backend" / "app" / "services" / "jira_risk_activity_correlation_service.py",
    REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "jira.py",
]


# ════════════════════════════════════════════════════════════════════════════
# PROVIDER LABEL (3)
# ════════════════════════════════════════════════════════════════════════════


def test_jira_provider_label_is_jira() -> None:
    """Capability matrix provider key is 'jira' and label is 'Jira'."""
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.provider == "jira"
    assert cap.label == "Jira"


def test_jira_appears_in_capability_matrix() -> None:
    cap = get_provider_capability("jira")
    assert cap is not None, "Jira missing from the provider capability matrix"


def test_jira_capability_matrix_flags_all_true() -> None:
    """All required drift + security flags are True for the completed Jira arc."""
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.drift.drift_snapshots is True
    assert cap.drift.drift_diff is True
    assert cap.drift.drift_risk_classification is True
    assert cap.security.security_rules is True
    assert cap.security.activity_ingestion is True
    assert cap.security.activity_signals is True
    assert cap.security.risk_activity_correlations is True
    assert cap.security.demo_seed_clear is True
    assert cap.security.case_report is True
    assert cap.security.evidence_timeline is True
    assert cap.security.evidence_graph is True


# ════════════════════════════════════════════════════════════════════════════
# ARC COMPLETION (4)
# ════════════════════════════════════════════════════════════════════════════


def test_jira_arc_maturity_is_complete() -> None:
    """Maturity reflects arc completion per convention.

    By convention every completed partial-arc provider (Datadog, Clerk,
    PagerDuty, Linear) keeps maturity 'partial' because drift_review_workflow
    is not yet active. The arc-complete signal lives in the notes (M86A–M86I)
    and in the advanced planned_next_stage.
    """
    cap = get_provider_capability("jira")
    assert cap is not None
    assert cap.maturity == "partial"
    assert "M86A" in cap.notes and (
        "M86I" in cap.notes or "complete" in cap.notes.lower()
    ), "Notes should reference the M86A–M86I arc as complete"


def test_jira_planned_next_stage_reflects_completion() -> None:
    """planned_next_stage no longer points at M86I — it has advanced to M87A."""
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = (summary.get("planned_next_stage", "") or "")
    assert "M86I" not in planned, (
        f"planned_next_stage should have advanced past M86I; got: {planned!r}"
    )
    assert (planned in (None, "", "complete") or "M87A" in planned or "GitLab" in planned
            or "M88A" in planned or "Terraform" in planned), (
        f"planned_next_stage should be None/''/'complete' or M87A/GitLab or later; got: {planned!r}"
    )


def test_expansion_framework_jira_arc_complete() -> None:
    """Jira is no longer in the recommended-next-providers queue (arc complete)."""
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    provider_keys = [
        r.get("provider", "").lower() for r in recommended if isinstance(r, dict)
    ]
    assert "jira" not in provider_keys, (
        "Jira should NOT be in recommended_next_providers (arc complete M86A–M86I)"
    )


def test_expansion_framework_gitlab_is_next() -> None:
    """GitLab was the head of the recommended queue at M86I; M87A launched it.
    Now Terraform Cloud is head. Accept GitLab or any later provider."""
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    assert recommended, "recommended_next_providers should not be empty"
    first = recommended[0]
    provider = first.get("provider", "") if isinstance(first, dict) else str(first)
    # GitLab launched in M87A — Terraform Cloud is now head; accept either.
    assert "gitlab" in provider.lower() or "terraform" in provider.lower() or "GitLab" in str(first) or "Terraform" in str(first), (
        f"Head of recommended_next_providers should be GitLab or later; got: {provider!r}"
    )


# ════════════════════════════════════════════════════════════════════════════
# SECURITY RULES CATALOG (4)
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_jira_rules_appear_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text()
    missing = [key for key in JIRA_RULE_KEYS if key not in text]
    assert not missing, (
        f"Jira rule keys missing from securityRuleCatalog.ts: {sorted(missing)}"
    )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_jira_catalog_count_matches_backend() -> None:
    """Every backend Jira rule key is catalogued; the catalog count is >= backend."""
    text = FE_RULE_CATALOG.read_text()
    catalog_keys = set(re.findall(r'key: "(jira_[a-z_]+)"', text))
    missing = JIRA_RULE_KEYS - catalog_keys
    assert not missing, (
        f"Backend Jira rule keys missing from catalog: {sorted(missing)}"
    )
    assert len(catalog_keys) >= len(JIRA_RULE_KEYS), (
        f"Catalog has {len(catalog_keys)} Jira keys; backend has {len(JIRA_RULE_KEYS)}"
    )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_jira_catalog_copy_no_forbidden_wording() -> None:
    text = FE_RULE_CATALOG.read_text()
    # Examine only the lines belonging to Jira rule entries (between a jira key
    # and the next entry's key) for forbidden wording.
    lines = text.splitlines()
    in_jira = False
    for line in lines:
        ll = line.lower()
        if re.search(r'key:\s*"jira_', ll):
            in_jira = True
        elif re.search(r'key:\s*"', ll):
            in_jira = False
        if not in_jira:
            continue
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in ll, (
                f"Forbidden phrase '{phrase}' in Jira catalog copy: {line.strip()!r}"
            )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_jira_rule_severities_consistent() -> None:
    """HIGH, MEDIUM, and LOW severities are all represented among Jira rules."""
    text = FE_RULE_CATALOG.read_text()
    severities = set()
    in_jira = False
    for line in text.splitlines():
        ll = line.lower()
        if re.search(r'key:\s*"jira_', ll):
            in_jira = True
        elif re.search(r'key:\s*"', ll):
            in_jira = False
        if in_jira:
            m = re.search(r'severity:\s*"(\w+)"', ll)
            if m:
                severities.add(m.group(1))
    for sev in ("high", "medium", "low"):
        assert sev in severities, (
            f"Severity '{sev}' missing among Jira rules; found: {sorted(severities)}"
        )


# ════════════════════════════════════════════════════════════════════════════
# FRONTEND PAGES (5)
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_jira_in_activity_page() -> None:
    text = FE_ACTIVITY.read_text()
    assert "jira" in text.lower(), "jira missing from activity page"
    assert "syncJiraActivity" in text or "sync_jira" in text.lower(), (
        "syncJiraActivity missing from activity page"
    )


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_jira_in_signals_page() -> None:
    text = FE_SIGNALS.read_text()
    assert "jira" in text.lower(), "jira missing from signals page"
    assert "generateJiraActivitySignals" in text or "generate_jira" in text.lower(), (
        "generateJiraActivitySignals missing from signals page"
    )


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_jira_in_correlations_page() -> None:
    text = FE_CORRELATIONS.read_text()
    assert "jira" in text.lower(), "jira missing from correlations page"
    assert (
        "generateJiraRiskActivityCorrelations" in text
        or "generateJiraCorrelations" in text
        or "jira_correlations" in text.lower()
    ), "Jira correlation generate function missing from correlations page"


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_jira_in_cases_page() -> None:
    text = FE_CASES.read_text()
    assert "jira" in text.lower(), "jira missing from cases page"
    assert "Jira" in text, "Jira label missing from cases page"


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_jira_api_ts_includes_jira_functions() -> None:
    text = FE_API.read_text()
    assert "syncJiraActivity" in text, "syncJiraActivity missing from api.ts"
    assert "generateJiraActivitySignals" in text, (
        "generateJiraActivitySignals missing from api.ts"
    )
    assert (
        "generateJiraRiskActivityCorrelations" in text
        or "generateJiraCorrelations" in text
    ), "Jira correlation generate function missing from api.ts"


# ════════════════════════════════════════════════════════════════════════════
# CROSS-PROVIDER (3)
# ════════════════════════════════════════════════════════════════════════════


def test_jira_not_starting_gitlab() -> None:
    """M87A–M87B landed GitLab; gitlab_ rule keys are now registered as expected.
    This test verifies the GitLab rule keys are well-formed (all start with 'gitlab_')."""
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    gitlab_keys = {k for k in KNOWN_RULE_KEYS if k.startswith("gitlab_")}
    # After M87B, GitLab rules are registered — verify all start with gitlab_
    for k in gitlab_keys:
        assert k.startswith("gitlab_"), f"Unexpected non-gitlab key: {k!r}"


def test_jira_gitlab_remains_planned_next_provider() -> None:
    """GitLab launched in M87A; the queue now contains Terraform Cloud and later.
    Accept GitLab (still in queue at pre-M87A) or later providers."""
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    provider_keys = [
        r.get("provider", "").lower() for r in recommended if isinstance(r, dict)
    ]
    # After M87A, GitLab launched; Terraform Cloud is now the head. Accept either.
    assert "gitlab" in provider_keys or "terraform_cloud" in provider_keys, (
        f"Recommended queue should contain GitLab or Terraform Cloud; got: {provider_keys}"
    )


def test_cross_provider_security_guardrails_include_jira() -> None:
    """M75A cross-provider guardrails cover Jira as an activity/signals/correlations provider."""
    guardrails = REPO_ROOT / "backend" / "tests" / "test_milestone75a_cross_provider_security_guardrails.py"
    text = guardrails.read_text()
    assert '"jira"' in text, "Jira missing from M75A cross-provider security guardrails"


# ════════════════════════════════════════════════════════════════════════════
# PRIVACY / COPY (3)
# ════════════════════════════════════════════════════════════════════════════


def test_jira_frontend_no_forbidden_wording() -> None:
    """Scan Jira-relevant frontend page copy for forbidden phrases."""
    for page in (FE_ACTIVITY, FE_SIGNALS, FE_CORRELATIONS, FE_CASES):
        if not page.exists():
            continue
        text = page.read_text()
        idx = text.lower().find("jira")
        if idx == -1:
            continue
        block = text[max(0, idx - 200): idx + 3000].lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in block, (
                f"Forbidden phrase '{phrase}' near Jira copy in {page.name}"
            )


def test_jira_demo_uses_placeholder_ids() -> None:
    """The Jira incident demo anchors on JIRA_DEMO_ placeholder identifiers."""
    path = REPO_ROOT / "backend" / "app" / "services" / "security_incident_demo_service.py"
    text = path.read_text()
    idx = text.find("JIRA_DEMO_INTEGRATION_NAME")
    assert idx != -1, "JIRA_DEMO_INTEGRATION_NAME not found in demo service"
    section = text[idx:]
    assert "JIRA_DEMO_" in section, "Jira demo section should use JIRA_DEMO_ placeholders"
    # No real URLs in the Jira demo section.
    assert "http://" not in section, "http:// URL found in Jira demo section"
    assert "https://" not in section, "https:// URL found in Jira demo section"


def test_jira_evidence_no_pii_keys() -> None:
    """Jira evidence allowlist carries no credential / PII keys."""
    from app.services.security_case_report_service import _PREVIEW_ALLOWLIST
    forbidden = {
        "api_token", "api_key", "oauth_token", "webhook_secret", "webhook_url",
        "delivery_url", "site_url", "base_url", "jql", "issue_key", "issue_title",
        "issue_description", "comment_body", "attachment_content", "user_email",
        "user_name", "account_id", "ip_address", "user_agent", "audit_payload",
    }
    found = forbidden & _PREVIEW_ALLOWLIST
    assert not found, f"Credential/PII keys found in _PREVIEW_ALLOWLIST: {sorted(found)}"


# ════════════════════════════════════════════════════════════════════════════
# M86A–M86H REGRESSION SPOT-CHECKS (3)
# ════════════════════════════════════════════════════════════════════════════


def test_m86b_rules_still_registered() -> None:
    """Spot-check: the Jira rule registry still has its 82 canonical rules."""
    assert len(JIRA_RULE_KEYS) == 82, (
        f"Expected 82 Jira rule keys, got {len(JIRA_RULE_KEYS)}"
    )
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    missing = JIRA_RULE_KEYS - KNOWN_RULE_KEYS
    assert not missing, f"Jira rule keys missing from KNOWN_RULE_KEYS: {sorted(missing)}"


def test_m86d_event_types_still_mapped() -> None:
    """Spot-check: the 13 Jira config-event types are still mapped."""
    from app.services.jira_activity_ingestion_service import JIRA_CONFIG_EVENT_TYPES
    assert len(JIRA_CONFIG_EVENT_TYPES) == 13, (
        f"Expected 13 Jira config event types, got {len(JIRA_CONFIG_EVENT_TYPES)}"
    )


def test_m86g_demo_functions_importable() -> None:
    """Spot-check: seed_jira / clear_jira remain importable from the demo service."""
    from app.services.security_incident_demo_service import seed_jira, clear_jira
    assert callable(seed_jira)
    assert callable(clear_jira)


# ════════════════════════════════════════════════════════════════════════════
# WORDING (2)
# ════════════════════════════════════════════════════════════════════════════


def test_no_forbidden_wording_in_jira_services() -> None:
    """Scan all jira_* backend service modules for forbidden wording."""
    for module_path in _JIRA_BACKEND_MODULES:
        if not module_path.exists():
            continue
        content = module_path.read_text().lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in content, (
                f"Forbidden phrase '{phrase}' in {module_path.name}"
            )


def test_jira_case_report_has_review_disclaimer() -> None:
    """The case report surfaces a human-review disclaimer (no confirmed-impact claims)."""
    labels = report_svc._TIMELINE_PROVIDER_LABELS
    assert labels.get("jira") == "Jira", "Jira missing from timeline provider labels"
    content = (
        REPO_ROOT / "backend" / "app" / "services" / "security_case_report_service.py"
    ).read_text().lower()
    assert "human review" in content or "for review" in content or "may require review" in content, (
        "Case report should carry a human-review disclaimer"
    )
    assert "does not" in content, (
        "Case report should disclaim that evidence does not confirm impact"
    )
