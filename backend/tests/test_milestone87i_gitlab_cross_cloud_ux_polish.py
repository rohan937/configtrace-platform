"""M87I — GitLab cross-cloud UX polish guardrails.

Durable, deterministic guardrails that pin the final GitLab arc (M87A–M87I)
state. This file adds NO product engine code — it verifies that GitLab is a
first-class completed provider across all internal security UX surfaces, demo
script, provider capability table, case report / timeline labels, and roadmap
handoff to Terraform Cloud (M88A).

Sections:

  A. PROVIDER LABEL
     GitLab capability-matrix provider name / label / flags.

  B. ARC COMPLETION
     Maturity reflects convention; planned_next_stage advanced to M88A.

  C. SECURITY RULES CATALOG
     securityRuleCatalog.ts contains every backend GitLab rule key; counts
     match; copy avoids forbidden wording; HIGH/MEDIUM/LOW all represented.

  D. FRONTEND PAGES
     activity / signals / correlations / cases pages include GitLab; api.ts
     has the GitLab sync / generate functions.

  E. DEMO-SCRIPT PAGE
     PROVIDER_CAPABILITY_TABLE includes GitLab (and Jira);
     NEXT_PROVIDERS_BRIEF points to Terraform Cloud at M88A.

  F. SECURITY DEMO SCRIPT LIB
     securityDemoScript.ts incident timeline text includes GitLab (and Jira).

  G. CASE REPORT
     _PREVIEW_ALLOWLIST includes all GitLab-safe keys;
     _TIMELINE_PROVIDER_LABELS["gitlab"] == "GitLab".

  H. PRIVACY / COPY
     No forbidden wording near GitLab frontend copy; demo uses GITLAB_DEMO_
     placeholder IDs; no PII keys in GitLab allowlist section.

  I. FRAMEWORK
     Terraform Cloud remains recommended-next; recommended queue includes TC.

  J. M87A–M87H REGRESSION SPOT-CHECKS
     25 rules still registered, signal types importable, demo functions exist.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_rules.gitlab import GITLAB_RULE_KEYS

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ROOT = REPO_ROOT / "frontend" / "src"
FE_ACTIVITY = FE_ROOT / "app" / "(app)" / "security" / "activity" / "page.tsx"
FE_SIGNALS = FE_ROOT / "app" / "(app)" / "security" / "signals" / "page.tsx"
FE_CORRELATIONS = FE_ROOT / "app" / "(app)" / "security" / "correlations" / "page.tsx"
FE_CASES = FE_ROOT / "app" / "(app)" / "security" / "cases" / "page.tsx"
FE_RULE_CATALOG = FE_ROOT / "lib" / "securityRuleCatalog.ts"
FE_API = FE_ROOT / "lib" / "api.ts"
FE_DEMO_SCRIPT_LIB = FE_ROOT / "lib" / "securityDemoScript.ts"
FE_DEMO_SCRIPT_PAGE = FE_ROOT / "app" / "(app)" / "security" / "demo-script" / "page.tsx"

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
    "repo exposed",
    "source code leaked",
    "token leaked",
    "secrets exposed",
    "credentials exposed",
]

_GITLAB_BACKEND_MODULES = [
    REPO_ROOT / "backend" / "app" / "services" / "gitlab_activity_ingestion_service.py",
    REPO_ROOT / "backend" / "app" / "services" / "gitlab_activity_signal_service.py",
    REPO_ROOT / "backend" / "app" / "services" / "gitlab_risk_activity_correlation_service.py",
    REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "gitlab.py",
]

# Keys that should appear in _PREVIEW_ALLOWLIST for the GitLab case report preview.
_EXPECTED_GITLAB_ALLOWLIST_KEYS = [
    "project_resource_id",
    "owner_resource_id",
    "owner_type",
    "pattern_category",
    "allow_force_push",
    "code_owner_approval_required",
    "push_access_level_category",
    "merge_access_level_category",
    "enabled",
    "ssl_verification_enabled",
    "webhook_scheme_category",
    "variable_count",
    "protected_variable_count",
    "masked_variable_count",
    "unprotected_unmasked_count",
    "gitlab_event_id",
    "event_source",
    "event_types",
    "operation_family",
    "matched_on",
    "correlation_reason",
    "correlation_strength",
    "signal_count",
    "activity_count",
    "risk_count",
    "lookback_hours",
    "window_start",
    "window_end",
]


# ════════════════════════════════════════════════════════════════════════════
# A. PROVIDER LABEL
# ════════════════════════════════════════════════════════════════════════════


def test_gitlab_provider_key_and_label() -> None:
    cap = get_provider_capability("gitlab")
    assert cap is not None
    assert cap.provider == "gitlab"
    assert cap.label == "GitLab"


def test_gitlab_appears_in_capability_matrix() -> None:
    cap = get_provider_capability("gitlab")
    assert cap is not None, "GitLab missing from the provider capability matrix"


def test_gitlab_capability_matrix_flags_all_true() -> None:
    cap = get_provider_capability("gitlab")
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
# B. ARC COMPLETION
# ════════════════════════════════════════════════════════════════════════════


def test_gitlab_arc_maturity_convention() -> None:
    """Maturity stays 'partial' per convention for completed partial-arc providers."""
    cap = get_provider_capability("gitlab")
    assert cap is not None
    assert cap.maturity == "partial"
    assert "M87A" in cap.notes, "Notes should reference M87A"
    assert "M87I" in cap.notes or "complete" in cap.notes.lower(), (
        "Notes should reference M87I arc completion"
    )


def test_gitlab_planned_next_stage_advanced_to_m88a() -> None:
    """planned_next_stage must not point at M87I — it has advanced to M88A."""
    fw = get_framework()
    summary = fw.get("summary", {})
    planned = summary.get("planned_next_stage", "") or ""
    assert "M87I" not in planned, (
        f"planned_next_stage should have advanced past M87I; got: {planned!r}"
    )
    # M88I complete — TC arc done; kubernetes is now the head
    assert ("M88A" in planned or "Terraform" in planned
            or "M88H" in planned or "M88I" in planned
            or "M89A" in planned or "Kubernetes" in planned), (
        f"planned_next_stage should point to M88A/Terraform or later; got: {planned!r}"
    )


def test_gitlab_not_in_recommended_providers_queue() -> None:
    """GitLab should not appear in recommended_next_providers (arc complete M87A–M87I)."""
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    provider_keys = [
        r.get("provider", "").lower() for r in recommended if isinstance(r, dict)
    ]
    assert "gitlab" not in provider_keys, (
        "GitLab should NOT be in recommended_next_providers (arc complete)"
    )


def test_terraform_cloud_is_head_of_recommended_queue() -> None:
    """Terraform Cloud is now the head of the recommended provider queue."""
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    assert recommended, "recommended_next_providers should not be empty"
    first = recommended[0]
    provider = first.get("provider", "") if isinstance(first, dict) else str(first)
    label = first.get("label", "") if isinstance(first, dict) else str(first)
    # M88I complete — kubernetes is now head of queue after TC arc
    assert ("terraform" in provider.lower() or "Terraform" in label
            or "kubernetes" in provider.lower() or "Kubernetes" in label), (
        f"Head of recommended_next_providers should be Terraform Cloud or Kubernetes; got: {provider!r}"
    )


# ════════════════════════════════════════════════════════════════════════════
# C. SECURITY RULES CATALOG
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_all_gitlab_rule_keys_in_frontend_catalog() -> None:
    text = FE_RULE_CATALOG.read_text()
    missing = [key for key in GITLAB_RULE_KEYS if key not in text]
    assert not missing, (
        f"GitLab rule keys missing from securityRuleCatalog.ts: {sorted(missing)}"
    )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_gitlab_catalog_count_matches_backend() -> None:
    text = FE_RULE_CATALOG.read_text()
    catalog_keys = set(re.findall(r'key: "(gitlab_[a-z_]+)"', text))
    missing = GITLAB_RULE_KEYS - catalog_keys
    assert not missing, (
        f"Backend GitLab rule keys missing from catalog: {sorted(missing)}"
    )
    assert len(catalog_keys) >= len(GITLAB_RULE_KEYS)


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_gitlab_catalog_copy_no_forbidden_wording() -> None:
    text = FE_RULE_CATALOG.read_text()
    lines = text.splitlines()
    in_gitlab = False
    for line in lines:
        ll = line.lower()
        if re.search(r'key:\s*"gitlab_', ll):
            in_gitlab = True
        elif re.search(r'key:\s*"', ll):
            in_gitlab = False
        if not in_gitlab:
            continue
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in ll, (
                f"Forbidden phrase '{phrase}' in GitLab catalog copy: {line.strip()!r}"
            )


@pytest.mark.skipif(not FE_RULE_CATALOG.exists(), reason="Frontend tree absent")
def test_gitlab_rule_severities_all_levels_represented() -> None:
    """HIGH, MEDIUM, and LOW are all represented among the 25 GitLab rules."""
    text = FE_RULE_CATALOG.read_text()
    severities: set[str] = set()
    in_gitlab = False
    for line in text.splitlines():
        ll = line.lower()
        if re.search(r'key:\s*"gitlab_', ll):
            in_gitlab = True
        elif re.search(r'key:\s*"', ll):
            in_gitlab = False
        if in_gitlab:
            m = re.search(r'severity:\s*"(\w+)"', ll)
            if m:
                severities.add(m.group(1))
    for sev in ("high", "medium", "low"):
        assert sev in severities, (
            f"Severity '{sev}' missing from GitLab rule catalog entries"
        )


# ════════════════════════════════════════════════════════════════════════════
# D. FRONTEND PAGES
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_activity_page_includes_gitlab_provider() -> None:
    text = FE_ACTIVITY.read_text()
    assert "gitlab" in text.lower()


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_activity_page_has_gitlab_event_types() -> None:
    text = FE_ACTIVITY.read_text()
    assert "GITLAB_EVENT_TYPES" in text or "gitlab." in text


@pytest.mark.skipif(not FE_ACTIVITY.exists(), reason="Frontend tree absent")
def test_activity_page_has_sync_gitlab_action() -> None:
    text = FE_ACTIVITY.read_text()
    assert "syncGitlabActivity" in text or "Sync GitLab" in text


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_signals_page_includes_gitlab_provider() -> None:
    text = FE_SIGNALS.read_text()
    assert "gitlab" in text.lower()


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_signals_page_has_gitlab_signal_types() -> None:
    text = FE_SIGNALS.read_text()
    assert "GITLAB_SIGNAL_TYPES" in text or "gitlab_" in text


@pytest.mark.skipif(not FE_SIGNALS.exists(), reason="Frontend tree absent")
def test_signals_page_has_generate_gitlab_action() -> None:
    text = FE_SIGNALS.read_text()
    assert "generateGitlabActivitySignals" in text or "Generate GitLab" in text


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_correlations_page_includes_gitlab_provider() -> None:
    text = FE_CORRELATIONS.read_text()
    assert "gitlab" in text.lower()


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_correlations_page_has_gitlab_correlation_types() -> None:
    text = FE_CORRELATIONS.read_text()
    assert "gitlab_" in text


@pytest.mark.skipif(not FE_CORRELATIONS.exists(), reason="Frontend tree absent")
def test_correlations_page_has_generate_gitlab_action() -> None:
    text = FE_CORRELATIONS.read_text()
    assert "generateGitlabRiskActivityCorrelations" in text or "Generate GitLab" in text


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_cases_page_includes_gitlab_provider() -> None:
    text = FE_CASES.read_text()
    assert "gitlab" in text.lower()


@pytest.mark.skipif(not FE_CASES.exists(), reason="Frontend tree absent")
def test_cases_page_has_gitlab_demo_card() -> None:
    text = FE_CASES.read_text()
    assert "GitLab" in text


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_api_ts_has_sync_gitlab_activity() -> None:
    text = FE_API.read_text()
    assert "syncGitlabActivity" in text


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_api_ts_has_generate_gitlab_signals() -> None:
    text = FE_API.read_text()
    assert "generateGitlabActivitySignals" in text


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_api_ts_has_generate_gitlab_correlations() -> None:
    text = FE_API.read_text()
    assert "generateGitlabRiskActivityCorrelations" in text


@pytest.mark.skipif(not FE_API.exists(), reason="Frontend tree absent")
def test_api_ts_provider_union_includes_gitlab() -> None:
    text = FE_API.read_text()
    assert '"gitlab"' in text


# ════════════════════════════════════════════════════════════════════════════
# E. DEMO-SCRIPT PAGE
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_demo_script_page_capability_table_includes_gitlab() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert '"gitlab"' in text, (
        "PROVIDER_CAPABILITY_TABLE in demo-script/page.tsx must include gitlab"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_demo_script_page_capability_table_includes_jira() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert '"jira"' in text, (
        "PROVIDER_CAPABILITY_TABLE in demo-script/page.tsx must include jira"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_demo_script_page_next_providers_points_to_terraform_cloud() -> None:
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    assert "Terraform Cloud" in text or "terraform_cloud" in text.lower(), (
        "NEXT_PROVIDERS_BRIEF should reference Terraform Cloud (M88A)"
    )
    assert "M88A" in text, (
        "NEXT_PROVIDERS_BRIEF should reference M88A milestone"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_demo_script_page_next_providers_not_stale_jira() -> None:
    """NEXT_PROVIDERS_BRIEF must not show Jira at M86A (Jira arc complete)."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    # The old stale entry was { label: "Jira", ..., milestone: "M86A" }
    # We check that "Jira" and "M86A" don't appear together in the NEXT_PROVIDERS_BRIEF block.
    # Extract the NEXT_PROVIDERS_BRIEF block.
    m = re.search(
        r'NEXT_PROVIDERS_BRIEF.*?=.*?\[.*?\];',
        text, re.DOTALL,
    )
    if m:
        brief_block = m.group(0)
        assert not ('"Jira"' in brief_block and "M86A" in brief_block), (
            "NEXT_PROVIDERS_BRIEF should not list Jira at M86A (arc complete)"
        )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_PAGE.exists(), reason="Frontend tree absent")
def test_demo_script_page_gitlab_capability_table_entry_is_complete() -> None:
    """GitLab entry in PROVIDER_CAPABILITY_TABLE must have all capabilities true."""
    text = FE_DEMO_SCRIPT_PAGE.read_text()
    # Find the gitlab row in the table. The pattern is:
    # provider: "gitlab", label: "GitLab", ..., demo: true
    gitlab_pattern = re.search(
        r'provider:\s*"gitlab".*?demo:\s*(true|false)',
        text, re.DOTALL,
    )
    assert gitlab_pattern is not None, "GitLab row not found in PROVIDER_CAPABILITY_TABLE"
    row_text = gitlab_pattern.group(0)
    assert "demo: true" in row_text or "demo:true" in row_text.replace(" ", ""), (
        "GitLab PROVIDER_CAPABILITY_TABLE entry must have demo: true"
    )


# ════════════════════════════════════════════════════════════════════════════
# F. SECURITY DEMO SCRIPT LIB
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_demo_script_lib_incident_seed_mentions_gitlab() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text()
    assert "GitLab" in text, (
        "securityDemoScript.ts incident seed talk-track should mention GitLab"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_demo_script_lib_incident_seed_mentions_jira() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text()
    assert "Jira" in text, (
        "securityDemoScript.ts incident seed talk-track should mention Jira"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_demo_script_lib_incident_timeline_mentions_gitlab() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text()
    # The "incident-timeline-graph" step talkTrack should list GitLab.
    assert "incident-timeline-graph" in text
    idx = text.find("incident-timeline-graph")
    section = text[idx: idx + 1200]
    assert "GitLab" in section, (
        "incident-timeline-graph step should mention GitLab"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_demo_script_lib_incident_clear_mentions_gitlab() -> None:
    text = FE_DEMO_SCRIPT_LIB.read_text()
    idx = text.find("incident-clear-demo")
    if idx == -1:
        idx = text.find("Clear demo")
    assert idx != -1, "clear-demo step not found in securityDemoScript.ts"
    section = text[idx: idx + 800]
    assert "GitLab" in section, (
        "incident-clear-demo step should mention GitLab"
    )


@pytest.mark.skipif(not FE_DEMO_SCRIPT_LIB.exists(), reason="Frontend tree absent")
def test_demo_script_lib_no_forbidden_gitlab_wording() -> None:
    """Forbidden phrases must not appear as positive claims in demo copy.

    The file legitimately uses forbidden phrases inside avoid:/negation contexts
    (e.g. avoid arrays, "Avoid '...'", "Never claims ..."). We check only lines
    that do not carry any negation indicator.
    """
    text = FE_DEMO_SCRIPT_LIB.read_text()
    negation_indicators = ("avoid", "don't", "never", "not a claim", "not a confirmed")
    for line in text.splitlines():
        ll = line.lower()
        # Skip lines that are themselves negation or avoidance guidance.
        if any(neg in ll for neg in negation_indicators):
            continue
        # Skip pure string-literal lines (array items in avoid: [...] blocks).
        stripped = ll.strip()
        if re.match(r'^"[^"]*",?$', stripped):
            continue
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in ll, (
                f"Forbidden phrase '{phrase}' used positively in securityDemoScript.ts: {line.strip()!r}"
            )


# ════════════════════════════════════════════════════════════════════════════
# G. CASE REPORT
# ════════════════════════════════════════════════════════════════════════════


def test_case_report_timeline_label_is_gitlab() -> None:
    from app.services import security_case_report_service as svc
    labels = svc._TIMELINE_PROVIDER_LABELS
    assert labels.get("gitlab") == "GitLab", (
        f"_TIMELINE_PROVIDER_LABELS['gitlab'] should be 'GitLab'; got {labels.get('gitlab')!r}"
    )


def test_case_report_preview_allowlist_has_gitlab_keys() -> None:
    from app.services import security_case_report_service as svc
    allowlist = svc._PREVIEW_ALLOWLIST
    missing = [k for k in _EXPECTED_GITLAB_ALLOWLIST_KEYS if k not in allowlist]
    assert not missing, (
        f"GitLab-safe keys missing from _PREVIEW_ALLOWLIST: {missing}"
    )


def test_case_report_preview_allowlist_no_gitlab_pii_keys() -> None:
    """The allowlist must not contain any forbidden GitLab raw-field names."""
    from app.services import security_case_report_service as svc
    allowlist = svc._PREVIEW_ALLOWLIST
    forbidden_keys = [
        "access_token", "token", "private_token", "oauth_token",
        "webhook_url", "webhook_secret", "secret_token",
        "ci_variable_name", "ci_variable_value", "variable_name", "variable_value",
        "deploy_key", "ssh_key", "runner_token", "runner_ip",
        "project_name", "group_name", "namespace_path",
        "repo_url", "branch_name", "commit_message",
        "merge_request_title", "issue_title",
        "pipeline_log", "job_log", "artifact",
        "user_email", "user_name", "username",
        "email", "name", "url",
    ]
    found = [k for k in forbidden_keys if k in allowlist]
    assert not found, (
        f"PII or raw-field keys found in _PREVIEW_ALLOWLIST: {found}"
    )


# ════════════════════════════════════════════════════════════════════════════
# H. PRIVACY / COPY
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("module_path", [str(p) for p in _GITLAB_BACKEND_MODULES])
def test_gitlab_module_no_forbidden_wording(module_path: str) -> None:
    path = Path(module_path)
    if not path.exists():
        pytest.skip(f"Module not found: {module_path}")
    text = path.read_text().lower()
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in text, (
            f"Forbidden phrase '{phrase}' found in {path.name}"
        )


def test_demo_service_gitlab_placeholder_ids_are_safe() -> None:
    """GitLab demo uses GITLAB_DEMO_ prefixed placeholder IDs, not real values."""
    from app.services import security_incident_demo_service as svc
    assert hasattr(svc, "GITLAB_DEMO_PROJECT_001")
    assert hasattr(svc, "GITLAB_DEMO_BRANCH_RULE_001")
    assert hasattr(svc, "GITLAB_DEMO_WEBHOOK_001")
    assert hasattr(svc, "GITLAB_DEMO_CI_VARIABLE_SUMMARY_001")
    # Placeholder IDs must not look like GitLab tokens (glpat- prefix)
    for attr in [
        "GITLAB_DEMO_PROJECT_001",
        "GITLAB_DEMO_BRANCH_RULE_001",
        "GITLAB_DEMO_WEBHOOK_001",
        "GITLAB_DEMO_CI_VARIABLE_SUMMARY_001",
    ]:
        value = getattr(svc, attr)
        assert not str(value).startswith("glpat-"), (
            f"{attr} looks like a real GitLab token: {value!r}"
        )


def test_demo_service_gitlab_no_real_urls_in_placeholders() -> None:
    """None of the GITLAB_DEMO_ placeholder IDs contain raw URLs."""
    from app.services import security_incident_demo_service as svc
    for attr in dir(svc):
        if not attr.startswith("GITLAB_DEMO_"):
            continue
        value = str(getattr(svc, attr))
        assert "http://" not in value and "https://" not in value, (
            f"{attr} contains a raw URL: {value!r}"
        )


# ════════════════════════════════════════════════════════════════════════════
# I. FRAMEWORK
# ════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_queue_contains_terraform_cloud() -> None:
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    provider_keys = [
        r.get("provider", "").lower() for r in recommended if isinstance(r, dict)
    ]
    # M88I complete — TC arc done; kubernetes is now head of queue
    assert (any("terraform" in p for p in provider_keys)
            or any("kubernetes" in p for p in provider_keys)), (
        "Terraform Cloud or Kubernetes should be in recommended_next_providers queue"
    )


def test_expansion_framework_queue_order() -> None:
    """Queue should be Terraform Cloud → Kubernetes → Sentry."""
    fw = get_framework()
    recommended = fw.get("recommended_next_providers", [])
    labels = [
        r.get("label", r.get("provider", "")) for r in recommended
        if isinstance(r, dict)
    ]
    # Check Terraform Cloud comes before Kubernetes (if both present)
    if "Terraform Cloud" in labels and "Kubernetes" in labels:
        assert labels.index("Terraform Cloud") < labels.index("Kubernetes")
    # Check Kubernetes before Sentry (if both present)
    if "Kubernetes" in labels and "Sentry" in labels:
        assert labels.index("Kubernetes") < labels.index("Sentry")


def test_expansion_framework_gitlab_arc_complete_in_notes() -> None:
    cap = get_provider_capability("gitlab")
    assert cap is not None
    notes_lower = cap.notes.lower()
    assert "m87a" in notes_lower or "m87" in notes_lower, (
        "GitLab capability notes should mention the M87 arc"
    )
    assert "m87i" in notes_lower or "complete" in notes_lower, (
        "GitLab capability notes should reflect M87I arc completion"
    )


# ════════════════════════════════════════════════════════════════════════════
# J. M87A–M87H REGRESSION SPOT-CHECKS
# ════════════════════════════════════════════════════════════════════════════


def test_gitlab_25_rules_still_registered() -> None:
    from app.services.security_rule_registry import KNOWN_RULE_KEYS
    gitlab_keys = {k for k in KNOWN_RULE_KEYS if k.startswith("gitlab_")}
    assert len(gitlab_keys) == 25, (
        f"Expected 25 GitLab rule keys; found {len(gitlab_keys)}: {sorted(gitlab_keys)}"
    )


def test_gitlab_signal_types_importable() -> None:
    from app.services.gitlab_activity_signal_service import GITLAB_SIGNAL_TYPES
    assert len(GITLAB_SIGNAL_TYPES) >= 17


def test_gitlab_correlation_types_importable() -> None:
    from app.services.gitlab_risk_activity_correlation_service import GITLAB_CORRELATION_TYPES
    assert len(GITLAB_CORRELATION_TYPES) == 11


def test_gitlab_demo_seed_clear_importable() -> None:
    from app.services.security_incident_demo_service import seed_gitlab, clear_gitlab
    assert callable(seed_gitlab)
    assert callable(clear_gitlab)


def test_gitlab_evaluator_dispatch() -> None:
    from app.services.security_finding_evaluator import evaluate_record
    record = {
        "record_type": "gitlab_project",
        "provider": "gitlab",
        "record_id": "test:abc",
        "resource_id": "abc123",
        "visibility_category": "healthy",
    }
    findings = evaluate_record(record, "gitlab")
    assert isinstance(findings, list)


def test_gitlab_activity_event_types_importable() -> None:
    from app.services.gitlab_activity_ingestion_service import GITLAB_CONFIG_EVENT_TYPES
    assert len(GITLAB_CONFIG_EVENT_TYPES) >= 18
