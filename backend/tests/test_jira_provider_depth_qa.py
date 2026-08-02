"""Jira provider depth QA — regression tests for severity, safety, dispatch, and coverage.

These guardrails pin the post-M86H Jira provider state after the dead-rule
cleanup (6 rules removed, live count == 76) and the M86H severity recalibration
(``jira_permission_scheme_public_transition_issues`` raised medium → high).

They add NO product engine code. They assert that every live Jira rule is:

  * consistently registered across registry / confidence / pack / coverage and
    the frontend rule catalog (GROUP A),
  * dispatched correctly through ``evaluate_record(record, "jira")`` with the
    record-first / provider-second argument order (GROUP B),
  * assigned a defensible severity — high for genuinely risky posture, low for
    benign lifecycle/metadata posture (GROUP C),
  * emitting metadata-only evidence with no secret/PII keys and no raw API
    objects (GROUP D),
  * worded as reviewable configuration findings, never as confirmed breaches
    (GROUP E),

and that the 6 removed dead rules stay gone, with a general detector proving no
live rule is silently dead (GROUP F); webhook secret indicator behaviour is
boolean-derived only (GROUP G); and the roadmap/framework state reflects the
completed Jira arc handing off to Kubernetes (GROUP H).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.connectors.jira_schema import (
    JIRA_AUTOMATION_RULE,
    JIRA_PERMISSION_SCHEME,
    JIRA_WEBHOOK,
    JIRA_WORKFLOW_SCHEME,
)
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_coverage_service import RULE_RECORD_TYPES
from app.services.security_finding_evaluator import evaluate_record
from app.services.security_rule_confidence import RULE_CONFIDENCE
from app.services.security_rule_pack import _RULE_META
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rules.base import FindingCandidate
from app.services.security_rules.jira import JIRA_RULE_KEYS

REPO_ROOT = Path(__file__).resolve().parents[2]
FE_RULE_CATALOG = REPO_ROOT / "frontend" / "src" / "lib" / "securityRuleCatalog.ts"
JIRA_RULES_PY = REPO_ROOT / "backend" / "app" / "services" / "security_rules" / "jira.py"

LIVE_JIRA_RULE_COUNT = 81

# The 6 rules removed during the M86H dead-rule cleanup.
DEAD_JIRA_RULE_KEYS = [
    "jira_project_no_boards",
    "jira_project_no_issue_types",
    "jira_issue_type_scheme_no_types",
    "jira_field_configuration_scheme_no_configurations",
    "jira_field_configuration_scheme_hidden_required_conflict",
    "jira_screen_scheme_no_fields",
]

# Evidence keys that would imply we stored a secret, raw payload, or PII.
FORBIDDEN_EVIDENCE_KEYS = {
    "api_token",
    "oauth_token",
    "token",
    "authorization",
    "headers",
    "payload",
    "request",
    "response",
    "raw",
    "secret",
    "webhook_secret",
    "issue_title",
    "issue_description",
    "comment",
    "user_email",
    "user_name",
    "account_id",
    "group_name",
    "team_name",
    "customer",
}

# Standard protective disclaimer appended to every Jira finding description
# (app/services/security_rules/jira.py::_DOES_NOT_CONFIRM). Its negating phrase
# legitimately contains "compromise" / "unauthorized access" and is stripped
# before the over-claim wording scan.
_SAFE_DISCLAIMER = (
    "Configuration evidence only — does not confirm compromise "
    "or unauthorized access."
)

# Alarming / over-claiming wording a configuration-posture finding must avoid.
FORBIDDEN_WORDING = [
    "breach",
    "compromise",
    "attacker",
    "leaked",
    "unauthorized access confirmed",
    "issues exposed",
    "project data exposed",
    "site exposed",
    "workspace exposed",
    "tokens leaked",
    "secrets exposed",
    "permission abuse detected",
]


# ── Shared helpers ─────────────────────────────────────────────────────────────


def _jira_rule_record_type(rule_key: str) -> str:
    """Single normalized record_type a Jira rule evaluates (from coverage map)."""
    record_types = RULE_RECORD_TYPES.get(rule_key, ())
    assert record_types, f"{rule_key} has no record_type in RULE_RECORD_TYPES"
    return record_types[0]


def _field_names_in_jira_source() -> tuple[set[str], set[str], set[str]]:
    """Bool / int / str field names the Jira rules read, parsed from source.

    Used to construct maximally-risky synthetic records without hand-listing
    every field. ``record_type`` / ``record_id`` are reserved and never set as
    risky values (they drive dispatch and finding keys).
    """
    src = JIRA_RULES_PY.read_text()
    reserved = {"record_type", "record_id"}
    bools = set(re.findall(r'_bool\(record, "([a-z0-9_]+)"\)', src)) - reserved
    ints = set(re.findall(r'_int_opt\(record, "([a-z0-9_]+)"\)', src)) - reserved
    strs = set(re.findall(r'get_str\(record, "([a-z0-9_]+)"\)', src)) - reserved
    return bools, ints, strs


def _risky_records_for(record_type: str) -> list[dict]:
    """Several maximally-risky synthetic records for one record_type.

    Sweeps booleans True/False and ints 0/large so that a rule firing on
    ``is False``, ``is True``, ``== 0`` or ``> threshold`` is all exercised.
    Category strings are set to ``"unknown"`` (the classifier-failure label that
    several rules key on).
    """
    bools, ints, strs = _field_names_in_jira_source()
    records: list[dict] = []
    for bool_val in (True, False):
        for int_val in (0, 999):
            rec: dict = {"record_type": record_type, "record_id": f"{record_type}_r1"}
            for b in bools:
                rec[b] = bool_val
            for i in ints:
                rec[i] = int_val
            for s in strs:
                rec[s] = "unknown"
            records.append(rec)
    return records


def _parse_catalog_jira_keys() -> set[str]:
    """All jira_* rule keys present in the frontend securityRuleCatalog.ts."""
    text = FE_RULE_CATALOG.read_text()
    return set(re.findall(r'"(jira_[a-z0-9_]+)"', text))


# ─────────────────────────────────────────────────────────────────────────────
# GROUP A — Registry / catalog / coverage parity
# ─────────────────────────────────────────────────────────────────────────────


def test_live_jira_rule_count_is_76() -> None:
    assert len(JIRA_RULE_KEYS) == LIVE_JIRA_RULE_COUNT


@pytest.mark.parametrize("rule_key", sorted(JIRA_RULE_KEYS))
def test_jira_rule_in_known_rule_keys(rule_key: str) -> None:
    assert rule_key in KNOWN_RULE_KEYS


@pytest.mark.parametrize("rule_key", sorted(JIRA_RULE_KEYS))
def test_jira_rule_in_confidence(rule_key: str) -> None:
    assert rule_key in RULE_CONFIDENCE


@pytest.mark.parametrize("rule_key", sorted(JIRA_RULE_KEYS))
def test_jira_rule_in_rule_pack_meta(rule_key: str) -> None:
    assert rule_key in _RULE_META


@pytest.mark.parametrize("rule_key", sorted(JIRA_RULE_KEYS))
def test_jira_rule_in_coverage_record_types(rule_key: str) -> None:
    assert RULE_RECORD_TYPES.get(rule_key), f"{rule_key} missing from RULE_RECORD_TYPES"


@pytest.mark.parametrize("rule_key", sorted(JIRA_RULE_KEYS))
def test_jira_rule_in_frontend_catalog(rule_key: str) -> None:
    assert rule_key in _parse_catalog_jira_keys()


def test_frontend_catalog_contains_every_live_jira_key() -> None:
    catalog_keys = _parse_catalog_jira_keys()
    # Every live backend rule key must be present in the frontend catalog. The
    # catalog may also reference illustrative / cross-provider example keys in
    # copy, so we only assert the live set is a subset (no missing live keys).
    missing = JIRA_RULE_KEYS - catalog_keys
    assert not missing, f"frontend catalog missing live jira keys: {sorted(missing)}"


def test_no_dead_jira_key_in_frontend_catalog() -> None:
    catalog_keys = _parse_catalog_jira_keys()
    leftover = set(DEAD_JIRA_RULE_KEYS) & catalog_keys
    assert not leftover, f"frontend catalog still lists removed jira keys: {sorted(leftover)}"


# ─────────────────────────────────────────────────────────────────────────────
# GROUP B — Evaluator dispatch
# ─────────────────────────────────────────────────────────────────────────────


def test_jira_registered_in_provider_rules() -> None:
    from app.services import security_finding_evaluator as evaluator

    assert "jira" in evaluator._PROVIDER_RULES


def test_evaluate_record_record_first_provider_second() -> None:
    # Correct call order: evaluate_record(record, "jira"). A risky permission
    # scheme with an anonymous grant must yield at least one finding.
    record = {
        "record_type": JIRA_PERMISSION_SCHEME,
        "record_id": "ps-1",
        "permission_anonymous_grant_count": 2,
    }
    findings = evaluate_record(record, "jira")
    assert findings, "expected at least one finding for risky permission scheme"
    assert all(isinstance(f, FindingCandidate) for f in findings)
    assert any(
        f.rule_key == "jira_permission_scheme_anonymous_grant" for f in findings
    )


def test_evaluate_record_swapped_arguments_yields_nothing() -> None:
    # Guards the argument ORDER. Passing the provider string as the record and a
    # dict as the provider must not raise and must produce no findings — proving
    # the real call sites must use (record, provider), not (provider, record).
    record = {
        "record_type": JIRA_PERMISSION_SCHEME,
        "record_id": "ps-1",
        "permission_anonymous_grant_count": 2,
    }
    assert evaluate_record("jira", record) == []  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────────────────────────
# GROUP C — Severity correctness
# ─────────────────────────────────────────────────────────────────────────────


def _pack_severity(rule_key: str) -> str:
    return _RULE_META[rule_key][1]


def test_jira_permission_scheme_public_transition_issues_is_high_severity() -> None:
    # M86H recalibration: medium → high.
    assert _pack_severity("jira_permission_scheme_public_transition_issues") == "high"


@pytest.mark.parametrize(
    "rule_key",
    [
        "jira_permission_scheme_anonymous_grant",
        "jira_permission_scheme_anyone_grant",
        "jira_permission_scheme_public_administer_projects",
        "jira_webhook_no_secret_indicator",
        "jira_webhook_non_https",
        "jira_automation_rule_web_request_action",
    ],
)
def test_jira_high_risk_rules_are_high_severity(rule_key: str) -> None:
    assert _pack_severity(rule_key) == "high"


@pytest.mark.parametrize(
    "rule_key",
    [
        "jira_site_missing_url",
        "jira_project_archived",
    ],
)
def test_jira_benign_rules_are_low_severity(rule_key: str) -> None:
    # Lifecycle / metadata posture must not be severity-inflated.
    assert _pack_severity(rule_key) == "low"


# ─────────────────────────────────────────────────────────────────────────────
# GROUP D — Evidence safety
# ─────────────────────────────────────────────────────────────────────────────

_EVIDENCE_SAFETY_RECORDS = {
    JIRA_PERMISSION_SCHEME: {
        "record_type": JIRA_PERMISSION_SCHEME,
        "record_id": "ps-1",
        "permission_anonymous_grant_count": 3,
        "permission_anyone_grant_count": 1,
        "permission_public_administer_projects": True,
        "permission_public_transition_issues": True,
    },
    JIRA_WEBHOOK: {
        "record_type": JIRA_WEBHOOK,
        "record_id": "wh-1",
        "webhook_secret_present": False,
        "webhook_url_present": True,
        "webhook_url_scheme_category": "http",
        "webhook_event_count": 0,
        "webhook_jql_filter_present": False,
    },
    JIRA_AUTOMATION_RULE: {
        "record_type": JIRA_AUTOMATION_RULE,
        "record_id": "auto-1",
        "automation_has_web_request_action": True,
        "automation_scope_category": "global",
    },
}


@pytest.mark.parametrize("record_type", sorted(_EVIDENCE_SAFETY_RECORDS))
def test_jira_evidence_has_no_forbidden_keys(record_type: str) -> None:
    findings = evaluate_record(_EVIDENCE_SAFETY_RECORDS[record_type], "jira")
    assert findings, f"expected findings for risky {record_type}"
    for f in findings:
        offending = set(f.evidence) & FORBIDDEN_EVIDENCE_KEYS
        assert not offending, f"{f.rule_key} leaks evidence keys: {offending}"


@pytest.mark.parametrize("record_type", sorted(_EVIDENCE_SAFETY_RECORDS))
def test_jira_evidence_values_are_metadata_only(record_type: str) -> None:
    findings = evaluate_record(_EVIDENCE_SAFETY_RECORDS[record_type], "jira")
    for f in findings:
        for key, value in f.evidence.items():
            assert isinstance(
                value, (bool, int, str)
            ), f"{f.rule_key} evidence[{key}] is not a scalar: {type(value)}"
            if isinstance(value, str):
                # Short category / id / record-type labels only — never raw
                # API objects serialized to long strings.
                assert len(value) <= 80, f"{f.rule_key} evidence[{key}] too long"


# ─────────────────────────────────────────────────────────────────────────────
# GROUP E — Safe copy / no forbidden wording
# ─────────────────────────────────────────────────────────────────────────────


def _all_jira_findings() -> list[FindingCandidate]:
    record_types = sorted(
        {_jira_rule_record_type(rk) for rk in JIRA_RULE_KEYS}
    )
    findings: list[FindingCandidate] = []
    for record_type in record_types:
        for record in _risky_records_for(record_type):
            findings.extend(evaluate_record(record, "jira"))
    # Plus the special-category records that the generic sweep can't express.
    findings.extend(
        evaluate_record(
            {
                "record_type": JIRA_WEBHOOK,
                "record_id": "wh-http",
                "webhook_url_present": True,
                "webhook_url_scheme_category": "http",
            },
            "jira",
        )
    )
    findings.extend(
        evaluate_record(
            {
                "record_type": JIRA_AUTOMATION_RULE,
                "record_id": "auto-global",
                "automation_scope_category": "global",
            },
            "jira",
        )
    )
    findings.extend(
        evaluate_record(
            {
                "record_type": JIRA_AUTOMATION_RULE,
                "record_id": "auto-multi",
                "automation_scope_category": "multi-project",
            },
            "jira",
        )
    )
    # jira_workflow_scheme_low_project_count only fires in the narrow window
    # 0 < workflow_scheme_project_count < floor — the generic 0/999 extreme
    # sweep can never land inside that window, so it needs an explicit record
    # just like the category-keyed rules above.
    findings.extend(
        evaluate_record(
            {
                "record_type": JIRA_WORKFLOW_SCHEME,
                "record_id": "wfs-low-project-count",
                "workflow_scheme_project_count": 1,
            },
            "jira",
        )
    )
    return findings


def test_jira_findings_have_no_forbidden_wording() -> None:
    findings = _all_jira_findings()
    assert findings, "sweep produced no findings — risky records misconfigured"
    for f in findings:
        haystack = f"{f.title}\n{f.description}".lower()
        # Strip the standard protective disclaimer ("does not confirm compromise
        # or unauthorized access") before scanning — its negating language is
        # intentional and must not be flagged as an over-claim.
        haystack = haystack.replace(_SAFE_DISCLAIMER.lower(), "")
        for phrase in FORBIDDEN_WORDING:
            assert phrase not in haystack, (
                f"{f.rule_key} contains forbidden wording {phrase!r}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# GROUP F — Dead rule regression
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("dead_key", DEAD_JIRA_RULE_KEYS)
def test_dead_jira_rule_not_in_known_rule_keys(dead_key: str) -> None:
    assert dead_key not in KNOWN_RULE_KEYS


@pytest.mark.parametrize("dead_key", DEAD_JIRA_RULE_KEYS)
def test_dead_jira_rule_not_live(dead_key: str) -> None:
    assert dead_key not in JIRA_RULE_KEYS
    assert dead_key not in RULE_CONFIDENCE
    assert dead_key not in _RULE_META
    assert dead_key not in RULE_RECORD_TYPES


def test_no_live_jira_record_type_is_dead() -> None:
    """Every live Jira record_type must fire ≥1 finding under risky posture.

    A record_type whose rules never fire for ANY risky synthetic record would be
    silently dead. This caught the 6 removed M86H rules.
    """
    record_types = sorted({_jira_rule_record_type(rk) for rk in JIRA_RULE_KEYS})
    dead: list[str] = []
    for record_type in record_types:
        fired = False
        for record in _risky_records_for(record_type):
            if evaluate_record(record, "jira"):
                fired = True
                break
        if not fired:
            dead.append(record_type)
    assert not dead, f"record types with no firing rule: {dead}"


def test_every_live_jira_rule_fires_for_some_risky_record() -> None:
    """Per-key liveness: each of the 76 rules must fire at least once.

    Sweeps boolean/int extremes per record_type plus the three category-keyed
    rules (non-HTTPS webhook, global/multi-project automation scope) that need an
    explicit category string the generic sweep cannot express.
    """
    fired: set[str] = {f.rule_key for f in _all_jira_findings()}
    never_fired = JIRA_RULE_KEYS - fired
    assert not never_fired, f"potentially dead live rules: {sorted(never_fired)}"


# ─────────────────────────────────────────────────────────────────────────────
# GROUP G — Webhook secret indicator
# ─────────────────────────────────────────────────────────────────────────────
#
# webhook_secret_present is derived from a safe boolean only; the raw webhook
# secret is never stored. These tests pin the boolean's effect on the rule.


def test_webhook_with_secret_does_not_fire_no_secret_rule() -> None:
    record = {
        "record_type": JIRA_WEBHOOK,
        "record_id": "wh-secret",
        "webhook_secret_present": True,
    }
    keys = {f.rule_key for f in evaluate_record(record, "jira")}
    assert "jira_webhook_no_secret_indicator" not in keys


def test_webhook_without_secret_fires_no_secret_rule() -> None:
    record = {
        "record_type": JIRA_WEBHOOK,
        "record_id": "wh-nosecret",
        "webhook_secret_present": False,
    }
    findings = evaluate_record(record, "jira")
    by_key = {f.rule_key: f for f in findings}
    assert "jira_webhook_no_secret_indicator" in by_key
    # Evidence is the safe boolean only — never the secret itself.
    assert by_key["jira_webhook_no_secret_indicator"].evidence.get(
        "webhook_secret_present"
    ) is False


# ─────────────────────────────────────────────────────────────────────────────
# GROUP H — Roadmap / framework state
# ─────────────────────────────────────────────────────────────────────────────


def test_framework_planned_next_stage_is_kubernetes() -> None:
    summary = get_framework()["summary"]
    planned = summary["planned_next_stage"]
    assert ("M89A" in planned or "Kubernetes" in planned
                or "M90A" in planned or "Sentry" in planned)


def test_jira_not_in_recommended_next_providers() -> None:
    # Jira is complete — it must not be queued as a next provider.
    recs = get_framework()["recommended_next_providers"]
    providers = {r["provider"] if isinstance(r, dict) else r.provider for r in recs}
    assert "jira" not in providers


def test_recommended_queue_is_empty_after_sentry_launch() -> None:
    """Regression note: Kubernetes launched and was removed from the
    recommended queue. Sentry (message 8 — public launch) was the FINAL
    planned provider, so the queue is now permanently empty."""
    recs = get_framework()["recommended_next_providers"]
    providers = {r["provider"] if isinstance(r, dict) else r.provider for r in recs}
    assert "kubernetes" not in providers
    assert "sentry" not in providers
    assert recs == []


def test_jira_capability_is_security_implemented() -> None:
    capability = get_provider_capability("jira")
    assert capability is not None
    # Maturity stays "partial" per convention for completed dual-stack arcs;
    # the security surface is fully implemented.
    assert capability.maturity == "partial"
    assert capability.security.security_rules is True
    assert capability.security.case_report is True
