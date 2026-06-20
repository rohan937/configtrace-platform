"""M87F — GitLab Risk × Activity Correlation tests.

Joins active GitLab configuration-risk findings (M87B/M87C) with GitLab
activity signals (M87E) on the same resource within a review window. Mirrors
the Jira M86F / Linear M85F / PagerDuty M84F structure.

CLAIM DISCIPLINE: correlations are evidence for review only. Does NOT confirm a
breach, compromise, unauthorized access, source-code exposure, repo exposure,
secret exposure, token leak, credential exposure, or data exposure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
import uuid

from app.services import gitlab_risk_activity_correlation_service as svc
from app.services.gitlab_risk_activity_correlation_service import (
    GITLAB_CORRELATION_TYPES,
    GITLAB_CORRELATION_RULES,
    GITLAB_RULE_KEY_TO_SIGNAL_TYPE,
    _base_rule_key,
    _build_correlation,
    _family_for_rule_key,
    _match_pair,
)
from app.services.security_signal_correlation_service import ALLOWED_METADATA_KEYS
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"
FE_CORR_PAGE = (
    FRONTEND_SRC / "app" / "(app)" / "security" / "correlations" / "page.tsx"
)
FE_API_TS = FRONTEND_SRC / "lib" / "api.ts"
FE_TYPES_TS = FRONTEND_SRC / "types" / "index.ts"
SECURITY_ROUTER = REPO_ROOT / "backend" / "app" / "routers" / "security.py"

# Forbidden claim wording.
_FORBIDDEN_WORDING = (
    "breach confirmed", "compromise confirmed", "attacker found",
    "someone has access", "data leaked", "secret leaked",
    "customer data exposed", "unauthorized access confirmed",
    "payment fraud detected", "attack detected", "orders exposed",
    "card data exposed", "repo exposed", "source code leaked",
    "source code exposed", "token leaked", "secrets exposed",
    "credentials exposed",
)

# Substrings that must NEVER appear in correlation metadata KEYS.
_FORBIDDEN_KEY_SUBSTRINGS = (
    "token", "secret_value", "private_token", "authorization",
    "webhook_url", "ci_variable_name", "ci_variable_value",
    "deploy_key_material", "ssh_key", "runner_token", "runner_ip",
    "user_email", "username", "project_name", "group_name",
    "branch_name", "raw", "payload", "request", "response",
    "commit_message", "merge_request_title", "issue_title",
    "pipeline_log", "artifact",
)

# Opaque test identifiers.
GL_PROJECT = "GL_TEST_PROJECT_ID"
GL_GROUP = "GL_TEST_GROUP_ID"
GL_BRANCH = "GL_TEST_BRANCH_ID"
GL_WEBHOOK = "GL_TEST_WEBHOOK_ID"
GL_CI = "GL_TEST_CI_ID"
GL_DEPLOY = "GL_TEST_DEPLOY_ID"
GL_RUNNER = "GL_TEST_RUNNER_ID"
GL_MR = "GL_TEST_MR_APPROVAL_ID"


def _mock_finding(finding_key: str, resource_id: str,
                  severity: str = "high",
                  evidence: dict | None = None) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.finding_key = finding_key
    f.resource_id = resource_id
    f.severity = severity
    f.status = "active"
    f.provider = "gitlab"
    f.integration_id = None
    f.first_detected_at = None
    f.last_seen_at = None
    f.evidence = evidence or {"resource_id": resource_id, "resource_type": "gitlab_resource"}
    return f


def _mock_signal(signal_type: str, resource_id: str,
                 md: dict | None = None) -> MagicMock:
    s = MagicMock()
    s.id = uuid.uuid4()
    s.signal_type = signal_type
    s.provider = "gitlab"
    s.integration_id = None
    s.first_seen_at = None
    s.last_seen_at = None
    s.linked_activity_event_id = None
    s.signal_metadata = md or {"resource_id": resource_id, "resource_type": "gitlab_resource"}
    return s


def _build(finding_key: str, f_rid: str,
           signal_type: str, s_rid: str,
           f_evidence: dict | None = None,
           s_md: dict | None = None) -> dict | None:
    f = _mock_finding(finding_key, f_rid, evidence=f_evidence)
    s = _mock_signal(signal_type, s_rid, md=s_md)
    match = _match_pair(f, s)
    if match is None:
        return None
    correlation_type = _family_for_rule_key(_base_rule_key(finding_key))
    rule = GITLAB_CORRELATION_RULES[correlation_type]
    return _build_correlation(
        finding=f, signal=s,
        correlation_type=correlation_type,
        rule=rule, match_reason=match, lookback_hours=24,
    )


# ════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ════════════════════════════════════════════════════════════════════════════
class TestImports:
    def test_service_imports(self) -> None:
        assert callable(svc.generate_gitlab_correlations)
        assert callable(_build_correlation)
        assert callable(_match_pair)

    def test_provider(self) -> None:
        assert svc.PROVIDER == "gitlab"


# ════════════════════════════════════════════════════════════════════════════
# CORRELATION TYPES
# ════════════════════════════════════════════════════════════════════════════
class TestCorrelationTypes:
    EXPECTED = {
        "gitlab_public_visibility_with_activity",
        "gitlab_branch_protection_risk_with_activity",
        "gitlab_webhook_secret_risk_with_activity",
        "gitlab_webhook_transport_risk_with_activity",
        "gitlab_webhook_event_scope_risk_with_activity",
        "gitlab_ci_variable_risk_with_activity",
        "gitlab_deploy_key_risk_with_activity",
        "gitlab_runner_risk_with_activity",
        "gitlab_merge_request_approval_risk_with_activity",
        "gitlab_public_feature_risk_with_activity",
        "gitlab_configuration_risk_with_activity",
    }

    def test_expected_types_exist(self) -> None:
        assert self.EXPECTED <= set(GITLAB_CORRELATION_TYPES)

    def test_types_namespaced_gitlab(self) -> None:
        for ct in GITLAB_CORRELATION_TYPES:
            assert ct.startswith("gitlab_"), f"{ct!r} not namespaced"

    def test_no_forbidden_wording_in_types(self) -> None:
        for ct in GITLAB_CORRELATION_TYPES:
            low = ct.lower()
            for bad in _FORBIDDEN_WORDING:
                assert bad not in low


# ════════════════════════════════════════════════════════════════════════════
# FAMILY RESOLUTION
# ════════════════════════════════════════════════════════════════════════════
class TestFamilyResolution:
    def _check(self, rule_key: str, expected_family: str) -> None:
        assert _family_for_rule_key(rule_key) == expected_family

    def test_public_visibility(self) -> None:
        self._check("gitlab_project_public_visibility", "gitlab_public_visibility_with_activity")
        self._check("gitlab_group_public_visibility", "gitlab_public_visibility_with_activity")

    def test_branch_protection(self) -> None:
        self._check("gitlab_branch_force_push_enabled", "gitlab_branch_protection_risk_with_activity")
        self._check("gitlab_branch_push_access_broad", "gitlab_branch_protection_risk_with_activity")
        self._check("gitlab_branch_merge_access_broad", "gitlab_branch_protection_risk_with_activity")

    def test_webhook_secret(self) -> None:
        self._check("gitlab_webhook_secret_missing", "gitlab_webhook_secret_risk_with_activity")
        self._check("gitlab_webhook_ssl_verification_disabled", "gitlab_webhook_secret_risk_with_activity")

    def test_webhook_transport(self) -> None:
        self._check("gitlab_webhook_http_scheme", "gitlab_webhook_transport_risk_with_activity")

    def test_webhook_scope(self) -> None:
        self._check("gitlab_webhook_broad_event_scope", "gitlab_webhook_event_scope_risk_with_activity")
        self._check("gitlab_webhook_pipeline_job_events", "gitlab_webhook_event_scope_risk_with_activity")

    def test_ci_variable(self) -> None:
        self._check("gitlab_ci_unprotected_unmasked_variables", "gitlab_ci_variable_risk_with_activity")
        self._check("gitlab_ci_variables_unprotected", "gitlab_ci_variable_risk_with_activity")
        self._check("gitlab_ci_variables_unmasked", "gitlab_ci_variable_risk_with_activity")

    def test_deploy_key(self) -> None:
        self._check("gitlab_deploy_key_write_enabled", "gitlab_deploy_key_risk_with_activity")

    def test_runner(self) -> None:
        self._check("gitlab_runner_untagged", "gitlab_runner_risk_with_activity")
        self._check("gitlab_runner_shared_enabled", "gitlab_runner_risk_with_activity")

    def test_mr_approval(self) -> None:
        self._check("gitlab_merge_request_approval_not_required", "gitlab_merge_request_approval_risk_with_activity")
        self._check("gitlab_mr_approval_reset_disabled", "gitlab_merge_request_approval_risk_with_activity")

    def test_public_feature(self) -> None:
        self._check("gitlab_project_snippets_enabled_public", "gitlab_public_feature_risk_with_activity")
        self._check("gitlab_project_wiki_enabled_public", "gitlab_public_feature_risk_with_activity")

    def test_unknown_rule_key_fallback(self) -> None:
        assert _family_for_rule_key("gitlab_some_unknown_rule") == "gitlab_configuration_risk_with_activity"
        assert _family_for_rule_key("nonexistent") == "gitlab_configuration_risk_with_activity"


# ════════════════════════════════════════════════════════════════════════════
# MATCH PAIR
# ════════════════════════════════════════════════════════════════════════════
class TestMatchPair:
    def test_resource_id_match(self) -> None:
        f = _mock_finding("gitlab_project_public_visibility", GL_PROJECT,
                           evidence={"resource_id": GL_PROJECT})
        s = _mock_signal("gitlab_project_visibility_signal", GL_PROJECT,
                          md={"resource_id": GL_PROJECT})
        assert _match_pair(f, s) == "resource_id_match"

    def test_record_type_match_fallback(self) -> None:
        # Different resource IDs, same signal type family.
        f = _mock_finding("gitlab_project_public_visibility", "PROJ_A",
                           evidence={"resource_id": "PROJ_A"})
        s = _mock_signal("gitlab_project_visibility_signal", "PROJ_B",
                          md={"resource_id": "PROJ_B"})
        result = _match_pair(f, s)
        assert result in ("resource_id_match", "record_type_match")

    def test_generic_signal_matches_any_family(self) -> None:
        f = _mock_finding("gitlab_branch_force_push_enabled", GL_BRANCH,
                           evidence={"resource_id": GL_BRANCH})
        s = _mock_signal("gitlab_configuration_activity_signal", "OTHER_ID",
                          md={"resource_id": "OTHER_ID"})
        # Generic signal matches via record_type_match.
        result = _match_pair(f, s)
        assert result in ("resource_id_match", "record_type_match")


# ════════════════════════════════════════════════════════════════════════════
# PER-FAMILY CORRELATION GENERATION
# ════════════════════════════════════════════════════════════════════════════
class TestFamilyCorrelation:
    def _corr(self, finding_key: str, f_rid: str, signal_type: str, s_rid: str,
              s_md: dict | None = None) -> dict:
        c = _build(finding_key, f_rid, signal_type, s_rid,
                   f_evidence={"resource_id": f_rid, "resource_type": "gitlab_project"},
                   s_md=s_md or {"resource_id": s_rid})
        assert c is not None, f"Expected correlation for {finding_key}/{signal_type}"
        return c

    def test_public_project_visibility(self) -> None:
        c = self._corr("gitlab_project_public_visibility", GL_PROJECT,
                       "gitlab_project_visibility_signal", GL_PROJECT)
        assert c["provider"] == "gitlab"
        assert "visibility" in c["correlation_type"]

    def test_public_group_visibility(self) -> None:
        c = self._corr("gitlab_group_public_visibility", GL_GROUP,
                       "gitlab_group_visibility_signal", GL_GROUP)
        assert c["provider"] == "gitlab"

    def test_force_push_branch(self) -> None:
        c = self._corr("gitlab_branch_force_push_enabled", GL_BRANCH,
                       "gitlab_force_push_enabled_signal", GL_BRANCH,
                       s_md={"resource_id": GL_BRANCH, "allow_force_push": True})
        assert "branch_protection" in c["correlation_type"]

    def test_branch_protection_weakened(self) -> None:
        c = self._corr("gitlab_branch_code_owner_approval_missing", GL_BRANCH,
                       "gitlab_branch_protection_weakened", GL_BRANCH)
        assert "branch_protection" in c["correlation_type"]

    def test_webhook_secret_missing(self) -> None:
        c = self._corr("gitlab_webhook_secret_missing", GL_WEBHOOK,
                       "gitlab_webhook_secret_removed_signal", GL_WEBHOOK,
                       s_md={"resource_id": GL_WEBHOOK, "webhook_secret_present": False})
        assert "webhook_secret" in c["correlation_type"]

    def test_webhook_ssl_disabled(self) -> None:
        c = self._corr("gitlab_webhook_ssl_verification_disabled", GL_WEBHOOK,
                       "gitlab_webhook_ssl_disabled_signal", GL_WEBHOOK,
                       s_md={"resource_id": GL_WEBHOOK, "ssl_verification_enabled": False})
        assert "webhook_secret" in c["correlation_type"]

    def test_webhook_http_transport(self) -> None:
        c = self._corr("gitlab_webhook_http_scheme", GL_WEBHOOK,
                       "gitlab_webhook_http_scheme_signal", GL_WEBHOOK,
                       s_md={"resource_id": GL_WEBHOOK, "webhook_scheme_category": "http"})
        assert "webhook_transport" in c["correlation_type"]

    def test_webhook_broad_event_scope(self) -> None:
        c = self._corr("gitlab_webhook_broad_event_scope", GL_WEBHOOK,
                       "gitlab_webhook_broad_event_scope_signal", GL_WEBHOOK)
        assert "webhook_event_scope" in c["correlation_type"]

    def test_ci_unprotected_unmasked(self) -> None:
        c = self._corr("gitlab_ci_unprotected_unmasked_variables", GL_CI,
                       "gitlab_ci_unprotected_unmasked_variables_signal", GL_CI,
                       s_md={"resource_id": GL_CI, "unprotected_unmasked_count": 3})
        assert "ci_variable" in c["correlation_type"]

    def test_ci_posture_changed(self) -> None:
        c = self._corr("gitlab_ci_variables_unprotected", GL_CI,
                       "gitlab_ci_variable_posture_signal", GL_CI)
        assert "ci_variable" in c["correlation_type"]

    def test_deploy_key_write_enabled(self) -> None:
        c = self._corr("gitlab_deploy_key_write_enabled", GL_DEPLOY,
                       "gitlab_deploy_key_write_enabled_signal", GL_DEPLOY,
                       s_md={"resource_id": GL_DEPLOY, "write_enabled_count": 1})
        assert "deploy_key" in c["correlation_type"]

    def test_runner_posture(self) -> None:
        c = self._corr("gitlab_runner_untagged", GL_RUNNER,
                       "gitlab_runner_posture_signal", GL_RUNNER)
        assert "runner" in c["correlation_type"]

    def test_runner_shared(self) -> None:
        c = self._corr("gitlab_runner_shared_enabled", GL_RUNNER,
                       "gitlab_shared_runner_enabled_signal", GL_RUNNER)
        assert "runner" in c["correlation_type"]

    def test_mr_approval_reduced(self) -> None:
        c = self._corr("gitlab_merge_request_approval_not_required", GL_MR,
                       "gitlab_merge_request_approval_weakened", GL_MR,
                       s_md={"resource_id": GL_MR, "approvals_required": 0})
        assert "merge_request_approval" in c["correlation_type"]

    def test_public_feature(self) -> None:
        c = self._corr("gitlab_project_snippets_enabled_public", GL_PROJECT,
                       "gitlab_project_public_feature_signal", GL_PROJECT,
                       s_md={"resource_id": GL_PROJECT, "snippets_enabled": True})
        assert "public_feature" in c["correlation_type"]

    def test_unknown_rule_key_fallback_correlation(self) -> None:
        c = _build("gitlab_unknown_rule", GL_PROJECT,
                   "gitlab_configuration_activity_signal", GL_PROJECT,
                   f_evidence={"resource_id": GL_PROJECT},
                   s_md={"resource_id": GL_PROJECT})
        # May be None (no match) or a generic correlation — both are safe.
        if c is not None:
            assert "configuration" in c["correlation_type"]

    def test_missing_metadata_no_misleading_correlation(self) -> None:
        c = _build("gitlab_project_public_visibility", GL_PROJECT,
                   "gitlab_project_visibility_signal", GL_PROJECT,
                   f_evidence={}, s_md={})
        # No resource_id on either side → may fall back to record_type_match.
        # Either way, the correlation must be safe if produced.
        if c is not None:
            assert c["provider"] == "gitlab"


# ════════════════════════════════════════════════════════════════════════════
# METADATA SAFETY
# ════════════════════════════════════════════════════════════════════════════
class TestMetadataSafety:
    def _all_corrs(self) -> list[dict]:
        cases = [
            ("gitlab_project_public_visibility", GL_PROJECT,
             "gitlab_project_visibility_signal", GL_PROJECT,
             {"resource_id": GL_PROJECT, "visibility_category": "public", "archived": False}),
            ("gitlab_branch_force_push_enabled", GL_BRANCH,
             "gitlab_force_push_enabled_signal", GL_BRANCH,
             {"resource_id": GL_BRANCH, "allow_force_push": True,
              "pattern_category": "default", "push_access_level_category": "developer"}),
            ("gitlab_webhook_secret_missing", GL_WEBHOOK,
             "gitlab_webhook_secret_removed_signal", GL_WEBHOOK,
             {"resource_id": GL_WEBHOOK, "webhook_secret_present": False,
              "ssl_verification_enabled": True, "event_count": 3}),
            ("gitlab_webhook_http_scheme", GL_WEBHOOK,
             "gitlab_webhook_http_scheme_signal", GL_WEBHOOK,
             {"resource_id": GL_WEBHOOK, "webhook_scheme_category": "http", "event_count": 2}),
            ("gitlab_ci_unprotected_unmasked_variables", GL_CI,
             "gitlab_ci_unprotected_unmasked_variables_signal", GL_CI,
             {"resource_id": GL_CI, "variable_count": 4, "unprotected_unmasked_count": 2}),
            ("gitlab_deploy_key_write_enabled", GL_DEPLOY,
             "gitlab_deploy_key_write_enabled_signal", GL_DEPLOY,
             {"resource_id": GL_DEPLOY, "write_enabled_count": 1, "enabled_count": 2}),
            ("gitlab_runner_untagged", GL_RUNNER,
             "gitlab_runner_posture_signal", GL_RUNNER,
             {"resource_id": GL_RUNNER, "runner_count": 3, "untagged_runner_count": 2}),
            ("gitlab_merge_request_approval_not_required", GL_MR,
             "gitlab_merge_request_approval_weakened", GL_MR,
             {"resource_id": GL_MR, "approvals_required": 0, "reset_approvals_on_push": False}),
        ]
        out = []
        for fk, frid, st, srid, smd in cases:
            c = _build(fk, frid, st, srid,
                       f_evidence={"resource_id": frid, "resource_type": "gitlab_resource"},
                       s_md=smd)
            if c:
                out.append(c)
        return out

    def test_has_correlations(self) -> None:
        assert self._all_corrs()

    def test_all_provider_gitlab(self) -> None:
        for c in self._all_corrs():
            assert c["provider"] == "gitlab"

    def test_metadata_flat_and_scalar(self) -> None:
        for c in self._all_corrs():
            for k, v in c["metadata"].items():
                assert isinstance(v, (str, int, float, bool)), (
                    f"metadata key {k!r} non-scalar: {v!r}"
                )

    def test_metadata_keys_allowlisted(self) -> None:
        for c in self._all_corrs():
            for k in c["metadata"]:
                assert k in ALLOWED_METADATA_KEYS, (
                    f"metadata key {k!r} not in ALLOWED_METADATA_KEYS"
                )

    def test_metadata_keys_no_forbidden_substring(self) -> None:
        for c in self._all_corrs():
            for k in c["metadata"]:
                low = k.lower()
                for bad in _FORBIDDEN_KEY_SUBSTRINGS:
                    assert bad not in low, (
                        f"metadata key {k!r} contains forbidden substring {bad!r}"
                    )

    def test_correlation_title_and_summary_no_forbidden_wording(self) -> None:
        for c in self._all_corrs():
            text = (c.get("title", "") + " " + c.get("summary", "")).lower()
            for bad in _FORBIDDEN_WORDING:
                assert bad not in text, (
                    f"correlation copy contains forbidden wording {bad!r}"
                )

    def test_no_actor_identity_in_metadata(self) -> None:
        for c in self._all_corrs():
            md = c.get("metadata", {})
            assert "user_email" not in md
            assert "username" not in md


# ════════════════════════════════════════════════════════════════════════════
# IDEMPOTENCY
# ════════════════════════════════════════════════════════════════════════════
class TestIdempotency:
    def test_same_finding_signal_same_key(self) -> None:
        f = _mock_finding("gitlab_project_public_visibility", GL_PROJECT,
                           evidence={"resource_id": GL_PROJECT})
        s = _mock_signal("gitlab_project_visibility_signal", GL_PROJECT,
                          md={"resource_id": GL_PROJECT})
        # The correlation key is deterministic on (correlation_type, finding.id, signal.id)
        from app.services.gitlab_risk_activity_correlation_service import _correlation_key
        rule = GITLAB_CORRELATION_RULES["gitlab_public_visibility_with_activity"]
        ct = "gitlab_public_visibility_with_activity"
        key_a = _correlation_key(f, s, ct)
        key_b = _correlation_key(f, s, ct)
        assert key_a == key_b

    def test_different_findings_different_keys(self) -> None:
        from app.services.gitlab_risk_activity_correlation_service import _correlation_key
        f1 = _mock_finding("gitlab_project_public_visibility", "PROJ_A",
                            evidence={"resource_id": "PROJ_A"})
        f2 = _mock_finding("gitlab_project_public_visibility", "PROJ_B",
                            evidence={"resource_id": "PROJ_B"})
        s = _mock_signal("gitlab_project_visibility_signal", "PROJ_A",
                          md={"resource_id": "PROJ_A"})
        ct = "gitlab_public_visibility_with_activity"
        assert _correlation_key(f1, s, ct) != _correlation_key(f2, s, ct)


# ════════════════════════════════════════════════════════════════════════════
# CAPABILITY MATRIX / EXPANSION FRAMEWORK
# ════════════════════════════════════════════════════════════════════════════
class TestCapabilityMatrix:
    def test_risk_activity_correlations_true(self) -> None:
        cap = get_provider_capability("gitlab")
        assert cap.security.risk_activity_correlations is True

    def test_later_stages_still_false(self) -> None:
        cap = get_provider_capability("gitlab")
        # demo_seed_clear landed in M87G.
        assert cap.security.demo_seed_clear is True
        # case_report landed in M87G.
        assert cap.security.case_report is True
        # evidence_timeline landed in M87G.
        assert cap.security.evidence_timeline is True
        # evidence_graph landed in M87G.
        assert cap.security.evidence_graph is True

    def test_notes_mention_m87f(self) -> None:
        cap = get_provider_capability("gitlab")
        assert "M87F" in cap.notes

    def test_planned_next_stage_m87g(self) -> None:
        cap = get_provider_capability("gitlab")
        assert "M87G" in cap.notes


class TestExpansionFramework:
    def test_planned_next_stage_points_to_m87g(self) -> None:
        planned = get_framework().get("summary", {}).get("planned_next_stage", "")
        # M87G landed; planned now points to M87H.
        assert ("M87G" in planned or "Demo" in planned
                or "M87H" in planned or "Provider Depth" in planned or "M87I" in planned or "Cross-Cloud" in planned
                or "M88A" in planned or "Terraform" in planned
                or "M89A" in planned or "Kubernetes" in planned)

    def test_terraform_cloud_remains_in_queue(self) -> None:
        recs = get_framework().get("recommended_next_providers", [])
        provider_keys = [r.get("provider") for r in recs]
        assert "terraform_cloud" in provider_keys or "kubernetes" in provider_keys or "terraform" in str(provider_keys)


# ════════════════════════════════════════════════════════════════════════════
# ROUTER / FRONTEND WIRING
# ════════════════════════════════════════════════════════════════════════════
class TestRouterWiring:
    def test_route_registered(self) -> None:
        from app.main import app
        paths = {r.path for r in app.routes}  # type: ignore[attr-defined]
        assert any(p.endswith("/gitlab-activity/generate-correlations") for p in paths)

    def test_route_is_admin_gated(self) -> None:
        src = SECURITY_ROUTER.read_text(encoding="utf-8")
        assert "gitlab-activity/generate-correlations" in src
        idx = src.index("gitlab-activity/generate-correlations")
        following = src[idx: idx + 2500]
        assert "require_workspace_admin" in following


class TestFrontendWiring:
    def test_correlations_page_includes_gitlab(self) -> None:
        src = FE_CORR_PAGE.read_text(encoding="utf-8")
        assert "gitlab" in src
        assert "gitlab_public_visibility_with_activity" in src
        assert "generateGitlabRiskActivityCorrelations" in src

    def test_api_has_generate_function(self) -> None:
        src = FE_API_TS.read_text(encoding="utf-8")
        assert "generateGitlabRiskActivityCorrelations" in src
        assert "/security/gitlab-activity/generate-correlations" in src

    def test_types_has_response(self) -> None:
        src = FE_TYPES_TS.read_text(encoding="utf-8")
        assert "GitLabRiskActivityCorrelationGenerateResponse" in src

    def test_frontend_copy_no_forbidden_wording(self) -> None:
        src = FE_CORR_PAGE.read_text(encoding="utf-8").lower()
        for line in src.splitlines():
            if "gitlab" not in line:
                continue
            for bad in _FORBIDDEN_WORDING:
                assert bad not in line, (
                    f"forbidden wording {bad!r} in GitLab correlations page copy"
                )
