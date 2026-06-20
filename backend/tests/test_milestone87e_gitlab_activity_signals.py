"""M87E — GitLab configuration activity signal tests.

Promotes M87D GitLab configuration-state activity events into review-worthy
Incident Signals. Mirrors the Jira M86E / Linear M85E / PagerDuty M84E
structure, adapted to GitLab's multi-event-type signal mapping.

CLAIM DISCIPLINE: configuration-state review signals only. Does NOT confirm a
breach, compromise, unauthorized access, source-code exposure, repo exposure,
secret exposure, token leak, credential exposure, or data exposure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from app.services import gitlab_activity_signal_service as svc
from app.services.gitlab_activity_signal_service import (
    GITLAB_EVENT_TO_SIGNAL_TYPE,
    GITLAB_SIGNAL_TYPES,
    _build_signal,
    _group_key,
    _severity,
)
from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"
FE_SIGNALS_PAGE = (
    FRONTEND_SRC / "app" / "(app)" / "security" / "signals" / "page.tsx"
)
FE_API_TS = FRONTEND_SRC / "lib" / "api.ts"
FE_TYPES_TS = FRONTEND_SRC / "types" / "index.ts"
SECURITY_ROUTER = REPO_ROOT / "backend" / "app" / "routers" / "security.py"

# Forbidden claim wording — must not appear in signal types or summaries.
_FORBIDDEN_WORDING = (
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
    "source code leaked",
    "source code exposed",
    "token leaked",
    "secrets exposed",
    "credentials exposed",
)

# Substrings that must NEVER appear in any signal metadata KEY.
_FORBIDDEN_METADATA_KEY_SUBSTRINGS = (
    "token",
    "secret_value",
    "private_token",
    "authorization",
    "webhook_url",
    "ci_variable_name",
    "ci_variable_value",
    "deploy_key_material",
    "ssh_key",
    "runner_token",
    "runner_ip",
    "user_email",
    "username",
    "project_name",
    "group_name",
    "branch_name",
    "raw",
    "payload",
    "request",
    "response",
    "commit_message",
    "merge_request_title",
    "issue_title",
    "pipeline_log",
    "artifact",
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


def _mock_event(event_type: str, resource_id: str, metadata: dict[str, Any] | None = None) -> MagicMock:
    """Build a minimal mock SecurityActivityEvent for unit tests."""
    ev = MagicMock()
    ev.event_type = event_type
    ev.provider = "gitlab"
    ev.source = "gitlab_activity_event"
    ev.resource_id = resource_id
    ev.resource_type = None
    ev.provider_event_id = f"gitlab:{event_type}:{resource_id}"
    ev.integration_id = None
    ev.occurred_at = None
    ev.ingested_at = None
    ev.created_at = None
    ev.event_metadata = metadata or {}
    return ev


def _build_single_group(event_type: str, resource_id: str,
                         metadata: dict[str, Any] | None = None) -> dict | None:
    ev = _mock_event(event_type, resource_id, metadata)
    return _build_signal([ev])


# ════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ════════════════════════════════════════════════════════════════════════════
class TestImports:
    def test_service_imports(self) -> None:
        assert callable(svc.generate_gitlab_activity_signals)
        assert callable(_build_signal)
        assert callable(_group_key)

    def test_provider_and_source(self) -> None:
        assert svc.PROVIDER == "gitlab"
        assert svc.SOURCE == "gitlab_activity_event"


# ════════════════════════════════════════════════════════════════════════════
# SIGNAL TYPES
# ════════════════════════════════════════════════════════════════════════════
class TestSignalTypes:
    EXPECTED = {
        "gitlab_project_visibility_signal",
        "gitlab_project_public_feature_signal",
        "gitlab_group_visibility_signal",
        "gitlab_force_push_enabled_signal",
        "gitlab_branch_protection_weakened",
        "gitlab_webhook_secret_removed_signal",
        "gitlab_webhook_ssl_disabled_signal",
        "gitlab_webhook_http_scheme_signal",
        "gitlab_webhook_broad_event_scope_signal",
        "gitlab_ci_unprotected_unmasked_variables_signal",
        "gitlab_ci_variable_posture_signal",
        "gitlab_deploy_key_write_enabled_signal",
        "gitlab_shared_runner_enabled_signal",
        "gitlab_runner_posture_signal",
        "gitlab_merge_request_approval_weakened",
        "gitlab_configuration_activity_signal",
    }

    def test_expected_signal_types_exist(self) -> None:
        assert self.EXPECTED <= set(GITLAB_SIGNAL_TYPES)

    def test_signal_types_namespaced_gitlab(self) -> None:
        for st in GITLAB_SIGNAL_TYPES:
            assert st.startswith("gitlab_"), f"{st!r} not namespaced gitlab_"

    def test_signal_types_have_no_forbidden_wording(self) -> None:
        for st in GITLAB_SIGNAL_TYPES:
            low = st.lower()
            for bad in _FORBIDDEN_WORDING:
                assert bad not in low


# ════════════════════════════════════════════════════════════════════════════
# SEVERITY MAPPING
# ════════════════════════════════════════════════════════════════════════════
class TestSeverity:
    def test_high_signal_types(self) -> None:
        high = [
            "gitlab_project_visibility_signal",
            "gitlab_group_visibility_signal",
            "gitlab_force_push_enabled_signal",
            "gitlab_webhook_secret_removed_signal",
            "gitlab_webhook_ssl_disabled_signal",
            "gitlab_webhook_http_scheme_signal",
            "gitlab_ci_unprotected_unmasked_variables_signal",
            "gitlab_deploy_key_write_enabled_signal",
        ]
        for st in high:
            assert _severity(st) == "high", f"{st} should be high"

    def test_medium_signal_types(self) -> None:
        medium = [
            "gitlab_branch_protection_weakened",
            "gitlab_webhook_broad_event_scope_signal",
            "gitlab_ci_variable_posture_signal",
            "gitlab_shared_runner_enabled_signal",
            "gitlab_runner_posture_signal",
            "gitlab_merge_request_approval_weakened",
            "gitlab_project_public_feature_signal",
        ]
        for st in medium:
            assert _severity(st) == "medium", f"{st} should be medium"

    def test_low_fallback(self) -> None:
        assert _severity("gitlab_configuration_activity_signal") == "low"


# ════════════════════════════════════════════════════════════════════════════
# GROUP KEY / IDEMPOTENCY
# ════════════════════════════════════════════════════════════════════════════
class TestGroupKey:
    def test_group_key_format(self) -> None:
        ev = _mock_event("gitlab.project.visibility_changed", GL_PROJECT,
                          {"resource_id": GL_PROJECT})
        gk = _group_key(ev)
        assert gk is not None
        assert "gitlab.activity" in gk
        assert "gitlab_project_visibility_signal" in gk
        assert GL_PROJECT in gk

    def test_unknown_event_type_returns_none(self) -> None:
        ev = _mock_event("nonexistent.event", GL_PROJECT)
        assert _group_key(ev) is None

    def test_same_inputs_same_group_key(self) -> None:
        ev1 = _mock_event("gitlab.branch_protection.force_push_enabled", GL_BRANCH,
                           {"resource_id": GL_BRANCH})
        ev2 = _mock_event("gitlab.branch_protection.force_push_enabled", GL_BRANCH,
                           {"resource_id": GL_BRANCH})
        assert _group_key(ev1) == _group_key(ev2)


# ════════════════════════════════════════════════════════════════════════════
# PER-EVENT-TYPE SIGNAL GENERATION
# ════════════════════════════════════════════════════════════════════════════
class TestEventToSignalMapping:
    def _signal(self, event_type: str, rid: str, md: dict | None = None) -> dict:
        result = _build_single_group(event_type, rid, md)
        assert result is not None, f"Expected signal from {event_type}, got None"
        return result

    def test_project_visibility_creates_high_signal(self) -> None:
        s = self._signal("gitlab.project.visibility_changed", GL_PROJECT,
                         {"resource_id": GL_PROJECT, "visibility_category": "public"})
        assert s["signal_type"] == "gitlab_project_visibility_signal"
        assert s["severity"] == "high"
        assert s["provider"] == "gitlab"

    def test_group_visibility_creates_high_signal(self) -> None:
        s = self._signal("gitlab.group.visibility_changed", GL_GROUP,
                         {"resource_id": GL_GROUP, "visibility_category": "public"})
        assert s["signal_type"] == "gitlab_group_visibility_signal"
        assert s["severity"] == "high"

    def test_force_push_creates_high_signal(self) -> None:
        s = self._signal("gitlab.branch_protection.force_push_enabled", GL_BRANCH,
                         {"resource_id": GL_BRANCH, "allow_force_push": True})
        assert s["signal_type"] == "gitlab_force_push_enabled_signal"
        assert s["severity"] == "high"

    def test_webhook_secret_removed_creates_high_signal(self) -> None:
        s = self._signal("gitlab.webhook.secret_removed", GL_WEBHOOK,
                         {"resource_id": GL_WEBHOOK, "webhook_secret_present": False})
        assert s["signal_type"] == "gitlab_webhook_secret_removed_signal"
        assert s["severity"] == "high"

    def test_webhook_ssl_disabled_creates_high_signal(self) -> None:
        s = self._signal("gitlab.webhook.ssl_verification_disabled", GL_WEBHOOK,
                         {"resource_id": GL_WEBHOOK, "ssl_verification_enabled": False})
        assert s["signal_type"] == "gitlab_webhook_ssl_disabled_signal"
        assert s["severity"] == "high"

    def test_webhook_http_scheme_creates_high_signal(self) -> None:
        s = self._signal("gitlab.webhook.http_scheme_detected", GL_WEBHOOK,
                         {"resource_id": GL_WEBHOOK, "webhook_scheme_category": "http"})
        assert s["signal_type"] == "gitlab_webhook_http_scheme_signal"
        assert s["severity"] == "high"

    def test_ci_unprotected_unmasked_creates_high_signal(self) -> None:
        s = self._signal("gitlab.ci_variables.unprotected_unmasked_detected", GL_CI,
                         {"resource_id": GL_CI, "unprotected_unmasked_count": 3})
        assert s["signal_type"] == "gitlab_ci_unprotected_unmasked_variables_signal"
        assert s["severity"] == "high"

    def test_deploy_key_write_enabled_creates_high_signal(self) -> None:
        s = self._signal("gitlab.deploy_key.write_enabled_detected", GL_DEPLOY,
                         {"resource_id": GL_DEPLOY, "write_enabled_count": 1})
        assert s["signal_type"] == "gitlab_deploy_key_write_enabled_signal"
        assert s["severity"] == "high"

    def test_branch_protection_updated_creates_medium_signal(self) -> None:
        s = self._signal("gitlab.branch_protection.updated", GL_BRANCH,
                         {"resource_id": GL_BRANCH})
        assert s["signal_type"] == "gitlab_branch_protection_weakened"
        assert s["severity"] == "medium"

    def test_runner_shared_creates_medium_signal(self) -> None:
        s = self._signal("gitlab.runner.shared_enabled", GL_RUNNER,
                         {"resource_id": GL_RUNNER, "shared_runner_enabled": True})
        assert s["signal_type"] == "gitlab_shared_runner_enabled_signal"
        assert s["severity"] == "medium"

    def test_runner_posture_creates_medium_signal(self) -> None:
        s = self._signal("gitlab.runner.posture_changed", GL_RUNNER,
                         {"resource_id": GL_RUNNER, "untagged_runner_count": 2})
        assert s["signal_type"] == "gitlab_runner_posture_signal"
        assert s["severity"] == "medium"

    def test_mr_approval_reduced_creates_medium_signal(self) -> None:
        s = self._signal("gitlab.merge_request_approval.requirement_reduced", GL_MR,
                         {"resource_id": GL_MR, "approvals_required": 0})
        assert s["signal_type"] == "gitlab_merge_request_approval_weakened"
        assert s["severity"] == "medium"

    def test_mr_approval_updated_creates_medium_signal(self) -> None:
        s = self._signal("gitlab.merge_request_approval.updated", GL_MR,
                         {"resource_id": GL_MR, "reset_approvals_on_push": False})
        assert s["signal_type"] == "gitlab_merge_request_approval_weakened"
        assert s["severity"] == "medium"

    def test_project_public_feature_creates_medium_signal(self) -> None:
        s = self._signal("gitlab.project_feature.public_feature_enabled", GL_PROJECT,
                         {"resource_id": GL_PROJECT, "wiki_enabled": True})
        assert s["signal_type"] == "gitlab_project_public_feature_signal"
        assert s["severity"] == "medium"

    def test_config_event_creates_low_signal(self) -> None:
        s = self._signal("gitlab.config.event", GL_PROJECT,
                         {"resource_id": GL_PROJECT})
        assert s["signal_type"] == "gitlab_configuration_activity_signal"
        assert s["severity"] == "low"

    def test_unknown_event_type_ignored_safely(self) -> None:
        result = _build_single_group("gitlab.unknown.never_heard_of", GL_PROJECT,
                                     {"resource_id": GL_PROJECT})
        assert result is None

    def test_missing_metadata_no_misleading_signal(self) -> None:
        # event with no metadata — should still produce a safe signal (just without extra fields)
        s = _build_single_group("gitlab.project.visibility_changed", GL_PROJECT)
        assert s is not None
        assert s["signal_type"] == "gitlab_project_visibility_signal"


# ════════════════════════════════════════════════════════════════════════════
# METADATA SAFETY
# ════════════════════════════════════════════════════════════════════════════
class TestMetadataSafety:
    def _all_signals(self) -> list[dict]:
        cases = [
            ("gitlab.project.visibility_changed", GL_PROJECT,
             {"resource_id": GL_PROJECT, "visibility_category": "public",
              "archived": False, "shared_runners_enabled": True,
              "protected_branch_count": 2, "webhook_count": 1,
              "ci_variable_count": 3, "deploy_key_count": 1, "approval_rule_count": 1}),
            ("gitlab.group.visibility_changed", GL_GROUP,
             {"resource_id": GL_GROUP, "visibility_category": "public",
              "project_count": 5, "subgroup_count": 2, "member_count_category": "small",
              "two_factor_requirement_enabled": False, "membership_lock": False}),
            ("gitlab.branch_protection.force_push_enabled", GL_BRANCH,
             {"resource_id": GL_BRANCH, "pattern_category": "default",
              "allow_force_push": True, "code_owner_approval_required": False,
              "push_access_level_category": "developer", "merge_access_level_category": "developer"}),
            ("gitlab.webhook.secret_removed", GL_WEBHOOK,
             {"resource_id": GL_WEBHOOK, "enabled": True,
              "webhook_secret_present": False, "ssl_verification_enabled": False,
              "webhook_scheme_category": "https", "event_count": 4}),
            ("gitlab.ci_variables.unprotected_unmasked_detected", GL_CI,
             {"resource_id": GL_CI, "variable_count": 4,
              "protected_variable_count": 0, "masked_variable_count": 0,
              "unprotected_unmasked_count": 2}),
            ("gitlab.deploy_key.write_enabled_detected", GL_DEPLOY,
             {"resource_id": GL_DEPLOY, "deploy_key_count": 2,
              "write_enabled_count": 1, "read_only_count": 1, "enabled_count": 2}),
            ("gitlab.runner.shared_enabled", GL_RUNNER,
             {"resource_id": GL_RUNNER, "runner_count": 3, "shared_runner_enabled": True,
              "locked_runner_count": 0, "untagged_runner_count": 2}),
            ("gitlab.merge_request_approval.requirement_reduced", GL_MR,
             {"resource_id": GL_MR, "approval_rule_count": 1,
              "approvals_required": 0, "code_owner_approval_required": False,
              "reset_approvals_on_push": False, "override_approvers_disabled": False}),
        ]
        out = []
        for et, rid, md in cases:
            s = _build_single_group(et, rid, md)
            if s:
                out.append(s)
        return out

    def test_has_signals(self) -> None:
        assert self._all_signals()

    def test_all_provider_gitlab(self) -> None:
        for s in self._all_signals():
            assert s["provider"] == "gitlab"
            assert s["evidence_level"] == "activity"
            assert s["confidence"] == "medium"

    def test_metadata_flat_and_scalar(self) -> None:
        for s in self._all_signals():
            for k, v in s["metadata"].items():
                assert isinstance(v, (str, int, float, bool)), (
                    f"metadata key {k!r} has non-scalar value {v!r}"
                )

    def test_metadata_keys_allowlisted(self) -> None:
        for s in self._all_signals():
            for k in s["metadata"]:
                assert k in ALLOWED_METADATA_KEYS, (
                    f"signal metadata key {k!r} not in ALLOWED_METADATA_KEYS"
                )

    def test_metadata_keys_no_forbidden_substring(self) -> None:
        for s in self._all_signals():
            for k in s["metadata"]:
                low = k.lower()
                for bad in _FORBIDDEN_METADATA_KEY_SUBSTRINGS:
                    assert bad not in low, (
                        f"metadata key {k!r} contains forbidden substring {bad!r}"
                    )

    def test_signal_summary_no_forbidden_wording(self) -> None:
        for s in self._all_signals():
            summary = (s.get("title", "") + " " + s.get("summary", "")).lower()
            for bad in _FORBIDDEN_WORDING:
                assert bad not in summary, (
                    f"signal copy contains forbidden wording {bad!r}"
                )

    def test_no_actor_identity_stored(self) -> None:
        for s in self._all_signals():
            md = s.get("metadata", {})
            assert "user_email" not in md
            assert "username" not in md
            assert "actor_email" not in md


# ════════════════════════════════════════════════════════════════════════════
# IDEMPOTENCY
# ════════════════════════════════════════════════════════════════════════════
class TestIdempotency:
    def test_same_event_same_group_key(self) -> None:
        ev1 = _mock_event("gitlab.project.visibility_changed", GL_PROJECT,
                           {"resource_id": GL_PROJECT})
        ev2 = _mock_event("gitlab.project.visibility_changed", GL_PROJECT,
                           {"resource_id": GL_PROJECT})
        assert _group_key(ev1) == _group_key(ev2)

    def test_different_resource_different_group_key(self) -> None:
        ev1 = _mock_event("gitlab.project.visibility_changed", "PROJECT_A",
                           {"resource_id": "PROJECT_A"})
        ev2 = _mock_event("gitlab.project.visibility_changed", "PROJECT_B",
                           {"resource_id": "PROJECT_B"})
        assert _group_key(ev1) != _group_key(ev2)


# ════════════════════════════════════════════════════════════════════════════
# CAPABILITY MATRIX / EXPANSION FRAMEWORK
# ════════════════════════════════════════════════════════════════════════════
class TestCapabilityMatrix:
    def test_activity_signals_true(self) -> None:
        cap = get_provider_capability("gitlab")
        assert cap.security.activity_signals is True

    def test_later_stages_still_false(self) -> None:
        cap = get_provider_capability("gitlab")
        # risk_activity_correlations landed in M87F.
        assert cap.security.risk_activity_correlations is True
        # demo_seed_clear landed in M87G.
        assert cap.security.demo_seed_clear is True
        # case_report landed in M87G.
        assert cap.security.case_report is True
        # evidence_timeline landed in M87G.
        assert cap.security.evidence_timeline is True
        # evidence_graph landed in M87G.
        assert cap.security.evidence_graph is True

    def test_notes_mention_m87e(self) -> None:
        cap = get_provider_capability("gitlab")
        assert "M87E" in cap.notes

    def test_planned_next_stage_m87f(self) -> None:
        cap = get_provider_capability("gitlab")
        # M87F landed; notes now advance to M87G.
        assert "M87F" in cap.notes or "M87G" in cap.notes


class TestExpansionFramework:
    def test_planned_next_stage_points_to_m87f(self) -> None:
        planned = get_framework().get("summary", {}).get("planned_next_stage", "")
        # M87F landed; planned now points to M87G.
        assert ("M87F" in planned or "Correlations" in planned
                or "M87G" in planned or "Demo" in planned or "M87H" in planned)

    def test_terraform_cloud_remains_in_queue(self) -> None:
        recs = get_framework().get("recommended_next_providers", [])
        provider_keys = [r.get("provider") for r in recs]
        assert "terraform_cloud" in provider_keys or "terraform" in str(provider_keys)


# ════════════════════════════════════════════════════════════════════════════
# ROUTER / FRONTEND WIRING
# ════════════════════════════════════════════════════════════════════════════
class TestRouterWiring:
    def test_route_registered(self) -> None:
        from app.main import app
        paths = {r.path for r in app.routes}  # type: ignore[attr-defined]
        assert any(p.endswith("/gitlab-activity/generate-signals") for p in paths)

    def test_route_is_admin_gated(self) -> None:
        src = SECURITY_ROUTER.read_text(encoding="utf-8")
        assert "gitlab-activity/generate-signals" in src
        idx = src.index("gitlab-activity/generate-signals")
        following = src[idx: idx + 2500]
        assert "require_workspace_admin" in following


class TestFrontendWiring:
    def test_signals_page_includes_gitlab(self) -> None:
        src = FE_SIGNALS_PAGE.read_text(encoding="utf-8")
        assert "gitlab" in src
        assert "GITLAB_SIGNAL_TYPES" in src
        assert "generateGitlabActivitySignals" in src

    def test_api_has_generate_function(self) -> None:
        src = FE_API_TS.read_text(encoding="utf-8")
        assert "generateGitlabActivitySignals" in src
        assert "/security/gitlab-activity/generate-signals" in src

    def test_types_has_response(self) -> None:
        src = FE_TYPES_TS.read_text(encoding="utf-8")
        assert "GitLabActivitySignalGenerateResponse" in src

    def test_frontend_copy_no_forbidden_wording(self) -> None:
        src = FE_SIGNALS_PAGE.read_text(encoding="utf-8").lower()
        for line in src.splitlines():
            if "gitlab" not in line:
                continue
            for bad in _FORBIDDEN_WORDING:
                assert bad not in line, (
                    f"forbidden wording {bad!r} in GitLab signals page copy"
                )
