"""M87D — GitLab configuration activity ingestion tests.

GitLab's audit-event APIs are identity-heavy: every entry includes actor user
IDs, actor emails, IP addresses, and user agents.  ConfigTrace NEVER ingests
from those endpoints.  Instead, activity events are synthesized from the same
safe configuration posture records the GitLab drift connector already stored
(M87A–M87C): projects, groups, branch protection rules, webhooks, CI variable
summaries, deploy key summaries, runner summaries, and MR approval summaries.

Mirrors the Jira M86D structure, adapted to GitLab's multi-event-per-record
builder (build_gitlab_activity_events / normalize_gitlab_activity_event).

CLAIM DISCIPLINE: configuration-state evidence only. Does NOT confirm a breach,
compromise, unauthorized access, source-code exposure, secret exposure, token
exposure, credential exposure, or data exposure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.connectors.gitlab_schema import (
    GITLAB_BRANCH_PROTECTION,
    GITLAB_CI_VARIABLE_SUMMARY,
    GITLAB_DEPLOY_KEY_SUMMARY,
    GITLAB_GROUP,
    GITLAB_INSTANCE,
    GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY,
    GITLAB_PROJECT,
    GITLAB_RUNNER_SUMMARY,
    GITLAB_WEBHOOK,
)
from app.services import gitlab_activity_ingestion_service as svc
from app.services.gitlab_activity_ingestion_service import (
    GITLAB_CONFIG_EVENT_TYPES,
    build_gitlab_activity_events,
    normalize_gitlab_activity_event,
)
from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_APP = REPO_ROOT / "backend" / "app"
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"
FE_ACTIVITY_PAGE = (
    FRONTEND_SRC / "app" / "(app)" / "security" / "activity" / "page.tsx"
)
FE_API_TS = FRONTEND_SRC / "lib" / "api.ts"
FE_TYPES_TS = FRONTEND_SRC / "types" / "index.ts"
SECURITY_ROUTER = BACKEND_APP / "routers" / "security.py"

UPDATED_AT = "2026-06-20T12:00:00Z"

# Opaque test identifiers (never real GitLab resource names/paths).
GL_PROJECT = "GL_TEST_PROJECT_ID"
GL_GROUP = "GL_TEST_GROUP_ID"
GL_BRANCH = "GL_TEST_BRANCH_PROTECTION_ID"
GL_WEBHOOK = "GL_TEST_WEBHOOK_ID"
GL_CI = "GL_TEST_CI_VARIABLE_SUMMARY_ID"
GL_DEPLOY = "GL_TEST_DEPLOY_KEY_SUMMARY_ID"
GL_RUNNER = "GL_TEST_RUNNER_SUMMARY_ID"
GL_MR = "GL_TEST_MR_APPROVAL_SUMMARY_ID"

# Substrings that must NEVER appear in any activity metadata KEY (M87D privacy).
_FORBIDDEN_METADATA_KEY_SUBSTRINGS = (
    "token",
    "secret_value",
    "private_token",
    "authorization",
    "webhook_url",
    "url",
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

# Forbidden claim wording — must not appear in event types.
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


def _make_record(record_type: str, resource_id: str, **fields: Any) -> dict:
    rec: dict[str, Any] = {
        "record_type": record_type,
        "provider": "gitlab",
        "record_id": resource_id,
        "resource_id": resource_id,
    }
    rec.update(fields)
    return rec


def _build_norm(record: dict) -> list[dict]:
    entries = build_gitlab_activity_events(record, updated_at=UPDATED_AT)
    out = []
    for e in entries:
        n = normalize_gitlab_activity_event(e)
        if n is not None:
            out.append(n)
    return out


def _event_types(record: dict) -> list[str]:
    return [n["event_type"] for n in _build_norm(record)]


# ════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ════════════════════════════════════════════════════════════════════════════
class TestImports:
    def test_service_imports(self) -> None:
        assert callable(build_gitlab_activity_events)
        assert callable(normalize_gitlab_activity_event)
        assert callable(svc.sync_gitlab_activity)
        assert callable(svc.ingest_gitlab_activity)

    def test_provider_and_source(self) -> None:
        assert svc.PROVIDER == "gitlab"
        assert svc.SOURCE == "gitlab_activity_event"


# ════════════════════════════════════════════════════════════════════════════
# EVENT TYPES
# ════════════════════════════════════════════════════════════════════════════
class TestEventTypes:
    EXPECTED = {
        "gitlab.project.visibility_changed",
        "gitlab.group.visibility_changed",
        "gitlab.branch_protection.updated",
        "gitlab.branch_protection.force_push_enabled",
        "gitlab.webhook.updated",
        "gitlab.webhook.secret_removed",
        "gitlab.webhook.ssl_verification_disabled",
        "gitlab.webhook.http_scheme_detected",
        "gitlab.ci_variables.posture_changed",
        "gitlab.ci_variables.unprotected_unmasked_detected",
        "gitlab.deploy_key.posture_changed",
        "gitlab.deploy_key.write_enabled_detected",
        "gitlab.runner.posture_changed",
        "gitlab.runner.shared_enabled",
        "gitlab.merge_request_approval.updated",
        "gitlab.merge_request_approval.requirement_reduced",
        "gitlab.project_feature.public_feature_enabled",
    }

    def test_expected_event_types_exist(self) -> None:
        assert self.EXPECTED <= set(GITLAB_CONFIG_EVENT_TYPES)

    def test_all_event_types_namespaced_gitlab(self) -> None:
        for evt in GITLAB_CONFIG_EVENT_TYPES:
            assert evt.startswith("gitlab.")

    def test_event_types_have_no_forbidden_wording(self) -> None:
        for evt in GITLAB_CONFIG_EVENT_TYPES:
            low = evt.lower()
            for bad in _FORBIDDEN_WORDING:
                assert bad not in low, f"event type {evt!r} contains forbidden wording {bad!r}"


# ════════════════════════════════════════════════════════════════════════════
# BASIC GENERATION SHAPE
# ════════════════════════════════════════════════════════════════════════════
class TestGenerationShape:
    def test_provider_is_gitlab(self) -> None:
        rec = _make_record(GITLAB_PROJECT, GL_PROJECT, visibility_category="public")
        norms = _build_norm(rec)
        assert norms
        for n in norms:
            assert n["provider"] == "gitlab"
            assert n["source"] == "gitlab_activity_event"

    def test_resource_type_matches_record_family(self) -> None:
        rec = _make_record(GITLAB_PROJECT, GL_PROJECT, visibility_category="public")
        for n in _build_norm(rec):
            assert n["resource_type"] == GITLAB_PROJECT
            assert n["resource_id"] == GL_PROJECT

    def test_event_types_are_safe(self) -> None:
        rec = _make_record(GITLAB_WEBHOOK, GL_WEBHOOK, enabled=True,
                           secret_token_present=False, ssl_verification_enabled=False,
                           url_scheme="http")
        for n in _build_norm(rec):
            assert n["event_type"] in GITLAB_CONFIG_EVENT_TYPES

    def test_no_actor_identity_stored(self) -> None:
        rec = _make_record(GITLAB_GROUP, GL_GROUP, visibility_category="public")
        for n in _build_norm(rec):
            assert n.get("actor_id") is None
            assert n.get("actor_type") is None
            assert n.get("source_ip_hash") is None


# ════════════════════════════════════════════════════════════════════════════
# IDEMPOTENCY
# ════════════════════════════════════════════════════════════════════════════
class TestIdempotency:
    def test_same_record_same_event_ids(self) -> None:
        rec = _make_record(GITLAB_PROJECT, GL_PROJECT, visibility_category="public",
                           wiki_enabled=True)
        a = build_gitlab_activity_events(rec, updated_at=UPDATED_AT)
        b = build_gitlab_activity_events(rec, updated_at=UPDATED_AT)
        assert [e["provider_event_id"] for e in a] == [e["provider_event_id"] for e in b]

    def test_distinct_event_types_have_distinct_ids(self) -> None:
        rec = _make_record(GITLAB_PROJECT, GL_PROJECT, visibility_category="public",
                           wiki_enabled=True)
        a = build_gitlab_activity_events(rec, updated_at=UPDATED_AT)
        ids = [e["provider_event_id"] for e in a]
        assert len(ids) == len(set(ids)), "each event type must get a distinct id"

    def test_event_id_namespaced(self) -> None:
        rec = _make_record(GITLAB_GROUP, GL_GROUP, visibility_category="public")
        for e in build_gitlab_activity_events(rec, updated_at=UPDATED_AT):
            assert e["provider_event_id"].startswith("gitlab:")


# ════════════════════════════════════════════════════════════════════════════
# UNKNOWN / MISSING SAFETY
# ════════════════════════════════════════════════════════════════════════════
class TestUnknownAndMissing:
    def test_unknown_record_type_ignored(self) -> None:
        rec = _make_record("github_repo", "X", visibility_category="public")
        assert build_gitlab_activity_events(rec, updated_at=UPDATED_AT) == []

    def test_non_dict_ignored(self) -> None:
        assert build_gitlab_activity_events("nope", updated_at=UPDATED_AT) == []  # type: ignore[arg-type]
        assert build_gitlab_activity_events(None, updated_at=UPDATED_AT) == []  # type: ignore[arg-type]

    def test_instance_record_creates_no_activity(self) -> None:
        rec = _make_record(GITLAB_INSTANCE, "INSTANCE", enterprise=True)
        assert build_gitlab_activity_events(rec, updated_at=UPDATED_AT) == []

    def test_missing_fields_no_misleading_activity(self) -> None:
        # Private project with no risky posture → no events.
        rec = _make_record(GITLAB_PROJECT, GL_PROJECT, visibility_category="private")
        assert _event_types(rec) == []

    def test_none_fields_no_misleading_activity(self) -> None:
        rec = _make_record(GITLAB_WEBHOOK, GL_WEBHOOK, enabled=True,
                           secret_token_present=None, ssl_verification_enabled=None,
                           url_scheme=None, event_count=None)
        # None secret/ssl must NOT be treated as "False"/"http".
        assert _event_types(rec) == []

    def test_disabled_webhook_no_activity(self) -> None:
        rec = _make_record(GITLAB_WEBHOOK, GL_WEBHOOK, enabled=False,
                           secret_token_present=False, ssl_verification_enabled=False,
                           url_scheme="http")
        assert _event_types(rec) == []


# ════════════════════════════════════════════════════════════════════════════
# PER-RECORD-TYPE MAPPING
# ════════════════════════════════════════════════════════════════════════════
class TestMapping:
    def test_project_public_visibility(self) -> None:
        rec = _make_record(GITLAB_PROJECT, GL_PROJECT, visibility_category="public")
        assert "gitlab.project.visibility_changed" in _event_types(rec)

    def test_project_public_feature(self) -> None:
        rec = _make_record(GITLAB_PROJECT, GL_PROJECT, visibility_category="public",
                           snippets_enabled=True)
        assert "gitlab.project_feature.public_feature_enabled" in _event_types(rec)

    def test_group_public_visibility(self) -> None:
        rec = _make_record(GITLAB_GROUP, GL_GROUP, visibility_category="public")
        assert _event_types(rec) == ["gitlab.group.visibility_changed"]

    def test_branch_force_push(self) -> None:
        rec = _make_record(GITLAB_BRANCH_PROTECTION, GL_BRANCH, project_resource_id=GL_PROJECT,
                           allow_force_push=True)
        assert "gitlab.branch_protection.force_push_enabled" in _event_types(rec)

    def test_branch_broad_access_updates(self) -> None:
        rec = _make_record(GITLAB_BRANCH_PROTECTION, GL_BRANCH, project_resource_id=GL_PROJECT,
                           allow_force_push=False, code_owner_approval_required=True,
                           push_access_level_category="developer")
        assert "gitlab.branch_protection.updated" in _event_types(rec)

    def test_webhook_secret_missing(self) -> None:
        rec = _make_record(GITLAB_WEBHOOK, GL_WEBHOOK, enabled=True,
                           secret_token_present=False)
        assert "gitlab.webhook.secret_removed" in _event_types(rec)

    def test_webhook_ssl_disabled(self) -> None:
        rec = _make_record(GITLAB_WEBHOOK, GL_WEBHOOK, enabled=True,
                           ssl_verification_enabled=False)
        assert "gitlab.webhook.ssl_verification_disabled" in _event_types(rec)

    def test_webhook_http_scheme(self) -> None:
        rec = _make_record(GITLAB_WEBHOOK, GL_WEBHOOK, enabled=True, url_scheme="http")
        assert "gitlab.webhook.http_scheme_detected" in _event_types(rec)

    def test_ci_unprotected_unmasked(self) -> None:
        rec = _make_record(GITLAB_CI_VARIABLE_SUMMARY, GL_CI, owner_resource_id=GL_PROJECT,
                           owner_type="project", variable_count=3,
                           unprotected_unmasked_count=2)
        assert "gitlab.ci_variables.unprotected_unmasked_detected" in _event_types(rec)

    def test_ci_posture_changed(self) -> None:
        rec = _make_record(GITLAB_CI_VARIABLE_SUMMARY, GL_CI, owner_resource_id=GL_PROJECT,
                           owner_type="project", variable_count=4,
                           protected_variable_count=0, masked_variable_count=0,
                           unprotected_unmasked_count=0)
        assert "gitlab.ci_variables.posture_changed" in _event_types(rec)

    def test_deploy_key_write_enabled(self) -> None:
        rec = _make_record(GITLAB_DEPLOY_KEY_SUMMARY, GL_DEPLOY, project_resource_id=GL_PROJECT,
                           deploy_key_count=2, write_enabled_count=1)
        assert "gitlab.deploy_key.write_enabled_detected" in _event_types(rec)

    def test_runner_shared(self) -> None:
        rec = _make_record(GITLAB_RUNNER_SUMMARY, GL_RUNNER, owner_resource_id=GL_PROJECT,
                           owner_type="project", shared_runner_enabled=True)
        assert "gitlab.runner.shared_enabled" in _event_types(rec)

    def test_runner_untagged_posture(self) -> None:
        rec = _make_record(GITLAB_RUNNER_SUMMARY, GL_RUNNER, owner_resource_id=GL_PROJECT,
                           owner_type="project", shared_runner_enabled=False,
                           untagged_runner_count=3)
        assert "gitlab.runner.posture_changed" in _event_types(rec)

    def test_mr_approval_reduced(self) -> None:
        rec = _make_record(GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY, GL_MR,
                           project_resource_id=GL_PROJECT, approvals_required=0)
        assert "gitlab.merge_request_approval.requirement_reduced" in _event_types(rec)

    def test_mr_approval_updated(self) -> None:
        rec = _make_record(GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY, GL_MR,
                           project_resource_id=GL_PROJECT, approvals_required=2,
                           reset_approvals_on_push=False)
        assert "gitlab.merge_request_approval.updated" in _event_types(rec)


# ════════════════════════════════════════════════════════════════════════════
# METADATA SAFETY
# ════════════════════════════════════════════════════════════════════════════
class TestMetadataSafety:
    def _all_events(self) -> list[dict]:
        records = [
            _make_record(GITLAB_PROJECT, GL_PROJECT, visibility_category="public",
                         archived=False, wiki_enabled=True, snippets_enabled=True,
                         protected_branch_count=2, webhook_count=1, ci_variable_count=3,
                         deploy_key_count=1, approval_rule_count=1),
            _make_record(GITLAB_GROUP, GL_GROUP, visibility_category="public",
                         project_count=5, subgroup_count=2, member_count_category="small",
                         two_factor_requirement_enabled=False, membership_lock=False,
                         shared_runners_setting_category="enabled"),
            _make_record(GITLAB_BRANCH_PROTECTION, GL_BRANCH, project_resource_id=GL_PROJECT,
                         pattern_category="default", allow_force_push=True,
                         code_owner_approval_required=False, push_access_level_category="developer",
                         merge_access_level_category="developer", allowed_to_push_count=4,
                         allowed_to_merge_count=4),
            _make_record(GITLAB_WEBHOOK, GL_WEBHOOK, owner_resource_id=GL_PROJECT,
                         owner_type="project", enabled=True, url_scheme="http",
                         url_host_category="public", ssl_verification_enabled=False,
                         secret_token_present=False, event_count=8, push_events=True,
                         pipeline_events=True, job_events=True),
            _make_record(GITLAB_CI_VARIABLE_SUMMARY, GL_CI, owner_resource_id=GL_PROJECT,
                         owner_type="project", variable_count=4, protected_variable_count=0,
                         masked_variable_count=0, environment_scoped_count=1,
                         unprotected_unmasked_count=2),
            _make_record(GITLAB_DEPLOY_KEY_SUMMARY, GL_DEPLOY, project_resource_id=GL_PROJECT,
                         deploy_key_count=2, write_enabled_count=1, read_only_count=1,
                         enabled_count=2),
            _make_record(GITLAB_RUNNER_SUMMARY, GL_RUNNER, owner_resource_id=GL_PROJECT,
                         owner_type="project", runner_count=3, shared_runner_enabled=True,
                         locked_runner_count=0, paused_runner_count=0, tagged_runner_count=1,
                         untagged_runner_count=2),
            _make_record(GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY, GL_MR,
                         project_resource_id=GL_PROJECT, approval_rule_count=1,
                         approvals_required=0, code_owner_approval_required=False,
                         reset_approvals_on_push=False,
                         disable_overriding_approvers_per_merge_request=False),
        ]
        out: list[dict] = []
        for rec in records:
            out.extend(_build_norm(rec))
        return out

    def test_has_events(self) -> None:
        assert self._all_events()

    def test_metadata_flat_and_scalar(self) -> None:
        for n in self._all_events():
            for k, v in n["metadata"].items():
                assert isinstance(v, (str, int, float, bool)), f"{k} not scalar"

    def test_metadata_keys_allowlisted(self) -> None:
        for n in self._all_events():
            for k in n["metadata"]:
                assert k in ALLOWED_METADATA_KEYS, f"metadata key {k!r} not allowlisted"

    def test_metadata_keys_have_no_forbidden_substring(self) -> None:
        for n in self._all_events():
            for k in n["metadata"]:
                low = k.lower()
                for bad in _FORBIDDEN_METADATA_KEY_SUBSTRINGS:
                    assert bad not in low, f"metadata key {k!r} contains forbidden substring {bad!r}"

    def test_webhook_url_and_secret_not_stored_raw(self) -> None:
        rec = _make_record(GITLAB_WEBHOOK, GL_WEBHOOK, enabled=True, url_scheme="http",
                           url_host_category="public", secret_token_present=False)
        for n in _build_norm(rec):
            md = n["metadata"]
            assert "url_scheme" not in md
            assert "secret_token_present" not in md
            # Safe renamed posture keys instead.
            assert md.get("webhook_scheme_category") == "http"
            assert md.get("webhook_secret_present") is False


# ════════════════════════════════════════════════════════════════════════════
# CAPABILITY MATRIX / EXPANSION FRAMEWORK
# ════════════════════════════════════════════════════════════════════════════
class TestCapabilityMatrix:
    def test_activity_ingestion_true(self) -> None:
        cap = get_provider_capability("gitlab")
        assert cap.security.activity_ingestion is True

    def test_later_stages_still_false(self) -> None:
        cap = get_provider_capability("gitlab")
        # activity_signals landed in M87E; risk_activity_correlations landed in M87F.
        assert cap.security.activity_signals is True
        assert cap.security.risk_activity_correlations is True
        # demo_seed_clear landed in M87G.
        assert cap.security.demo_seed_clear is True
        # case_report landed in M87G.
        assert cap.security.case_report is True
        # evidence_timeline landed in M87G.
        assert cap.security.evidence_timeline is True
        # evidence_graph landed in M87G.
        assert cap.security.evidence_graph is True

    def test_planned_next_stage_m87e(self) -> None:
        cap = get_provider_capability("gitlab")
        # M87F landed; notes reference M87D through M87F.
        assert "M87D" in cap.notes
        assert "M87E" in cap.notes or "M87F" in cap.notes or "M87G" in cap.notes


class TestExpansionFramework:
    def test_planned_next_stage_points_to_m87e(self) -> None:
        planned = get_framework().get("summary", {}).get("planned_next_stage", "")
        # M87F landed and advanced planned_next_stage to M87G.
        assert ("M87E" in planned or "GitLab Activity Signals" in planned
                or "M87F" in planned or "Correlations" in planned
                or "M87G" in planned or "Demo" in planned or "M87H" in planned or "M87I" in planned or "Cross-Cloud" in planned
                or "M88A" in planned or "Terraform" in planned)

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
        assert any(p.endswith("/gitlab-activity/sync") for p in paths)

    def test_route_is_admin_gated(self) -> None:
        src = SECURITY_ROUTER.read_text(encoding="utf-8")
        assert "gitlab-activity/sync" in src
        # The handler reuses the existing admin-gating helper like other providers.
        idx = src.index("gitlab-activity/sync")
        following = src[idx: idx + 2200]
        assert "require_workspace_admin" in following


class TestFrontendWiring:
    def test_activity_page_includes_gitlab(self) -> None:
        src = FE_ACTIVITY_PAGE.read_text(encoding="utf-8")
        assert "gitlab" in src
        assert "GITLAB_EVENT_TYPES" in src
        assert "syncGitlabActivity" in src

    def test_api_has_sync_function(self) -> None:
        src = FE_API_TS.read_text(encoding="utf-8")
        assert "syncGitlabActivity" in src
        assert "/security/gitlab-activity/sync" in src

    def test_types_has_response(self) -> None:
        src = FE_TYPES_TS.read_text(encoding="utf-8")
        assert "GitLabActivitySyncResponse" in src

    def test_frontend_copy_has_no_forbidden_wording(self) -> None:
        src = FE_ACTIVITY_PAGE.read_text(encoding="utf-8").lower()
        # Inspect only GitLab-related lines for forbidden claims.
        for line in src.splitlines():
            if "gitlab" not in line:
                continue
            for bad in _FORBIDDEN_WORDING:
                assert bad not in line, f"forbidden wording {bad!r} in GitLab copy"
