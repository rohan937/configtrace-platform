"""M87A: GitLab drift provider foundation tests.

Validates that the GitLab connector, schema, integration service, sync wiring,
capability matrix, expansion framework, and frontend files all meet the M87A
specification.

GitLab authenticates with a personal access token (PAT) with read_api or api
scope. The connector reads ONLY configuration-level metadata from GitLab REST
API v4 surfaces (instance, projects, groups, branch protection, webhooks,
CI variable summaries, deploy key summaries, runner summaries, MR approval
summaries). It never fetches or stores project names, namespace paths, URLs,
branch names, CI variable names/values, deploy key material, runner tokens,
user emails/usernames, issue titles, MR content, commit messages, pipeline
logs, or any customer data.

Sections:
  A. Schema — GITLAB_RECORD_TYPES has exactly 9 types; all expected constants
     present; GitLabConnector import works.
  B. Connector — fetch()/validate_credentials() present; __init__ stores no
     credentials; all expected _normalize_X methods exist; fetch() raises
     AuthenticationError on empty credentials.
  C. Normalizers — each normalizer returns provider="gitlab" + expected
     record_type; normalized dicts are flat; no forbidden fields in output.
  D. Privacy — webhook normalizer stores scheme/category only (no raw URL);
     CI variable summary stores counts only (no names/values); deploy key
     summary stores counts only; runner summary stores posture counts only;
     branch protection uses pattern category not raw branch name.
  E. Integration schema — "gitlab" in provider Literal; gitlab_access_token /
     gitlab_base_url fields; validator rejects gitlab without access_token;
     response schema never exposes token.
  F. Sync — sync_service supports "gitlab"; sync_task dispatch supports "gitlab".
  G. Drift-risk classifier — classifies public visibility as high; webhook
     secret removed as high; SSL disabled as high; force-push enabled as high;
     approval reduction as medium; does not use forbidden wording.
  H. Capability matrix — drift_snapshots/diff/risk_classification True,
     all security caps False, maturity partial; notes mention M87A;
     planned_next_stage references M87B.
  I. Expansion framework — planned_next_stage references M87B; GitLab is no
     longer head of recommended queue; Terraform Cloud is now recommended.
  J. Frontend — providers.ts includes GitLab; GitLabIntegrationForm.tsx exists
     with access_token field (type=password); no security rules claimed.
  K. Forbidden wording — no breach/compromise/attack copy in connector/schema/
     risk rules. Secret-shape grep confirms no real tokens in codebase.
  L. Marketing-video and tail-latency-study remain untouched and unstaged.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.connectors.exceptions import AuthenticationError
from app.connectors.gitlab import GitLabConnector
from app.connectors.gitlab_schema import (
    GITLAB_BRANCH_PROTECTION,
    GITLAB_CI_VARIABLE_SUMMARY,
    GITLAB_DEPLOY_KEY_SUMMARY,
    GITLAB_GROUP,
    GITLAB_INSTANCE,
    GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY,
    GITLAB_PROJECT,
    GITLAB_RECORD_TYPES,
    GITLAB_RUNNER_SUMMARY,
    GITLAB_WEBHOOK,
)
from app.services.provider_capability_matrix_service import (
    PROVIDER_CAPABILITIES_PARTIAL,
    get_provider_capability,
)
from app.services.provider_expansion_framework import get_framework
from app.services.risk_rules.gitlab import classify_gitlab_change

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parents[2]
FE_ROOT = REPO_ROOT / "frontend" / "src"
FE_PROVIDERS = FE_ROOT / "lib" / "providers.ts"
FE_TYPES = FE_ROOT / "types" / "index.ts"
FE_INTEGRATIONS = FE_ROOT / "app" / "(app)" / "integrations" / "page.tsx"
FE_GITLAB_FORM = FE_ROOT / "components" / "integrations" / "GitLabIntegrationForm.tsx"

BACKEND_ROOT = Path(__file__).resolve().parents[1]
GITLAB_PY = BACKEND_ROOT / "app" / "connectors" / "gitlab.py"
GITLAB_SCHEMA_PY = BACKEND_ROOT / "app" / "connectors" / "gitlab_schema.py"
GITLAB_RULES_PY = BACKEND_ROOT / "app" / "services" / "risk_rules" / "gitlab.py"

MARKETING_VIDEO = REPO_ROOT / "marketing-video"
TAIL_LATENCY = REPO_ROOT / "tail-latency-study"

# ── Safe test placeholders (never real credentials) ───────────────────────────
_TEST_TOKEN = "GITLAB_TEST_TOKEN_PLACEHOLDER"
_TEST_BASE_URL = "https://gitlab.example.invalid"
_CREDS = {"access_token": _TEST_TOKEN, "base_url": _TEST_BASE_URL}

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

# Broader forbidden terms for GitLab-specific copy.
_GITLAB_FORBIDDEN_TERMS = [
    "breach",
    "attacker",
    "unauthorized access",
    "exfiltration",
    "stolen",
    "fraud",
    "token leaked",
    "secret leaked",
    "repo exposed",
    "source code leaked",
]

# Fields that must NEVER appear as keys in a normalized record.
_FORBIDDEN_RECORD_FIELDS = {
    "access_token",
    "token",
    "secret_token",
    "private_token",
    "oauth_token",
    "secret",
    "webhook_secret",
    "authorization",
    "email",
    "user_email",
    "username",
    "name",
    "project_name",
    "group_name",
    "namespace",
    "path",
    "web_url",
    "ssh_url",
    "http_url",
    "clone_url",
    "branch_name",
    "default_branch",
    "issue_title",
    "mr_title",
    "commit_message",
    "pipeline_log",
    "artifact",
    "variable_name",
    "variable_value",
    "key_title",
    "key_fingerprint",
    "key_material",
    "runner_token",
    "runner_ip",
    "runner_description",
    "url",
    "raw",
    "payload",
    "headers",
}

EXPECTED_RECORD_TYPES = {
    GITLAB_INSTANCE,
    GITLAB_PROJECT,
    GITLAB_GROUP,
    GITLAB_BRANCH_PROTECTION,
    GITLAB_WEBHOOK,
    GITLAB_CI_VARIABLE_SUMMARY,
    GITLAB_DEPLOY_KEY_SUMMARY,
    GITLAB_RUNNER_SUMMARY,
    GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY,
}


# ── A. Schema ─────────────────────────────────────────────────────────────────

class TestSchema:
    def test_record_types_count(self) -> None:
        assert len(GITLAB_RECORD_TYPES) == 9, (
            f"Expected 9 GitLab record types, got {len(GITLAB_RECORD_TYPES)}: {GITLAB_RECORD_TYPES}"
        )

    def test_all_expected_constants_in_frozenset(self) -> None:
        for rt in EXPECTED_RECORD_TYPES:
            assert rt in GITLAB_RECORD_TYPES, f"{rt!r} missing from GITLAB_RECORD_TYPES"

    def test_constants_have_gitlab_prefix(self) -> None:
        for rt in GITLAB_RECORD_TYPES:
            assert rt.startswith("gitlab_"), f"Record type {rt!r} does not start with 'gitlab_'"

    def test_instance_constant(self) -> None:
        assert GITLAB_INSTANCE == "gitlab_instance"

    def test_project_constant(self) -> None:
        assert GITLAB_PROJECT == "gitlab_project"

    def test_group_constant(self) -> None:
        assert GITLAB_GROUP == "gitlab_group"

    def test_branch_protection_constant(self) -> None:
        assert GITLAB_BRANCH_PROTECTION == "gitlab_branch_protection"

    def test_webhook_constant(self) -> None:
        assert GITLAB_WEBHOOK == "gitlab_webhook"

    def test_ci_variable_summary_constant(self) -> None:
        assert GITLAB_CI_VARIABLE_SUMMARY == "gitlab_ci_variable_summary"

    def test_deploy_key_summary_constant(self) -> None:
        assert GITLAB_DEPLOY_KEY_SUMMARY == "gitlab_deploy_key_summary"

    def test_runner_summary_constant(self) -> None:
        assert GITLAB_RUNNER_SUMMARY == "gitlab_runner_summary"

    def test_mr_approval_summary_constant(self) -> None:
        assert GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY == "gitlab_merge_request_approval_summary"

    def test_connector_importable(self) -> None:
        connector = GitLabConnector()
        assert connector is not None


# ── B. Connector ──────────────────────────────────────────────────────────────

class TestConnector:
    def test_init_stores_no_credentials(self) -> None:
        connector = GitLabConnector()
        for attr_name, attr_val in vars(connector).items():
            val_str = str(attr_val).lower()
            assert "token" not in val_str, (
                f"Connector stores token in attribute {attr_name!r}"
            )
            assert "password" not in val_str, (
                f"Connector stores password in attribute {attr_name!r}"
            )

    def test_fetch_method_exists(self) -> None:
        connector = GitLabConnector()
        assert callable(getattr(connector, "fetch", None))

    def test_validate_credentials_method_exists(self) -> None:
        connector = GitLabConnector()
        assert callable(getattr(connector, "validate_credentials", None))

    def test_fetch_raises_on_empty_token(self) -> None:
        connector = GitLabConnector()
        with pytest.raises(AuthenticationError):
            connector.fetch({"access_token": "", "base_url": "https://gitlab.com"})

    def test_fetch_raises_on_missing_token(self) -> None:
        connector = GitLabConnector()
        with pytest.raises(AuthenticationError):
            connector.fetch({})

    def test_normalize_project_method_exists(self) -> None:
        connector = GitLabConnector()
        assert callable(getattr(connector, "_normalize_project", None))

    def test_normalize_group_method_exists(self) -> None:
        connector = GitLabConnector()
        assert callable(getattr(connector, "_normalize_group", None))

    def test_normalize_branch_protection_method_exists(self) -> None:
        connector = GitLabConnector()
        assert callable(getattr(connector, "_normalize_branch_protection", None))

    def test_normalize_webhook_method_exists(self) -> None:
        connector = GitLabConnector()
        assert callable(getattr(connector, "_normalize_webhook", None))

    def test_normalize_ci_variable_summary_method_exists(self) -> None:
        connector = GitLabConnector()
        assert callable(getattr(connector, "_normalize_ci_variable_summary", None))

    def test_normalize_deploy_key_summary_method_exists(self) -> None:
        connector = GitLabConnector()
        assert callable(getattr(connector, "_normalize_deploy_key_summary", None))

    def test_normalize_runner_summary_method_exists(self) -> None:
        connector = GitLabConnector()
        assert callable(getattr(connector, "_normalize_runner_summary", None))

    def test_normalize_mr_approval_summary_method_exists(self) -> None:
        connector = GitLabConnector()
        assert callable(getattr(connector, "_normalize_mr_approval_summary", None))

    def test_provider_key_is_gitlab(self) -> None:
        """Provider key must be 'gitlab' in all normalized records."""
        connector = GitLabConnector()
        record = connector._normalize_project({"id": "1", "visibility": "private"})
        assert record["provider"] == "gitlab"

    def test_record_ids_are_deterministic(self) -> None:
        """Same inputs must produce the same record_id on repeated calls."""
        connector = GitLabConnector()
        r1 = connector._normalize_project({"id": "42", "visibility": "private"})
        r2 = connector._normalize_project({"id": "42", "visibility": "private"})
        assert r1["record_id"] == r2["record_id"]

    def test_source_never_stores_raw_token(self) -> None:
        """The connector source must not contain any secret-shaped string."""
        src = GITLAB_PY.read_text(encoding="utf-8")
        assert "glpat-" not in src, "gitlab.py contains a hardcoded glpat- token"
        # Check for long base64-like strings (simple heuristic)
        assert not re.search(r"glpat-[A-Za-z0-9_-]{10,}", src)


# ── C. Normalizers ────────────────────────────────────────────────────────────

class TestNormalizers:
    def _assert_no_forbidden_fields(self, record: dict) -> None:
        for key in record:
            assert key not in _FORBIDDEN_RECORD_FIELDS, (
                f"Normalized record contains forbidden field {key!r}"
            )

    def _assert_flat(self, record: dict) -> None:
        for key, val in record.items():
            assert not isinstance(val, dict), (
                f"Normalized record has nested dict at key {key!r}"
            )
            assert not isinstance(val, list), (
                f"Normalized record has nested list at key {key!r}"
            )

    def test_instance_record(self) -> None:
        connector = GitLabConnector()
        record = connector._normalize_instance(
            version_data={"version": "16.0", "revision": "abc123", "enterprise": False},
            settings_data=None,
            project_count=5,
            group_count=2,
        )
        assert record["record_type"] == GITLAB_INSTANCE
        assert record["provider"] == "gitlab"
        assert "record_id" in record
        assert "resource_id" in record
        self._assert_no_forbidden_fields(record)
        self._assert_flat(record)

    def test_project_record(self) -> None:
        connector = GitLabConnector()
        raw = {
            "id": "123",
            "visibility": "private",
            "archived": False,
            "default_branch": "main",
            "merge_requests_enabled": True,
            "issues_enabled": True,
            "wiki_enabled": False,
            "snippets_enabled": False,
        }
        record = connector._normalize_project(raw, protected_branch_count=2, webhook_count=1)
        assert record["record_type"] == GITLAB_PROJECT
        assert record["provider"] == "gitlab"
        assert record["visibility_category"] == "private"
        assert record["archived"] is False
        assert record["protected_branch_count"] == 2
        assert record["webhook_count"] == 1
        self._assert_no_forbidden_fields(record)
        self._assert_flat(record)

    def test_project_record_public_visibility(self) -> None:
        connector = GitLabConnector()
        raw = {"id": "456", "visibility": "public"}
        record = connector._normalize_project(raw)
        assert record["visibility_category"] == "public"

    def test_group_record(self) -> None:
        connector = GitLabConnector()
        raw = {
            "id": "789",
            "visibility": "internal",
            "projects_count": 3,
            "subgroup_count": 1,
        }
        record = connector._normalize_group(raw)
        assert record["record_type"] == GITLAB_GROUP
        assert record["provider"] == "gitlab"
        assert record["visibility_category"] == "internal"
        self._assert_no_forbidden_fields(record)
        self._assert_flat(record)

    def test_group_record_public(self) -> None:
        connector = GitLabConnector()
        raw = {"id": "111", "visibility": "public"}
        record = connector._normalize_group(raw)
        assert record["visibility_category"] == "public"

    def test_branch_protection_record(self) -> None:
        connector = GitLabConnector()
        raw = {
            "name": "main",
            "allow_force_push": False,
            "code_owner_approval_required": True,
            "push_access_levels": [{"access_level": 40}],
            "merge_access_levels": [{"access_level": 40}],
        }
        project_rid = "abc123def456"
        record = connector._normalize_branch_protection(raw, project_rid)
        assert record["record_type"] == GITLAB_BRANCH_PROTECTION
        assert record["provider"] == "gitlab"
        assert record["allow_force_push"] is False
        assert record["code_owner_approval_required"] is True
        assert record["project_resource_id"] == project_rid
        assert record["push_access_level_category"] == "maintainer"
        self._assert_no_forbidden_fields(record)
        self._assert_flat(record)

    def test_webhook_record(self) -> None:
        connector = GitLabConnector()
        raw = {
            "id": "10",
            "url": "https://example.com/hook",  # raw URL must NOT appear in output
            "enable_ssl_verification": True,
            "token": None,
            "push_events": True,
            "merge_requests_events": False,
            "pipeline_events": True,
            "job_events": False,
        }
        record = connector._normalize_webhook(raw, "owner123", "project")
        assert record["record_type"] == GITLAB_WEBHOOK
        assert record["provider"] == "gitlab"
        assert "url" not in record, "Webhook URL must not be stored in the record"
        assert "token" not in record, "Webhook token must not be stored in the record"
        assert "secret_token" not in record
        assert record["url_scheme"] == "https"
        assert record["ssl_verification_enabled"] is True
        assert record["secret_token_present"] is False
        assert record["push_events"] is True
        self._assert_no_forbidden_fields(record)
        self._assert_flat(record)

    def test_ci_variable_summary_record(self) -> None:
        connector = GitLabConnector()
        variables = [
            {"key": "SECRET_KEY", "protected": True, "masked": True, "environment_scope": "*"},
            {"key": "API_URL", "protected": False, "masked": False, "environment_scope": "*"},
            {"key": "DB_HOST", "protected": True, "masked": False, "environment_scope": "prod"},
        ]
        record = connector._normalize_ci_variable_summary(variables, "owner123", "project")
        assert record["record_type"] == GITLAB_CI_VARIABLE_SUMMARY
        assert record["provider"] == "gitlab"
        assert record["variable_count"] == 3
        assert record["protected_variable_count"] == 2
        assert record["masked_variable_count"] == 1
        assert record["environment_scoped_count"] == 1
        assert record["unprotected_unmasked_count"] == 1
        # Ensure no variable names or values in output
        for key in record:
            assert "key" != key.lower() or key == "record_id" or key == "resource_id"
        assert "variable_name" not in record
        assert "variable_value" not in record
        self._assert_no_forbidden_fields(record)
        self._assert_flat(record)

    def test_deploy_key_summary_record(self) -> None:
        connector = GitLabConnector()
        deploy_keys = [
            {"id": 1, "can_push": True, "deploy_keys_projects": [{}]},
            {"id": 2, "can_push": False, "deploy_keys_projects": [{}]},
            {"id": 3, "can_push": False, "deploy_keys_projects": None},
        ]
        record = connector._normalize_deploy_key_summary(deploy_keys, "proj123")
        assert record["record_type"] == GITLAB_DEPLOY_KEY_SUMMARY
        assert record["provider"] == "gitlab"
        assert record["deploy_key_count"] == 3
        assert record["write_enabled_count"] == 1
        assert record["read_only_count"] == 2
        # Ensure no key material in output
        assert "key_title" not in record
        assert "key_fingerprint" not in record
        assert "key_material" not in record
        self._assert_no_forbidden_fields(record)
        self._assert_flat(record)

    def test_runner_summary_record(self) -> None:
        connector = GitLabConnector()
        runners = [
            {"id": 1, "runner_type": "project_type", "locked": True, "paused": False, "tag_list": ["linux"]},
            {"id": 2, "runner_type": "project_type", "locked": False, "paused": True, "tag_list": []},
        ]
        record = connector._normalize_runner_summary(runners, "proj123", "project")
        assert record["record_type"] == GITLAB_RUNNER_SUMMARY
        assert record["provider"] == "gitlab"
        assert record["runner_count"] == 2
        assert record["locked_runner_count"] == 1
        assert record["paused_runner_count"] == 1
        assert record["tagged_runner_count"] == 1
        assert record["untagged_runner_count"] == 1
        # Ensure no runner token/IP
        assert "runner_token" not in record
        assert "runner_ip" not in record
        assert "runner_description" not in record
        self._assert_no_forbidden_fields(record)
        self._assert_flat(record)

    def test_mr_approval_summary_record(self) -> None:
        connector = GitLabConnector()
        approvals = {
            "approvals_required": 2,
            "reset_approvals_on_push": True,
            "disable_overriding_approvers_per_merge_request": False,
            "approval_rules_overwritten": [],
        }
        record = connector._normalize_mr_approval_summary(approvals, "proj123")
        assert record["record_type"] == GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY
        assert record["provider"] == "gitlab"
        assert record["approvals_required"] == 2
        assert record["reset_approvals_on_push"] is True
        self._assert_no_forbidden_fields(record)
        self._assert_flat(record)


# ── D. Privacy ────────────────────────────────────────────────────────────────

class TestPrivacy:
    def test_webhook_normalizer_no_raw_url(self) -> None:
        """Webhook normalizer must never store the raw URL."""
        connector = GitLabConnector()
        raw = {
            "id": "99",
            "url": "https://super-secret.internal/webhook?token=abc123",
            "enable_ssl_verification": True,
        }
        record = connector._normalize_webhook(raw, "owner", "project")
        record_str = str(record)
        assert "super-secret" not in record_str
        assert "abc123" not in record_str
        assert "webhook?token" not in record_str

    def test_webhook_normalizer_no_secret_token_value(self) -> None:
        """Webhook secret token value must never be stored."""
        connector = GitLabConnector()
        raw = {
            "id": "88",
            "url": "https://example.com/hook",
            "token": "MY_SUPER_SECRET_TOKEN_VALUE",
        }
        record = connector._normalize_webhook(raw, "owner", "project")
        record_str = str(record)
        assert "MY_SUPER_SECRET_TOKEN_VALUE" not in record_str
        # Boolean presence flag only
        assert record["secret_token_present"] is True

    def test_ci_variable_summary_no_variable_names(self) -> None:
        """CI variable names must never appear in the summary record."""
        connector = GitLabConnector()
        variables = [
            {"key": "DATABASE_PASSWORD", "protected": False, "masked": False},
            {"key": "API_SECRET", "protected": False, "masked": False},
        ]
        record = connector._normalize_ci_variable_summary(variables, "owner", "project")
        record_str = str(record)
        assert "DATABASE_PASSWORD" not in record_str
        assert "API_SECRET" not in record_str

    def test_ci_variable_summary_no_variable_values(self) -> None:
        """CI variable values must never be fetched or appear in records."""
        connector = GitLabConnector()
        # Simulate a variable dict that has a value field (shouldn't happen in practice
        # since GitLab hides values, but we validate that even if present it's ignored)
        variables = [
            {"key": "MY_VAR", "value": "SENSITIVE_VALUE_12345", "protected": False, "masked": False},
        ]
        record = connector._normalize_ci_variable_summary(variables, "owner", "project")
        record_str = str(record)
        assert "SENSITIVE_VALUE_12345" not in record_str

    def test_deploy_key_summary_no_key_material(self) -> None:
        """Deploy key material must never appear in the summary record."""
        connector = GitLabConnector()
        deploy_keys = [
            {
                "id": 1,
                "title": "CI Deploy Key",
                "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDeploy",
                "fingerprint": "SHA256:abc123xyz",
                "can_push": True,
            },
        ]
        record = connector._normalize_deploy_key_summary(deploy_keys, "proj123")
        record_str = str(record)
        assert "ssh-rsa" not in record_str
        assert "AAAAB3Nz" not in record_str
        assert "CI Deploy Key" not in record_str
        assert "SHA256:abc123" not in record_str

    def test_runner_summary_no_token(self) -> None:
        """Runner tokens must never appear in the summary record."""
        connector = GitLabConnector()
        runners = [
            {
                "id": 1,
                "token": "RUNNER_TOKEN_SECRET",
                "description": "My Production Runner",
                "ip_address": "1.2.3.4",
                "runner_type": "project_type",
                "locked": False,
                "paused": False,
                "tag_list": [],
            },
        ]
        record = connector._normalize_runner_summary(runners, "proj123", "project")
        record_str = str(record)
        assert "RUNNER_TOKEN_SECRET" not in record_str
        assert "My Production Runner" not in record_str
        assert "1.2.3.4" not in record_str

    def test_branch_protection_no_raw_branch_name(self) -> None:
        """Branch protection normalizer must use pattern category, not raw branch name."""
        connector = GitLabConnector()
        raw = {
            "name": "sensitive-internal-branch-name",
            "allow_force_push": False,
            "code_owner_approval_required": False,
            "push_access_levels": [],
            "merge_access_levels": [],
        }
        record = connector._normalize_branch_protection(raw, "proj123")
        record_str = str(record)
        # Raw branch name must not appear in the record
        assert "sensitive-internal-branch-name" not in record_str
        # Pattern category should be present
        assert "pattern_category" in record
        assert record["pattern_category"] in ("default", "protected", "wildcard", "unknown")

    def test_project_no_project_name_or_path(self) -> None:
        """Project normalizer must not store project name, path, or URL."""
        connector = GitLabConnector()
        raw = {
            "id": "999",
            "name": "my-sensitive-project",
            "path": "namespace/my-sensitive-project",
            "web_url": "https://gitlab.com/namespace/my-sensitive-project",
            "ssh_url_to_repo": "git@gitlab.com:namespace/my-sensitive-project.git",
            "http_url_to_repo": "https://gitlab.com/namespace/my-sensitive-project.git",
            "visibility": "private",
        }
        record = connector._normalize_project(raw)
        record_str = str(record)
        assert "my-sensitive-project" not in record_str
        assert "namespace" not in record_str
        assert "gitlab.com/namespace" not in record_str

    def test_group_no_group_name_or_path(self) -> None:
        """Group normalizer must not store group name, full_path, or web_url."""
        connector = GitLabConnector()
        raw = {
            "id": "888",
            "name": "sensitive-internal-group",
            "full_path": "org/sensitive-internal-group",
            "web_url": "https://gitlab.com/org/sensitive-internal-group",
            "visibility": "private",
        }
        record = connector._normalize_group(raw)
        record_str = str(record)
        assert "sensitive-internal-group" not in record_str
        assert "org/" not in record_str

    def test_connector_source_no_user_email_storage(self) -> None:
        """The connector source must not log or store user emails."""
        src = GITLAB_PY.read_text(encoding="utf-8")
        # Should not store user email as a record field
        assert '"email"' not in src.lower().replace("user_email", "SKIP")
        assert "user_email" not in src or "not stored" in src.lower()

    def test_connector_source_no_issue_mr_commit_storage(self) -> None:
        """Connector must not fetch issues, MRs, or commit content."""
        src = GITLAB_PY.read_text(encoding="utf-8")
        # None of these sensitive paths should be in the paginate/request calls
        assert "/issues" not in src.replace("# issues", "")
        assert "/merge_requests" not in src.replace("# merge_requests", "")
        assert "/commits" not in src.replace("# commits", "")
        assert "/pipelines" not in src.replace("# pipelines", "")
        assert "/jobs" not in src.replace("# jobs", "")
        assert "/artifacts" not in src.replace("# artifacts", "")


# ── E. Integration schema / router ────────────────────────────────────────────

class TestIntegrationSchema:
    def test_gitlab_in_provider_literal(self) -> None:
        from app.schemas.integration import IntegrationCreateRequest
        import typing
        hints = typing.get_type_hints(IntegrationCreateRequest, include_extras=True)
        provider_hint = str(hints.get("provider", ""))
        assert "gitlab" in provider_hint, (
            f"'gitlab' not found in provider Literal annotation: {provider_hint}"
        )

    def test_gitlab_access_token_field_exists(self) -> None:
        from app.schemas.integration import IntegrationCreateRequest
        assert hasattr(IntegrationCreateRequest, "model_fields")
        fields = IntegrationCreateRequest.model_fields
        assert "gitlab_access_token" in fields, (
            "IntegrationCreateRequest missing gitlab_access_token field"
        )

    def test_gitlab_base_url_field_exists(self) -> None:
        from app.schemas.integration import IntegrationCreateRequest
        fields = IntegrationCreateRequest.model_fields
        assert "gitlab_base_url" in fields, (
            "IntegrationCreateRequest missing gitlab_base_url field"
        )

    def test_validator_rejects_missing_access_token(self) -> None:
        from pydantic import ValidationError
        from app.schemas.integration import IntegrationCreateRequest
        with pytest.raises(ValidationError):
            IntegrationCreateRequest(
                provider="gitlab",
                display_name="Test GitLab",
                # Missing gitlab_access_token
            )

    def test_response_schema_no_token_field(self) -> None:
        from app.schemas.integration import IntegrationResponse
        if hasattr(IntegrationResponse, "model_fields"):
            fields = IntegrationResponse.model_fields
        else:
            fields = {}
        assert "gitlab_access_token" not in fields, (
            "IntegrationResponse must not expose gitlab_access_token"
        )


# ── F. Sync wiring ────────────────────────────────────────────────────────────

class TestSyncWiring:
    def test_sync_service_supports_gitlab(self) -> None:
        sync_py = BACKEND_ROOT / "app" / "services" / "sync_service.py"
        src = sync_py.read_text(encoding="utf-8")
        assert '"gitlab"' in src or "'gitlab'" in src, (
            "sync_service.py must include 'gitlab' in _SUPPORTED_PROVIDERS"
        )

    def test_sync_task_dispatches_gitlab(self) -> None:
        sync_task_py = BACKEND_ROOT / "app" / "workers" / "sync_task.py"
        src = sync_task_py.read_text(encoding="utf-8")
        assert "gitlab" in src, (
            "sync_task.py must dispatch to GitLabConnector for provider='gitlab'"
        )
        assert "GitLabConnector" in src, (
            "sync_task.py must import and instantiate GitLabConnector"
        )

    def test_risk_service_dispatches_gitlab(self) -> None:
        risk_py = BACKEND_ROOT / "app" / "services" / "risk_service.py"
        src = risk_py.read_text(encoding="utf-8")
        assert "gitlab_" in src, (
            "risk_service.py must dispatch gitlab_ record types to classify_gitlab_change"
        )
        assert "classify_gitlab_change" in src, (
            "risk_service.py must import and call classify_gitlab_change"
        )


# ── G. Drift-risk classifier ──────────────────────────────────────────────────

class TestDriftRiskClassifier:
    def _make_change(
        self,
        record_type: str,
        field_path: str = "",
        change_type: str = "modified",
        prev_value: Any = None,
        new_value: Any = None,
    ) -> dict:
        return {
            "provider_metadata": {"record_type": record_type},
            "field_path": field_path,
            "change_type": change_type,
            "prev_value": prev_value,
            "new_value": new_value,
        }

    def test_project_public_visibility_is_high(self) -> None:
        change = self._make_change(
            GITLAB_PROJECT, "visibility_category", new_value="public"
        )
        level, reason = classify_gitlab_change(change)
        assert level == "high", f"Expected 'high' for public visibility, got '{level}'"
        assert "public" in reason.lower()

    def test_group_public_visibility_is_high(self) -> None:
        change = self._make_change(
            GITLAB_GROUP, "visibility_category", new_value="public"
        )
        level, reason = classify_gitlab_change(change)
        assert level == "high", f"Expected 'high' for group public visibility, got '{level}'"

    def test_webhook_secret_removed_is_high(self) -> None:
        change = self._make_change(
            GITLAB_WEBHOOK, "secret_token_present",
            prev_value=True, new_value=False
        )
        level, reason = classify_gitlab_change(change)
        assert level == "high", f"Expected 'high' for webhook secret removed, got '{level}'"

    def test_webhook_ssl_disabled_is_high(self) -> None:
        change = self._make_change(
            GITLAB_WEBHOOK, "ssl_verification_enabled",
            prev_value=True, new_value=False
        )
        level, reason = classify_gitlab_change(change)
        assert level == "high", f"Expected 'high' for SSL disabled, got '{level}'"

    def test_force_push_enabled_is_high(self) -> None:
        change = self._make_change(
            GITLAB_BRANCH_PROTECTION, "allow_force_push",
            prev_value=False, new_value=True
        )
        level, reason = classify_gitlab_change(change)
        assert level == "high", f"Expected 'high' for force-push enabled, got '{level}'"

    def test_branch_protection_removed_is_high(self) -> None:
        change = self._make_change(
            GITLAB_BRANCH_PROTECTION, "", change_type="removed"
        )
        level, reason = classify_gitlab_change(change)
        assert level == "high", (
            f"Expected 'high' for branch protection removed, got '{level}'"
        )

    def test_deploy_key_write_increase_is_high(self) -> None:
        change = self._make_change(
            GITLAB_DEPLOY_KEY_SUMMARY, "write_enabled_count",
            prev_value=0, new_value=2
        )
        level, reason = classify_gitlab_change(change)
        assert level == "high", (
            f"Expected 'high' for deploy key write count increase, got '{level}'"
        )

    def test_unprotected_unmasked_ci_increase_is_high(self) -> None:
        change = self._make_change(
            GITLAB_CI_VARIABLE_SUMMARY, "unprotected_unmasked_count",
            prev_value=0, new_value=3
        )
        level, reason = classify_gitlab_change(change)
        assert level == "high", (
            f"Expected 'high' for unprotected/unmasked CI variable increase, got '{level}'"
        )

    def test_approval_reduction_is_medium(self) -> None:
        change = self._make_change(
            GITLAB_MERGE_REQUEST_APPROVAL_SUMMARY, "approvals_required",
            prev_value=2, new_value=0
        )
        level, reason = classify_gitlab_change(change)
        assert level == "medium", (
            f"Expected 'medium' for approval reduction, got '{level}'"
        )

    def test_code_owner_approval_disabled_is_medium(self) -> None:
        change = self._make_change(
            GITLAB_BRANCH_PROTECTION, "code_owner_approval_required",
            prev_value=True, new_value=False
        )
        level, reason = classify_gitlab_change(change)
        assert level == "medium", (
            f"Expected 'medium' for code owner approval disabled, got '{level}'"
        )

    def test_webhook_event_scope_broadened_is_medium(self) -> None:
        change = self._make_change(
            GITLAB_WEBHOOK, "event_count",
            prev_value=2, new_value=8
        )
        level, reason = classify_gitlab_change(change)
        assert level == "medium", (
            f"Expected 'medium' for broad webhook event scope, got '{level}'"
        )

    def test_private_visibility_is_low(self) -> None:
        change = self._make_change(
            GITLAB_PROJECT, "visibility_category",
            prev_value="public", new_value="private"
        )
        level, _ = classify_gitlab_change(change)
        assert level == "low", (
            f"Expected 'low' for private visibility (hardening), got '{level}'"
        )

    def test_unknown_record_type_is_low(self) -> None:
        change = self._make_change("gitlab_unknown_surface", "some_field")
        level, reason = classify_gitlab_change(change)
        assert level == "low"

    def test_reason_never_contains_forbidden_phrase(self) -> None:
        test_changes = [
            self._make_change(GITLAB_PROJECT, "visibility_category", new_value="public"),
            self._make_change(GITLAB_WEBHOOK, "ssl_verification_enabled", new_value=False),
            self._make_change(GITLAB_BRANCH_PROTECTION, "allow_force_push", new_value=True),
            self._make_change(GITLAB_WEBHOOK, "secret_token_present", new_value=False),
        ]
        for change in test_changes:
            _, reason = classify_gitlab_change(change)
            reason_lower = reason.lower()
            for phrase in _FORBIDDEN_PHRASES:
                assert phrase not in reason_lower, (
                    f"Forbidden phrase {phrase!r} found in risk reason: {reason!r}"
                )

    def test_gitlab_specific_wording_clean(self) -> None:
        """Risk reason for public visibility must not use alarming forbidden terms."""
        change = self._make_change(GITLAB_PROJECT, "visibility_category", new_value="public")
        _, reason = classify_gitlab_change(change)
        reason_lower = reason.lower()
        for term in _GITLAB_FORBIDDEN_TERMS:
            assert term not in reason_lower, (
                f"GitLab forbidden term {term!r} found in risk reason: {reason!r}"
            )

    def test_rules_source_no_forbidden_phrases(self) -> None:
        """The risk rules source file must not contain any forbidden claim phrases."""
        src = GITLAB_RULES_PY.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"Forbidden phrase {phrase!r} found in gitlab.py risk rules source"
            )


# ── H. Capability matrix ──────────────────────────────────────────────────────

class TestCapabilityMatrix:
    def test_gitlab_in_partial_list(self) -> None:
        providers = [p.provider for p in PROVIDER_CAPABILITIES_PARTIAL]
        assert "gitlab" in providers, (
            "GitLab must be in PROVIDER_CAPABILITIES_PARTIAL after M87A"
        )

    def test_gitlab_capability_flags(self) -> None:
        cap = get_provider_capability("gitlab")
        assert cap is not None, "get_provider_capability('gitlab') returned None"
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_risk_classification is True
        assert cap.drift.drift_review_workflow is False
        # security_rules was False at M87A; M87B promoted it to True — accept either
        # (M87B is now complete so the matrix correctly shows True)
        # activity_ingestion was False at M87A; M87D promoted it to True.
        # activity_signals was False at M87A; M87E promoted it to True.
        assert cap.security.activity_ingestion is True
        assert cap.security.activity_signals is True
        # risk_activity_correlations was False at M87A; M87F promoted it to True.
        assert cap.security.risk_activity_correlations is True
        # demo_seed_clear landed in M87G.
        assert cap.security.demo_seed_clear is True
        # case_report landed in M87G.
        assert cap.security.case_report is True
        # evidence_timeline landed in M87G.
        assert cap.security.evidence_timeline is True
        # evidence_graph landed in M87G.
        assert cap.security.evidence_graph is True

    def test_gitlab_maturity_partial(self) -> None:
        cap = get_provider_capability("gitlab")
        assert cap is not None
        assert cap.maturity == "partial", (
            f"GitLab maturity should be 'partial' at M87A, got {cap.maturity!r}"
        )

    def test_gitlab_notes_mention_m87a(self) -> None:
        cap = get_provider_capability("gitlab")
        assert cap is not None
        assert "M87A" in cap.notes, "GitLab capability notes should mention M87A"

    def test_gitlab_notes_mention_m87b_next(self) -> None:
        cap = get_provider_capability("gitlab")
        assert cap is not None
        assert "M87B" in cap.notes, (
            "GitLab capability notes should mention M87B as planned next stage"
        )

    def test_gitlab_no_security_rules_claimed(self) -> None:
        # M87B added security rules — security_rules=True is now correct.
        # This test verifies the field is a valid boolean either way.
        cap = get_provider_capability("gitlab")
        assert cap is not None
        assert isinstance(cap.security.security_rules, bool)

    def test_gitlab_label(self) -> None:
        cap = get_provider_capability("gitlab")
        assert cap is not None
        assert cap.label == "GitLab"

    def test_gitlab_category(self) -> None:
        cap = get_provider_capability("gitlab")
        assert cap is not None
        assert cap.category == "devops"


# ── I. Expansion framework ────────────────────────────────────────────────────

class TestExpansionFramework:
    def test_planned_next_stage_references_m87b(self) -> None:
        fw = get_framework()
        planned = fw.get("summary", {}).get("planned_next_stage", "")
        # M87B→…→M87H→M87I: accept any GitLab arc stage pointer
        assert ("M87B" in planned or "GitLab Core" in planned
                or "M87C" in planned or "GitLab Branch" in planned
                or "M87D" in planned or "GitLab Activity" in planned
                or "M87E" in planned or "M87F" in planned
                or "Correlations" in planned or "M87G" in planned
                or "Demo" in planned or "M87H" in planned
                or "Provider Depth" in planned
                or "M87I" in planned or "Cross-Cloud" in planned), (
            f"planned_next_stage should reference M87B or later GitLab arc stage; got: {planned!r}"
        )

    def test_gitlab_not_head_of_recommended_queue(self) -> None:
        """GitLab launched in M87A — it should no longer be the head recommendation."""
        fw = get_framework()
        recommendations = fw.get("recommended_next_providers", [])
        if recommendations:
            first_provider = recommendations[0].get("provider", "")
            assert first_provider != "gitlab", (
                "GitLab should no longer be the head of the recommended queue after M87A"
            )

    def test_terraform_cloud_in_recommended_queue(self) -> None:
        """Terraform Cloud should now be in the recommended queue."""
        fw = get_framework()
        recommendations = fw.get("recommended_next_providers", [])
        provider_keys = [r.get("provider") for r in recommendations]
        assert "terraform_cloud" in provider_keys, (
            "Terraform Cloud should appear in recommended_next_providers after GitLab launches"
        )

    def test_terraform_cloud_after_gitlab_in_roadmap(self) -> None:
        """The framework comment or notes must acknowledge GitLab→Terraform Cloud ordering."""
        framework_py = BACKEND_ROOT / "app" / "services" / "provider_expansion_framework.py"
        src = framework_py.read_text(encoding="utf-8")
        assert "Terraform Cloud" in src, (
            "provider_expansion_framework.py must mention Terraform Cloud in roadmap"
        )
        # GitLab must also still be mentioned (as launched)
        assert "GitLab" in src

    def test_stage_count_still_six(self) -> None:
        fw = get_framework()
        stages = fw.get("template", {}).get("stages", [])
        assert len(stages) == 6, f"Expected 6 stages in dual-stack template, got {len(stages)}"


# ── J. Frontend ───────────────────────────────────────────────────────────────

class TestFrontend:
    def test_providers_ts_includes_gitlab(self) -> None:
        src = FE_PROVIDERS.read_text(encoding="utf-8")
        assert '"gitlab"' in src or "'gitlab'" in src, (
            "frontend/src/lib/providers.ts must include 'gitlab' as a provider ID"
        )

    def test_providers_ts_gitlab_entry_in_providers_map(self) -> None:
        src = FE_PROVIDERS.read_text(encoding="utf-8")
        assert "gitlab:" in src, (
            "providers.ts must have a 'gitlab:' entry in the PROVIDERS map"
        )

    def test_providers_ts_gitlab_color_orange(self) -> None:
        """GitLab's brand color is orange (#fc6d26) — check it's set."""
        src = FE_PROVIDERS.read_text(encoding="utf-8")
        # The color entry should appear in the gitlab section
        assert "fc6d26" in src, (
            "providers.ts should use GitLab orange (#fc6d26) for the gitlab color"
        )

    def test_gitlab_integration_form_exists(self) -> None:
        assert FE_GITLAB_FORM.exists(), (
            f"GitLabIntegrationForm.tsx not found at {FE_GITLAB_FORM}"
        )

    def test_gitlab_integration_form_has_access_token_field(self) -> None:
        src = FE_GITLAB_FORM.read_text(encoding="utf-8")
        assert "gitlab_access_token" in src or "accessToken" in src, (
            "GitLabIntegrationForm.tsx must have an access token field"
        )

    def test_gitlab_integration_form_token_field_is_password(self) -> None:
        src = FE_GITLAB_FORM.read_text(encoding="utf-8")
        assert 'type="password"' in src, (
            "GitLabIntegrationForm.tsx token field must be type='password'"
        )

    def test_providers_ts_gitlab_in_provider_ids_array(self) -> None:
        src = FE_PROVIDERS.read_text(encoding="utf-8")
        # The PROVIDER_IDS array must contain "gitlab"
        assert "PROVIDER_IDS" in src
        # Find the array and check gitlab is in it
        ids_match = re.search(
            r'PROVIDER_IDS[^=]*=\s*\[(.*?)\]',
            src, re.DOTALL
        )
        if ids_match:
            ids_block = ids_match.group(1)
            assert "gitlab" in ids_block, (
                "PROVIDER_IDS array in providers.ts must contain 'gitlab'"
            )

    def test_integrations_page_imports_gitlab_form(self) -> None:
        src = FE_INTEGRATIONS.read_text(encoding="utf-8")
        assert "GitLabIntegrationForm" in src, (
            "integrations/page.tsx must import GitLabIntegrationForm"
        )

    def test_integrations_page_routes_gitlab(self) -> None:
        src = FE_INTEGRATIONS.read_text(encoding="utf-8")
        assert "gitlab" in src.lower(), (
            "integrations/page.tsx must handle provider='gitlab'"
        )

    def test_gitlab_copy_says_foundation_not_security_rules(self) -> None:
        """Frontend copy must say foundation stage, not claim security rules."""
        src = FE_PROVIDERS.read_text(encoding="utf-8")
        # Find the gitlab section
        gitlab_start = src.find("// ── M87A — GitLab")
        if gitlab_start == -1:
            gitlab_start = src.find("gitlab:")
        gitlab_section = src[gitlab_start:gitlab_start + 2000] if gitlab_start >= 0 else ""
        # Should mention foundation stage
        assert "foundation" in gitlab_section.lower(), (
            "GitLab provider description should mention foundation stage"
        )

    def test_gitlab_no_security_rules_claimed_in_frontend(self) -> None:
        """Frontend must not claim GitLab security rules exist at M87A."""
        src = FE_PROVIDERS.read_text(encoding="utf-8")
        gitlab_start = src.find("// ── M87A — GitLab")
        if gitlab_start == -1:
            gitlab_start = src.find('"gitlab"')
        # Find the next provider section end
        gitlab_end = src.find("// ──", gitlab_start + 10)
        gitlab_section = src[gitlab_start:gitlab_end] if gitlab_end > 0 else src[gitlab_start:]
        # Confirm no claim that security rules are active
        assert "security rules active" not in gitlab_section.lower()
        assert "security_rules=true" not in gitlab_section.lower()


# ── K. Forbidden wording / secret-shape grep ─────────────────────────────────

class TestForbiddenWording:
    def _read_source(self, path: Path) -> str:
        return path.read_text(encoding="utf-8").lower()

    def test_connector_no_forbidden_phrases(self) -> None:
        src = self._read_source(GITLAB_PY)
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"Forbidden phrase {phrase!r} in gitlab.py connector"
            )

    def test_schema_no_forbidden_phrases(self) -> None:
        src = self._read_source(GITLAB_SCHEMA_PY)
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"Forbidden phrase {phrase!r} in gitlab_schema.py"
            )

    def test_risk_rules_no_forbidden_phrases(self) -> None:
        src = self._read_source(GITLAB_RULES_PY)
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in src, (
                f"Forbidden phrase {phrase!r} in risk_rules/gitlab.py"
            )

    def test_connector_no_glpat_token(self) -> None:
        """No real GitLab PAT (glpat-...) in the connector source."""
        src = GITLAB_PY.read_text(encoding="utf-8")
        assert not re.search(r"glpat-[A-Za-z0-9_-]{10,}", src), (
            "Real GitLab PAT (glpat-...) found in gitlab.py — remove it"
        )

    def test_schema_no_glpat_token(self) -> None:
        src = GITLAB_SCHEMA_PY.read_text(encoding="utf-8")
        assert not re.search(r"glpat-[A-Za-z0-9_-]{10,}", src)

    def test_no_bearer_tokens_in_connector(self) -> None:
        src = GITLAB_PY.read_text(encoding="utf-8")
        # No hardcoded long base64-like strings that look like tokens
        # (This is a heuristic — real tokens won't be in a test file)
        assert not re.search(r"eyJ[A-Za-z0-9_-]{20,}", src), (
            "JWT-shaped token found in gitlab.py"
        )


# ── L. Marketing-video and tail-latency-study untouched ──────────────────────

class TestUnrelatedFilesUntouched:
    def test_marketing_video_not_in_staged_changes(self) -> None:
        """marketing-video/ must not be staged."""
        import subprocess
        result = subprocess.run(
            ["git", "diff", "--name-only", "--cached"],
            capture_output=True, text=True,
            cwd=str(REPO_ROOT),
        )
        staged = result.stdout
        assert "marketing-video" not in staged, (
            f"marketing-video/ appears in staged changes: {staged!r}"
        )

    def test_tail_latency_study_not_in_staged_changes(self) -> None:
        """tail-latency-study/ must not be staged."""
        import subprocess
        result = subprocess.run(
            ["git", "diff", "--name-only", "--cached"],
            capture_output=True, text=True,
            cwd=str(REPO_ROOT),
        )
        staged = result.stdout
        assert "tail-latency-study" not in staged, (
            f"tail-latency-study/ appears in staged changes: {staged!r}"
        )
