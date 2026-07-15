"""Tests for M33: Vercel Provider MVP.

Test coverage
-------------
1. VercelConnector.fetch() normalises records correctly and NEVER includes
   env var values in output.
2. VercelConnector.validate_credentials() succeeds on 200, raises
   AuthenticationError on 401/403, raises ConnectorError on 404.
3. VercelConnector retry / error handling (429, 500, network error).
4. Risk classification (classify_vercel_change) for env var, project, domain.
5. Diff service tracked-fields dispatch for vercel_ record types.
6. Failure classifier returns vercel_* error codes for Vercel provider.
7. Schema validation: vercel provider requires vercel_token + vercel_project_id.
8. Integration creation (unit-level): creates correct Integration + Resource rows.
9. Reconnect credentials: handles Vercel provider.
10. Sync task: routes to VercelConnector for vercel provider.

SECURITY invariants asserted in every test that touches env vars:
  - Returned records must NOT contain a ``value`` key.
  - Returned records must NOT contain any other key whose value looks like
    a secret (e.g. the literal string "secret_value" from mock data).
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
import httpx

from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.vercel import (
    VercelConnector,
    _normalize_domain,
    _normalize_env_var,
    _normalize_project,
)
from app.connectors.vercel_schema import (
    VERCEL_DEPLOYMENT_PROTECTION,
    VERCEL_DOMAIN,
    VERCEL_ENV_VAR,
    VERCEL_PROJECT,
)
from app.services.risk_rules.vercel import classify_vercel_change


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ─────────────────────────────────────────────────────────────────────────────

CREDS = {
    "vercel_token": "tok_test_abc",
    "vercel_project_id": "prj_test123",
}

# Raw API responses (simplified)

RAW_PROJECT = {
    "id": "prj_test123",
    "name": "my-project",
    "framework": "nextjs",
    "buildCommand": None,
    "installCommand": None,
    "outputDirectory": None,
    "rootDirectory": None,
    "nodeVersion": "20.x",
    # Git connection
    "link": {
        "type": "github",
        "repo": "acme/my-project",
        "productionBranch": "main",
    },
    # Deployment protection (both off by default)
    "ssoProtection": None,
    "passwordProtection": None,
}

RAW_PROJECT_WITH_PROTECTION = {
    "id": "prj_protected",
    "name": "protected-project",
    "framework": "nextjs",
    "buildCommand": None,
    "installCommand": None,
    "outputDirectory": None,
    "rootDirectory": None,
    "nodeVersion": "20.x",
    "link": {
        "type": "github",
        "repo": "acme/protected-project",
        "productionBranch": "main",
    },
    "ssoProtection": {"deploymentType": "all"},
    "passwordProtection": {"deploymentType": "preview"},
}

RAW_ENV_VAR = {
    "id": "env_abc",
    "key": "DATABASE_URL",
    "type": "encrypted",
    "target": ["production"],
    "gitBranch": None,
    "createdAt": 1700000000000,
    "updatedAt": 1700001000000,
    # SECURITY: "value" is present in the real API response — we must drop it.
    "value": "postgres://user:secret_value@host/db",
}

RAW_ENV_VAR_DEV = {
    "id": "env_dev",
    "key": "DEBUG",
    "type": "plain",
    "target": ["development"],
    "gitBranch": None,
    "createdAt": 1700000000000,
    "updatedAt": 1700000000000,
    "value": "true",
}

RAW_DOMAIN = {
    "name": "app.example.com",
    "verified": True,
    "gitBranch": None,
    "redirect": None,
    "createdAt": 1700000000000,
    "updatedAt": 1700000000000,
}


def _make_response(status_code: int, json_body: dict) -> MagicMock:
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.is_success = (200 <= status_code < 300)
    resp.json.return_value = json_body
    resp.headers = {}
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# 1. Normalisation helpers — SECURITY: value must be absent
# ─────────────────────────────────────────────────────────────────────────────


class TestNormalisation:
    def test_normalize_project_fields(self):
        record = _normalize_project(RAW_PROJECT)
        assert record["record_id"] == "prj_test123"
        assert record["record_type"] == VERCEL_PROJECT
        assert record["name"] == "my-project"
        assert record["framework"] == "nextjs"
        assert record["node_version"] == "20.x"
        assert record["build_command"] is None
        assert record["install_command"] is None

    def test_normalize_project_git_connection(self):
        """Connector extracts git_repository and git_branch (production branch)."""
        record = _normalize_project(RAW_PROJECT)
        assert record["git_repository"] == "acme/my-project"
        assert record["git_branch"] == "main"

    def test_normalize_project_no_git_link(self):
        """Projects without a git link return None for git fields."""
        raw = {**RAW_PROJECT, "link": None}
        record = _normalize_project(raw)
        assert record["git_repository"] is None
        assert record["git_branch"] is None

    def test_normalize_project_git_repository_fallback(self):
        """Falls back to gitRepository field if link is absent."""
        raw = {**RAW_PROJECT, "link": None, "gitRepository": {"repo": "org/fallback-repo"}}
        record = _normalize_project(raw)
        assert record["git_repository"] == "org/fallback-repo"

    def test_normalize_project_protection_disabled(self):
        """sso_protection and password_protection are None when disabled."""
        record = _normalize_project(RAW_PROJECT)
        assert record["sso_protection"] is None
        assert record["password_protection"] is None

    def test_normalize_project_protection_enabled(self):
        """sso_protection and password_protection capture deploymentType string."""
        record = _normalize_project(RAW_PROJECT_WITH_PROTECTION)
        assert record["sso_protection"] == "all"
        assert record["password_protection"] == "preview"

    def test_normalize_env_var_drops_value(self):
        """SECURITY: the 'value' field must NEVER appear in normalized records."""
        record = _normalize_env_var(RAW_ENV_VAR)
        assert "value" not in record, (
            "SECURITY VIOLATION: 'value' field found in normalized env var record. "
            "Vercel env var values must never be stored."
        )
        # Also confirm the secret string itself is not present
        import json
        record_json = json.dumps(record)
        assert "secret_value" not in record_json, (
            "SECURITY VIOLATION: secret content leaked into normalized env var record."
        )

    def test_normalize_env_var_metadata_correct(self):
        record = _normalize_env_var(RAW_ENV_VAR)
        assert record["record_id"] == "env_abc"
        assert record["record_type"] == VERCEL_ENV_VAR
        assert record["name"] == "DATABASE_URL"
        assert record["key"] == "DATABASE_URL"
        assert record["env_type"] == "encrypted"
        assert record["target"] == ["production"]  # sorted
        assert record["git_branch"] is None
        assert record["created_at"] == 1700000000000
        assert record["updated_at"] == 1700001000000

    def test_normalize_env_var_target_sorted(self):
        raw = {**RAW_ENV_VAR, "target": ["development", "preview", "production"]}
        record = _normalize_env_var(raw)
        assert record["target"] == sorted(["development", "preview", "production"])

    def test_normalize_env_var_string_target_converted_to_list(self):
        """Vercel sometimes returns target as a string for single-env vars."""
        raw = {**RAW_ENV_VAR, "target": "production"}
        record = _normalize_env_var(raw)
        assert record["target"] == ["production"]

    def test_normalize_domain_fields(self):
        record = _normalize_domain(RAW_DOMAIN)
        assert record["record_id"] == "app.example.com"
        assert record["record_type"] == VERCEL_DOMAIN
        assert record["name"] == "app.example.com"
        assert record["verified"] is True
        assert record["redirect"] is None


# ─────────────────────────────────────────────────────────────────────────────
# 2. VercelConnector.fetch() — SECURITY: value must be absent in full fetch
# ─────────────────────────────────────────────────────────────────────────────


class TestVercelConnectorFetch:
    """Test the full fetch() pipeline using mocked HTTP responses."""

    def _make_connector(self):
        return VercelConnector()

    def _mock_responses(self) -> list:
        """Return a list of mock responses for project, env, domains."""
        project_resp = _make_response(200, RAW_PROJECT)
        env_resp = _make_response(200, {
            "envs": [RAW_ENV_VAR, RAW_ENV_VAR_DEV],
            "pagination": {},  # no next cursor
        })
        domain_resp = _make_response(200, {
            "domains": [RAW_DOMAIN],
            "pagination": {},
        })
        return [project_resp, env_resp, domain_resp]

    @patch("httpx.get")
    def test_fetch_returns_correct_record_count(self, mock_get):
        mock_get.side_effect = self._mock_responses()
        records = self._make_connector().fetch(CREDS)
        # 1 project + 2 env vars + 1 domain + 1 deployment-protection = 5.
        # The deployment-protection record is derived from the project response
        # (no extra API call) so vercel_preview_unprotected has a reachable
        # production record source.
        assert len(records) == 5

    @patch("httpx.get")
    def test_fetch_record_types(self, mock_get):
        mock_get.side_effect = self._mock_responses()
        records = self._make_connector().fetch(CREDS)
        types = {r["record_type"] for r in records}
        assert types == {
            VERCEL_PROJECT,
            VERCEL_ENV_VAR,
            VERCEL_DOMAIN,
            VERCEL_DEPLOYMENT_PROTECTION,
        }

    @patch("httpx.get")
    def test_fetch_no_value_in_any_record(self, mock_get):
        """SECURITY: no record in the full fetch output may contain 'value'."""
        mock_get.side_effect = self._mock_responses()
        records = self._make_connector().fetch(CREDS)
        import json
        for record in records:
            assert "value" not in record, (
                f"SECURITY VIOLATION: 'value' key found in record: {record}"
            )
            record_json = json.dumps(record)
            assert "secret_value" not in record_json, (
                f"SECURITY VIOLATION: secret content leaked into record: {record}"
            )

    @patch("httpx.get")
    def test_fetch_env_var_production_target(self, mock_get):
        mock_get.side_effect = self._mock_responses()
        records = self._make_connector().fetch(CREDS)
        env_vars = [r for r in records if r["record_type"] == VERCEL_ENV_VAR]
        prod_vars = [r for r in env_vars if "production" in r["target"]]
        assert len(prod_vars) == 1
        assert prod_vars[0]["key"] == "DATABASE_URL"

    @patch("httpx.get")
    def test_fetch_pagination_followed(self, mock_get):
        """Connector follows cursor pagination for env vars."""
        project_resp = _make_response(200, RAW_PROJECT)
        env_page1 = _make_response(200, {
            "envs": [RAW_ENV_VAR],
            "pagination": {"next": 1700001000000},
        })
        env_page2 = _make_response(200, {
            "envs": [RAW_ENV_VAR_DEV],
            "pagination": {},  # no next
        })
        domain_resp = _make_response(200, {"domains": [], "pagination": {}})
        mock_get.side_effect = [project_resp, env_page1, env_page2, domain_resp]

        records = self._make_connector().fetch(CREDS)
        env_vars = [r for r in records if r["record_type"] == VERCEL_ENV_VAR]
        assert len(env_vars) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 3. VercelConnector error handling
# ─────────────────────────────────────────────────────────────────────────────


class TestVercelConnectorErrors:
    def _make_connector(self):
        return VercelConnector()

    @patch("httpx.get")
    def test_401_raises_auth_error(self, mock_get):
        mock_get.return_value = _make_response(401, {"error": "unauthorized"})
        with pytest.raises(AuthenticationError):
            self._make_connector().validate_credentials(CREDS)

    @patch("httpx.get")
    def test_403_raises_auth_error(self, mock_get):
        mock_get.return_value = _make_response(403, {"error": "forbidden"})
        with pytest.raises(AuthenticationError):
            self._make_connector().validate_credentials(CREDS)

    @patch("httpx.get")
    def test_404_raises_connector_error(self, mock_get):
        resp = _make_response(404, {"error": "not_found"})
        mock_get.return_value = resp
        with pytest.raises(ConnectorError) as exc_info:
            self._make_connector().validate_credentials(CREDS)
        assert exc_info.value.status_code == 404

    @patch("httpx.get")
    def test_429_retries_then_raises_rate_limit(self, mock_get):
        rate_limited = _make_response(429, {"error": "rate_limited"})
        rate_limited.headers = {"Retry-After": "0"}
        mock_get.return_value = rate_limited
        with pytest.raises(RateLimitError):
            self._make_connector().validate_credentials(CREDS)
        # Should have retried _MAX_RETRIES times
        assert mock_get.call_count == 3

    @patch("httpx.get")
    def test_500_retries_then_raises_connector_error(self, mock_get):
        server_error = _make_response(500, {"error": "internal"})
        mock_get.return_value = server_error
        with pytest.raises(ConnectorError) as exc_info:
            self._make_connector().validate_credentials(CREDS)
        assert exc_info.value.status_code == 500

    @patch("httpx.get")
    def test_network_error_raises_network_error(self, mock_get):
        mock_get.side_effect = httpx.RequestError("connection refused")
        with pytest.raises(NetworkError):
            self._make_connector().validate_credentials(CREDS)

    @patch("httpx.get")
    def test_validate_credentials_success(self, mock_get):
        mock_get.return_value = _make_response(200, RAW_PROJECT)
        result = self._make_connector().validate_credentials(CREDS)
        assert result is True

    def test_validate_credentials_missing_token(self):
        result = self._make_connector().validate_credentials({
            "vercel_token": "",
            "vercel_project_id": "prj_xxx",
        })
        assert result is False

    def test_validate_credentials_missing_project_id(self):
        result = self._make_connector().validate_credentials({
            "vercel_token": "tok_abc",
            "vercel_project_id": "",
        })
        assert result is False


# ─────────────────────────────────────────────────────────────────────────────
# 4. Risk classification — classify_vercel_change
# ─────────────────────────────────────────────────────────────────────────────


class TestVercelRiskClassification:
    """Test risk rules for Vercel record types."""

    def _change(
        self,
        change_type: str,
        record_type: str,
        record_name: str = "",
        field_path: str | None = None,
        prev_value=None,
        new_value=None,
    ) -> dict:
        return {
            "change_type": change_type,
            "field_path": field_path,
            "prev_value": prev_value,
            "new_value": new_value,
            "provider_metadata": {
                "record_type": record_type,
                "record_name": record_name,
            },
        }

    # ── vercel_env_var ────────────────────────────────────────────────────────

    def test_sensitive_env_var_removed_from_prod_is_critical(self):
        level, _ = classify_vercel_change(self._change(
            change_type="removed",
            record_type=VERCEL_ENV_VAR,
            record_name="DATABASE_URL",
            prev_value={"target": ["production"], "key": "DATABASE_URL"},
        ))
        assert level == "critical"

    def test_nonsensitive_env_var_removed_from_prod_is_high(self):
        level, _ = classify_vercel_change(self._change(
            change_type="removed",
            record_type=VERCEL_ENV_VAR,
            record_name="FEATURE_FLAG",
            prev_value={"target": ["production"], "key": "FEATURE_FLAG"},
        ))
        assert level == "high"

    def test_env_var_removed_from_dev_is_medium(self):
        level, _ = classify_vercel_change(self._change(
            change_type="removed",
            record_type=VERCEL_ENV_VAR,
            record_name="DATABASE_URL",
            prev_value={"target": ["development"], "key": "DATABASE_URL"},
        ))
        assert level == "medium"

    def test_sensitive_env_var_added_to_prod_is_medium(self):
        # Adding a sensitive var to prod is medium: it's new capability, not a breakage.
        # Removing is critical/high because the app likely crashes.
        level, _ = classify_vercel_change(self._change(
            change_type="added",
            record_type=VERCEL_ENV_VAR,
            record_name="API_KEY",
            new_value={"target": ["production"], "key": "API_KEY"},
        ))
        assert level == "medium"

    def test_env_var_added_to_prod_nonsensitive_is_medium(self):
        level, _ = classify_vercel_change(self._change(
            change_type="added",
            record_type=VERCEL_ENV_VAR,
            record_name="FEATURE_ENABLED",
            new_value={"target": ["production"], "key": "FEATURE_ENABLED"},
        ))
        assert level == "medium"

    def test_env_var_added_to_dev_is_low(self):
        level, _ = classify_vercel_change(self._change(
            change_type="added",
            record_type=VERCEL_ENV_VAR,
            record_name="DATABASE_URL",
            new_value={"target": ["development"], "key": "DATABASE_URL"},
        ))
        assert level == "low"

    def test_env_var_promoted_to_prod_is_high(self):
        level, _ = classify_vercel_change(self._change(
            change_type="modified",
            record_type=VERCEL_ENV_VAR,
            record_name="DATABASE_URL",
            field_path="target",
            prev_value=["development"],
            new_value=["production"],
        ))
        assert level == "high"

    def test_env_var_demoted_from_prod_is_high(self):
        level, _ = classify_vercel_change(self._change(
            change_type="modified",
            record_type=VERCEL_ENV_VAR,
            record_name="DATABASE_URL",
            field_path="target",
            prev_value=["production"],
            new_value=["development"],
        ))
        assert level == "high"

    def test_sensitive_env_var_updated_at_is_high(self):
        level, _ = classify_vercel_change(self._change(
            change_type="modified",
            record_type=VERCEL_ENV_VAR,
            record_name="SECRET_KEY",
            field_path="updated_at",
            prev_value=1700000000000,
            new_value=1700001000000,
        ))
        assert level == "high"

    def test_nonsensitive_env_var_updated_at_is_medium(self):
        level, _ = classify_vercel_change(self._change(
            change_type="modified",
            record_type=VERCEL_ENV_VAR,
            record_name="FEATURE_ENABLED",
            field_path="updated_at",
            prev_value=1700000000000,
            new_value=1700001000000,
        ))
        assert level == "medium"

    def test_env_type_downgrade_encrypted_to_plain_is_high(self):
        level, _ = classify_vercel_change(self._change(
            change_type="modified",
            record_type=VERCEL_ENV_VAR,
            record_name="API_KEY",
            field_path="env_type",
            prev_value="encrypted",
            new_value="plain",
        ))
        assert level == "high"

    # ── vercel_project ────────────────────────────────────────────────────────

    def test_build_command_modified_is_high(self):
        level, _ = classify_vercel_change(self._change(
            change_type="modified",
            record_type=VERCEL_PROJECT,
            field_path="build_command",
            prev_value=None,
            new_value="npm run build && curl http://evil.com",
        ))
        assert level == "high"

    def test_framework_modified_is_high(self):
        # Framework change affects build strategy, routing, and output structure.
        level, _ = classify_vercel_change(self._change(
            change_type="modified",
            record_type=VERCEL_PROJECT,
            field_path="framework",
            prev_value="nextjs",
            new_value="remix",
        ))
        assert level == "high"

    def test_node_version_modified_is_medium(self):
        level, _ = classify_vercel_change(self._change(
            change_type="modified",
            record_type=VERCEL_PROJECT,
            field_path="node_version",
            prev_value="18.x",
            new_value="20.x",
        ))
        assert level == "medium"

    # ── vercel_domain ─────────────────────────────────────────────────────────

    def test_domain_removed_is_critical(self):
        level, _ = classify_vercel_change(self._change(
            change_type="removed",
            record_type=VERCEL_DOMAIN,
            record_name="app.example.com",
            prev_value={"name": "app.example.com"},
        ))
        assert level == "critical"

    def test_domain_added_is_medium(self):
        level, _ = classify_vercel_change(self._change(
            change_type="added",
            record_type=VERCEL_DOMAIN,
            record_name="staging.example.com",
            new_value={"name": "staging.example.com"},
        ))
        assert level == "medium"

    def test_domain_unverified_is_high(self):
        level, _ = classify_vercel_change(self._change(
            change_type="modified",
            record_type=VERCEL_DOMAIN,
            record_name="app.example.com",
            field_path="verified",
            prev_value=True,
            new_value=False,
        ))
        assert level == "high"

    def test_domain_verified_is_low(self):
        level, _ = classify_vercel_change(self._change(
            change_type="modified",
            record_type=VERCEL_DOMAIN,
            record_name="app.example.com",
            field_path="verified",
            prev_value=False,
            new_value=True,
        ))
        assert level == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Diff service: tracked fields for vercel_ types
# ─────────────────────────────────────────────────────────────────────────────


class TestDiffServiceVercel:
    def test_tracked_fields_vercel_project(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "vercel_project"}
        fields = _tracked_fields_for(record)
        # Build pipeline
        assert "build_command" in fields
        assert "install_command" in fields
        assert "root_directory" in fields
        assert "output_directory" in fields
        # Runtime / framework
        assert "framework" in fields
        assert "node_version" in fields
        # Project identity
        assert "name" in fields
        # Git connection
        assert "git_repository" in fields
        assert "git_branch" in fields
        # Deployment protection
        assert "sso_protection" in fields
        assert "password_protection" in fields
        # Safety: internal metadata fields must NOT be tracked
        assert "record_id" not in fields
        assert "record_type" not in fields

    def test_tracked_fields_vercel_env_var(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "vercel_env_var"}
        fields = _tracked_fields_for(record)
        assert "target" in fields
        assert "updated_at" in fields
        assert "env_type" in fields
        # SECURITY: "value" should absolutely NOT be in tracked fields
        assert "value" not in fields, (
            "SECURITY VIOLATION: 'value' is in tracked fields for vercel_env_var. "
            "Env var values must never be diffed or stored."
        )

    def test_tracked_fields_vercel_domain(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "vercel_domain"}
        fields = _tracked_fields_for(record)
        assert "verified" in fields
        assert "redirect" in fields

    def test_tracked_fields_unknown_vercel_type_returns_empty(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "vercel_unknown_future_type"}
        fields = _tracked_fields_for(record)
        assert fields == ()

    def test_tracked_fields_vercel_deployment_protection(self):
        """Regression guard: vercel_deployment_protection was previously
        missing entirely from the tracked-fields map, so compute_diff never
        detected SSO/password/preview-protection drift even though the
        connector's fetch() already emits this record and a classifier
        already existed for it."""
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "vercel_deployment_protection"}
        fields = _tracked_fields_for(record)
        assert "sso_enabled" in fields
        assert "password_enabled" in fields
        assert "preview_deployments_protected" in fields

    def test_real_compute_diff_detects_deployment_protection_disabled(self):
        """Real compute_diff() -> classify_vercel_change() integration, not a
        hand-built mock: proves the previously-undetected SSO-disable is now
        both tracked and classified as high."""
        from app.services.diff_service import compute_diff
        from app.services.risk_rules.vercel import classify_vercel_change

        class _FakeSnap:
            def __init__(self, state):
                self.state = state

        prev = [{
            "record_type": "vercel_deployment_protection", "record_id": "prj_1",
            "name": "my-app", "sso_enabled": True, "password_enabled": False,
            "preview_deployments_protected": True,
        }]
        new = [{**prev[0], "sso_enabled": False, "preview_deployments_protected": False}]
        changes = compute_diff(_FakeSnap(prev), _FakeSnap(new))
        assert len(changes) == 2, "expected sso_enabled and preview_deployments_protected changes"
        for change in changes:
            level, _ = classify_vercel_change(change)
            assert level == "high", f"{change['field_path']} expected high, got {level}"

    def test_cloudflare_record_still_uses_dns_fields(self):
        from app.services.diff_service import _tracked_fields_for
        record = {"record_type": "A"}
        fields = _tracked_fields_for(record)
        assert "content" in fields
        assert "ttl" in fields


# ─────────────────────────────────────────────────────────────────────────────
# 6. Failure classifier — vercel_* error codes
# ─────────────────────────────────────────────────────────────────────────────


class TestFailureClassifierVercel:
    def test_auth_error_vercel_returns_token_revoked(self):
        from app.core.failure_classifier import classify_failure
        exc = AuthenticationError("bad token")
        result = classify_failure(exc, provider="vercel")
        assert result.error_code == "vercel_token_revoked"
        assert result.category == "authentication"

    def test_connector_404_vercel_returns_project_not_found(self):
        from app.core.failure_classifier import classify_failure
        exc = ConnectorError("not found", status_code=404)
        result = classify_failure(exc, provider="vercel")
        assert result.error_code == "vercel_project_not_found"
        assert result.category == "resource_missing"

    def test_connector_500_vercel_returns_api_unavailable(self):
        from app.core.failure_classifier import classify_failure
        exc = ConnectorError("server error", status_code=500)
        result = classify_failure(exc, provider="vercel")
        assert result.error_code == "vercel_api_unavailable"
        assert result.category == "provider_unavailable"

    def test_network_error_vercel_returns_network_error(self):
        from app.core.failure_classifier import classify_failure
        exc = NetworkError("connection refused")
        result = classify_failure(exc, provider="vercel")
        assert result.error_code == "network_error"
        assert result.category == "network"

    def test_rate_limit_vercel_returns_rate_limited(self):
        from app.core.failure_classifier import classify_failure
        exc = RateLimitError("rate limited")
        result = classify_failure(exc, provider="vercel")
        assert result.error_code == "rate_limit_exceeded"
        assert result.category == "rate_limited"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Schema validation
# ─────────────────────────────────────────────────────────────────────────────


class TestSchemaValidation:
    def test_vercel_provider_accepted(self):
        from app.schemas.integration import IntegrationCreateRequest
        req = IntegrationCreateRequest(
            provider="vercel",
            display_name="My Vercel",
            vercel_token="tok_abc",
            vercel_project_id="prj_xxx",
        )
        assert req.provider == "vercel"

    def test_vercel_requires_token(self):
        from app.schemas.integration import IntegrationCreateRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError) as exc_info:
            IntegrationCreateRequest(
                provider="vercel",
                display_name="My Vercel",
                vercel_project_id="prj_xxx",
                # vercel_token missing
            )
        assert "vercel_token" in str(exc_info.value)

    def test_vercel_requires_project_id(self):
        from app.schemas.integration import IntegrationCreateRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError) as exc_info:
            IntegrationCreateRequest(
                provider="vercel",
                display_name="My Vercel",
                vercel_token="tok_abc",
                # vercel_project_id missing
            )
        assert "vercel_project_id" in str(exc_info.value)

    def test_reconnect_schema_accepts_vercel_token(self):
        from app.schemas.integration import IntegrationReconnectRequest
        req = IntegrationReconnectRequest(vercel_token="tok_new_abc")
        assert req.vercel_token == "tok_new_abc"

    def test_cloudflare_still_works(self):
        from app.schemas.integration import IntegrationCreateRequest
        req = IntegrationCreateRequest(
            provider="cloudflare",
            display_name="CF",
            api_token="tok",
            zone_id="zone123",
        )
        assert req.provider == "cloudflare"

    def test_github_still_works(self):
        from app.schemas.integration import IntegrationCreateRequest
        req = IntegrationCreateRequest(
            provider="github",
            display_name="GH",
            github_token="ghp_abc",
            repo_owner="owner",
            repo_name="repo",
        )
        assert req.provider == "github"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Integration service: _create_vercel_integration (DB-level test)
# ─────────────────────────────────────────────────────────────────────────────


class TestCreateVercelIntegration:
    """Tests the integration creation flow using the real test DB session."""

    @patch("app.connectors.vercel.VercelConnector.validate_credentials", return_value=True)
    def test_creates_integration_and_resource(self, mock_validate, db_session, test_user):
        from app.models.integration import Integration
        from app.models.resource import Resource
        from app.services.integration_service import create_integration

        integration = create_integration(
            user_id=test_user.id,
            provider="vercel",
            display_name="Test Vercel",
            credentials={
                "vercel_token": "tok_test",
                "vercel_project_id": "prj_test",
            },
            db=db_session,
        )

        assert integration.provider == "vercel"
        assert integration.display_name == "Test Vercel"
        assert integration.status == "active"
        # Credentials must be encrypted, not plaintext
        assert integration.encrypted_credentials is not None
        assert b"tok_test" not in integration.encrypted_credentials

        # One Resource should be created
        resource = (
            db_session.query(Resource)
            .filter(Resource.integration_id == integration.id)
            .first()
        )
        assert resource is not None
        assert resource.provider_resource_type == "vercel_project"
        assert resource.provider_resource_id == "prj_test"

    @patch("app.connectors.vercel.VercelConnector.validate_credentials", return_value=True)
    def test_duplicate_project_raises_value_error(self, mock_validate, db_session, test_user):
        from app.services.integration_service import create_integration

        creds = {"vercel_token": "tok_test", "vercel_project_id": "prj_dup"}
        create_integration(
            user_id=test_user.id,
            provider="vercel",
            display_name="First",
            credentials=creds,
            db=db_session,
        )

        with pytest.raises(ValueError, match="already connected"):
            create_integration(
                user_id=test_user.id,
                provider="vercel",
                display_name="Second",
                credentials=creds,
                db=db_session,
            )

    @patch("app.connectors.vercel.VercelConnector.validate_credentials")
    def test_auth_error_propagates(self, mock_validate, db_session, test_user):
        mock_validate.side_effect = AuthenticationError("bad token")
        from app.services.integration_service import create_integration

        with pytest.raises(AuthenticationError):
            create_integration(
                user_id=test_user.id,
                provider="vercel",
                display_name="Fail",
                credentials={"vercel_token": "bad", "vercel_project_id": "prj_x"},
                db=db_session,
            )


# ─────────────────────────────────────────────────────────────────────────────
# 9. Reconnect credentials — vercel provider
# ─────────────────────────────────────────────────────────────────────────────


class TestReconnectVercel:
    @patch("app.connectors.vercel.VercelConnector.validate_credentials", return_value=True)
    def test_reconnect_replaces_token(self, mock_validate, db_session, test_user):
        from app.services.integration_service import create_integration, reconnect_credentials
        from app.core.encryption import decrypt_credentials

        # Create an integration first
        with patch("app.connectors.vercel.VercelConnector.validate_credentials", return_value=True):
            integration = create_integration(
                user_id=test_user.id,
                provider="vercel",
                display_name="Test Vercel Reconnect",
                credentials={
                    "vercel_token": "tok_old",
                    "vercel_project_id": "prj_reconnect",
                },
                db=db_session,
            )

        # Now reconnect with a new token
        updated = reconnect_credentials(
            integration_id=integration.id,
            user_id=test_user.id,
            new_token="tok_new",
            db=db_session,
        )

        # Decrypt and verify
        creds = decrypt_credentials(
            updated.encrypted_credentials,
            updated.credential_iv,
        )
        assert creds["vercel_token"] == "tok_new"
        assert creds["vercel_project_id"] == "prj_reconnect"  # unchanged


# ─────────────────────────────────────────────────────────────────────────────
# 10. Sync task: vercel provider branch (unit-level)
# ─────────────────────────────────────────────────────────────────────────────


class TestSyncTaskVercelBranch:
    """Verify the sync_task routes to VercelConnector for vercel integrations."""

    @patch("app.connectors.vercel.VercelConnector.validate_credentials", return_value=True)
    def test_sync_task_uses_vercel_connector(self, mock_validate, db_session, test_user):
        from app.services.integration_service import create_integration
        from app.models.resource import Resource
        from app.workers.sync_task import sync_integration

        # Create the integration
        with patch("app.connectors.vercel.VercelConnector.validate_credentials", return_value=True):
            integration = create_integration(
                user_id=test_user.id,
                provider="vercel",
                display_name="Sync Test Vercel",
                credentials={
                    "vercel_token": "tok_sync",
                    "vercel_project_id": "prj_sync",
                },
                db=db_session,
            )

        resource = (
            db_session.query(Resource)
            .filter(Resource.integration_id == integration.id)
            .first()
        )
        assert resource is not None

        # Create a SyncRun
        from app.services.sync_service import create_sync_run
        run = create_sync_run(
            user_id=test_user.id,
            integration_id=integration.id,
            db=db_session,
        )

        # Patch VercelConnector.fetch and snapshot service
        mock_records = [
            {
                "record_id": "prj_sync",
                "record_type": VERCEL_PROJECT,
                "name": "my-project",
                "framework": "nextjs",
                "build_command": None,
                "output_directory": None,
                "root_directory": None,
                "node_version": "20.x",
            }
        ]
        with (
            patch(
                "app.connectors.vercel.VercelConnector.fetch",
                return_value=mock_records,
            ),
            patch(
                "app.services.snapshot_service.store_snapshot",
                return_value=(MagicMock(id=uuid.uuid4()), False),
            ),
            patch(
                "app.services.snapshot_service.get_latest_snapshot",
                return_value=None,
            ),
            patch(
                "app.services.alert_service.dispatch_alerts_for_sync",
                return_value={"eligible": 0, "already_alerted": 0, "sent": 0, "recorded": 0, "failed": 0},
            ),
        ):
            result = sync_integration.apply(
                args=(str(run.id), str(integration.id), str(test_user.id))
            )

        assert result.successful(), f"Sync task failed: {result.result}"

        db_session.expire_all()
        from app.models.integration import Integration as IntegrationModel
        refreshed = db_session.get(IntegrationModel, integration.id)
        assert refreshed is not None
        assert refreshed.consecutive_failure_count == 0


# ─────────────────────────────────────────────────────────────────────────────
# 11. Risk service dispatch: vercel_ types route to Vercel rules
# ─────────────────────────────────────────────────────────────────────────────


class TestRiskServiceDispatch:
    def test_vercel_env_var_dispatches_to_vercel_rules(self):
        from app.services.risk_service import classify_change
        change = {
            "change_type": "removed",
            "field_path": None,
            "prev_value": {"target": ["production"], "key": "DATABASE_URL"},
            "new_value": None,
            "provider_metadata": {
                "record_type": "vercel_env_var",
                "record_name": "DATABASE_URL",
            },
        }
        level, reason = classify_change(change)
        assert level == "critical"
        assert "production" in reason.lower() or "sensitive" in reason.lower()

    def test_vercel_domain_dispatches_to_vercel_rules(self):
        from app.services.risk_service import classify_change
        change = {
            "change_type": "removed",
            "field_path": None,
            "prev_value": {"name": "app.example.com"},
            "new_value": None,
            "provider_metadata": {
                "record_type": "vercel_domain",
                "record_name": "app.example.com",
            },
        }
        level, _ = classify_change(change)
        assert level == "critical"

    def test_github_still_dispatches_to_github_rules(self):
        from app.services.risk_service import classify_change
        change = {
            "change_type": "modified",
            "field_path": "visibility",
            "prev_value": "private",
            "new_value": "public",
            "provider_metadata": {
                "record_type": "github_repo_settings",
                "record_name": "my-repo",
            },
        }
        level, _ = classify_change(change)
        assert level in ("critical", "high", "medium", "low")

    def test_cloudflare_still_dispatches_to_dns_rules(self):
        from app.services.risk_service import classify_change
        change = {
            "change_type": "removed",
            "field_path": None,
            "prev_value": None,
            "new_value": None,
            "provider_metadata": {
                "record_type": "A",
                "record_name": "api.example.com",
            },
        }
        level, _ = classify_change(change)
        assert level in ("critical", "high", "medium", "low")


# ─────────────────────────────────────────────────────────────────────────────
# 12. Vercel risk classification — precision pass (M33 risk matrix)
# ─────────────────────────────────────────────────────────────────────────────


class TestVercelRiskPrecision:
    """Comprehensive risk matrix tests covering all normalized record types/fields.

    Each test drives a specific (record_type, field_path, change_type, value
    direction) combination and asserts the expected risk level AND that the
    reason string is human-readable (not empty, mentions what changed).
    """

    def _change(
        self,
        change_type: str,
        record_type: str,
        record_name: str = "",
        field_path: str | None = None,
        prev_value=None,
        new_value=None,
        record_content: dict | None = None,
    ) -> dict:
        meta: dict = {"record_type": record_type, "record_name": record_name}
        if record_content is not None:
            meta["record_content"] = record_content
        return {
            "change_type": change_type,
            "field_path": field_path,
            "prev_value": prev_value,
            "new_value": new_value,
            "provider_metadata": meta,
        }

    def _assert(self, change: dict, expected_level: str, *, reason_contains: str = "") -> None:
        """Helper: classify change, assert level, optionally assert reason substring."""
        level, reason = classify_vercel_change(change)
        assert level == expected_level, (
            f"Expected {expected_level!r}, got {level!r}. Reason: {reason}"
        )
        assert reason, "Risk reason must not be empty."
        if reason_contains:
            assert reason_contains.lower() in reason.lower(), (
                f"Expected reason to contain {reason_contains!r}. Got: {reason}"
            )

    # ── vercel_project: build pipeline ───────────────────────────────────────

    def test_build_command_changed_is_high(self):
        self._assert(
            self._change("modified", VERCEL_PROJECT, field_path="build_command",
                         prev_value=None, new_value="npm run build:prod"),
            "high", reason_contains="build command",
        )

    def test_install_command_changed_is_high(self):
        self._assert(
            self._change("modified", VERCEL_PROJECT, field_path="install_command",
                         prev_value=None, new_value="npm ci --ignore-scripts"),
            "high", reason_contains="install command",
        )

    def test_install_command_cleared_is_high(self):
        """Removing a custom install command (reverting to default) is also High."""
        self._assert(
            self._change("modified", VERCEL_PROJECT, field_path="install_command",
                         prev_value="npm ci", new_value=None),
            "high", reason_contains="install command",
        )

    def test_root_directory_changed_is_high(self):
        self._assert(
            self._change("modified", VERCEL_PROJECT, field_path="root_directory",
                         prev_value=None, new_value="apps/web"),
            "high", reason_contains="root directory",
        )

    def test_root_directory_cleared_is_high(self):
        self._assert(
            self._change("modified", VERCEL_PROJECT, field_path="root_directory",
                         prev_value="apps/web", new_value=None),
            "high", reason_contains="root directory",
        )

    def test_output_directory_changed_is_medium(self):
        self._assert(
            self._change("modified", VERCEL_PROJECT, field_path="output_directory",
                         prev_value=None, new_value="dist"),
            "medium", reason_contains="output directory",
        )

    # ── vercel_project: framework / runtime ──────────────────────────────────

    def test_framework_changed_is_high(self):
        """Framework preset change alters build strategy and routing — High."""
        self._assert(
            self._change("modified", VERCEL_PROJECT, field_path="framework",
                         prev_value="nextjs", new_value="remix"),
            "high", reason_contains="framework",
        )

    def test_framework_cleared_is_high(self):
        """Unsetting framework preset is High (changes build detection)."""
        self._assert(
            self._change("modified", VERCEL_PROJECT, field_path="framework",
                         prev_value="nextjs", new_value=None),
            "high", reason_contains="framework",
        )

    def test_node_version_changed_is_medium(self):
        self._assert(
            self._change("modified", VERCEL_PROJECT, field_path="node_version",
                         prev_value="18.x", new_value="20.x"),
            "medium", reason_contains="node",
        )

    # ── vercel_project: identity ──────────────────────────────────────────────

    def test_project_renamed_is_medium(self):
        self._assert(
            self._change("modified", VERCEL_PROJECT, record_name="old-project",
                         field_path="name", prev_value="old-project", new_value="new-project"),
            "medium", reason_contains="name",
        )

    # ── vercel_project: git connection ────────────────────────────────────────

    def test_production_branch_changed_is_high(self):
        """Production branch change determines which commits get deployed — High."""
        self._assert(
            self._change("modified", VERCEL_PROJECT, field_path="git_branch",
                         prev_value="main", new_value="staging"),
            "high", reason_contains="production branch",
        )

    def test_git_repository_changed_is_high(self):
        """Changing the connected repo is a significant supply-chain event — High."""
        self._assert(
            self._change("modified", VERCEL_PROJECT, field_path="git_repository",
                         prev_value="acme/app", new_value="acme/app-fork"),
            "high", reason_contains="repository",
        )

    # ── vercel_project: deployment protection ─────────────────────────────────

    def test_sso_protection_disabled_is_critical(self):
        """SSO protection removed — deployments may become publicly accessible — Critical."""
        self._assert(
            self._change("modified", VERCEL_PROJECT, record_name="my-app",
                         field_path="sso_protection",
                         prev_value="all", new_value=None),
            "critical", reason_contains="sso",
        )

    def test_sso_protection_enabled_is_low(self):
        """SSO protection added — security hardening — Low."""
        self._assert(
            self._change("modified", VERCEL_PROJECT, record_name="my-app",
                         field_path="sso_protection",
                         prev_value=None, new_value="all"),
            "low", reason_contains="sso",
        )

    def test_sso_protection_scope_changed_is_medium(self):
        """SSO protection scope narrowed (preview → all still active) — Medium."""
        self._assert(
            self._change("modified", VERCEL_PROJECT, record_name="my-app",
                         field_path="sso_protection",
                         prev_value="preview", new_value="all"),
            "medium",
        )

    def test_password_protection_disabled_is_high(self):
        """Password protection removed — deployments may become accessible — High."""
        self._assert(
            self._change("modified", VERCEL_PROJECT, record_name="my-app",
                         field_path="password_protection",
                         prev_value="all", new_value=None),
            "high", reason_contains="password protection",
        )

    def test_password_protection_enabled_is_low(self):
        """Password protection added — security hardening — Low."""
        self._assert(
            self._change("modified", VERCEL_PROJECT, record_name="my-app",
                         field_path="password_protection",
                         prev_value=None, new_value="all"),
            "low", reason_contains="password protection",
        )

    def test_project_routine_field_change_is_low(self):
        """Unknown project field change falls through to Low catch-all."""
        level, reason = classify_vercel_change(self._change(
            "modified", VERCEL_PROJECT, field_path="some_future_field",
            prev_value="a", new_value="b",
        ))
        assert level == "low"
        assert reason

    # ── vercel_env_var: removed ───────────────────────────────────────────────

    def test_sensitive_env_var_removed_from_prod_is_critical(self):
        self._assert(
            self._change("removed", VERCEL_ENV_VAR, record_name="DATABASE_URL",
                         prev_value={"target": ["production"], "key": "DATABASE_URL"}),
            "critical", reason_contains="production",
        )

    def test_nonsensitive_env_var_removed_from_prod_is_high(self):
        self._assert(
            self._change("removed", VERCEL_ENV_VAR, record_name="FEATURE_FLAG",
                         prev_value={"target": ["production"], "key": "FEATURE_FLAG"}),
            "high", reason_contains="production",
        )

    def test_sensitive_env_var_removed_from_preview_is_medium(self):
        self._assert(
            self._change("removed", VERCEL_ENV_VAR, record_name="DATABASE_URL",
                         prev_value={"target": ["preview"], "key": "DATABASE_URL"}),
            "medium",
        )

    def test_env_var_removed_from_development_is_medium(self):
        self._assert(
            self._change("removed", VERCEL_ENV_VAR, record_name="DEBUG",
                         prev_value={"target": ["development"], "key": "DEBUG"}),
            "medium",
        )

    # ── vercel_env_var: added ─────────────────────────────────────────────────

    def test_sensitive_env_var_added_to_prod_is_medium(self):
        """Adding (not removing) a secret to prod is medium — new capability, not breakage."""
        self._assert(
            self._change("added", VERCEL_ENV_VAR, record_name="STRIPE_SECRET_KEY",
                         new_value={"target": ["production"], "key": "STRIPE_SECRET_KEY"}),
            "medium", reason_contains="production",
        )

    def test_nonsensitive_env_var_added_to_prod_is_medium(self):
        self._assert(
            self._change("added", VERCEL_ENV_VAR, record_name="ENABLE_FEATURE",
                         new_value={"target": ["production"], "key": "ENABLE_FEATURE"}),
            "medium",
        )

    def test_sensitive_env_var_added_to_preview_is_low(self):
        self._assert(
            self._change("added", VERCEL_ENV_VAR, record_name="DATABASE_URL",
                         new_value={"target": ["preview"], "key": "DATABASE_URL"}),
            "low",
        )

    def test_env_var_added_to_development_is_low(self):
        self._assert(
            self._change("added", VERCEL_ENV_VAR, record_name="LOG_LEVEL",
                         new_value={"target": ["development"], "key": "LOG_LEVEL"}),
            "low",
        )

    # ── vercel_env_var: modified — target ─────────────────────────────────────

    def test_env_var_promoted_to_production_is_high(self):
        self._assert(
            self._change("modified", VERCEL_ENV_VAR, record_name="DATABASE_URL",
                         field_path="target",
                         prev_value=["development"], new_value=["production"]),
            "high", reason_contains="promoted",
        )

    def test_env_var_demoted_from_production_is_high(self):
        self._assert(
            self._change("modified", VERCEL_ENV_VAR, record_name="DATABASE_URL",
                         field_path="target",
                         prev_value=["production"], new_value=["development"]),
            "high", reason_contains="production",
        )

    def test_env_var_target_changed_neither_prod_is_medium(self):
        self._assert(
            self._change("modified", VERCEL_ENV_VAR, record_name="DEBUG",
                         field_path="target",
                         prev_value=["development"], new_value=["preview", "development"]),
            "medium",
        )

    # ── vercel_env_var: modified — updated_at ────────────────────────────────

    def test_sensitive_env_var_updated_at_is_high(self):
        self._assert(
            self._change("modified", VERCEL_ENV_VAR, record_name="JWT_SECRET",
                         field_path="updated_at",
                         prev_value=1700000000000, new_value=1700005000000),
            "high", reason_contains="rotated",
        )

    def test_nonsensitive_env_var_updated_at_is_medium(self):
        self._assert(
            self._change("modified", VERCEL_ENV_VAR, record_name="FEATURE_FLAG",
                         field_path="updated_at",
                         prev_value=1700000000000, new_value=1700005000000),
            "medium",
        )

    # ── vercel_env_var: modified — env_type ──────────────────────────────────

    def test_env_type_downgrade_encrypted_to_plain_is_high(self):
        self._assert(
            self._change("modified", VERCEL_ENV_VAR, record_name="API_KEY",
                         field_path="env_type",
                         prev_value="encrypted", new_value="plain"),
            "high", reason_contains="plaintext",
        )

    def test_env_type_downgrade_secret_to_plain_is_high(self):
        self._assert(
            self._change("modified", VERCEL_ENV_VAR, record_name="DB_PASSWORD",
                         field_path="env_type",
                         prev_value="secret", new_value="plain"),
            "high", reason_contains="plaintext",
        )

    def test_env_type_upgrade_plain_to_encrypted_is_low(self):
        """Upgrading encryption is a security hardening — Low."""
        self._assert(
            self._change("modified", VERCEL_ENV_VAR, record_name="DB_PASSWORD",
                         field_path="env_type",
                         prev_value="plain", new_value="encrypted"),
            "low", reason_contains="encrypted",
        )

    def test_env_type_other_change_is_medium(self):
        self._assert(
            self._change("modified", VERCEL_ENV_VAR, record_name="SOME_VAR",
                         field_path="env_type",
                         prev_value="system", new_value="plain"),
            "medium",
        )

    # ── vercel_env_var: modified — key rename / git_branch ───────────────────

    def test_env_var_renamed_is_medium(self):
        self._assert(
            self._change("modified", VERCEL_ENV_VAR, record_name="OLD_KEY",
                         field_path="key",
                         prev_value="OLD_KEY", new_value="NEW_KEY"),
            "medium", reason_contains="renamed",
        )

    def test_env_var_git_branch_changed_is_medium(self):
        self._assert(
            self._change("modified", VERCEL_ENV_VAR, record_name="NEXT_PUBLIC_API_URL",
                         field_path="git_branch",
                         prev_value="feature/old", new_value="feature/new"),
            "medium", reason_contains="branch",
        )

    # ── vercel_domain: removed ────────────────────────────────────────────────

    def test_production_domain_removed_is_critical(self):
        """Custom domain without git_branch = production domain — Critical."""
        self._assert(
            self._change("removed", VERCEL_DOMAIN, record_name="app.example.com",
                         prev_value={"git_branch": None, "name": "app.example.com"}),
            "critical", reason_contains="production domain",
        )

    def test_preview_domain_removed_is_medium(self):
        """Branch-specific domain removed — Medium (scoped to one branch)."""
        self._assert(
            self._change("removed", VERCEL_DOMAIN, record_name="feature-foo.example.com",
                         prev_value={"git_branch": "feature/foo", "name": "feature-foo.example.com"}),
            "medium",
        )

    def test_domain_removed_no_context_is_critical(self):
        """Domain removed with no context dict — treated as production (conservative)."""
        self._assert(
            self._change("removed", VERCEL_DOMAIN, record_name="unknown.example.com",
                         prev_value=None),
            "critical",
        )

    # ── vercel_domain: added ──────────────────────────────────────────────────

    def test_custom_domain_added_is_medium(self):
        """Custom domain without git_branch — medium (needs DNS + SSL verification)."""
        self._assert(
            self._change("added", VERCEL_DOMAIN, record_name="app.example.com",
                         new_value={"git_branch": None, "name": "app.example.com"}),
            "medium", reason_contains="dns",
        )

    def test_preview_domain_added_is_low(self):
        """Preview branch domain added — Low (routine branch setup)."""
        self._assert(
            self._change("added", VERCEL_DOMAIN, record_name="pr-42.example.com",
                         new_value={"git_branch": "feature/pr-42", "name": "pr-42.example.com"}),
            "low",
        )

    # ── vercel_domain: modified — verified ───────────────────────────────────

    def test_domain_verified_true_to_false_is_high(self):
        self._assert(
            self._change("modified", VERCEL_DOMAIN, record_name="app.example.com",
                         field_path="verified", prev_value=True, new_value=False),
            "high", reason_contains="verified",
        )

    def test_domain_verified_false_to_true_is_low(self):
        self._assert(
            self._change("modified", VERCEL_DOMAIN, record_name="app.example.com",
                         field_path="verified", prev_value=False, new_value=True),
            "low", reason_contains="verified",
        )

    # ── vercel_domain: modified — redirect ───────────────────────────────────

    def test_production_domain_redirect_changed_is_high(self):
        """Redirect on a production (no git_branch) domain is High."""
        self._assert(
            self._change(
                "modified", VERCEL_DOMAIN, record_name="app.example.com",
                field_path="redirect",
                prev_value="old.example.com", new_value="new.example.com",
                record_content={"git_branch": None, "name": "app.example.com"},
            ),
            "high", reason_contains="redirect",
        )

    def test_production_domain_redirect_removed_is_medium(self):
        """Removing a redirect (reverting to direct resolution) is Medium."""
        self._assert(
            self._change(
                "modified", VERCEL_DOMAIN, record_name="app.example.com",
                field_path="redirect",
                prev_value="other.example.com", new_value=None,
                record_content={"git_branch": None, "name": "app.example.com"},
            ),
            "medium", reason_contains="redirect",
        )

    def test_preview_domain_redirect_changed_is_medium(self):
        """Redirect change on a branch domain is Medium."""
        self._assert(
            self._change(
                "modified", VERCEL_DOMAIN, record_name="branch.example.com",
                field_path="redirect",
                prev_value="old.example.com", new_value="new.example.com",
                record_content={"git_branch": "feature/foo", "name": "branch.example.com"},
            ),
            "medium",
        )

    def test_domain_git_branch_changed_is_low(self):
        """Domain reassigned to a different branch — Low (preview scope change)."""
        self._assert(
            self._change("modified", VERCEL_DOMAIN, record_name="branch.example.com",
                         field_path="git_branch",
                         prev_value="feature/old", new_value="feature/new"),
            "low",
        )

    # ── catch-all ─────────────────────────────────────────────────────────────

    def test_unknown_vercel_record_type_is_low(self):
        level, reason = classify_vercel_change(self._change(
            "modified", "vercel_future_record_type",
            field_path="some_field", prev_value="a", new_value="b",
        ))
        assert level == "low"
        assert reason

    # ── sensitive env var name patterns ──────────────────────────────────────

    def test_next_public_env_var_is_sensitive(self):
        """NEXT_PUBLIC_ prefix exposes values in the client bundle — treat as sensitive."""
        level, _ = classify_vercel_change(self._change(
            "removed", VERCEL_ENV_VAR, record_name="NEXT_PUBLIC_CLERK_KEY",
            prev_value={"target": ["production"], "key": "NEXT_PUBLIC_CLERK_KEY"},
        ))
        assert level == "critical"

    def test_auth_env_var_is_sensitive(self):
        level, _ = classify_vercel_change(self._change(
            "removed", VERCEL_ENV_VAR, record_name="AUTH_SECRET",
            prev_value={"target": ["production"], "key": "AUTH_SECRET"},
        ))
        assert level == "critical"

    def test_url_env_var_is_sensitive(self):
        """URLs often contain embedded credentials (postgres://user:pass@host)."""
        level, _ = classify_vercel_change(self._change(
            "removed", VERCEL_ENV_VAR, record_name="DATABASE_URL",
            prev_value={"target": ["production"], "key": "DATABASE_URL"},
        ))
        assert level == "critical"

    def test_session_env_var_is_sensitive(self):
        level, _ = classify_vercel_change(self._change(
            "removed", VERCEL_ENV_VAR, record_name="SESSION_SECRET",
            prev_value={"target": ["production"], "key": "SESSION_SECRET"},
        ))
        assert level == "critical"

    def test_jwt_env_var_is_sensitive(self):
        level, _ = classify_vercel_change(self._change(
            "removed", VERCEL_ENV_VAR, record_name="JWT_SECRET",
            prev_value={"target": ["production"], "key": "JWT_SECRET"},
        ))
        assert level == "critical"

    # ── risk reason quality ───────────────────────────────────────────────────

    def test_all_risk_reasons_are_human_readable(self):
        """Spot-check: every classified change produces a non-empty sentence."""
        cases = [
            self._change("removed", VERCEL_ENV_VAR, record_name="X", prev_value={"target": ["production"]}),
            self._change("added", VERCEL_PROJECT, field_path="build_command", new_value="npm run build"),
            self._change("removed", VERCEL_DOMAIN, record_name="app.test.com", prev_value={"git_branch": None}),
            self._change("modified", VERCEL_PROJECT, field_path="sso_protection", prev_value="all", new_value=None),
        ]
        for change in cases:
            level, reason = classify_vercel_change(change)
            assert reason, f"Empty reason for change: {change}"
            assert reason[0].isupper(), f"Reason should start with capital letter: {reason!r}"
            assert len(reason) > 20, f"Reason too short (probably a placeholder): {reason!r}"
