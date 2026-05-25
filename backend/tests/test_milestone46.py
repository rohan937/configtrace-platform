"""Tests for Milestone 46: AWS ECS/EKS/ECR Container Platform Config.

Covers:
- Security hard rules: no GetLogEvents, no K8s API, no GetAuthorizationToken,
  no env values stored, no image layers pulled
- Schema registration: all 9 M46 types in AWS_RECORD_TYPES
- Diff service tracked field registration for all 9 M46 types
- Risk classification: aws_ecs_cluster, aws_ecs_service, aws_ecs_task_definition
- Risk classification: aws_eks_cluster, aws_eks_node_group, aws_eks_fargate_profile,
  aws_eks_addon
- Risk classification: aws_ecr_repository, aws_ecr_registry_scanning_config
- Failure classification: classify_aws_ecs_failure, classify_aws_eks_failure,
  classify_aws_ecr_failure
- Connector normalization: _fetch_ecs_in_region, _fetch_eks_in_region,
  _fetch_ecr_in_region
- Helper functions: _ecs_env_key_info, _ecr_policy_is_public,
  _eks_public_access_cidrs_open, _classify_container_name_sensitivity
- Service inventory: ecs, eks, ecr in enabled_surfaces (not future_surfaces)
- Fail-soft: per-region errors do not abort full fetch
- M45 regression guard: M45 record types still classified correctly
"""

import inspect
import pytest
from unittest.mock import MagicMock, patch, call

from app.connectors.aws import (
    AWSConnector,
    _hash_kms_key_id,
    _extract_tag_keys,
    _classify_container_name_sensitivity,
    _ecs_env_key_info,
    _ecr_policy_is_public,
    _eks_public_access_cidrs_open,
    _ecs_secret_ref_count,
)
from app.connectors.aws_schema import (
    AWS_ECS_CLUSTER,
    AWS_ECS_SERVICE,
    AWS_ECS_TASK_DEFINITION,
    AWS_EKS_CLUSTER,
    AWS_EKS_NODE_GROUP,
    AWS_EKS_FARGATE_PROFILE,
    AWS_EKS_ADDON,
    AWS_ECR_REPOSITORY,
    AWS_ECR_REGISTRY_SCANNING_CONFIG,
    AWS_SERVICE_INVENTORY,
    AWS_SECURITYHUB_ACCOUNT,     # M45 regression
    AWS_CLOUDTRAIL_TRAIL,        # M45 regression
    AWS_GUARDDUTY_DETECTOR,      # M45 regression
    AWS_RECORD_TYPES,
)
from app.services.diff_service import _tracked_fields_for
from app.services.risk_rules.aws import classify_aws_change
from app.core.failure_classifier import (
    classify_aws_ecs_failure,
    classify_aws_eks_failure,
    classify_aws_ecr_failure,
)
from app.connectors.exceptions import (
    ConnectorError,
    AuthenticationError,
    RateLimitError,
    NetworkError,
)


# ─────────────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_connector():
    """Create an AWSConnector without calling __init__ (no DB needed)."""
    return AWSConnector.__new__(AWSConnector)


def _creds(regions=None):
    return {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_default_region": "us-east-1",
        "aws_selected_regions": regions or ["us-east-1"],
    }


def _ecs_change(
    record_type=AWS_ECS_CLUSTER,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="my-cluster",
):
    return {
        "record_type": record_type,
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
        },
    }


def _eks_change(
    record_type=AWS_EKS_CLUSTER,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="my-eks-cluster",
):
    return {
        "record_type": record_type,
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
        },
    }


def _ecr_change(
    record_type=AWS_ECR_REPOSITORY,
    change_type="modified",
    field_path=None,
    new_value=None,
    prev_value=None,
    record_name="my-repo",
):
    return {
        "record_type": record_type,
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "provider_metadata": {
            "record_type": record_type,
            "record_name": record_name,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. Security hard rules
# ─────────────────────────────────────────────────────────────────────────────

class TestM46SecurityHardRules:
    """Verify that forbidden API calls never appear in ECS/EKS/ECR connector code."""

    def _code_lines_of(self, method_name: str) -> str:
        """Return source code with docstring/comment lines stripped out."""
        import re
        conn = _make_connector()
        method = getattr(conn, method_name, None)
        if method is None:
            return ""
        src = inspect.getsource(method)
        # Strip triple-quoted docstrings
        src = re.sub(r'""".*?"""', '', src, flags=re.DOTALL)
        # Strip single-line comments
        src = "\n".join(
            line for line in src.splitlines()
            if not line.strip().startswith("#")
        )
        return src

    def test_ecs_no_get_log_events(self):
        """logs:GetLogEvents must never be called in ECS connector code."""
        code = self._code_lines_of("_fetch_ecs_in_region")
        assert "get_log_events" not in code.lower(), (
            "get_log_events must never be called in ECS connector code"
        )

    def test_ecs_no_env_values(self):
        """ECS connector must never access 'value' from environment dict."""
        src = self._code_lines_of("_fetch_ecs_in_region")
        # The env key extractor only accesses 'name', not 'value'
        assert 'item["value"]' not in src
        assert "env_vars.values()" not in src

    def test_eks_no_kubernetes_api(self):
        """EKS connector must never call Kubernetes API endpoints."""
        code_in = self._code_lines_of("_fetch_eks_in_region")
        code_res = self._code_lines_of("_fetch_eks_resources")
        full_code = code_in + code_res
        # No direct k8s API calls
        forbidden = ["list_pods", "list_secrets", "list_config_maps", "list_events"]
        for call_name in forbidden:
            assert call_name not in full_code, (
                f"{call_name} must never be called in EKS connector"
            )

    def test_ecr_no_get_authorization_token(self):
        """ecr:GetAuthorizationToken must never be called in ECR connector code."""
        code = self._code_lines_of("_fetch_ecr_in_region")
        assert "get_authorization_token" not in code.lower(), (
            "get_authorization_token must never be called in ECR connector code"
        )

    def test_ecr_no_get_download_url_for_layer(self):
        """ecr:GetDownloadUrlForLayer must never appear in ECR connector code."""
        code = self._code_lines_of("_fetch_ecr_in_region")
        assert "GetDownloadUrlForLayer" not in code
        assert "BatchGetImage" not in code

    def test_ecr_raw_policy_not_stored(self):
        """Raw ECR repository policy JSON must never be stored in the record."""
        code = self._code_lines_of("_fetch_ecr_in_region")
        # The function must call _ecr_policy_is_public but not store raw_policy
        assert "_ecr_policy_is_public" in code
        # Ensure raw_policy is not put into the record dict
        assert '"raw_policy"' not in code
        assert "'raw_policy'" not in code

    def test_ecs_secret_ref_count_only(self):
        """ECS connector stores only secret ref count, not ARNs or names."""
        code = self._code_lines_of("_fetch_ecs_in_region")
        assert "_ecs_secret_ref_count" in code
        # Make sure we store secret_ref_count not secret_arns
        assert "secret_arns" not in code
        assert "valueFrom" not in code  # The ARN field must not be stored


# ─────────────────────────────────────────────────────────────────────────────
# 2. Schema registration
# ─────────────────────────────────────────────────────────────────────────────

class TestM46SchemaRegistration:
    """All 9 M46 record types must be registered in AWS_RECORD_TYPES."""

    _M46_TYPES = [
        AWS_ECS_CLUSTER,
        AWS_ECS_SERVICE,
        AWS_ECS_TASK_DEFINITION,
        AWS_EKS_CLUSTER,
        AWS_EKS_NODE_GROUP,
        AWS_EKS_FARGATE_PROFILE,
        AWS_EKS_ADDON,
        AWS_ECR_REPOSITORY,
        AWS_ECR_REGISTRY_SCANNING_CONFIG,
    ]

    @pytest.mark.parametrize("rt", _M46_TYPES)
    def test_record_type_in_aws_record_types(self, rt):
        assert rt in AWS_RECORD_TYPES, f"{rt} not in AWS_RECORD_TYPES"

    def test_all_nine_types_registered(self):
        assert len(self._M46_TYPES) == 9
        for rt in self._M46_TYPES:
            assert rt in AWS_RECORD_TYPES


# ─────────────────────────────────────────────────────────────────────────────
# 3. Diff service tracked fields
# ─────────────────────────────────────────────────────────────────────────────

class TestM46TrackedFields:
    """Every M46 record type must have tracked fields registered."""

    def _fields(self, rt: str) -> tuple:
        return _tracked_fields_for({"record_type": rt})

    def test_ecs_cluster_tracked_fields(self):
        fields = self._fields(AWS_ECS_CLUSTER)
        assert len(fields) > 0
        assert "container_insights_enabled" in fields
        assert "status" in fields
        assert "has_fargate_capacity" in fields
        assert "tag_keys" in fields
        # SECURITY: must not track task logs or env values
        assert "task_logs" not in fields
        assert "env_values" not in fields

    def test_ecs_service_tracked_fields(self):
        fields = self._fields(AWS_ECS_SERVICE)
        assert "has_public_ip" in fields
        assert "circuit_breaker_enabled" in fields
        assert "desired_count" in fields
        assert "task_definition_arn_hash" in fields
        # Raw ARNs must not be tracked
        assert "task_definition_arn" not in fields

    def test_ecs_task_definition_tracked_fields(self):
        fields = self._fields(AWS_ECS_TASK_DEFINITION)
        assert "has_privileged_container" in fields
        assert "secret_ref_count" in fields
        assert "env_key_count" in fields
        assert "env_sensitive_key_count" in fields
        assert "task_role_arn_hash" in fields
        assert "execution_role_arn_hash" in fields
        # SECURITY: must not track raw env values or secret values
        assert "env_values" not in fields
        assert "env_key_values" not in fields
        assert "secret_values" not in fields
        # Raw ARNs must not be tracked
        assert "task_role_arn" not in fields
        assert "execution_role_arn" not in fields

    def test_eks_cluster_tracked_fields(self):
        fields = self._fields(AWS_EKS_CLUSTER)
        assert "endpoint_public_access" in fields
        assert "endpoint_private_access" in fields
        assert "public_access_fully_open" in fields
        assert "secrets_encryption_enabled" in fields
        assert "has_audit_logging" in fields
        assert "kubernetes_version" in fields
        assert "kms_key_hash" in fields
        # SECURITY: must not track raw CIDR lists or subnet IDs
        assert "public_access_cidrs_raw" not in fields
        assert "subnet_ids" not in fields

    def test_eks_node_group_tracked_fields(self):
        fields = self._fields(AWS_EKS_NODE_GROUP)
        assert "ssh_unrestricted" in fields
        assert "has_remote_access" in fields
        assert "ami_type" in fields
        assert "capacity_type" in fields
        assert "node_role_arn_hash" in fields
        assert "node_role_arn" not in fields

    def test_eks_fargate_profile_tracked_fields(self):
        fields = self._fields(AWS_EKS_FARGATE_PROFILE)
        assert "status" in fields
        assert "selector_count" in fields
        assert "selector_namespaces" in fields
        assert "pod_execution_role_arn_hash" in fields
        assert "pod_execution_role_arn" not in fields

    def test_eks_addon_tracked_fields(self):
        fields = self._fields(AWS_EKS_ADDON)
        assert "status" in fields
        assert "addon_version" in fields
        assert "service_account_role_hash" in fields
        assert "service_account_role_arn" not in fields

    def test_ecr_repository_tracked_fields(self):
        fields = self._fields(AWS_ECR_REPOSITORY)
        assert "policy_is_public" in fields
        assert "scan_on_push" in fields
        assert "tag_immutable" in fields
        assert "lifecycle_policy_present" in fields
        assert "kms_key_hash" in fields
        # SECURITY: raw policy JSON must not be tracked
        assert "policy_json" not in fields
        assert "raw_policy" not in fields
        assert "kms_key_id" not in fields

    def test_ecr_registry_scanning_config_tracked_fields(self):
        fields = self._fields(AWS_ECR_REGISTRY_SCANNING_CONFIG)
        assert "scan_type" in fields
        assert "rule_count" in fields
        assert "repo_filter_count" in fields
        assert "scan_frequency_types" in fields


# ─────────────────────────────────────────────────────────────────────────────
# 4. Helper functions
# ─────────────────────────────────────────────────────────────────────────────

class TestM46HelperFunctions:
    """Unit tests for M46 pure helper functions."""

    # _ecs_env_key_info
    def test_ecs_env_key_info_empty(self):
        keys, count, sensitive = _ecs_env_key_info([])
        assert keys == []
        assert count == 0
        assert sensitive == 0

    def test_ecs_env_key_info_never_reads_value(self):
        """Ensure values are never touched even if present."""
        env = [
            {"name": "APP_NAME", "value": "my-super-secret-value-NEVER-STORE-THIS"},
            {"name": "DB_PASSWORD", "value": "hunter2-NEVER-STORE-THIS"},
        ]
        keys, count, sensitive = _ecs_env_key_info(env)
        assert "APP_NAME" in keys
        assert "DB_PASSWORD" in keys
        assert count == 2
        assert sensitive >= 1  # DB_PASSWORD is sensitive (contains 'password')
        # Values must not appear in the returned data at all
        result_str = str(keys) + str(count) + str(sensitive)
        assert "hunter2" not in result_str
        assert "my-super-secret-value" not in result_str

    def test_ecs_env_key_info_sensitive_detection(self):
        env = [
            {"name": "LOG_LEVEL", "value": "info"},
            {"name": "DATABASE_URL", "value": "postgres://NEVER-STORE"},
            {"name": "API_KEY", "value": "sk-NEVER-STORE"},
            {"name": "MAX_RETRIES", "value": "3"},
        ]
        keys, count, sensitive = _ecs_env_key_info(env)
        assert count == 4
        assert sensitive >= 2  # DATABASE_URL and API_KEY are sensitive

    def test_ecs_env_key_info_sorted(self):
        env = [{"name": "Z_VAR"}, {"name": "A_VAR"}, {"name": "M_VAR"}]
        keys, count, _ = _ecs_env_key_info(env)
        assert keys == ["A_VAR", "M_VAR", "Z_VAR"]

    # _ecs_secret_ref_count
    def test_ecs_secret_ref_count_empty(self):
        assert _ecs_secret_ref_count([]) == 0
        assert _ecs_secret_ref_count(None) == 0  # type: ignore[arg-type]

    def test_ecs_secret_ref_count_returns_count_only(self):
        secrets = [
            {"name": "DB_PASS", "valueFrom": "arn:aws:secretsmanager:us-east-1:123:secret:db-pass"},
            {"name": "API_TOKEN", "valueFrom": "arn:aws:ssm:us-east-1:123:parameter/token"},
        ]
        count = _ecs_secret_ref_count(secrets)
        assert count == 2

    # _ecr_policy_is_public
    def test_ecr_policy_star_principal_is_public(self):
        policy = '{"Statement":[{"Effect":"Allow","Principal":"*","Action":["ecr:GetDownloadUrlForLayer"]}]}'
        assert _ecr_policy_is_public(policy, "123456789012") is True

    def test_ecr_policy_same_account_not_public(self):
        policy = '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"ecr:*"}]}'
        assert _ecr_policy_is_public(policy, "123456789012") is False

    def test_ecr_policy_cross_account_is_public(self):
        policy = '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999888777666:root"},"Action":"ecr:*"}]}'
        assert _ecr_policy_is_public(policy, "123456789012") is True

    def test_ecr_policy_deny_not_public(self):
        policy = '{"Statement":[{"Effect":"Deny","Principal":"*","Action":"ecr:*"}]}'
        assert _ecr_policy_is_public(policy, "123456789012") is False

    def test_ecr_policy_empty_not_public(self):
        assert _ecr_policy_is_public("", "123456789012") is False
        assert _ecr_policy_is_public(None, "123456789012") is False  # type: ignore[arg-type]

    def test_ecr_policy_invalid_json_not_public(self):
        assert _ecr_policy_is_public("{invalid}", "123456789012") is False

    # _eks_public_access_cidrs_open
    def test_eks_open_cidrs_ipv4(self):
        assert _eks_public_access_cidrs_open(["0.0.0.0/0"]) is True

    def test_eks_open_cidrs_ipv6(self):
        assert _eks_public_access_cidrs_open(["::/0"]) is True

    def test_eks_restricted_cidrs(self):
        assert _eks_public_access_cidrs_open(["10.0.0.0/8"]) is False
        assert _eks_public_access_cidrs_open(["203.0.113.0/24"]) is False

    def test_eks_empty_cidrs_considered_open(self):
        """Empty CIDR list means no restriction — treated as fully open."""
        assert _eks_public_access_cidrs_open([]) is True

    # _classify_container_name_sensitivity
    def test_container_name_prod_sensitive(self):
        assert _classify_container_name_sensitivity("prod-api") == "production"
        assert _classify_container_name_sensitivity("production-cluster") == "production"

    def test_container_name_payment_sensitive(self):
        assert _classify_container_name_sensitivity("payment-service") == "payment"

    def test_container_name_none_sensitivity(self):
        # Use names with no matching patterns
        # Avoid: "sandbox" (contains "db"), "worker" (in "internal" patterns)
        assert _classify_container_name_sensitivity("my-cluster") == "none"
        assert _classify_container_name_sensitivity("telemetry") == "none"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Risk classification — ECS
# ─────────────────────────────────────────────────────────────────────────────

class TestM46ECSRiskClassification:

    # aws_ecs_cluster
    def test_ecs_cluster_added(self):
        change = _ecs_change(change_type="added")
        sev, msg = classify_aws_change(change)
        assert sev == "low"
        assert "added" in msg.lower()

    def test_ecs_cluster_removed_sensitive(self):
        change = _ecs_change(change_type="removed", record_name="prod-cluster")
        sev, msg = classify_aws_change(change)
        assert sev == "high"
        assert "prod-cluster" in msg

    def test_ecs_cluster_removed_non_sensitive(self):
        change = _ecs_change(change_type="removed", record_name="dev-cluster")
        sev, msg = classify_aws_change(change)
        assert sev == "medium"

    def test_ecs_cluster_status_failed(self):
        change = _ecs_change(field_path="status", new_value="FAILED", record_name="prod-cluster")
        sev, msg = classify_aws_change(change)
        assert sev == "critical"
        assert "FAILED" in msg

    def test_ecs_cluster_status_inactive(self):
        change = _ecs_change(field_path="status", new_value="INACTIVE", record_name="dev-cluster")
        sev, msg = classify_aws_change(change)
        assert sev == "high"

    def test_ecs_cluster_container_insights_disabled_sensitive(self):
        change = _ecs_change(
            field_path="container_insights_enabled",
            new_value=False,
            record_name="prod-cluster",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "medium"
        assert "Container Insights" in msg

    def test_ecs_cluster_container_insights_disabled_non_sensitive(self):
        change = _ecs_change(
            field_path="container_insights_enabled",
            new_value=False,
            record_name="dev-cluster",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "low"

    def test_ecs_cluster_container_insights_enabled(self):
        change = _ecs_change(field_path="container_insights_enabled", new_value=True)
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    # aws_ecs_service
    def test_ecs_service_has_public_ip_sensitive(self):
        change = _ecs_change(
            record_type=AWS_ECS_SERVICE,
            field_path="has_public_ip",
            new_value=True,
            record_name="prod-api",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "high"
        assert "public IP" in msg or "public" in msg.lower()

    def test_ecs_service_has_public_ip_non_sensitive(self):
        change = _ecs_change(
            record_type=AWS_ECS_SERVICE,
            field_path="has_public_ip",
            new_value=True,
            record_name="dev-worker",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "medium"

    def test_ecs_service_has_public_ip_removed(self):
        change = _ecs_change(
            record_type=AWS_ECS_SERVICE,
            field_path="has_public_ip",
            new_value=False,
        )
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_ecs_service_desired_count_zero_sensitive(self):
        change = _ecs_change(
            record_type=AWS_ECS_SERVICE,
            field_path="desired_count",
            new_value=0,
            prev_value=3,
            record_name="prod-api",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "high"
        assert "0" in msg or "stop" in msg.lower()

    def test_ecs_service_desired_count_decreased(self):
        change = _ecs_change(
            record_type=AWS_ECS_SERVICE,
            field_path="desired_count",
            new_value=1,
            prev_value=5,
        )
        sev, _ = classify_aws_change(change)
        assert sev == "medium"

    def test_ecs_service_circuit_breaker_disabled_sensitive(self):
        change = _ecs_change(
            record_type=AWS_ECS_SERVICE,
            field_path="circuit_breaker_enabled",
            new_value=False,
            record_name="prod-payments",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "medium"
        assert "circuit breaker" in msg.lower()

    # aws_ecs_task_definition
    def test_ecs_task_def_privileged_sensitive(self):
        change = _ecs_change(
            record_type=AWS_ECS_TASK_DEFINITION,
            field_path="has_privileged_container",
            new_value=True,
            record_name="prod-api:5",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "critical"
        assert "privileged" in msg.lower()

    def test_ecs_task_def_privileged_non_sensitive(self):
        change = _ecs_change(
            record_type=AWS_ECS_TASK_DEFINITION,
            field_path="has_privileged_container",
            new_value=True,
            record_name="dev-worker:2",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "high"
        assert "privileged" in msg.lower()

    def test_ecs_task_def_privileged_removed(self):
        change = _ecs_change(
            record_type=AWS_ECS_TASK_DEFINITION,
            field_path="has_privileged_container",
            new_value=False,
        )
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_ecs_task_def_secret_ref_count_increased(self):
        change = _ecs_change(
            record_type=AWS_ECS_TASK_DEFINITION,
            field_path="secret_ref_count",
            new_value=5,
            prev_value=2,
        )
        sev, msg = classify_aws_change(change)
        assert sev == "medium"
        assert "secret" in msg.lower()

    def test_ecs_task_def_secret_ref_count_decreased(self):
        change = _ecs_change(
            record_type=AWS_ECS_TASK_DEFINITION,
            field_path="secret_ref_count",
            new_value=1,
            prev_value=3,
        )
        sev, _ = classify_aws_change(change)
        assert sev == "medium"

    def test_ecs_task_def_env_sensitive_key_count_increased(self):
        change = _ecs_change(
            record_type=AWS_ECS_TASK_DEFINITION,
            field_path="env_sensitive_key_count",
            new_value=3,
            prev_value=1,
        )
        sev, msg = classify_aws_change(change)
        assert sev == "medium"
        assert "sensitive" in msg.lower() or "environment" in msg.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 6. Risk classification — EKS
# ─────────────────────────────────────────────────────────────────────────────

class TestM46EKSRiskClassification:

    # aws_eks_cluster
    def test_eks_cluster_added(self):
        change = _eks_change(change_type="added")
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_eks_cluster_public_fully_open_sensitive(self):
        change = _eks_change(
            field_path="public_access_fully_open",
            new_value=True,
            record_name="prod-cluster",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "critical"
        assert "0.0.0.0/0" in msg or "any IP" in msg.lower() or "publicly" in msg.lower()

    def test_eks_cluster_public_fully_open_non_sensitive(self):
        change = _eks_change(
            field_path="public_access_fully_open",
            new_value=True,
            record_name="dev-cluster",
        )
        sev, _ = classify_aws_change(change)
        assert sev == "high"

    def test_eks_cluster_public_access_tightened(self):
        change = _eks_change(field_path="public_access_fully_open", new_value=False)
        sev, _ = classify_aws_change(change)
        assert sev == "medium"

    def test_eks_cluster_endpoint_public_access_enabled_sensitive(self):
        change = _eks_change(
            field_path="endpoint_public_access",
            new_value=True,
            record_name="prod-eks",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "high"

    def test_eks_cluster_endpoint_public_disabled(self):
        change = _eks_change(field_path="endpoint_public_access", new_value=False)
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_eks_cluster_secrets_encryption_disabled_sensitive(self):
        change = _eks_change(
            field_path="secrets_encryption_enabled",
            new_value=False,
            record_name="prod-cluster",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "high"
        assert "encrypt" in msg.lower() or "KMS" in msg or "secret" in msg.lower()

    def test_eks_cluster_secrets_encryption_enabled(self):
        change = _eks_change(field_path="secrets_encryption_enabled", new_value=True)
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_eks_cluster_audit_logging_disabled_sensitive(self):
        change = _eks_change(
            field_path="has_audit_logging",
            new_value=False,
            record_name="prod-cluster",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "high"
        assert "audit" in msg.lower()

    def test_eks_cluster_audit_logging_enabled(self):
        change = _eks_change(field_path="has_audit_logging", new_value=True)
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_eks_cluster_version_change(self):
        change = _eks_change(
            field_path="kubernetes_version",
            new_value="1.28",
            prev_value="1.27",
        )
        sev, msg = classify_aws_change(change)
        assert sev in ("low", "medium")
        assert "version" in msg.lower() or "1.28" in msg

    # aws_eks_node_group
    def test_eks_node_group_ssh_unrestricted_sensitive(self):
        change = _eks_change(
            record_type=AWS_EKS_NODE_GROUP,
            field_path="ssh_unrestricted",
            new_value=True,
            record_name="prod-nodegroup",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "high"
        assert "SSH" in msg or "ssh" in msg.lower()

    def test_eks_node_group_ssh_unrestricted_non_sensitive(self):
        change = _eks_change(
            record_type=AWS_EKS_NODE_GROUP,
            field_path="ssh_unrestricted",
            new_value=True,
            record_name="dev-nodegroup",
        )
        sev, _ = classify_aws_change(change)
        assert sev == "medium"

    def test_eks_node_group_ssh_restricted(self):
        change = _eks_change(
            record_type=AWS_EKS_NODE_GROUP,
            field_path="ssh_unrestricted",
            new_value=False,
        )
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_eks_node_group_status_degraded(self):
        change = _eks_change(
            record_type=AWS_EKS_NODE_GROUP,
            field_path="status",
            new_value="DEGRADED",
        )
        sev, _ = classify_aws_change(change)
        assert sev == "high"

    def test_eks_node_group_has_remote_access_enabled(self):
        change = _eks_change(
            record_type=AWS_EKS_NODE_GROUP,
            field_path="has_remote_access",
            new_value=True,
        )
        sev, _ = classify_aws_change(change)
        assert sev == "medium"

    # aws_eks_fargate_profile
    def test_eks_fargate_profile_added(self):
        change = _eks_change(record_type=AWS_EKS_FARGATE_PROFILE, change_type="added")
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_eks_fargate_profile_removed(self):
        change = _eks_change(record_type=AWS_EKS_FARGATE_PROFILE, change_type="removed")
        sev, _ = classify_aws_change(change)
        assert sev == "medium"

    def test_eks_fargate_profile_status_failed(self):
        change = _eks_change(
            record_type=AWS_EKS_FARGATE_PROFILE,
            field_path="status",
            new_value="CREATE_FAILED",
        )
        sev, _ = classify_aws_change(change)
        assert sev == "high"

    def test_eks_fargate_profile_namespaces_changed(self):
        change = _eks_change(
            record_type=AWS_EKS_FARGATE_PROFILE,
            field_path="selector_namespaces",
            new_value=["production"],
            prev_value=["default"],
        )
        sev, _ = classify_aws_change(change)
        assert sev == "medium"

    # aws_eks_addon
    def test_eks_addon_added(self):
        change = _eks_change(record_type=AWS_EKS_ADDON, change_type="added")
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_eks_addon_removed(self):
        change = _eks_change(record_type=AWS_EKS_ADDON, change_type="removed")
        sev, _ = classify_aws_change(change)
        assert sev == "medium"

    def test_eks_addon_status_degraded(self):
        change = _eks_change(
            record_type=AWS_EKS_ADDON,
            field_path="status",
            new_value="DEGRADED",
        )
        sev, _ = classify_aws_change(change)
        assert sev == "high"

    def test_eks_addon_version_changed(self):
        change = _eks_change(
            record_type=AWS_EKS_ADDON,
            field_path="addon_version",
            new_value="v1.12.0-eksbuild.1",
            prev_value="v1.11.0-eksbuild.1",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "low"
        assert "version" in msg.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 7. Risk classification — ECR
# ─────────────────────────────────────────────────────────────────────────────

class TestM46ECRRiskClassification:

    # aws_ecr_repository
    def test_ecr_repo_added(self):
        change = _ecr_change(change_type="added")
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_ecr_repo_policy_public_sensitive(self):
        change = _ecr_change(
            field_path="policy_is_public",
            new_value=True,
            record_name="prod-app-images",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "critical"
        assert "public" in msg.lower() or "external" in msg.lower()

    def test_ecr_repo_policy_public_non_sensitive(self):
        change = _ecr_change(
            field_path="policy_is_public",
            new_value=True,
            record_name="dev-images",
        )
        sev, _ = classify_aws_change(change)
        assert sev == "high"

    def test_ecr_repo_policy_no_longer_public(self):
        change = _ecr_change(field_path="policy_is_public", new_value=False)
        sev, _ = classify_aws_change(change)
        assert sev == "medium"

    def test_ecr_repo_scan_on_push_disabled_sensitive(self):
        change = _ecr_change(
            field_path="scan_on_push",
            new_value=False,
            record_name="prod-images",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "medium"
        assert "scan" in msg.lower()

    def test_ecr_repo_scan_on_push_disabled_non_sensitive(self):
        change = _ecr_change(
            field_path="scan_on_push",
            new_value=False,
            record_name="dev-images",
        )
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_ecr_repo_scan_on_push_enabled(self):
        change = _ecr_change(field_path="scan_on_push", new_value=True)
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_ecr_repo_tag_mutable(self):
        change = _ecr_change(
            field_path="tag_immutable",
            new_value=False,
            record_name="prod-images",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "medium"
        assert "mutable" in msg.lower() or "mutab" in msg.lower()

    def test_ecr_repo_tag_immutable(self):
        change = _ecr_change(field_path="tag_immutable", new_value=True)
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_ecr_repo_lifecycle_removed(self):
        change = _ecr_change(field_path="lifecycle_policy_present", new_value=False)
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_ecr_repo_policy_added(self):
        change = _ecr_change(field_path="policy_present", new_value=True)
        sev, msg = classify_aws_change(change)
        assert sev == "medium"
        assert "policy" in msg.lower()

    # aws_ecr_registry_scanning_config
    def test_ecr_scan_config_added(self):
        change = _ecr_change(
            record_type=AWS_ECR_REGISTRY_SCANNING_CONFIG,
            change_type="added",
        )
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_ecr_scan_config_downgrade_to_basic(self):
        change = _ecr_change(
            record_type=AWS_ECR_REGISTRY_SCANNING_CONFIG,
            field_path="scan_type",
            new_value="BASIC",
            prev_value="ENHANCED",
        )
        sev, msg = classify_aws_change(change)
        assert sev == "high"
        assert "BASIC" in msg or "ENHANCED" in msg

    def test_ecr_scan_config_upgrade_to_enhanced(self):
        change = _ecr_change(
            record_type=AWS_ECR_REGISTRY_SCANNING_CONFIG,
            field_path="scan_type",
            new_value="ENHANCED",
            prev_value="BASIC",
        )
        sev, _ = classify_aws_change(change)
        assert sev == "low"

    def test_ecr_scan_config_all_rules_removed(self):
        change = _ecr_change(
            record_type=AWS_ECR_REGISTRY_SCANNING_CONFIG,
            field_path="rule_count",
            new_value=0,
            prev_value=3,
        )
        sev, msg = classify_aws_change(change)
        assert sev == "high"
        assert "rule" in msg.lower() or "scan" in msg.lower()

    def test_ecr_scan_config_rules_decreased(self):
        change = _ecr_change(
            record_type=AWS_ECR_REGISTRY_SCANNING_CONFIG,
            field_path="rule_count",
            new_value=1,
            prev_value=3,
        )
        sev, _ = classify_aws_change(change)
        assert sev == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Failure classifiers
# ─────────────────────────────────────────────────────────────────────────────

class TestM46FailureClassifiers:

    # ECS
    def test_ecs_failure_auth_error(self):
        fc = classify_aws_ecs_failure("ListClusters", AuthenticationError("denied"))
        assert fc.category == "authentication"
        assert fc.error_code == "aws_ecs_access_denied"
        assert "ecs" in fc.recommended_action.lower() or "ECS" in fc.recommended_action

    def test_ecs_failure_rate_limited(self):
        fc = classify_aws_ecs_failure("DescribeClusters", RateLimitError("throttled"))
        assert fc.category == "rate_limited"
        assert fc.error_code == "aws_ecs_rate_limited"

    def test_ecs_failure_network_error(self):
        fc = classify_aws_ecs_failure("ListServices", NetworkError("timeout"))
        assert fc.category == "network"
        assert fc.error_code == "network_error"

    def test_ecs_failure_403(self):
        exc = ConnectorError("access denied", status_code=403)
        fc = classify_aws_ecs_failure("DescribeServices", exc)
        assert fc.category == "authentication"

    def test_ecs_failure_500(self):
        exc = ConnectorError("internal error", status_code=500)
        fc = classify_aws_ecs_failure("ListClusters", exc)
        assert fc.category == "provider_unavailable"

    def test_ecs_failure_known_api_codes(self):
        for api in ["ListClusters", "DescribeClusters", "ListServices",
                    "DescribeServices", "ListTaskDefinitions", "DescribeTaskDefinition"]:
            fc = classify_aws_ecs_failure(api, Exception("oops"))
            assert fc.error_code != ""

    # EKS
    def test_eks_failure_auth_error(self):
        fc = classify_aws_eks_failure("ListClusters", AuthenticationError("denied"))
        assert fc.category == "authentication"
        assert fc.error_code == "aws_eks_access_denied"
        assert "eks" in fc.recommended_action.lower() or "EKS" in fc.recommended_action

    def test_eks_failure_rate_limited(self):
        fc = classify_aws_eks_failure("DescribeCluster", RateLimitError("throttled"))
        assert fc.category == "rate_limited"
        assert fc.error_code == "aws_eks_rate_limited"

    def test_eks_failure_network_error(self):
        fc = classify_aws_eks_failure("ListNodegroups", NetworkError("timeout"))
        assert fc.category == "network"
        assert fc.error_code == "network_error"

    def test_eks_failure_403(self):
        exc = ConnectorError("access denied", status_code=403)
        fc = classify_aws_eks_failure("DescribeCluster", exc)
        assert fc.category == "authentication"

    def test_eks_failure_known_api_codes(self):
        for api in ["ListClusters", "DescribeCluster", "ListNodegroups",
                    "DescribeNodegroup", "ListFargateProfiles", "DescribeFargateProfile",
                    "ListAddons", "DescribeAddon"]:
            fc = classify_aws_eks_failure(api, Exception("oops"))
            assert fc.error_code != ""

    # ECR
    def test_ecr_failure_auth_error(self):
        fc = classify_aws_ecr_failure("DescribeRepositories", AuthenticationError("denied"))
        assert fc.category == "authentication"
        assert fc.error_code == "aws_ecr_access_denied"
        assert "ecr" in fc.recommended_action.lower() or "ECR" in fc.recommended_action

    def test_ecr_failure_rate_limited(self):
        fc = classify_aws_ecr_failure("GetRepositoryPolicy", RateLimitError("throttled"))
        assert fc.category == "rate_limited"
        assert fc.error_code == "aws_ecr_rate_limited"

    def test_ecr_failure_network_error(self):
        fc = classify_aws_ecr_failure("GetLifecyclePolicy", NetworkError("timeout"))
        assert fc.category == "network"
        assert fc.error_code == "network_error"

    def test_ecr_failure_403(self):
        exc = ConnectorError("access denied", status_code=403)
        fc = classify_aws_ecr_failure("DescribeRepositories", exc)
        assert fc.category == "authentication"

    def test_ecr_failure_known_api_codes(self):
        for api in ["DescribeRepositories", "GetRepositoryPolicy",
                    "GetLifecyclePolicy", "GetRegistryScanningConfiguration"]:
            fc = classify_aws_ecr_failure(api, Exception("oops"))
            assert fc.error_code != ""

    def test_ecr_failure_action_mentions_no_image_pull(self):
        """ECR failure message must clarify images are never pulled."""
        fc = classify_aws_ecr_failure("DescribeRepositories", AuthenticationError("denied"))
        action_lower = fc.recommended_action.lower()
        # Message should clarify that images are never pulled / auth token not requested
        assert "never" in action_lower or "images" in action_lower


# ─────────────────────────────────────────────────────────────────────────────
# 9. Service inventory: ecs/eks/ecr in enabled_surfaces
# ─────────────────────────────────────────────────────────────────────────────

class TestM46ServiceInventory:

    def _make_inventory(self):
        conn = _make_connector()
        creds = _creds()
        return conn._fetch_service_inventory(creds)

    def test_ecs_in_enabled_surfaces(self):
        inv = self._make_inventory()
        assert "ecs" in inv["enabled_surfaces"]

    def test_eks_in_enabled_surfaces(self):
        inv = self._make_inventory()
        assert "eks" in inv["enabled_surfaces"]

    def test_ecr_in_enabled_surfaces(self):
        inv = self._make_inventory()
        assert "ecr" in inv["enabled_surfaces"]

    def test_ecs_not_in_future_surfaces(self):
        inv = self._make_inventory()
        assert "ecs" not in inv.get("future_surfaces", [])

    def test_eks_not_in_future_surfaces(self):
        inv = self._make_inventory()
        assert "eks" not in inv.get("future_surfaces", [])

    def test_ecr_not_in_future_surfaces(self):
        inv = self._make_inventory()
        assert "ecr" not in inv.get("future_surfaces", [])

    def test_inventory_count_fields_present(self):
        inv = self._make_inventory()
        assert "ecs_cluster_count" in inv
        assert "eks_cluster_count" in inv
        assert "ecr_repository_count" in inv


# ─────────────────────────────────────────────────────────────────────────────
# 10. Connector normalization: _fetch_ecs_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestM46ECSConnectorNormalization:

    def _make_ecs_client(self):
        client = MagicMock()
        # ListClusters
        client.list_clusters.return_value = {
            "clusterArns": ["arn:aws:ecs:us-east-1:123:cluster/my-cluster"],
        }
        # DescribeClusters
        client.describe_clusters.return_value = {
            "clusters": [{
                "clusterArn": "arn:aws:ecs:us-east-1:123:cluster/my-cluster",
                "clusterName": "my-cluster",
                "status": "ACTIVE",
                "registeredContainerInstancesCount": 2,
                "runningTasksCount": 5,
                "pendingTasksCount": 0,
                "activeServicesCount": 3,
                "capacityProviders": ["FARGATE", "FARGATE_SPOT"],
                "defaultCapacityProviderStrategy": [],
                "settings": [{"name": "containerInsights", "value": "enabled"}],
                "tags": [{"key": "env", "value": "test"}],
            }],
        }
        # ListServices
        client.list_services.return_value = {
            "serviceArns": ["arn:aws:ecs:us-east-1:123:service/my-cluster/my-svc"],
        }
        # DescribeServices
        client.describe_services.return_value = {
            "services": [{
                "serviceArn": "arn:aws:ecs:us-east-1:123:service/my-cluster/my-svc",
                "serviceName": "my-svc",
                "status": "ACTIVE",
                "launchType": "FARGATE",
                "schedulingStrategy": "REPLICA",
                "desiredCount": 2,
                "runningCount": 2,
                "networkConfiguration": {
                    "awsvpcConfiguration": {
                        "assignPublicIp": "DISABLED",
                    }
                },
                "loadBalancers": [],
                "taskDefinition": "arn:aws:ecs:us-east-1:123:task-definition/my-td:1",
                "deployments": [{}],
                "deploymentConfiguration": {
                    "deploymentCircuitBreaker": {"enable": True, "rollback": True}
                },
                "serviceConnectConfiguration": {"enabled": False},
                "tags": [],
            }],
        }
        # DescribeTaskDefinition
        client.describe_task_definition.return_value = {
            "taskDefinition": {
                "taskDefinitionArn": "arn:aws:ecs:us-east-1:123:task-definition/my-td:1",
                "family": "my-td",
                "revision": 1,
                "status": "ACTIVE",
                "networkMode": "awsvpc",
                "requiresCompatibilities": ["FARGATE"],
                "cpu": "256",
                "memory": "512",
                "taskRoleArn": "arn:aws:iam::123:role/task-role",
                "executionRoleArn": "arn:aws:iam::123:role/exec-role",
                "volumes": [],
                "containerDefinitions": [{
                    "name": "app",
                    "environment": [
                        {"name": "LOG_LEVEL", "value": "info-NEVER-STORE"},
                        {"name": "DB_PASSWORD", "value": "s3cr3t-NEVER-STORE"},
                    ],
                    "secrets": [
                        {"name": "API_KEY", "valueFrom": "arn:aws:ssm:::secret-NEVER-STORE"},
                    ],
                    "privileged": False,
                    "readonlyRootFilesystem": True,
                    "logConfiguration": {"logDriver": "awslogs"},
                }],
            },
            "tags": [{"key": "team", "value": "platform"}],
        }
        return client

    def test_ecs_cluster_record_structure(self):
        conn = _make_connector()
        client = self._make_ecs_client()
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        records = conn._fetch_ecs_in_region(client, "123456789012", "us-east-1")
        cluster_records = [r for r in records if r["record_type"] == AWS_ECS_CLUSTER]
        assert len(cluster_records) == 1
        r = cluster_records[0]
        assert r["name"] == "my-cluster"
        assert r["status"] == "ACTIVE"
        assert r["container_insights_enabled"] is True
        assert r["has_fargate_capacity"] is True
        assert r["account_id"] == "123456789012"
        assert r["region"] == "us-east-1"

    def test_ecs_service_record_structure(self):
        conn = _make_connector()
        client = self._make_ecs_client()
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        records = conn._fetch_ecs_in_region(client, "123456789012", "us-east-1")
        svc_records = [r for r in records if r["record_type"] == AWS_ECS_SERVICE]
        assert len(svc_records) == 1
        r = svc_records[0]
        assert r["name"] == "my-svc"
        assert r["launch_type"] == "FARGATE"
        assert r["has_public_ip"] is False
        assert r["circuit_breaker_enabled"] is True

    def test_ecs_task_definition_env_values_never_stored(self):
        conn = _make_connector()
        client = self._make_ecs_client()
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        records = conn._fetch_ecs_in_region(client, "123456789012", "us-east-1")
        td_records = [r for r in records if r["record_type"] == AWS_ECS_TASK_DEFINITION]
        assert len(td_records) == 1
        r = td_records[0]
        # Values must never appear in the record
        record_str = str(r)
        assert "s3cr3t-NEVER-STORE" not in record_str
        assert "info-NEVER-STORE" not in record_str
        assert "secret-NEVER-STORE" not in record_str
        # Counts must be present
        assert r["env_key_count"] == 2
        assert r["env_sensitive_key_count"] >= 1  # DB_PASSWORD is sensitive
        assert r["secret_ref_count"] == 1

    def test_ecs_task_definition_role_arns_hashed(self):
        conn = _make_connector()
        client = self._make_ecs_client()
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        records = conn._fetch_ecs_in_region(client, "123456789012", "us-east-1")
        td_records = [r for r in records if r["record_type"] == AWS_ECS_TASK_DEFINITION]
        r = td_records[0]
        # Raw ARNs must not be stored
        record_str = str(r)
        assert "arn:aws:iam::123:role/task-role" not in record_str
        assert "arn:aws:iam::123:role/exec-role" not in record_str
        # Hash must be present
        assert r["task_role_arn_hash"] is not None
        assert r["execution_role_arn_hash"] is not None
        assert len(r["task_role_arn_hash"]) == 12  # _hash_kms_key_id convention


# ─────────────────────────────────────────────────────────────────────────────
# 11. Connector normalization: _fetch_eks_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestM46EKSConnectorNormalization:

    def _make_eks_client(self):
        client = MagicMock()
        client.list_clusters.return_value = {"clusters": ["my-eks"]}
        client.describe_cluster.return_value = {
            "cluster": {
                "name": "my-eks",
                "arn": "arn:aws:eks:us-east-1:123:cluster/my-eks",
                "status": "ACTIVE",
                "version": "1.28",
                "platformVersion": "eks.5",
                "roleArn": "arn:aws:iam::123:role/eks-role",
                "kubernetesNetworkConfig": {"ipFamily": "ipv4"},
                "resourcesVpcConfig": {
                    "endpointPublicAccess": False,
                    "endpointPrivateAccess": True,
                    "publicAccessCidrs": ["10.0.0.0/8"],
                    "subnetIds": ["subnet-1", "subnet-2"],
                    "securityGroupIds": ["sg-1"],
                },
                "logging": {
                    "clusterLogging": [
                        {"types": ["api", "audit", "authenticator"], "enabled": True}
                    ]
                },
                "encryptionConfig": [{
                    "resources": ["secrets"],
                    "provider": {"keyArn": "arn:aws:kms:us-east-1:123:key/my-key"},
                }],
                "tags": {"env": "test"},
            }
        }
        client.list_nodegroups.return_value = {"nodegroups": []}
        client.list_fargate_profiles.return_value = {"fargateProfileNames": []}
        client.list_addons.return_value = {"addons": []}
        return client

    def test_eks_cluster_record_structure(self):
        conn = _make_connector()
        client = self._make_eks_client()
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        records = conn._fetch_eks_in_region(client, "123456789012", "us-east-1")
        cluster_records = [r for r in records if r["record_type"] == AWS_EKS_CLUSTER]
        assert len(cluster_records) == 1
        r = cluster_records[0]
        assert r["name"] == "my-eks"
        assert r["kubernetes_version"] == "1.28"
        assert r["endpoint_public_access"] is False
        assert r["endpoint_private_access"] is True
        assert r["public_access_fully_open"] is False  # private endpoint, restricted CIDRs
        assert r["secrets_encryption_enabled"] is True
        assert r["has_audit_logging"] is True
        assert r["kms_key_hash"] is not None
        assert len(r["kms_key_hash"]) == 12

    def test_eks_cluster_raw_role_arn_not_stored(self):
        conn = _make_connector()
        client = self._make_eks_client()
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        records = conn._fetch_eks_in_region(client, "123456789012", "us-east-1")
        cluster_records = [r for r in records if r["record_type"] == AWS_EKS_CLUSTER]
        r = cluster_records[0]
        record_str = str(r)
        assert "arn:aws:iam::123:role/eks-role" not in record_str
        assert r["role_arn_hash"] is not None

    def test_eks_cluster_no_kubernetes_api_calls(self):
        """Connector must not call any Kubernetes API methods."""
        conn = _make_connector()
        client = self._make_eks_client()
        calls_made = []
        original_call = lambda fn, **kwargs: fn(**kwargs)
        def tracking_call(fn, **kwargs):
            calls_made.append(fn.__name__ if hasattr(fn, '__name__') else str(fn))
            return original_call(fn, **kwargs)
        conn._call_aws = tracking_call
        conn._fetch_eks_in_region(client, "123456789012", "us-east-1")
        k8s_apis = {"list_pods", "list_secrets", "list_config_maps", "list_namespaces"}
        for c in calls_made:
            assert c not in k8s_apis, f"Kubernetes API {c!r} was called — forbidden"


# ─────────────────────────────────────────────────────────────────────────────
# 12. Connector normalization: _fetch_ecr_in_region
# ─────────────────────────────────────────────────────────────────────────────

class TestM46ECRConnectorNormalization:

    def _make_ecr_client(self):
        client = MagicMock()
        client.describe_repositories.return_value = {
            "repositories": [{
                "repositoryArn": "arn:aws:ecr:us-east-1:123:repository/my-repo",
                "repositoryName": "my-repo",
                "imageTagMutability": "IMMUTABLE",
                "imageScanningConfiguration": {"scanOnPush": True},
                "encryptionConfiguration": {
                    "encryptionType": "KMS",
                    "kmsKey": "arn:aws:kms:us-east-1:123:key/my-key",
                },
                "tags": [{"Key": "env", "Value": "prod"}],
            }],
        }
        # No policy
        client.get_repository_policy.side_effect = ConnectorError(
            "RepositoryPolicyNotFoundException", status_code=400
        )
        # No lifecycle policy
        client.get_lifecycle_policy.side_effect = ConnectorError(
            "LifecyclePolicyNotFoundException", status_code=400
        )
        client.get_registry_scanning_configuration.return_value = {
            "scanType": "ENHANCED",
            "rules": [
                {"scanFrequency": "CONTINUOUS_SCAN", "repositoryFilters": [{"filter": "*"}]},
            ],
        }
        return client

    def test_ecr_repository_record_structure(self):
        conn = _make_connector()
        client = self._make_ecr_client()
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        records = conn._fetch_ecr_in_region(client, "123456789012", "us-east-1")
        repo_records = [r for r in records if r["record_type"] == AWS_ECR_REPOSITORY]
        assert len(repo_records) == 1
        r = repo_records[0]
        assert r["name"] == "my-repo"
        assert r["tag_immutable"] is True
        assert r["scan_on_push"] is True
        assert r["encryption_type"] == "KMS"
        assert r["kms_key_hash"] is not None
        assert r["policy_present"] is False
        assert r["policy_is_public"] is False
        assert r["lifecycle_policy_present"] is False

    def test_ecr_raw_kms_key_not_stored(self):
        conn = _make_connector()
        client = self._make_ecr_client()
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        records = conn._fetch_ecr_in_region(client, "123456789012", "us-east-1")
        repo_records = [r for r in records if r["record_type"] == AWS_ECR_REPOSITORY]
        r = repo_records[0]
        record_str = str(r)
        assert "arn:aws:kms:us-east-1:123:key/my-key" not in record_str
        assert len(r["kms_key_hash"]) == 12

    def test_ecr_registry_scanning_config_record(self):
        conn = _make_connector()
        client = self._make_ecr_client()
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        records = conn._fetch_ecr_in_region(client, "123456789012", "us-east-1")
        scan_records = [r for r in records if r["record_type"] == AWS_ECR_REGISTRY_SCANNING_CONFIG]
        assert len(scan_records) == 1
        r = scan_records[0]
        assert r["scan_type"] == "ENHANCED"
        assert r["rule_count"] == 1
        assert r["repo_filter_count"] == 1

    def test_ecr_get_authorization_token_never_called(self):
        conn = _make_connector()
        client = self._make_ecr_client()
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        conn._fetch_ecr_in_region(client, "123456789012", "us-east-1")
        client.get_authorization_token.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# 13. Fail-soft behavior
# ─────────────────────────────────────────────────────────────────────────────

class TestM46FailSoft:

    def test_ecs_region_failure_does_not_abort(self):
        """If ECS fails in one region, other regions must still complete."""
        conn = _make_connector()
        creds = _creds(regions=["us-east-1", "eu-west-1"])

        call_count = {"n": 0}

        def mock_make_client(service, credentials, region=None):
            if service != "ecs":
                return MagicMock()
            call_count["n"] += 1
            client = MagicMock()
            if region == "us-east-1":
                client.list_clusters.side_effect = Exception("us-east-1 failure")
            else:
                client.list_clusters.return_value = {"clusterArns": []}
            return client

        conn._make_client = mock_make_client
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        # Must not raise
        records = conn._fetch_ecs_resources(creds, "123456789012")
        assert isinstance(records, list)

    def test_eks_region_failure_does_not_abort(self):
        conn = _make_connector()
        creds = _creds(regions=["us-east-1", "eu-west-1"])

        def mock_make_client(service, credentials, region=None):
            if service != "eks":
                return MagicMock()
            client = MagicMock()
            if region == "us-east-1":
                client.list_clusters.side_effect = Exception("us-east-1 eks failure")
            else:
                client.list_clusters.return_value = {"clusters": []}
            return client

        conn._make_client = mock_make_client
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        records = conn._fetch_eks_resources(creds, "123456789012")
        assert isinstance(records, list)

    def test_ecr_region_failure_does_not_abort(self):
        conn = _make_connector()
        creds = _creds(regions=["us-east-1", "eu-west-1"])

        def mock_make_client(service, credentials, region=None):
            if service != "ecr":
                return MagicMock()
            client = MagicMock()
            if region == "us-east-1":
                client.describe_repositories.side_effect = Exception("ecr failure")
            else:
                client.describe_repositories.return_value = {"repositories": []}
                client.get_registry_scanning_configuration.return_value = {
                    "scanType": "BASIC", "rules": [],
                }
            return client

        conn._make_client = mock_make_client
        conn._call_aws = lambda fn, **kwargs: fn(**kwargs)
        records = conn._fetch_ecr_resources(creds, "123456789012")
        assert isinstance(records, list)


# ─────────────────────────────────────────────────────────────────────────────
# 14. M45 regression guard
# ─────────────────────────────────────────────────────────────────────────────

class TestM45RegressionGuard:
    """Ensure M45 types still route to their classifiers after M46 was added."""

    def test_cloudtrail_trail_still_classified(self):
        change = {
            "record_type": AWS_CLOUDTRAIL_TRAIL,
            "change_type": "modified",
            "field_path": "is_logging",
            "new_value": False,
            "prev_value": True,
            "provider_metadata": {
                "record_type": AWS_CLOUDTRAIL_TRAIL,
                "record_name": "my-trail",
                "is_organization_trail": False,
                "is_multi_region_trail": False,
            },
        }
        sev, msg = classify_aws_change(change)
        assert sev in ("medium", "high", "critical")
        assert "trail" in msg.lower() or "logging" in msg.lower() or "Trail" in msg

    def test_guardduty_detector_still_classified(self):
        change = {
            "record_type": AWS_GUARDDUTY_DETECTOR,
            "change_type": "modified",
            "field_path": "status",
            "new_value": "DISABLED",
            "prev_value": "ENABLED",
            "provider_metadata": {
                "record_type": AWS_GUARDDUTY_DETECTOR,
                "record_name": "guardduty-us-east-1-abc",
            },
        }
        sev, msg = classify_aws_change(change)
        assert sev in ("high", "critical")
        assert "GuardDuty" in msg or "guardduty" in msg.lower()

    def test_securityhub_account_still_classified(self):
        change = {
            "record_type": AWS_SECURITYHUB_ACCOUNT,
            "change_type": "modified",
            "field_path": "hub_enabled",
            "new_value": False,
            "prev_value": True,
            "provider_metadata": {
                "record_type": AWS_SECURITYHUB_ACCOUNT,
                "record_name": "securityhub-us-east-1",
            },
        }
        sev, msg = classify_aws_change(change)
        assert sev in ("high", "critical")
        assert "Security Hub" in msg or "hub" in msg.lower()

    def test_m45_types_in_aws_record_types(self):
        from app.connectors.aws_schema import (
            AWS_CLOUDTRAIL_TRAIL, AWS_CLOUDTRAIL_EVENT_DATA_STORE,
            AWS_GUARDDUTY_DETECTOR, AWS_GUARDDUTY_PUBLISHING_DESTINATION,
            AWS_SECURITYHUB_ACCOUNT, AWS_SECURITYHUB_STANDARD_SUBSCRIPTION,
            AWS_SECURITYHUB_FINDING_AGGREGATOR,
        )
        for rt in [
            AWS_CLOUDTRAIL_TRAIL, AWS_CLOUDTRAIL_EVENT_DATA_STORE,
            AWS_GUARDDUTY_DETECTOR, AWS_GUARDDUTY_PUBLISHING_DESTINATION,
            AWS_SECURITYHUB_ACCOUNT, AWS_SECURITYHUB_STANDARD_SUBSCRIPTION,
            AWS_SECURITYHUB_FINDING_AGGREGATOR,
        ]:
            assert rt in AWS_RECORD_TYPES, f"M45 regression: {rt} missing from AWS_RECORD_TYPES"
