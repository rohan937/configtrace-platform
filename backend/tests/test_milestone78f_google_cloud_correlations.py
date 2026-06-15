"""M78F — Google Cloud configuration-risk × Google Cloud Audit Log correlations.

Correlates ACTIVE Google Cloud configuration-risk findings (provider="google_cloud",
from M78B/M78C rules) with Google Cloud Audit Log events
(source="google_cloud_audit_log", from M78D ingestion) on the SAME Google Cloud
resource within the finding's review window.

Matching rules tested:
  - Resource-name match: finding.evidence[name_field] == event.metadata[event_name_field]
    for firewall / storage / SQL / Cloud Run / GKE
  - project_id agreement (defense-in-depth) — if both sides expose it
  - Aggregate match: project_id + finding_family for IAM / service-account-key /
    Secret Manager
  - NEVER provider-only, NEVER project-only for resource-bearing findings,
    NEVER different objects, NEVER different projects

Privacy + claim discipline also asserted:
  - No principal emails / SA emails / principal IDs anywhere in metadata
  - No caller IPs / userAgent anywhere in metadata
  - No raw protoPayload / request / response / authenticationInfo /
    authorizationInfo / full IAM bindings
  - No forbidden phrases in summaries / titles
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest.mock import MagicMock

import pytest

from app.services.security_signal_correlation_service import (
    GOOGLE_CLOUD_CORRELATION_RULES,
    PROVIDER_GOOGLE_CLOUD,
    _gcp_match_resource,
    _gcp_match_aggregate,
    _gcp_resource_label,
    _gcp_finding_resource_name,
    build_google_cloud_correlation,
    generate_google_cloud_correlations,
    sanitize_correlation_metadata,
    ALLOWED_METADATA_KEYS as CORR_ALLOWED_KEYS,
)
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

_FORBIDDEN_CLAIM_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

_FORBIDDEN_METADATA_KEYS = {
    "private_key", "signed_jwt", "access_token", "refresh_token",
    "authorization", "principal_email", "service_account_email",
    "caller_ip", "callerip", "user_agent", "useragent",
    "proto_payload", "protopayload", "request", "response",
    "authentication_info", "authenticationinfo", "authorization_info",
    "authorizationinfo", "bindings", "full_iam_bindings",
    "database_name", "database_user", "password", "connection_string",
    "query_data", "env_var", "env_var_value",
    "secret_name", "secret_value", "secret_payload",
    "kubeconfig", "node_name", "pod_spec", "workload_data",
    "principal_id", "object_id", "ip_address", "upn",
}

# Use a recent timestamp so events fall inside the default 24-hour window.
_NOW = datetime.now(timezone.utc)


def _assert_clean_metadata(metadata: dict) -> None:
    for key in metadata:
        assert key.lower() not in _FORBIDDEN_METADATA_KEYS, (
            f"correlation metadata contains forbidden key: {key!r}"
        )


def _assert_clean_copy(text: str) -> None:
    low = text.lower()
    for phrase in _FORBIDDEN_CLAIM_PHRASES:
        assert phrase not in low, (
            f"forbidden wording {phrase!r} in: {text[:300]!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Mock helpers
# ──────────────────────────────────────────────────────────────────────────────


def _mock_finding(
    *,
    finding_key: str,
    evidence: dict,
    severity: str = "high",
    title: Optional[str] = None,
    first_detected_at: Optional[datetime] = None,
    last_seen_at: Optional[datetime] = None,
) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.finding_key = finding_key
    f.severity = severity
    f.title = title or f"Google Cloud finding: {finding_key}"
    f.provider = "google_cloud"
    f.status = "active"
    f.evidence = evidence
    f.first_detected_at = first_detected_at or (_NOW - timedelta(hours=1))
    f.last_seen_at = last_seen_at or _NOW
    f.linked_change_id = None
    f.integration_id = uuid.uuid4()
    f.resource_id = uuid.uuid4()
    return f


def _mock_event(
    *,
    event_type: str,
    metadata: dict,
    occurred_at: Optional[datetime] = None,
) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.provider = "google_cloud"
    ev.source = "google_cloud_audit_log"
    ev.event_type = event_type
    ev.event_metadata = metadata
    ev.occurred_at = occurred_at or _NOW
    ev.actor_id = None
    return ev


# ══════════════════════════════════════════════════════════════════════════════
# Rule completeness
# ══════════════════════════════════════════════════════════════════════════════


class TestRuleCompleteness:
    """Every M78B+M78C Google Cloud rule has a correlation entry."""

    def test_all_m78b_rules_have_correlation_entry(self):
        m78b = {
            "google_cloud_iam_public_member",
            "google_cloud_iam_broad_privileged_role",
            "google_cloud_firewall_public_admin_ingress",
            "google_cloud_firewall_public_broad_ingress",
            "google_cloud_firewall_rule_no_targets",
            "google_cloud_storage_public_access_prevention_disabled",
            "google_cloud_storage_uniform_access_disabled",
            "google_cloud_storage_versioning_disabled",
            "google_cloud_storage_retention_not_locked",
        }
        missing = m78b - set(GOOGLE_CLOUD_CORRELATION_RULES)
        assert missing == set(), f"M78B rules without correlation: {missing}"

    def test_all_m78c_rules_have_correlation_entry(self):
        m78c = {
            "google_cloud_sql_public_network_access",
            "google_cloud_sql_weak_tls",
            "google_cloud_sql_backups_disabled",
            "google_cloud_sql_deletion_protection_disabled",
            "google_cloud_run_public_invoker",
            "google_cloud_run_all_ingress",
            "google_cloud_gke_public_control_plane",
            "google_cloud_gke_legacy_abac_enabled",
            "google_cloud_gke_network_policy_disabled",
            "google_cloud_gke_workload_identity_disabled",
            "google_cloud_service_account_user_managed_keys",
            "google_cloud_service_account_old_keys",
            "google_cloud_secret_manager_auto_replication_without_cmek",
        }
        missing = m78c - set(GOOGLE_CLOUD_CORRELATION_RULES)
        assert missing == set(), f"M78C rules without correlation: {missing}"

    def test_22_finding_rules_covered(self):
        assert len(GOOGLE_CLOUD_CORRELATION_RULES) == 22

    def test_8_distinct_correlation_types(self):
        types = {r["correlation_type"] for r in GOOGLE_CLOUD_CORRELATION_RULES.values()}
        assert types == {
            "google_cloud_iam_risk_activity_correlation",
            "google_cloud_firewall_risk_activity_correlation",
            "google_cloud_storage_risk_activity_correlation",
            "google_cloud_sql_risk_activity_correlation",
            "google_cloud_run_risk_activity_correlation",
            "google_cloud_gke_risk_activity_correlation",
            "google_cloud_service_account_key_risk_activity_correlation",
            "google_cloud_secret_manager_risk_activity_correlation",
        }

    def test_all_correlation_types_start_with_google_cloud(self):
        for r in GOOGLE_CLOUD_CORRELATION_RULES.values():
            assert r["correlation_type"].startswith("google_cloud_"), (
                f"correlation_type does not start with google_cloud_: {r}"
            )

    def test_aggregate_rules_have_no_name_fields(self):
        """IAM, SA key, Secret Manager rules must be aggregate (no name_field)."""
        aggregate_finding_keys = {
            "google_cloud_iam_public_member",
            "google_cloud_iam_broad_privileged_role",
            "google_cloud_service_account_user_managed_keys",
            "google_cloud_service_account_old_keys",
            "google_cloud_secret_manager_auto_replication_without_cmek",
        }
        for fk in aggregate_finding_keys:
            rule = GOOGLE_CLOUD_CORRELATION_RULES[fk]
            assert rule["name_field"] is None, (
                f"{fk!r} should be aggregate (name_field=None)"
            )
            assert rule["event_name_field"] is None
            assert rule.get("finding_family"), f"{fk!r} missing finding_family"

    def test_resource_rules_have_name_fields(self):
        """Firewall/storage/SQL/Run/GKE must have explicit name fields."""
        resource_finding_keys = {
            "google_cloud_firewall_public_admin_ingress",
            "google_cloud_firewall_public_broad_ingress",
            "google_cloud_firewall_rule_no_targets",
            "google_cloud_storage_public_access_prevention_disabled",
            "google_cloud_storage_uniform_access_disabled",
            "google_cloud_storage_versioning_disabled",
            "google_cloud_storage_retention_not_locked",
            "google_cloud_sql_public_network_access",
            "google_cloud_sql_weak_tls",
            "google_cloud_sql_backups_disabled",
            "google_cloud_sql_deletion_protection_disabled",
            "google_cloud_run_public_invoker",
            "google_cloud_run_all_ingress",
            "google_cloud_gke_public_control_plane",
            "google_cloud_gke_legacy_abac_enabled",
            "google_cloud_gke_network_policy_disabled",
            "google_cloud_gke_workload_identity_disabled",
        }
        for fk in resource_finding_keys:
            rule = GOOGLE_CLOUD_CORRELATION_RULES[fk]
            assert rule["name_field"] is not None, (
                f"{fk!r} should require a resource name match"
            )
            assert rule["event_name_field"] is not None


# ══════════════════════════════════════════════════════════════════════════════
# Resource matching
# ══════════════════════════════════════════════════════════════════════════════


class TestResourceMatching:
    """Resource-name + project_id matching for resource-bearing findings."""

    def test_firewall_name_and_project_match_high_confidence(self):
        f = _mock_finding(
            finding_key="google_cloud_firewall_public_admin_ingress:fw1",
            evidence={
                "firewall_rule_name": "allow-ssh", "project_id": "p1",
                "rule": "google_cloud_firewall_public_admin_ingress",
            },
        )
        ev = _mock_event(
            event_type="google_cloud.firewall_rule.updated",
            metadata={"firewall_rule_name": "allow-ssh", "project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_firewall_public_admin_ingress"]
        assert _gcp_match_resource(f, ev, rule) == "firewall_rule_name+project_id"

    def test_firewall_name_only_match_medium_confidence(self):
        f = _mock_finding(
            finding_key="google_cloud_firewall_public_admin_ingress:fw1",
            evidence={"firewall_rule_name": "allow-ssh"},
        )
        ev = _mock_event(
            event_type="google_cloud.firewall_rule.updated",
            metadata={"firewall_rule_name": "allow-ssh"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_firewall_public_admin_ingress"]
        assert _gcp_match_resource(f, ev, rule) == "firewall_rule_name"

    def test_firewall_name_mismatch_returns_none(self):
        f = _mock_finding(
            finding_key="google_cloud_firewall_public_admin_ingress:fw-a",
            evidence={"firewall_rule_name": "fw-a", "project_id": "p1"},
        )
        ev = _mock_event(
            event_type="google_cloud.firewall_rule.updated",
            metadata={"firewall_rule_name": "fw-b", "project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_firewall_public_admin_ingress"]
        assert _gcp_match_resource(f, ev, rule) is None

    def test_project_mismatch_returns_none(self):
        """Same firewall rule name in different projects must not correlate."""
        f = _mock_finding(
            finding_key="google_cloud_firewall_public_admin_ingress:fw1",
            evidence={"firewall_rule_name": "allow-ssh", "project_id": "p-a"},
        )
        ev = _mock_event(
            event_type="google_cloud.firewall_rule.updated",
            metadata={"firewall_rule_name": "allow-ssh", "project_id": "p-b"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_firewall_public_admin_ingress"]
        assert _gcp_match_resource(f, ev, rule) is None

    def test_storage_bucket_match(self):
        f = _mock_finding(
            finding_key="google_cloud_storage_public_access_prevention_disabled:b1",
            evidence={
                "bucket_name": "my-bucket",
                "rule": "google_cloud_storage_public_access_prevention_disabled",
            },
        )
        ev = _mock_event(
            event_type="google_cloud.storage_bucket.updated",
            metadata={"bucket_name": "my-bucket", "project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_storage_public_access_prevention_disabled"]
        # Finding has no project_id → name-only match
        assert _gcp_match_resource(f, ev, rule) == "bucket_name"

    def test_storage_iam_event_correlates(self):
        f = _mock_finding(
            finding_key="google_cloud_storage_public_access_prevention_disabled:b1",
            evidence={"bucket_name": "my-bucket"},
        )
        ev = _mock_event(
            event_type="google_cloud.storage_iam.updated",
            metadata={"bucket_name": "my-bucket"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_storage_public_access_prevention_disabled"]
        assert ev.event_type in rule["activity_types"]
        assert _gcp_match_resource(f, ev, rule) == "bucket_name"

    def test_sql_instance_match_with_cross_field_mapping(self):
        """Finding evidence uses 'instance_name'; event metadata uses 'sql_instance_name'."""
        f = _mock_finding(
            finding_key="google_cloud_sql_public_network_access:i1",
            evidence={
                "instance_name": "my-sql", "project_id": "p1",
                "rule": "google_cloud_sql_public_network_access",
            },
        )
        ev = _mock_event(
            event_type="google_cloud.sql_instance.updated",
            metadata={"sql_instance_name": "my-sql", "project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_sql_public_network_access"]
        assert _gcp_match_resource(f, ev, rule) == "sql_instance_name+project_id"

    def test_cloud_run_match_with_cross_field_mapping(self):
        """Finding evidence uses 'service_name'; event metadata uses 'run_service_name'."""
        f = _mock_finding(
            finding_key="google_cloud_run_public_invoker:s1",
            evidence={"service_name": "my-svc", "project_id": "p1"},
        )
        ev = _mock_event(
            event_type="google_cloud.run_service.updated",
            metadata={"run_service_name": "my-svc", "project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_run_public_invoker"]
        assert _gcp_match_resource(f, ev, rule) == "run_service_name+project_id"

    def test_gke_cluster_match_with_cross_field_mapping(self):
        """Finding evidence uses 'cluster_name'; event metadata uses 'gke_cluster_name'."""
        f = _mock_finding(
            finding_key="google_cloud_gke_public_control_plane:c1",
            evidence={"cluster_name": "my-cluster", "project_id": "p1"},
        )
        ev = _mock_event(
            event_type="google_cloud.gke_cluster.updated",
            metadata={"gke_cluster_name": "my-cluster", "project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_gke_public_control_plane"]
        assert _gcp_match_resource(f, ev, rule) == "gke_cluster_name+project_id"

    def test_finding_without_name_field_does_not_match(self):
        """Finding lacking name field returns None even if event has it."""
        f = _mock_finding(
            finding_key="google_cloud_firewall_public_admin_ingress:fw1",
            evidence={"project_id": "p1"},  # no firewall_rule_name
        )
        ev = _mock_event(
            event_type="google_cloud.firewall_rule.updated",
            metadata={"firewall_rule_name": "allow-ssh", "project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_firewall_public_admin_ingress"]
        assert _gcp_match_resource(f, ev, rule) is None

    def test_event_without_name_field_does_not_match(self):
        """Event lacking name field returns None even if finding has it."""
        f = _mock_finding(
            finding_key="google_cloud_firewall_public_admin_ingress:fw1",
            evidence={"firewall_rule_name": "allow-ssh"},
        )
        ev = _mock_event(
            event_type="google_cloud.firewall_rule.updated",
            metadata={"project_id": "p1"},  # no firewall_rule_name
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_firewall_public_admin_ingress"]
        assert _gcp_match_resource(f, ev, rule) is None


# ══════════════════════════════════════════════════════════════════════════════
# Aggregate matching (IAM / SA-key / Secret Manager)
# ══════════════════════════════════════════════════════════════════════════════


class TestAggregateMatching:
    """Project + family aggregate matching for findings with no resource name."""

    def test_iam_aggregate_match(self):
        f = _mock_finding(
            finding_key="google_cloud_iam_public_member:p1",
            evidence={"project_id": "p1", "rule": "google_cloud_iam_public_member"},
        )
        ev = _mock_event(
            event_type="google_cloud.iam_policy.updated",
            metadata={"project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_iam_public_member"]
        assert _gcp_match_aggregate(f, ev, rule) == "project_id+iam"

    def test_iam_aggregate_project_mismatch_returns_none(self):
        f = _mock_finding(
            finding_key="google_cloud_iam_public_member:p1",
            evidence={"project_id": "p-a"},
        )
        ev = _mock_event(
            event_type="google_cloud.iam_policy.updated",
            metadata={"project_id": "p-b"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_iam_public_member"]
        assert _gcp_match_aggregate(f, ev, rule) is None

    def test_iam_aggregate_missing_finding_project_returns_none(self):
        f = _mock_finding(
            finding_key="google_cloud_iam_public_member:p1",
            evidence={},  # no project_id
        )
        ev = _mock_event(
            event_type="google_cloud.iam_policy.updated",
            metadata={"project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_iam_public_member"]
        assert _gcp_match_aggregate(f, ev, rule) is None

    def test_iam_aggregate_missing_event_project_returns_none(self):
        f = _mock_finding(
            finding_key="google_cloud_iam_public_member:p1",
            evidence={"project_id": "p1"},
        )
        ev = _mock_event(
            event_type="google_cloud.iam_policy.updated",
            metadata={},  # no project_id
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_iam_public_member"]
        assert _gcp_match_aggregate(f, ev, rule) is None

    def test_service_account_key_aggregate_match(self):
        f = _mock_finding(
            finding_key="google_cloud_service_account_user_managed_keys:p1",
            evidence={"project_id": "p1"},
        )
        ev = _mock_event(
            event_type="google_cloud.service_account_key.created",
            metadata={"project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_service_account_user_managed_keys"]
        assert _gcp_match_aggregate(f, ev, rule) == "project_id+service_account_key"

    def test_secret_manager_aggregate_match(self):
        f = _mock_finding(
            finding_key="google_cloud_secret_manager_auto_replication_without_cmek:p1",
            evidence={"project_id": "p1"},
        )
        ev = _mock_event(
            event_type="google_cloud.secret.updated",
            metadata={"project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_secret_manager_auto_replication_without_cmek"]
        assert _gcp_match_aggregate(f, ev, rule) == "project_id+secret_manager"

    def test_aggregate_never_uses_principal_or_sa_email(self):
        """Even when event metadata happens to contain unsafe keys, the matcher must
        only consult project_id, never principal_email / service_account_email / etc."""
        f = _mock_finding(
            finding_key="google_cloud_iam_public_member:p1",
            evidence={"project_id": "p1"},
        )
        ev = _mock_event(
            event_type="google_cloud.iam_policy.updated",
            metadata={
                "project_id": "p1",
                # Hypothetical poisoning — the matcher must not depend on these
                # for the join decision (sanitization will drop them at the
                # metadata layer anyway).
                "principal_email": "alice@example.com",
                "service_account_email": "sa@p1.iam.gserviceaccount.com",
            },
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_iam_public_member"]
        assert _gcp_match_aggregate(f, ev, rule) == "project_id+iam"


# ══════════════════════════════════════════════════════════════════════════════
# Negative correlations (cross-family / wrong-event-type)
# ══════════════════════════════════════════════════════════════════════════════


class TestNegativeCorrelations:
    """Wrong family + cross-resource matches must NEVER correlate."""

    def test_firewall_finding_does_not_match_storage_event(self):
        f = _mock_finding(
            finding_key="google_cloud_firewall_public_admin_ingress:fw1",
            evidence={"firewall_rule_name": "allow-ssh", "project_id": "p1"},
        )
        ev = _mock_event(
            event_type="google_cloud.storage_bucket.updated",
            metadata={"bucket_name": "x", "project_id": "p1"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_firewall_public_admin_ingress"]
        # The activity_types check is done by the generator, but we verify here
        # that the event_type isn't in the rule's activity_types.
        assert ev.event_type not in rule["activity_types"]

    def test_storage_finding_does_not_match_sql_event(self):
        f = _mock_finding(
            finding_key="google_cloud_storage_public_access_prevention_disabled:b1",
            evidence={"bucket_name": "my-bucket"},
        )
        ev = _mock_event(
            event_type="google_cloud.sql_instance.updated",
            metadata={"sql_instance_name": "x"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_storage_public_access_prevention_disabled"]
        assert ev.event_type not in rule["activity_types"]

    def test_gke_finding_does_not_match_run_event(self):
        f = _mock_finding(
            finding_key="google_cloud_gke_public_control_plane:c1",
            evidence={"cluster_name": "my-cluster"},
        )
        ev = _mock_event(
            event_type="google_cloud.run_service.updated",
            metadata={"run_service_name": "x"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_gke_public_control_plane"]
        assert ev.event_type not in rule["activity_types"]

    def test_iam_finding_does_not_match_firewall_event(self):
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_iam_public_member"]
        assert "google_cloud.firewall_rule.updated" not in rule["activity_types"]

    def test_secret_finding_does_not_match_iam_event(self):
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_secret_manager_auto_replication_without_cmek"]
        assert "google_cloud.iam_policy.updated" not in rule["activity_types"]

    def test_resource_finding_aggregate_match_not_used(self):
        """Resource-bearing findings (e.g. firewall) must NOT fall back to
        aggregate matching even when names are missing — the matcher returns None."""
        f = _mock_finding(
            finding_key="google_cloud_firewall_public_admin_ingress:fw1",
            evidence={"project_id": "p1"},  # no firewall_rule_name
        )
        ev = _mock_event(
            event_type="google_cloud.firewall_rule.updated",
            metadata={"project_id": "p1"},  # no firewall_rule_name
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_firewall_public_admin_ingress"]
        # Resource matcher returns None (no resource name on either side).
        assert _gcp_match_resource(f, ev, rule) is None

    def test_different_buckets_do_not_match(self):
        f = _mock_finding(
            finding_key="google_cloud_storage_public_access_prevention_disabled:b1",
            evidence={"bucket_name": "bucket-a"},
        )
        ev = _mock_event(
            event_type="google_cloud.storage_bucket.updated",
            metadata={"bucket_name": "bucket-b"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_storage_public_access_prevention_disabled"]
        assert _gcp_match_resource(f, ev, rule) is None

    def test_different_sql_instances_do_not_match(self):
        f = _mock_finding(
            finding_key="google_cloud_sql_public_network_access:i1",
            evidence={"instance_name": "sql-a"},
        )
        ev = _mock_event(
            event_type="google_cloud.sql_instance.updated",
            metadata={"sql_instance_name": "sql-b"},
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_sql_public_network_access"]
        assert _gcp_match_resource(f, ev, rule) is None


# ══════════════════════════════════════════════════════════════════════════════
# build_google_cloud_correlation
# ══════════════════════════════════════════════════════════════════════════════


class TestBuildCorrelation:
    def _build_firewall(self, **f_overrides: Any) -> dict:
        f = _mock_finding(
            finding_key="google_cloud_firewall_public_admin_ingress:fw1",
            evidence={
                "firewall_rule_name": "allow-ssh", "project_id": "p1",
                "network_name": "default",
                "rule": "google_cloud_firewall_public_admin_ingress",
            },
            **f_overrides,
        )
        ev = _mock_event(
            event_type="google_cloud.firewall_rule.updated",
            metadata={
                "firewall_rule_name": "allow-ssh",
                "project_id": "p1",
                "service_name": "compute.googleapis.com",
                "method_name": "compute.firewalls.patch",
                "operation_name": "compute.firewalls.patch",
                "operation_family": "compute.firewalls",
                "operation_action": "patch",
                "google_cloud_event_id": "evt-abc",
                "category": "Admin Activity",
            },
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_firewall_public_admin_ingress"]
        return build_google_cloud_correlation(
            finding=f, event=ev, rule=rule,
            matched_on="firewall_rule_name+project_id",
            resource_label='firewall rule "allow-ssh"',
        )

    def test_correlation_has_required_fields(self):
        c = self._build_firewall()
        assert c["provider"] == PROVIDER_GOOGLE_CLOUD
        assert c["correlation_type"] == "google_cloud_firewall_risk_activity_correlation"
        assert c["correlation_key"] == "google_cloud_firewall_risk_activity_correlation"
        assert c["severity"] in ("critical", "high", "medium")
        assert c["status"] == "open"
        assert c["title"]
        assert c["summary"]
        assert c["linked_finding_id"] is not None
        assert c["linked_activity_event_id"] is not None

    def test_high_confidence_when_project_matches(self):
        c = self._build_firewall()
        assert c["confidence"] == "high"
        assert c["metadata"]["match_confidence"] == "high"

    def test_medium_confidence_when_name_only(self):
        f = _mock_finding(
            finding_key="google_cloud_firewall_public_admin_ingress:fw1",
            evidence={"firewall_rule_name": "allow-ssh"},  # no project_id
        )
        ev = _mock_event(
            event_type="google_cloud.firewall_rule.updated",
            metadata={"firewall_rule_name": "allow-ssh"},  # no project_id
        )
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_firewall_public_admin_ingress"]
        c = build_google_cloud_correlation(
            finding=f, event=ev, rule=rule,
            matched_on="firewall_rule_name",
            resource_label='firewall rule "allow-ssh"',
        )
        assert c["confidence"] == "medium"
        assert c["metadata"]["match_confidence"] == "medium"

    def test_severity_inherits_from_finding(self):
        c = self._build_firewall(severity="critical")
        assert c["severity"] == "critical"

    def test_low_severity_floored_to_medium(self):
        """Low-severity findings are review-priority-floored to medium."""
        c = self._build_firewall(severity="low")
        assert c["severity"] == "medium"

    def test_metadata_has_only_allowed_keys(self):
        c = self._build_firewall()
        for key in c["metadata"]:
            assert key in CORR_ALLOWED_KEYS, (
                f"metadata key {key!r} not in ALLOWED_METADATA_KEYS"
            )

    def test_metadata_clean_of_forbidden_keys(self):
        c = self._build_firewall()
        _assert_clean_metadata(c["metadata"])

    def test_metadata_carries_safe_resource_identifiers(self):
        c = self._build_firewall()
        meta = c["metadata"]
        assert meta["firewall_rule_name"] == "allow-ssh"
        assert meta["project_id"] == "p1"
        assert meta["finding_rule"] == "google_cloud_firewall_public_admin_ingress"
        assert meta["finding_family"] == "firewall"

    def test_title_and_summary_clean(self):
        c = self._build_firewall()
        _assert_clean_copy(c["title"])
        _assert_clean_copy(c["summary"])

    def test_window_set(self):
        c = self._build_firewall()
        assert c["window_start"] is not None
        assert c["window_end"] is not None
        assert c["window_start"] <= c["window_end"]


# ══════════════════════════════════════════════════════════════════════════════
# Metadata sanitization
# ══════════════════════════════════════════════════════════════════════════════


class TestMetadataSanitization:
    def test_principal_email_dropped(self):
        meta = sanitize_correlation_metadata({
            "project_id": "p1",
            "principal_email": "alice@example.com",  # not allowlisted
            "service_account_email": "sa@p1.iam.gserviceaccount.com",
            "caller_ip": "1.2.3.4",
            "user_agent": "gcloud/1.0",
        })
        assert "principal_email" not in meta
        assert "service_account_email" not in meta
        assert "caller_ip" not in meta
        assert "user_agent" not in meta
        assert meta["project_id"] == "p1"

    def test_raw_payload_dropped(self):
        meta = sanitize_correlation_metadata({
            "project_id": "p1",
            "protoPayload": {"request": {}, "response": {}},  # nested dict dropped
            "request": "raw",
            "response": "raw",
            "authenticationInfo": {"principalEmail": "x"},
        })
        assert "protoPayload" not in meta
        assert "request" not in meta
        assert "response" not in meta
        assert "authenticationInfo" not in meta

    def test_full_iam_bindings_dropped(self):
        meta = sanitize_correlation_metadata({
            "project_id": "p1",
            "bindings": [{"role": "roles/owner", "members": ["user:x"]}],
        })
        assert "bindings" not in meta

    def test_secret_name_and_value_dropped(self):
        meta = sanitize_correlation_metadata({
            "project_id": "p1",
            "secret_name": "db-password",
            "secret_value": "hunter2",
            "secret_payload": "x",
        })
        assert "secret_name" not in meta
        assert "secret_value" not in meta
        assert "secret_payload" not in meta

    def test_kubeconfig_dropped(self):
        meta = sanitize_correlation_metadata({
            "project_id": "p1",
            "kubeconfig": "apiVersion: v1",
            "node_name": "node-1",
            "pod_spec": "{...}",
        })
        assert "kubeconfig" not in meta
        assert "node_name" not in meta
        assert "pod_spec" not in meta

    def test_database_credentials_dropped(self):
        meta = sanitize_correlation_metadata({
            "project_id": "p1",
            "database_name": "prod",
            "database_user": "admin",
            "password": "hunter2",
            "connection_string": "postgres://...",
            "query_data": "SELECT *",
        })
        for k in ("database_name", "database_user", "password", "connection_string", "query_data"):
            assert k not in meta

    def test_env_var_dropped(self):
        meta = sanitize_correlation_metadata({
            "project_id": "p1",
            "env_var": "FOO",
            "env_var_value": "bar",
        })
        assert "env_var" not in meta
        assert "env_var_value" not in meta

    def test_safe_gcp_identifiers_kept(self):
        meta = sanitize_correlation_metadata({
            "project_id": "p1",
            "firewall_rule_name": "fw-1",
            "network_name": "default",
            "bucket_name": "b1",
            "sql_instance_name": "sql-1",
            "run_service_name": "svc-1",
            "gke_cluster_name": "k8s-1",
            "service_name": "compute.googleapis.com",
            "method_name": "compute.firewalls.patch",
            "google_cloud_event_id": "evt-abc",
            "status_code": 0,
            "finding_family": "firewall",
        })
        assert meta["project_id"] == "p1"
        assert meta["firewall_rule_name"] == "fw-1"
        assert meta["bucket_name"] == "b1"
        assert meta["sql_instance_name"] == "sql-1"
        assert meta["run_service_name"] == "svc-1"
        assert meta["gke_cluster_name"] == "k8s-1"
        assert meta["status_code"] == 0
        assert meta["finding_family"] == "firewall"


# ══════════════════════════════════════════════════════════════════════════════
# Generator: end-to-end via mocked db
# ══════════════════════════════════════════════════════════════════════════════


class TestGenerateCorrelations:
    """End-to-end tests of generate_google_cloud_correlations() with mocked db."""

    def _db_with(self, findings: list, events: list) -> MagicMock:
        db = MagicMock()

        # The service calls db.query(SecurityFinding)... and db.query(SecurityActivityEvent)...
        # We dispatch on the model passed in.
        def query_side_effect(model):
            q = MagicMock()
            # Determine if this is the finding or event query.
            from app.models.security_finding import SecurityFinding
            from app.models.security_activity_event import SecurityActivityEvent
            if model is SecurityFinding:
                items = findings
            elif model is SecurityActivityEvent:
                items = events
            else:
                items = []
            q.filter.return_value.limit.return_value.all.return_value = items
            return q

        db.query.side_effect = query_side_effect
        return db

    def test_returns_expected_shape(self):
        db = self._db_with([], [])
        result = generate_google_cloud_correlations(
            workspace_id=uuid.uuid4(), db=db,
        )
        assert result["provider"] == PROVIDER_GOOGLE_CLOUD
        assert result["findings_scanned"] == 0
        assert result["events_scanned"] == 0
        assert result["correlations_created"] == 0
        assert result["correlations_skipped"] == 0

    def test_unknown_finding_keys_skipped(self):
        f = _mock_finding(
            finding_key="aws_random_finding:1",
            evidence={"firewall_rule_name": "x", "project_id": "p1"},
        )
        # Even though we provide a "firewall" event, the finding doesn't map
        # to a GCP correlation rule.
        ev = _mock_event(
            event_type="google_cloud.firewall_rule.updated",
            metadata={"firewall_rule_name": "x", "project_id": "p1"},
        )
        db = self._db_with([f], [ev])
        result = generate_google_cloud_correlations(
            workspace_id=uuid.uuid4(), db=db,
        )
        # The filter removes the unknown finding key.
        assert result["findings_scanned"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# Privacy across all rule patterns
# ══════════════════════════════════════════════════════════════════════════════


class TestPrivacyAcrossAllRules:
    """Build a correlation for every rule and verify metadata + copy are clean."""

    def _build_for_rule(self, finding_key: str) -> dict:
        rule = GOOGLE_CLOUD_CORRELATION_RULES[finding_key]
        if rule["name_field"] is None:
            # Aggregate rule
            f = _mock_finding(
                finding_key=f"{finding_key}:p1",
                evidence={"project_id": "p1"},
            )
            event_type = next(iter(rule["activity_types"]))
            ev = _mock_event(
                event_type=event_type,
                metadata={"project_id": "p1"},
            )
            matched_on = f"project_id+{rule['finding_family']}"
            resource_label = _gcp_resource_label(f, rule, None)
        else:
            f = _mock_finding(
                finding_key=f"{finding_key}:res1",
                evidence={rule["name_field"]: "res1", "project_id": "p1"},
            )
            event_type = next(iter(rule["activity_types"]))
            ev = _mock_event(
                event_type=event_type,
                metadata={rule["event_name_field"]: "res1", "project_id": "p1"},
            )
            matched_on = f"{rule['event_name_field']}+project_id"
            resource_label = _gcp_resource_label(f, rule, "res1")

        return build_google_cloud_correlation(
            finding=f, event=ev, rule=rule,
            matched_on=matched_on, resource_label=resource_label,
        )

    def test_all_rules_produce_clean_metadata(self):
        for fk in GOOGLE_CLOUD_CORRELATION_RULES:
            c = self._build_for_rule(fk)
            _assert_clean_metadata(c["metadata"])

    def test_all_rules_produce_clean_copy(self):
        for fk in GOOGLE_CLOUD_CORRELATION_RULES:
            c = self._build_for_rule(fk)
            _assert_clean_copy(c["title"])
            _assert_clean_copy(c["summary"])

    def test_all_rules_carry_provider_google_cloud(self):
        for fk in GOOGLE_CLOUD_CORRELATION_RULES:
            c = self._build_for_rule(fk)
            assert c["provider"] == PROVIDER_GOOGLE_CLOUD

    def test_all_rules_have_finding_family_metadata(self):
        """Every correlation must carry finding_family for downstream filtering."""
        for fk in GOOGLE_CLOUD_CORRELATION_RULES:
            c = self._build_for_rule(fk)
            assert c["metadata"].get("finding_family"), (
                f"{fk!r} missing finding_family in metadata"
            )


# ══════════════════════════════════════════════════════════════════════════════
# Resource label
# ══════════════════════════════════════════════════════════════════════════════


class TestResourceLabel:
    def test_resource_label_with_name(self):
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_firewall_public_admin_ingress"]
        f = _mock_finding(finding_key="x:fw1", evidence={"firewall_rule_name": "allow-ssh"})
        label = _gcp_resource_label(f, rule, "allow-ssh")
        assert "allow-ssh" in label
        assert "firewall rule" in label

    def test_resource_label_aggregate_uses_project(self):
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_iam_public_member"]
        f = _mock_finding(finding_key="x:p1", evidence={"project_id": "my-project"})
        label = _gcp_resource_label(f, rule, None)
        assert "my-project" in label

    def test_resource_label_aggregate_no_project_falls_back(self):
        rule = GOOGLE_CLOUD_CORRELATION_RULES["google_cloud_iam_public_member"]
        f = _mock_finding(finding_key="x:p1", evidence={})
        label = _gcp_resource_label(f, rule, None)
        assert label == rule["kind"]  # bare kind


# ══════════════════════════════════════════════════════════════════════════════
# Capability matrix + expansion framework
# ══════════════════════════════════════════════════════════════════════════════


class TestCapabilityMatrix:
    def test_risk_activity_correlations_now_true(self):
        cap = get_provider_capability("google_cloud")
        assert cap is not None
        assert cap.security.risk_activity_correlations is True

    def test_activity_signals_still_true(self):
        cap = get_provider_capability("google_cloud")
        assert cap.security.activity_signals is True

    def test_activity_ingestion_still_true(self):
        cap = get_provider_capability("google_cloud")
        assert cap.security.activity_ingestion is True

    def test_demo_seed_clear_now_true(self):
        """Flipped in M78G."""
        cap = get_provider_capability("google_cloud")
        assert cap.security.demo_seed_clear is True

    def test_case_report_now_true(self):
        """Flipped in M78G (generic case report renderer supports google_cloud)."""
        cap = get_provider_capability("google_cloud")
        assert cap.security.case_report is True

    def test_maturity_still_partial(self):
        cap = get_provider_capability("google_cloud")
        assert cap.maturity == "partial"

    def test_google_cloud_still_partial_list(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES_PARTIAL, PROVIDER_CAPABILITIES,
        )
        partial = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        complete = {p.provider for p in PROVIDER_CAPABILITIES}
        assert "google_cloud" in partial
        assert "google_cloud" not in complete

    def test_notes_mention_correlations(self):
        cap = get_provider_capability("google_cloud")
        assert "correlation" in cap.notes.lower() or "Correlation" in cap.notes


class TestExpansionFramework:
    def test_planned_next_stage_is_m78h(self):
        """Rolled forward in M79A: Twilio launched → M79B Twilio Core Security Foundation."""
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M79B" in planned
        assert "Twilio" in planned

    def test_planned_next_stage_mentions_polish_or_ux(self):
        """After M79A, next stage is M79B: Twilio Core Security Foundation."""
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M79B" in planned or "Twilio" in planned

    def test_m78f_not_in_planned_next_stage(self):
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M78F" not in planned
