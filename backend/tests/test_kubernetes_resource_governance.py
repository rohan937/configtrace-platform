"""Kubernetes resource-governance tests (Kubernetes message 5 of 9).

Covers ResourceQuota collection/normalization, Kubernetes quantity
parsing (CPU/memory, malformed/zero/missing distinctions), LimitRange
collection/normalization, and namespace governance rollups (including
absence vs. API-denied distinction and cross-control aggregation).

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from kubernetes.client.rest import ApiException

from app.connectors.kubernetes import (
    _build_namespace_governance_postures,
    _collect_limit_ranges,
    _collect_resource_quotas,
    _normalize_limit_range,
    _normalize_resource_quota,
    parse_cpu_quantity_millicores,
    parse_memory_quantity_bytes,
)
from app.connectors.kubernetes_schema import POLICY_COVERAGE_BROAD, POLICY_COVERAGE_NONE, POLICY_COVERAGE_PARTIAL
from tests._kubernetes_admission_fixtures import (
    make_limit_range,
    make_limit_range_item,
    make_resource_quota,
    page,
)


def _rq(**kwargs):
    obj = make_resource_quota(**kwargs)
    return _normalize_resource_quota(obj, cluster_id="uid:c1", cluster_name="c1")


def _lr(**kwargs):
    obj = make_limit_range(**kwargs)
    return _normalize_limit_range(obj, cluster_id="uid:c1", cluster_name="c1")


# ── AX-BF: ResourceQuota fields ────────────────────────────────────────────────

class TestResourceQuotaFields:
    def test_AX_cpu(self):
        record = _rq(hard={"cpu": "4"})
        assert record["hard_cpu_limit_present"] is True
        assert record["hard_cpu_limit_millicores"] == 4000

    def test_AY_memory(self):
        record = _rq(hard={"memory": "8Gi"})
        assert record["hard_memory_limit_present"] is True
        assert record["hard_memory_limit_bytes"] == 8 * 1024**3

    def test_AZ_pods(self):
        record = _rq(hard={"pods": "50"})
        assert record["pod_count_limit_present"] is True
        assert record["pod_count_limit"] == 50

    def test_BA_services(self):
        assert _rq(hard={"services": "10"})["service_count_limit_present"] is True

    def test_BB_load_balancers(self):
        assert _rq(hard={"services.loadbalancers": "2"})["load_balancer_count_limit_present"] is True

    def test_BC_pvcs(self):
        assert _rq(hard={"persistentvolumeclaims": "5"})["pvc_count_limit_present"] is True

    def test_BD_storage(self):
        assert _rq(hard={"requests.storage": "100Gi"})["storage_request_limit_present"] is True

    def test_BE_secrets(self):
        assert _rq(hard={"count/secrets": "10"})["secret_count_limit_present"] is True

    def test_BF_configmaps(self):
        assert _rq(hard={"count/configmaps": "10"})["configmap_count_limit_present"] is True

    def test_quota_scope(self):
        record = _rq(scopes=["NotTerminating", "BestEffort"])
        assert record["scope_categories"] == ["BestEffort", "NotTerminating"]

    def test_quota_scope_selector_present(self):
        from types import SimpleNamespace as NS
        record = _rq(scope_selector=NS(match_expressions=[]))
        assert record["scope_selector_present"] is True


class TestResourceQuotaCoverage:
    def test_BG_broad_coverage(self):
        record = _rq(hard={"cpu": "4", "memory": "8Gi", "pods": "50", "services": "10"})
        assert record["resource_control_coverage_category"] == POLICY_COVERAGE_BROAD

    def test_BH_quota_removed_no_hard_limits(self):
        record = _rq(hard={})
        assert record["resource_control_coverage_category"] == POLICY_COVERAGE_NONE

    def test_partial_coverage(self):
        record = _rq(hard={"cpu": "4"})
        assert record["resource_control_coverage_category"] == POLICY_COVERAGE_PARTIAL


class TestQuantityParsing:
    def test_cpu_millicores(self):
        assert parse_cpu_quantity_millicores("500m") == 500
        assert parse_cpu_quantity_millicores("2") == 2000
        assert parse_cpu_quantity_millicores("1.5") == 1500

    def test_memory_bytes(self):
        assert parse_memory_quantity_bytes("128Mi") == 128 * 1024**2
        assert parse_memory_quantity_bytes("1Gi") == 1024**3
        assert parse_memory_quantity_bytes("500M") == 500_000_000

    def test_BI_malformed_quantity(self):
        assert parse_cpu_quantity_millicores("not-a-number") is None
        assert parse_memory_quantity_bytes("garbage") is None

    def test_BJ_exact_zero_quantity(self):
        assert parse_cpu_quantity_millicores("0") == 0
        assert parse_memory_quantity_bytes("0") == 0

    def test_BK_missing_quantity_is_none_not_zero(self):
        record = _rq(hard={})
        assert record["hard_cpu_limit_millicores"] is None
        # Never coerce "missing" to 0 — it's structurally None.
        assert record["hard_cpu_limit_millicores"] != 0

    def test_CR_unknown_quantity_not_zero(self):
        record = _rq(hard={"cpu": "not-a-cpu-value"})
        assert record["hard_cpu_limit_present"] is True  # key present
        assert record["hard_cpu_limit_millicores"] is None  # but unparseable -> unknown, not 0


# ── BL-BV: LimitRange fields ───────────────────────────────────────────────────

class TestLimitRangeFields:
    def test_BL_default_cpu(self):
        item = make_limit_range_item(item_type="Container", default={"cpu": "500m"})
        record = _lr(items=[item])
        assert record["container_default_present"] is True
        assert record["cpu_policy_coverage_category"] in (POLICY_COVERAGE_PARTIAL, POLICY_COVERAGE_BROAD)

    def test_BM_default_memory(self):
        item = make_limit_range_item(item_type="Container", default={"memory": "256Mi"})
        record = _lr(items=[item])
        assert record["memory_policy_coverage_category"] in (POLICY_COVERAGE_PARTIAL, POLICY_COVERAGE_BROAD)

    def test_BN_default_request_cpu(self):
        item = make_limit_range_item(item_type="Container", default_request={"cpu": "250m"})
        record = _lr(items=[item])
        assert record["container_default_request_present"] is True

    def test_BO_default_request_memory(self):
        item = make_limit_range_item(item_type="Container", default_request={"memory": "128Mi"})
        record = _lr(items=[item])
        assert record["container_default_request_present"] is True

    def test_BP_container_max(self):
        item = make_limit_range_item(item_type="Container", max_={"cpu": "2"})
        record = _lr(items=[item])
        assert record["container_max_present"] is True

    def test_BQ_container_min(self):
        item = make_limit_range_item(item_type="Container", min_={"cpu": "10m"})
        record = _lr(items=[item])
        assert record["container_min_present"] is True

    def test_BR_pod_max(self):
        item = make_limit_range_item(item_type="Pod", max_={"cpu": "4"})
        record = _lr(items=[item])
        assert record["pod_max_present"] is True

    def test_BS_pod_min(self):
        item = make_limit_range_item(item_type="Pod", min_={"cpu": "100m"})
        record = _lr(items=[item])
        assert record["pod_min_present"] is True

    def test_BT_pvc_min_max(self):
        item = make_limit_range_item(item_type="PersistentVolumeClaim", min_={"storage": "1Gi"}, max_={"storage": "100Gi"})
        record = _lr(items=[item])
        assert record["pvc_min_present"] is True
        assert record["pvc_max_present"] is True

    def test_BU_ratio_constraint(self):
        item = make_limit_range_item(item_type="Container", ratio={"cpu": "4"})
        record = _lr(items=[item])
        assert record["request_to_limit_ratio_present"] is True

    def test_full_defaulting_coverage(self):
        item = make_limit_range_item(
            item_type="Container",
            default={"cpu": "1"}, default_request={"cpu": "500m"}, max_={"cpu": "2"}, min_={"cpu": "10m"},
        )
        pod_item = make_limit_range_item(item_type="Pod", max_={"cpu": "4"}, min_={"cpu": "50m"})
        record = _lr(items=[item, pod_item])
        assert record["defaulting_coverage_category"] == POLICY_COVERAGE_BROAD


class TestResourceQuotaLimitRangeCollectionFailSoft:
    def test_CC_quota_api_denied(self):
        list_fn = MagicMock(side_effect=ApiException(status=403))
        records, status = _collect_resource_quotas(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "partial"
        assert records == []

    def test_CF_malformed_quota_isolated(self):
        good = make_resource_quota(name="good")
        malformed = object()
        list_fn = MagicMock(return_value=page([malformed, good]))
        records, status = _collect_resource_quotas(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert len(records) == 1

    def test_namespace_allowlist_quota(self):
        quotas = [make_resource_quota(namespace="prod", name="a"), make_resource_quota(namespace="staging", name="b")]
        list_fn = MagicMock(return_value=page(quotas))
        records, _status = _collect_resource_quotas(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=["prod"],
        )
        assert [r["namespace"] for r in records] == ["prod"]

    def test_limit_range_pagination(self):
        pages = [
            page([make_limit_range(name="a")], continue_token="tok1"),
            page([make_limit_range(name="b")], continue_token=None),
        ]
        list_fn = MagicMock(side_effect=pages)
        records, status = _collect_limit_ranges(
            list_fn, cluster_id="c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert status == "complete"
        assert {r["name"] for r in records} == {"a", "b"}

    def test_CI_stable_uid_identity(self):
        rq = make_resource_quota(uid="stable-uid")
        list_fn = MagicMock(return_value=page([rq]))
        records, _status = _collect_resource_quotas(
            list_fn, cluster_id="uid:c1", cluster_name="c1", namespace_allowlist=None,
        )
        assert records[0]["record_id"] == "uid:c1/resource_quota/prod/stable-uid"


# ── BW-BZ: namespace governance rollups ───────────────────────────────────────

class TestNamespaceGovernanceRollup:
    def test_BW_namespace_governance_safe(self):
        namespace_records = [{"name": "prod"}]
        records = _build_namespace_governance_postures(
            namespace_records=namespace_records, psa_records=[{"namespace": "prod", "enforce_level": "restricted"}],
            validating_webhook_records=[], mutating_webhook_records=[],
            quota_records=[{"namespace": "prod"}], limit_range_records=[{"namespace": "prod"}],
            network_posture_records=[{"namespace": "prod", "policy_coverage_category": "broad"}],
            workload_records=[], service_account_records=[],
            cluster_id="c1", cluster_name="c1",
            admission_collection_status="complete", quota_collection_status="complete",
            limit_range_collection_status="complete",
        )
        assert records[0]["governance_risk_summary"] == "standard"
        assert records[0]["quota_coverage_category"] == "broad"

    def test_BX_weak_psa_plus_privileged_workload(self):
        records = _build_namespace_governance_postures(
            namespace_records=[{"name": "prod"}], psa_records=[{"namespace": "prod", "enforce_level": "privileged"}],
            validating_webhook_records=[], mutating_webhook_records=[],
            quota_records=[], limit_range_records=[],
            network_posture_records=[],
            workload_records=[{"namespace": "prod", "security_posture_summary": "privileged_or_host_access"}],
            service_account_records=[],
            cluster_id="c1", cluster_name="c1",
            admission_collection_status="complete", quota_collection_status="complete",
            limit_range_collection_status="complete",
        )
        assert "privileged_workload_weak_psa" in records[0]["governance_risk_summary"]
        assert records[0]["privileged_workload_present"] is True

    def test_BY_high_privilege_identity_plus_weak_governance(self):
        records = _build_namespace_governance_postures(
            namespace_records=[{"name": "prod"}], psa_records=[{"namespace": "prod", "enforce_level": "restricted"}],
            validating_webhook_records=[], mutating_webhook_records=[],
            quota_records=[], limit_range_records=[],
            network_posture_records=[{"namespace": "prod", "policy_coverage_category": "none"}],
            workload_records=[],
            service_account_records=[{"namespace": "prod", "cluster_admin_bound": True}],
            cluster_id="c1", cluster_name="c1",
            admission_collection_status="complete", quota_collection_status="complete",
            limit_range_collection_status="complete",
        )
        assert "high_privilege_identity_weak_governance" in records[0]["governance_risk_summary"]
        assert records[0]["high_privilege_service_account_present"] is True

    def test_BZ_network_isolation_plus_psa_rollup(self):
        records = _build_namespace_governance_postures(
            namespace_records=[{"name": "prod"}], psa_records=[{"namespace": "prod", "enforce_level": "restricted"}],
            validating_webhook_records=[], mutating_webhook_records=[],
            quota_records=[], limit_range_records=[],
            network_posture_records=[{"namespace": "prod", "policy_coverage_category": "broad"}],
            workload_records=[], service_account_records=[],
            cluster_id="c1", cluster_name="c1",
            admission_collection_status="complete", quota_collection_status="complete",
            limit_range_collection_status="complete",
        )
        assert records[0]["psa_enforcement_category"] == "restricted"
        assert records[0]["network_policy_coverage_category"] == "broad"

    def test_CA_webhook_applicability_unknown_narrow_selector(self):
        # A webhook with only a narrow (label-based) selector cannot be
        # resolved to "applies to this namespace" without evaluating
        # arbitrary namespace labels — coverage is "partial", not "full".
        records = _build_namespace_governance_postures(
            namespace_records=[{"name": "prod"}], psa_records=[],
            validating_webhook_records=[{"namespace_selector_category": "narrow"}],
            mutating_webhook_records=[],
            quota_records=[], limit_range_records=[], network_posture_records=[],
            workload_records=[], service_account_records=[],
            cluster_id="c1", cluster_name="c1",
            admission_collection_status="complete", quota_collection_status="complete",
            limit_range_collection_status="complete",
        )
        assert records[0]["validating_webhook_coverage_category"] == "partial"

    def test_full_webhook_coverage_when_unrestricted_webhook_exists(self):
        records = _build_namespace_governance_postures(
            namespace_records=[{"name": "prod"}], psa_records=[],
            validating_webhook_records=[{"namespace_selector_category": "absent"}],
            mutating_webhook_records=[],
            quota_records=[], limit_range_records=[], network_posture_records=[],
            workload_records=[], service_account_records=[],
            cluster_id="c1", cluster_name="c1",
            admission_collection_status="complete", quota_collection_status="complete",
            limit_range_collection_status="complete",
        )
        assert records[0]["validating_webhook_coverage_category"] == "full"

    def test_CS_permission_denied_not_interpreted_as_absent_controls(self):
        records = _build_namespace_governance_postures(
            namespace_records=[{"name": "prod"}], psa_records=[],
            validating_webhook_records=[], mutating_webhook_records=[],
            quota_records=[], limit_range_records=[], network_posture_records=[],
            workload_records=[], service_account_records=[],
            cluster_id="c1", cluster_name="c1",
            admission_collection_status="complete", quota_collection_status="partial",
            limit_range_collection_status="complete",
        )
        # Permission denial on quota collection -> "unknown", never "none".
        assert records[0]["quota_coverage_category"] == "unknown"
        assert records[0]["governance_completeness_category"] == "partial"


class TestSensitiveDataExclusion:
    def test_CO_no_arbitrary_quota_hard_keys_leaked_verbatim_beyond_normalized_fields(self):
        import json
        record = _rq(hard={"cpu": "4", "some.custom.crd/widgets": "99"})
        # Only the explicitly-normalized keys produce fields; unrecognized
        # keys contribute only to hard_limit_key_count, never their own
        # literal key/value pair.
        assert "some.custom.crd/widgets" not in json.dumps(record)
        assert record["hard_limit_key_count"] == 2
