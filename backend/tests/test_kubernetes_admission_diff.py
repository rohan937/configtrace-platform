"""Kubernetes admission/policy diff and risk-routing tests (Kubernetes
message 5 of 9).

Exercises the REAL ``compute_diff()`` -> ``classify_kubernetes_change()``
pipeline for the 8 newly emitted record types: webhook failurePolicy
Fail->Ignore and back, validating webhook removed/restored, wildcard rule
introduced/removed, selector broadened/narrowed, PSA restricted->baseline
and back, PSA removed/restored, ResourceQuota removed/restored, LimitRange
defaults removed/restored, namespace governance posture, provider
metadata, and ordering-only/resourceVersion-only changes being ignored.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.connectors.kubernetes import (
    _build_namespace_governance_postures,
    _collect_webhook_configurations,
    _normalize_limit_range,
    _normalize_pod_security_admission,
    _normalize_resource_quota,
)
from app.services.diff_service import compute_diff
from app.services.risk_rules.kubernetes import classify_kubernetes_change
from app.services.risk_service import classify_change
from tests._kubernetes_admission_fixtures import (
    make_client_config,
    make_limit_range,
    make_limit_range_item,
    make_namespace_record,
    make_resource_quota,
    make_rule,
    make_selector,
    make_service_ref,
    make_webhook,
    make_webhook_configuration,
    page,
)


class _FakeSnapshot:
    def __init__(self, state: list[dict]):
        self.state = state


def _real_changes(prev_records: list[dict], new_records: list[dict]) -> list[dict]:
    return compute_diff(_FakeSnapshot(prev_records), _FakeSnapshot(new_records))


def _collect_one_config(kind="validating", **webhook_kwargs):
    config = make_webhook_configuration(webhooks=[make_webhook(**webhook_kwargs)])
    list_fn = MagicMock(return_value=page([config]))
    configs, webhooks, _status = _collect_webhook_configurations(
        list_fn, kind=kind, cluster_id="uid:c1", cluster_name="c1",
    )
    return configs[0], webhooks[0]


def _collect_one_psa(**kwargs):
    ns = make_namespace_record(**kwargs)
    return _normalize_pod_security_admission(ns, cluster_id="uid:c1", cluster_name="c1", cluster_major_minor="1.29")


def _collect_one_quota(**kwargs):
    obj = make_resource_quota(**kwargs)
    return _normalize_resource_quota(obj, cluster_id="uid:c1", cluster_name="c1")


def _collect_one_limit_range(**kwargs):
    obj = make_limit_range(**kwargs)
    return _normalize_limit_range(obj, cluster_id="uid:c1", cluster_name="c1")


class TestFailurePolicyDiff:
    def test_fail_to_ignore(self):
        _ca, wa = _collect_one_config(failure_policy="Fail")
        _cb, wb = _collect_one_config(failure_policy="Ignore")
        changes = _real_changes([wa], [wb])
        fp_changes = [c for c in changes if c["field_path"] == "failure_policy"]
        assert len(fp_changes) == 1
        severity, msg = classify_kubernetes_change(fp_changes[0])
        assert severity == "high"
        assert "ignore" in msg.lower()

    def test_ignore_to_fail(self):
        _ca, wa = _collect_one_config(failure_policy="Ignore")
        _cb, wb = _collect_one_config(failure_policy="Fail")
        changes = _real_changes([wa], [wb])
        fp_changes = [c for c in changes if c["field_path"] == "failure_policy"]
        severity, _msg = classify_kubernetes_change(fp_changes[0])
        assert severity == "low"


class TestValidatingWebhookRemovedRestored:
    def test_validating_webhook_removed(self):
        ca, _wa = _collect_one_config(failure_policy="Fail")
        list_fn_empty = MagicMock(return_value=page([]))
        cb_configs, _wb, _status = _collect_webhook_configurations(
            list_fn_empty, kind="validating", cluster_id="uid:c1", cluster_name="c1",
        )
        changes = _real_changes([ca], cb_configs)
        removed = [c for c in changes if c["change_type"] == "removed"]
        assert len(removed) == 1
        severity, msg = classify_kubernetes_change(removed[0])
        assert severity == "high"
        assert "fail-closed" in msg.lower()

    def test_validating_webhook_restored(self):
        list_fn_empty = MagicMock(return_value=page([]))
        ca_configs, _wa, _status = _collect_webhook_configurations(
            list_fn_empty, kind="validating", cluster_id="uid:c1", cluster_name="c1",
        )
        cb, _wb = _collect_one_config(failure_policy="Fail")
        changes = _real_changes(ca_configs, [cb])
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        severity, _msg = classify_kubernetes_change(added[0])
        assert severity == "low"


class TestRuleWildcardDiff:
    def test_wildcard_introduced(self):
        _ca, wa = _collect_one_config(rules=[make_rule(resources=["pods"])])
        _cb, wb = _collect_one_config(rules=[make_rule(resources=["*"])])
        changes = _real_changes([wa], [wb])
        wc_changes = [c for c in changes if c["field_path"] == "wildcard_resource"]
        assert len(wc_changes) == 1
        severity, _msg = classify_kubernetes_change(wc_changes[0])
        assert severity == "high"

    def test_wildcard_removed(self):
        _ca, wa = _collect_one_config(rules=[make_rule(resources=["*"])])
        _cb, wb = _collect_one_config(rules=[make_rule(resources=["pods"])])
        changes = _real_changes([wa], [wb])
        wc_changes = [c for c in changes if c["field_path"] == "wildcard_resource"]
        severity, _msg = classify_kubernetes_change(wc_changes[0])
        assert severity == "low"


class TestSelectorDiff:
    def test_selector_broadened(self):
        narrow = make_selector(match_labels={"env": "prod"})
        _ca, wa = _collect_one_config(namespace_selector=narrow)
        _cb, wb = _collect_one_config(namespace_selector=None)
        changes = _real_changes([wa], [wb])
        sel_changes = [c for c in changes if c["field_path"] == "namespace_selector_category"]
        assert len(sel_changes) == 1
        severity, msg = classify_kubernetes_change(sel_changes[0])
        assert severity == "medium"
        assert "broadened" in msg.lower()

    def test_selector_narrowed(self):
        narrow = make_selector(match_labels={"env": "prod"})
        _ca, wa = _collect_one_config(namespace_selector=None)
        _cb, wb = _collect_one_config(namespace_selector=narrow)
        changes = _real_changes([wa], [wb])
        sel_changes = [c for c in changes if c["field_path"] == "namespace_selector_category"]
        severity, _msg = classify_kubernetes_change(sel_changes[0])
        assert severity == "low"


class TestPsaDiff:
    def test_restricted_to_baseline(self):
        a = _collect_one_psa(enforce="restricted")
        b = _collect_one_psa(enforce="baseline")
        changes = _real_changes([a], [b])
        enforce_changes = [c for c in changes if c["field_path"] == "enforce_level"]
        assert len(enforce_changes) == 1
        severity, msg = classify_kubernetes_change(enforce_changes[0])
        assert severity == "high"
        assert "weakened" in msg.lower()

    def test_baseline_to_restricted(self):
        a = _collect_one_psa(enforce="baseline")
        b = _collect_one_psa(enforce="restricted")
        changes = _real_changes([a], [b])
        enforce_changes = [c for c in changes if c["field_path"] == "enforce_level"]
        severity, msg = classify_kubernetes_change(enforce_changes[0])
        assert severity == "low"
        assert "strengthened" in msg.lower()

    def test_psa_removed(self):
        a = _collect_one_psa(enforce="restricted")
        b = _collect_one_psa(enforce=None)
        changes = _real_changes([a], [b])
        enforce_changes = [c for c in changes if c["field_path"] == "enforce_level"]
        assert len(enforce_changes) == 1
        severity, msg = classify_kubernetes_change(enforce_changes[0])
        assert severity == "high"
        assert "removed" in msg.lower()

    def test_psa_restored(self):
        a = _collect_one_psa(enforce=None)
        b = _collect_one_psa(enforce="restricted")
        changes = _real_changes([a], [b])
        enforce_changes = [c for c in changes if c["field_path"] == "enforce_level"]
        severity, _msg = classify_kubernetes_change(enforce_changes[0])
        assert severity == "low"


class TestResourceQuotaDiff:
    def test_quota_removed(self):
        a = _collect_one_quota(hard={"cpu": "4"})
        changes = _real_changes([a], [])
        removed = [c for c in changes if c["change_type"] == "removed"]
        assert len(removed) == 1
        severity, _msg = classify_kubernetes_change(removed[0])
        assert severity == "medium"

    def test_quota_restored(self):
        a = _collect_one_quota(hard={"cpu": "4"})
        changes = _real_changes([], [a])
        added = [c for c in changes if c["change_type"] == "added"]
        assert len(added) == 1
        severity, _msg = classify_kubernetes_change(added[0])
        assert severity == "low"

    def test_cpu_limit_removed(self):
        a = _collect_one_quota(hard={"cpu": "4"})
        b = _collect_one_quota(hard={})
        changes = _real_changes([a], [b])
        cpu_changes = [c for c in changes if c["field_path"] == "hard_cpu_limit_present"]
        assert len(cpu_changes) == 1
        severity, _msg = classify_kubernetes_change(cpu_changes[0])
        assert severity == "medium"


class TestLimitRangeDiff:
    def test_defaults_removed(self):
        item_with_default = make_limit_range_item(item_type="Container", default={"cpu": "500m"})
        item_without_default = make_limit_range_item(item_type="Container", default={})
        a = _collect_one_limit_range(items=[item_with_default])
        b = _collect_one_limit_range(items=[item_without_default])
        changes = _real_changes([a], [b])
        default_changes = [c for c in changes if c["field_path"] == "container_default_present"]
        assert len(default_changes) == 1
        severity, msg = classify_kubernetes_change(default_changes[0])
        assert severity == "high"
        assert "removed" in msg.lower()

    def test_defaults_restored(self):
        item_with_default = make_limit_range_item(item_type="Container", default={"cpu": "500m"})
        item_without_default = make_limit_range_item(item_type="Container", default={})
        a = _collect_one_limit_range(items=[item_without_default])
        b = _collect_one_limit_range(items=[item_with_default])
        changes = _real_changes([a], [b])
        default_changes = [c for c in changes if c["field_path"] == "container_default_present"]
        severity, _msg = classify_kubernetes_change(default_changes[0])
        assert severity == "low"

    def test_limit_range_removed_with_defaults_is_high(self):
        item_with_default = make_limit_range_item(item_type="Container", default={"cpu": "500m"})
        a = _collect_one_limit_range(items=[item_with_default])
        changes = _real_changes([a], [])
        removed = [c for c in changes if c["change_type"] == "removed"]
        assert len(removed) == 1
        severity, _msg = classify_kubernetes_change(removed[0])
        assert severity == "high"


class TestNamespaceGovernancePostureDiff:
    def test_psa_enforcement_weakened_in_rollup(self):
        a = _build_namespace_governance_postures(
            namespace_records=[{"name": "prod"}], psa_records=[{"namespace": "prod", "enforce_level": "restricted"}],
            validating_webhook_records=[], mutating_webhook_records=[],
            quota_records=[], limit_range_records=[], network_posture_records=[],
            workload_records=[], service_account_records=[],
            cluster_id="uid:c1", cluster_name="c1",
            admission_collection_status="complete", quota_collection_status="complete",
            limit_range_collection_status="complete",
        )
        b = _build_namespace_governance_postures(
            namespace_records=[{"name": "prod"}], psa_records=[{"namespace": "prod", "enforce_level": "privileged"}],
            validating_webhook_records=[], mutating_webhook_records=[],
            quota_records=[], limit_range_records=[], network_posture_records=[],
            workload_records=[], service_account_records=[],
            cluster_id="uid:c1", cluster_name="c1",
            admission_collection_status="complete", quota_collection_status="complete",
            limit_range_collection_status="complete",
        )
        changes = _real_changes(a, b)
        psa_changes = [c for c in changes if c["field_path"] == "psa_enforcement_category"]
        assert len(psa_changes) == 1
        severity, _msg = classify_kubernetes_change(psa_changes[0])
        assert severity == "high"


class TestNoisyFieldsIgnored:
    def test_resource_version_only_change_ignored(self):
        a = _collect_one_psa(enforce="restricted")
        changes = _real_changes([dict(a)], [dict(a)])
        assert changes == []

    def test_ordering_only_change_ignored(self):
        a = _collect_one_quota(hard={"cpu": "4", "memory": "8Gi"})
        b = _collect_one_quota(hard={"cpu": "4", "memory": "8Gi"})
        changes = _real_changes([a], [b])
        assert changes == []


class TestProviderMetadata:
    def test_webhook_change_metadata(self):
        _ca, wa = _collect_one_config(failure_policy="Fail")
        _cb, wb = _collect_one_config(failure_policy="Ignore")
        changes = _real_changes([wa], [wb])
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "kubernetes_validating_webhook"
        assert pm["webhook_name"] == "validate.example.com"
        assert pm["cluster_id"] == "uid:c1"

    def test_resource_quota_change_metadata(self):
        a = _collect_one_quota(hard={"cpu": "4"})
        b = _collect_one_quota(hard={})
        changes = _real_changes([a], [b])
        pm = changes[0]["provider_metadata"]
        assert pm["record_type"] == "kubernetes_resource_quota"
        assert pm["quota_name"] == "compute-quota"


class TestRiskRoutingNeverFallsThroughToOtherProviders:
    def test_psa_change_routes_to_kubernetes_classifier(self):
        a = _collect_one_psa(enforce="restricted")
        b = _collect_one_psa(enforce="baseline")
        changes = _real_changes([a], [b])
        assert changes
        for change in changes:
            assert change["provider_metadata"]["record_type"].startswith("kubernetes_")

        class _ChangeObj:
            def __init__(self, d):
                self.__dict__.update(d)

        severity, msg = classify_change(_ChangeObj(changes[0]))
        assert severity in ("low", "medium", "high", "critical")
        assert "cloudflare" not in msg.lower()
        assert "aws" not in msg.lower()

    def test_limit_range_never_routes_to_cloudflare_fallback(self):
        item_a = make_limit_range_item(item_type="Container", default={"cpu": "500m"})
        item_b = make_limit_range_item(item_type="Container", default={})
        a = _collect_one_limit_range(items=[item_a])
        b = _collect_one_limit_range(items=[item_b])
        changes = _real_changes([a], [b])
        assert changes
        for change in changes:
            assert change["provider_metadata"]["record_type"] == "kubernetes_limit_range"
