"""Kubernetes admission webhook tests (Kubernetes message 5 of 9).

Covers ValidatingWebhookConfiguration/MutatingWebhookConfiguration
collection, per-webhook normalization, selector/rule categorization,
client handling (Service vs external URL), fail-soft behavior, pagination,
and malformed-item isolation.

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from kubernetes.client.rest import ApiException

from app.connectors.kubernetes import (
    _collect_webhook_configurations,
    _normalize_webhook_configuration,
)
from app.connectors.kubernetes_schema import (
    ALLOWED_NAMESPACES_ALL,
    CLIENT_TYPE_SERVICE,
    CLIENT_TYPE_URL,
    FAILURE_POLICY_FAIL,
    FAILURE_POLICY_IGNORE,
    FAILURE_POLICY_UNKNOWN,
    MATCH_POLICY_EQUIVALENT,
    MATCH_POLICY_EXACT,
    SELECTOR_ABSENT,
    SELECTOR_EMPTY_ALL,
    SELECTOR_NARROW,
    SIDE_EFFECTS_NONE,
    SIDE_EFFECTS_UNKNOWN,
    WEBHOOK_SECURITY_POSTURE_FAIL_CLOSED_BROAD,
    WEBHOOK_SECURITY_POSTURE_FAIL_CLOSED_NARROW,
    WEBHOOK_SECURITY_POSTURE_FAIL_OPEN,
)
from tests._kubernetes_admission_fixtures import (
    make_client_config,
    make_rule,
    make_selector,
    make_service_ref,
    make_webhook,
    make_webhook_configuration,
    page,
)


def _wh_record(**kwargs):
    config = make_webhook_configuration(webhooks=[make_webhook(**kwargs)])
    _config_record, webhooks = _normalize_webhook_configuration(config, kind="validating", cluster_id="uid:c1", cluster_name="c1")
    return webhooks[0]


def _config(kind="validating", **kwargs):
    config = make_webhook_configuration(**kwargs)
    return _normalize_webhook_configuration(config, kind=kind, cluster_id="uid:c1", cluster_name="c1")


# ── A-B: safe baselines ───────────────────────────────────────────────────────

class TestSafeBaselines:
    def test_A_validating_webhook_safe_baseline(self):
        record = _wh_record()
        assert record["webhook_type"] == "validating"
        assert record["failure_policy"] == FAILURE_POLICY_FAIL

    def test_B_mutating_webhook_safe_baseline(self):
        config = make_webhook_configuration(webhooks=[make_webhook()])
        _config_record, webhooks = _normalize_webhook_configuration(config, kind="mutating", cluster_id="c1", cluster_name="c1")
        assert webhooks[0]["webhook_type"] == "mutating"


# ── C-E: failure policy ────────────────────────────────────────────────────────

class TestFailurePolicy:
    def test_C_fail(self):
        assert _wh_record(failure_policy="Fail")["failure_policy"] == FAILURE_POLICY_FAIL

    def test_D_ignore(self):
        assert _wh_record(failure_policy="Ignore")["failure_policy"] == FAILURE_POLICY_IGNORE

    def test_E_missing(self):
        assert _wh_record(failure_policy=None)["failure_policy"] == FAILURE_POLICY_UNKNOWN


# ── F-G: match policy ──────────────────────────────────────────────────────────

class TestMatchPolicy:
    def test_F_exact(self):
        assert _wh_record(match_policy="Exact")["match_policy"] == MATCH_POLICY_EXACT

    def test_G_equivalent(self):
        assert _wh_record(match_policy="Equivalent")["match_policy"] == MATCH_POLICY_EQUIVALENT


# ── H-I: side effects ──────────────────────────────────────────────────────────

class TestSideEffects:
    def test_H_none(self):
        assert _wh_record(side_effects="None")["side_effects"] == SIDE_EFFECTS_NONE

    def test_I_unknown(self):
        assert _wh_record(side_effects="Unknown")["side_effects"] == SIDE_EFFECTS_UNKNOWN


# ── J-K: timeout ────────────────────────────────────────────────────────────────

class TestTimeout:
    def test_J_low(self):
        assert _wh_record(timeout_seconds=1)["timeout_seconds"] == 1

    def test_K_high(self):
        assert _wh_record(timeout_seconds=30)["timeout_seconds"] == 30


# ── L-N: clients ────────────────────────────────────────────────────────────────

class TestClients:
    def test_L_in_cluster_service(self):
        record = _wh_record(client_config=make_client_config(service=make_service_ref()))
        assert record["client_type"] == CLIENT_TYPE_SERVICE
        assert record["service_namespace"] == "kube-system"

    def test_M_external_https_url(self):
        record = _wh_record(client_config=make_client_config(url="https://admission.example.com/validate"))
        assert record["client_type"] == CLIENT_TYPE_URL
        assert record["plaintext_http_client"] is False

    def test_N_external_http_url(self):
        record = _wh_record(client_config=make_client_config(url="http://admission.example.com/validate"))
        assert record["client_type"] == CLIENT_TYPE_URL
        assert record["plaintext_http_client"] is True


# ── O-P: CA bundle ──────────────────────────────────────────────────────────────

class TestCaBundle:
    def test_O_present(self):
        record = _wh_record(client_config=make_client_config(service=make_service_ref(), ca_bundle=b"fake-ca-bytes"))
        assert record["ca_bundle_present"] is True

    def test_P_absent(self):
        record = _wh_record(client_config=make_client_config(service=make_service_ref(), ca_bundle=None))
        assert record["ca_bundle_present"] is False

    def test_ca_bundle_bytes_never_persisted(self):
        import json
        record = _wh_record(client_config=make_client_config(service=make_service_ref(), ca_bundle=b"fake-ca-bytes"))
        assert "fake-ca-bytes" not in json.dumps(record)


# ── Q-S: selectors ──────────────────────────────────────────────────────────────

class TestSelectors:
    def test_Q_namespace_selector_absent(self):
        assert _wh_record(namespace_selector=None)["namespace_selector_category"] == SELECTOR_ABSENT

    def test_R_namespace_selector_empty(self):
        empty_selector = make_selector(match_labels={}, match_expressions=[])
        assert _wh_record(namespace_selector=empty_selector)["namespace_selector_category"] == SELECTOR_EMPTY_ALL

    def test_S_object_selector_present(self):
        record = _wh_record(object_selector=make_selector(match_labels={"kubernetes.io/metadata.name": "prod"}))
        assert record["object_selector_category"] == SELECTOR_NARROW


# ── T-W: wildcard rule categorization ─────────────────────────────────────────

class TestWildcardRules:
    def test_T_wildcard_operation(self):
        record = _wh_record(rules=[make_rule(operations=["*"])])
        assert record["wildcard_operation"] is True

    def test_U_wildcard_api_group(self):
        record = _wh_record(rules=[make_rule(api_groups=["*"])])
        assert record["wildcard_api_group"] is True

    def test_V_wildcard_api_version(self):
        record = _wh_record(rules=[make_rule(api_versions=["*"])])
        assert record["wildcard_api_version"] is True

    def test_W_wildcard_resource(self):
        record = _wh_record(rules=[make_rule(resources=["*"])])
        assert record["wildcard_resource"] is True


# ── X-AD: resource/scope categorization ───────────────────────────────────────

class TestResourceScopeCategorization:
    def test_X_pod_scope(self):
        record = _wh_record(rules=[make_rule(resources=["pods"])])
        assert "pods" in record["resource_categories"]

    def test_Y_rbac_scope(self):
        record = _wh_record(rules=[make_rule(api_groups=["rbac.authorization.k8s.io"], resources=["roles"])])
        assert "roles" in record["resource_categories"]

    def test_Z_secret_scope(self):
        record = _wh_record(rules=[make_rule(resources=["secrets"])])
        assert "secrets" in record["resource_categories"]

    def test_AA_crd_scope(self):
        record = _wh_record(rules=[make_rule(api_groups=["apiextensions.k8s.io"], resources=["customresourcedefinitions"])])
        assert "customresourcedefinitions" in record["resource_categories"]

    def test_AB_namespace_scope(self):
        record = _wh_record(rules=[make_rule(resources=["namespaces"])])
        assert "namespaces" in record["resource_categories"]

    def test_AC_cluster_scope(self):
        record = _wh_record(rules=[make_rule(scope="Cluster")])
        assert record["scope_category"] == "Cluster"

    def test_AD_namespaced_scope(self):
        record = _wh_record(rules=[make_rule(scope="Namespaced")])
        assert record["scope_category"] == "Namespaced"


class TestReinvocationPolicy:
    def test_AJ_never(self):
        config = make_webhook_configuration(webhooks=[make_webhook(reinvocation_policy="Never")])
        _config_record, webhooks = _normalize_webhook_configuration(config, kind="mutating", cluster_id="c1", cluster_name="c1")
        assert webhooks[0]["reinvocation_policy"] == "Never"

    def test_AK_if_needed(self):
        config = make_webhook_configuration(webhooks=[make_webhook(reinvocation_policy="IfNeeded")])
        _config_record, webhooks = _normalize_webhook_configuration(config, kind="mutating", cluster_id="c1", cluster_name="c1")
        assert webhooks[0]["reinvocation_policy"] == "IfNeeded"

    def test_reinvocation_policy_none_for_validating(self):
        record = _wh_record()
        assert record["reinvocation_policy"] is None


# ── Configuration-level aggregation ────────────────────────────────────────────

class TestConfigurationAggregation:
    def test_fail_closed_broad_posture(self):
        config = make_webhook_configuration(webhooks=[make_webhook(
            failure_policy="Fail", rules=[make_rule(operations=["*"], api_groups=["*"], resources=["*"])],
        )])
        config_record, _webhooks = _normalize_webhook_configuration(config, kind="validating", cluster_id="c1", cluster_name="c1")
        assert config_record["security_posture_summary"] == WEBHOOK_SECURITY_POSTURE_FAIL_CLOSED_BROAD

    def test_fail_closed_narrow_posture(self):
        config = make_webhook_configuration(webhooks=[make_webhook(failure_policy="Fail")])
        config_record, _webhooks = _normalize_webhook_configuration(config, kind="validating", cluster_id="c1", cluster_name="c1")
        assert config_record["security_posture_summary"] == WEBHOOK_SECURITY_POSTURE_FAIL_CLOSED_NARROW

    def test_fail_open_posture(self):
        config = make_webhook_configuration(webhooks=[make_webhook(failure_policy="Ignore")])
        config_record, _webhooks = _normalize_webhook_configuration(config, kind="validating", cluster_id="c1", cluster_name="c1")
        assert config_record["security_posture_summary"] == WEBHOOK_SECURITY_POSTURE_FAIL_OPEN


# ── CA, CB, CD, CE: fail-soft and malformed isolation ─────────────────────────

class TestFailSoftAndIsolation:
    def test_CB_admission_api_denied_reports_partial(self):
        list_fn = MagicMock(side_effect=ApiException(status=403))
        configs, webhooks, status = _collect_webhook_configurations(
            list_fn, kind="validating", cluster_id="c1", cluster_name="c1",
        )
        assert status == "partial"
        assert configs == [] and webhooks == []

    def test_CD_one_family_denied_others_succeed(self):
        deny_fn = MagicMock(side_effect=ApiException(status=403))
        ok_fn = MagicMock(return_value=page([make_webhook_configuration()]))
        _c1, _w1, denied_status = _collect_webhook_configurations(
            deny_fn, kind="validating", cluster_id="c1", cluster_name="c1",
        )
        c2, _w2, ok_status = _collect_webhook_configurations(
            ok_fn, kind="mutating", cluster_id="c1", cluster_name="c1",
        )
        assert denied_status == "partial"
        assert ok_status == "complete"
        assert len(c2) == 1

    def test_CE_malformed_webhook_isolated(self):
        class _RaisingWebhook:
            @property
            def name(self):
                raise ValueError("malformed")

        good = make_webhook(name="good")
        config = make_webhook_configuration(webhooks=[_RaisingWebhook(), good])
        config_record, webhooks = _normalize_webhook_configuration(config, kind="validating", cluster_id="c1", cluster_name="c1")
        assert config_record["webhook_count"] == 1
        assert webhooks[0]["webhook_name"] == "good"

    def test_malformed_configuration_isolated(self):
        good = make_webhook_configuration(name="good-config")
        malformed = object()
        list_fn = MagicMock(return_value=page([malformed, good]))
        configs, _webhooks, status = _collect_webhook_configurations(
            list_fn, kind="validating", cluster_id="c1", cluster_name="c1",
        )
        assert status == "complete"
        assert len(configs) == 1
        assert configs[0]["name"] == "good-config"


class TestPaginationAndOrdering:
    def test_CG_pagination(self):
        pages = [
            page([make_webhook_configuration(name="a")], continue_token="tok1"),
            page([make_webhook_configuration(name="b")], continue_token=None),
        ]
        list_fn = MagicMock(side_effect=pages)
        configs, _webhooks, status = _collect_webhook_configurations(
            list_fn, kind="validating", cluster_id="c1", cluster_name="c1",
        )
        assert status == "complete"
        assert {c["name"] for c in configs} == {"a", "b"}

    def test_CH_repeated_continuation_token(self):
        pages = [
            page([make_webhook_configuration(name="a")], continue_token="tok1"),
            page([make_webhook_configuration(name="b")], continue_token="tok1"),
        ]
        list_fn = MagicMock(side_effect=pages)
        configs, _webhooks, status = _collect_webhook_configurations(
            list_fn, kind="validating", cluster_id="c1", cluster_name="c1",
        )
        assert status == "partial"
        assert {c["name"] for c in configs} == {"a", "b"}

    def test_CI_stable_uid_identity(self):
        config = make_webhook_configuration(uid="stable-uid")
        list_fn = MagicMock(return_value=page([config]))
        configs, _webhooks, _status = _collect_webhook_configurations(
            list_fn, kind="validating", cluster_id="uid:c1", cluster_name="c1",
        )
        assert configs[0]["record_id"] == "uid:c1/validating_webhook_configuration/stable-uid"


class TestSensitiveDataExclusion:
    def test_CN_no_arbitrary_selector_values_persisted(self):
        import json
        record = _wh_record(namespace_selector=make_selector(match_labels={"secret-project": "phoenix-codename"}))
        assert "secret-project" not in json.dumps(record)
        assert "phoenix-codename" not in json.dumps(record)
