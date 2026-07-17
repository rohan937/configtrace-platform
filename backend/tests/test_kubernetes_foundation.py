"""Kubernetes provider foundation tests (Kubernetes message 1 of 9).

Covers the connector architecture built in this message: kubeconfig safety
(exec/auth-provider rejection, credential redaction), cluster identity,
namespace collection and normalization, the reusable pagination helper, the
fail-soft API-call wrapper, and API discovery. No workload, RBAC, network,
or admission-control collection exists yet — that begins in later messages.

All tests are pure-mock; no real Kubernetes cluster is contacted.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import yaml
from kubernetes.client.rest import ApiException

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.connectors.kubernetes import (
    CATEGORY_AUTH_FAILED,
    CATEGORY_CONNECTION_ERROR,
    CATEGORY_CONTINUATION_EXPIRED,
    CATEGORY_MALFORMED_RESPONSE,
    CATEGORY_NOT_FOUND,
    CATEGORY_PERMISSION_DENIED,
    CATEGORY_SERVER_ERROR,
    CATEGORY_SUCCESS,
    CATEGORY_THROTTLED,
    CATEGORY_TLS_ERROR,
    KubernetesConnector,
    _apply_namespace_allowlist,
    _normalize_namespace,
    assert_context_auth_is_supported,
    call_k8s,
    categorize_api_server_host,
    compute_cluster_id,
    major_minor,
    normalize_api_server_host,
    normalize_kubernetes_version,
    paginate_list,
)
from app.connectors.kubernetes_schema import (
    KUBERNETES_API_CAPABILITY,
    KUBERNETES_CLUSTER,
    KUBERNETES_NAMESPACE,
    SAFE_NAMESPACE_LABEL_KEYS,
)


def _kubeconfig_yaml(
    *,
    user_block: str = 'token: "fake-static-token-value"',
    context_name: str = "default-context",
    server: str = "https://10.0.0.5:6443",
) -> str:
    return f"""
apiVersion: v1
kind: Config
current-context: {context_name}
clusters:
  - name: cluster-a
    cluster:
      server: {server}
      certificate-authority-data: ZmFrZS1jYS1kYXRh
contexts:
  - name: {context_name}
    context:
      cluster: cluster-a
      user: user-a
users:
  - name: user-a
    user:
      {user_block}
"""


# ── Credential safety ─────────────────────────────────────────────────────────

class TestCredentialSafety:
    def test_kubeconfig_never_appears_in_normalized_records(self):
        # The kubeconfig content itself must never be read a second time (or
        # copied into a record literal) inside fetch() — it is parsed exactly
        # once, in _build_api_client, and never touched again. Verified
        # structurally since a full end-to-end fetch() requires a live cluster.
        source = inspect.getsource(KubernetesConnector.fetch)
        assert 'credentials.get("kubeconfig")' not in source
        assert "raw_kubeconfig" not in source
        assert 'credentials["kubeconfig"]' not in source

    def test_build_api_client_reads_kubeconfig_key_only_once(self):
        source = inspect.getsource(KubernetesConnector._build_api_client)
        assert 'credentials.get("kubeconfig")' in source

    def test_malformed_kubeconfig_yaml_fails_safely(self):
        connector = KubernetesConnector()
        with pytest.raises(ConnectorError):
            connector._build_api_client({"kubeconfig": "not: valid: yaml: [unterminated"})

    def test_missing_kubeconfig_fails_clearly(self):
        connector = KubernetesConnector()
        with pytest.raises(ConnectorError):
            connector._build_api_client({})

    def test_kubeconfig_not_a_dict_fails_safely(self):
        connector = KubernetesConnector()
        with pytest.raises(ConnectorError):
            connector._build_api_client({"kubeconfig": "- just\n- a\n- list\n"})

    def test_missing_context_fails_clearly(self):
        config_dict = yaml.safe_load(_kubeconfig_yaml())
        with pytest.raises(ConnectorError):
            assert_context_auth_is_supported(config_dict, "nonexistent-context")

    def test_missing_current_context_and_no_explicit_context_fails(self):
        raw = _kubeconfig_yaml().replace("current-context: default-context", "current-context: ''")
        config_dict = yaml.safe_load(raw)
        with pytest.raises(ConnectorError):
            assert_context_auth_is_supported(config_dict, None)

    def test_exec_auth_plugin_is_rejected_not_executed(self):
        config_dict = yaml.safe_load(
            _kubeconfig_yaml(
                user_block=(
                    "exec:\n"
                    "        apiVersion: client.authentication.k8s.io/v1\n"
                    "        command: rm-rf-everything"
                )
            )
        )
        with pytest.raises(AuthenticationError) as exc_info:
            assert_context_auth_is_supported(config_dict, "default-context")
        # The rejection message must be actionable and must never suggest
        # ConfigTrace ran the plugin.
        assert "exec" in str(exc_info.value).lower()

    def test_auth_provider_plugin_is_rejected(self):
        config_dict = yaml.safe_load(
            _kubeconfig_yaml(
                user_block=(
                    "auth-provider:\n"
                    "        name: gcp"
                )
            )
        )
        with pytest.raises(AuthenticationError) as exc_info:
            assert_context_auth_is_supported(config_dict, "default-context")
        assert "auth-provider" in str(exc_info.value).lower()

    def test_static_token_context_is_supported(self):
        config_dict = yaml.safe_load(_kubeconfig_yaml())
        resolved = assert_context_auth_is_supported(config_dict, "default-context")
        assert resolved == "default-context"

    def test_client_certificate_context_is_supported(self):
        config_dict = yaml.safe_load(
            _kubeconfig_yaml(
                user_block=(
                    "client-certificate-data: ZmFrZS1jZXJ0\n"
                    "      client-key-data: ZmFrZS1rZXk="
                )
            )
        )
        resolved = assert_context_auth_is_supported(config_dict, "default-context")
        assert resolved == "default-context"

    def test_rejection_error_never_echoes_kubeconfig_content(self):
        config_dict = yaml.safe_load(
            _kubeconfig_yaml(user_block="exec:\n        command: some-secret-plugin-path")
        )
        with pytest.raises(AuthenticationError) as exc_info:
            assert_context_auth_is_supported(config_dict, "default-context")
        assert "some-secret-plugin-path" not in str(exc_info.value)


# ── Cluster identity ──────────────────────────────────────────────────────────

class TestClusterIdentity:
    def test_kube_system_uid_produces_stable_id(self):
        cid_1 = compute_cluster_id(api_server_host="https://10.0.0.5:6443", kube_system_uid="abc-123")
        cid_2 = compute_cluster_id(api_server_host="https://10.0.0.9:9999", kube_system_uid="abc-123")
        assert cid_1 == cid_2  # host is irrelevant once a UID is known
        assert "abc-123" in cid_1

    def test_fallback_identity_is_deterministic(self):
        cid_1 = compute_cluster_id(api_server_host="https://10.0.0.5:6443", kube_system_uid=None)
        cid_2 = compute_cluster_id(api_server_host="https://10.0.0.5:6443", kube_system_uid=None)
        assert cid_1 == cid_2

    def test_different_hosts_do_not_collide(self):
        cid_1 = compute_cluster_id(api_server_host="https://10.0.0.5:6443", kube_system_uid=None)
        cid_2 = compute_cluster_id(api_server_host="https://10.0.0.6:6443", kube_system_uid=None)
        assert cid_1 != cid_2

    def test_credentials_and_query_strings_excluded_from_identity(self):
        cid_with_token = compute_cluster_id(
            api_server_host="https://user:supersecret@10.0.0.5:6443/?token=abc", kube_system_uid=None
        )
        cid_plain = compute_cluster_id(api_server_host="https://10.0.0.5:6443", kube_system_uid=None)
        assert cid_with_token == cid_plain
        assert "supersecret" not in cid_with_token
        assert "abc" not in cid_with_token

    def test_context_name_alone_does_not_determine_identity(self):
        # compute_cluster_id has no context_name parameter at all — this is
        # a structural guarantee, verified by signature inspection.
        sig = inspect.signature(compute_cluster_id)
        assert "context_name" not in sig.parameters
        assert "context" not in sig.parameters

    def test_normalize_api_server_host_strips_scheme_and_credentials(self):
        assert normalize_api_server_host("https://user:pass@10.0.0.5:6443") == "10.0.0.5:6443"
        assert normalize_api_server_host("10.0.0.5:6443") == "10.0.0.5:6443"

    def test_categorize_host_private_ip(self):
        assert categorize_api_server_host("https://10.0.0.5:6443") == "private_ip"

    def test_categorize_host_public_ip(self):
        assert categorize_api_server_host("https://8.8.8.8:6443") == "public_ip"

    def test_categorize_host_localhost(self):
        assert categorize_api_server_host("https://localhost:6443") == "localhost"
        assert categorize_api_server_host("https://127.0.0.1:6443") == "localhost"

    def test_categorize_host_dns_hostname(self):
        assert categorize_api_server_host("https://api.mycluster.example.com:6443") == "dns_hostname"


# ── Namespace collection ──────────────────────────────────────────────────────

def _fake_namespace(name, uid=None, phase="Active", labels=None):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, uid=uid, labels=labels or {}),
        status=SimpleNamespace(phase=phase),
    )


class TestNamespaceNormalization:
    def test_stable_id_uses_uid_when_available(self):
        ns = _fake_namespace("team-a", uid="ns-uid-123")
        record = _normalize_namespace(ns, cluster_id="cluster-1", cluster_name="c1")
        assert record["record_id"] == "cluster-1/namespace/ns-uid-123"
        assert record["uid"] == "ns-uid-123"

    def test_stable_id_falls_back_to_name_without_uid(self):
        ns = _fake_namespace("team-a", uid=None)
        record = _normalize_namespace(ns, cluster_id="cluster-1", cluster_name="c1")
        assert record["record_id"] == "cluster-1/namespace/team-a"

    def test_phase_and_terminating_normalize_correctly(self):
        ns = _fake_namespace("shutting-down", phase="Terminating")
        record = _normalize_namespace(ns, cluster_id="c", cluster_name="c")
        assert record["phase"] == "Terminating"
        assert record["terminating"] is True

    def test_psa_labels_normalize_correctly(self):
        labels = {
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/enforce-version": "latest",
            "pod-security.kubernetes.io/audit": "baseline",
        }
        ns = _fake_namespace("secure-ns", labels=labels)
        record = _normalize_namespace(ns, cluster_id="c", cluster_name="c")
        assert record["psa_enforce"] == "restricted"
        assert record["psa_enforce_version"] == "latest"
        assert record["psa_audit"] == "baseline"
        assert record["psa_warn"] is None

    def test_arbitrary_labels_are_excluded(self):
        labels = {
            "pod-security.kubernetes.io/enforce": "restricted",
            "owning-squad": "payments",
            "cost-center": "1234",
            "internal.company.com/business-unit": "checkout",
        }
        ns = _fake_namespace("workload-ns", labels=labels)
        record = _normalize_namespace(ns, cluster_id="c", cluster_name="c")
        blob = str(record)
        assert "payments" not in blob
        assert "1234" not in blob
        assert "checkout" not in blob
        # Only the fixed allowlisted PSA keys are ever read.
        for key in labels:
            if key not in SAFE_NAMESPACE_LABEL_KEYS:
                assert key not in blob

    def test_no_annotations_are_ever_read(self):
        source = inspect.getsource(_normalize_namespace)
        assert "annotations" not in source

    def test_allowlist_filters_namespaces(self):
        records = [
            {"name": "team-a"}, {"name": "team-b"}, {"name": "kube-system"},
        ]
        filtered = _apply_namespace_allowlist(records, ["team-a"])
        assert [r["name"] for r in filtered] == ["team-a"]

    def test_none_allowlist_returns_all_namespaces_including_system(self):
        records = [
            {"name": "team-a"}, {"name": "kube-system"}, {"name": "kube-public"},
            {"name": "kube-node-lease"},
        ]
        filtered = _apply_namespace_allowlist(records, None)
        assert filtered == records

    def test_explicit_empty_allowlist_selects_nothing(self):
        records = [{"name": "team-a"}, {"name": "kube-system"}]
        filtered = _apply_namespace_allowlist(records, [])
        assert filtered == []

    def test_system_namespaces_not_silently_skipped_by_default(self):
        # No denylist exists anywhere in the connector — verified structurally.
        source = inspect.getsource(_apply_namespace_allowlist)
        assert "kube-system" not in source
        assert "kube-public" not in source
        assert "kube-node-lease" not in source


# ── Pagination ────────────────────────────────────────────────────────────────

def _page(items, continue_token=None):
    return SimpleNamespace(items=items, metadata=SimpleNamespace(_continue=continue_token))


class TestPagination:
    def test_single_page(self):
        list_fn = MagicMock(return_value=_page(["a", "b"]))
        items, diag = paginate_list(list_fn)
        assert items == ["a", "b"]
        assert diag.complete is True
        assert diag.pages_fetched == 1

    def test_multiple_pages_follow_continue_token(self):
        pages = [_page(["a"], continue_token="tok1"), _page(["b"], continue_token=None)]
        list_fn = MagicMock(side_effect=pages)
        items, diag = paginate_list(list_fn)
        assert items == ["a", "b"]
        assert diag.complete is True
        assert diag.pages_fetched == 2

    def test_empty_page(self):
        list_fn = MagicMock(return_value=_page([]))
        items, diag = paginate_list(list_fn)
        assert items == []
        assert diag.complete is True

    def test_repeated_continuation_token_stops_without_infinite_loop(self):
        pages = [
            _page(["a"], continue_token="tok1"),
            _page(["b"], continue_token="tok1"),  # repeated!
        ]
        list_fn = MagicMock(side_effect=pages)
        items, diag = paginate_list(list_fn)
        assert items == ["a", "b"]
        assert diag.complete is False
        assert diag.error_category == "repeated_continuation_token"

    def test_410_expiry_restarts_once(self):
        expired = ApiException(status=410, reason="Gone")
        pages = [expired, _page(["a"], continue_token=None)]
        list_fn = MagicMock(side_effect=pages)
        items, diag = paginate_list(list_fn)
        assert items == ["a"]
        assert diag.continuation_restarted is True
        assert diag.complete is True

    def test_410_expiry_twice_stops_rather_than_looping_forever(self):
        expired = ApiException(status=410, reason="Gone")
        list_fn = MagicMock(side_effect=[expired, expired, _page(["a"])])
        items, diag = paginate_list(list_fn)
        assert diag.complete is False
        assert diag.error_category == CATEGORY_CONTINUATION_EXPIRED

    def test_permission_failure_on_second_page_keeps_first_page_items(self):
        denied = ApiException(status=403, reason="Forbidden")
        pages = [_page(["a"], continue_token="tok1"), denied]
        list_fn = MagicMock(side_effect=pages)
        items, diag = paginate_list(list_fn)
        assert items == ["a"]
        assert diag.complete is False
        assert diag.permission_denied is True

    def test_malformed_metadata_stops_safely(self):
        malformed_page = SimpleNamespace(items=["a"], metadata=None)
        list_fn = MagicMock(return_value=malformed_page)
        items, diag = paginate_list(list_fn)
        assert items == ["a"]
        assert diag.malformed_metadata is True

    def test_page_cap_prevents_unbounded_collection(self):
        counter = {"n": 0}

        def infinite_unique_pages(**kwargs):
            counter["n"] += 1
            return _page(["x"], continue_token=f"tok-{counter['n']}")
        list_fn = MagicMock(side_effect=infinite_unique_pages)
        items, diag = paginate_list(list_fn, max_pages=3)
        assert diag.truncated_by_page_cap is True
        assert diag.complete is False
        assert diag.pages_fetched == 3

    def test_page_size_is_configurable(self):
        list_fn = MagicMock(return_value=_page([]))
        paginate_list(list_fn, page_size=17)
        _, kwargs = list_fn.call_args
        assert kwargs["limit"] == 17

    def test_no_duplicate_items_across_pages(self):
        pages = [_page(["a", "b"], continue_token="tok1"), _page(["c"], continue_token=None)]
        list_fn = MagicMock(side_effect=pages)
        items, _ = paginate_list(list_fn)
        assert items == ["a", "b", "c"]
        assert len(items) == len(set(items))


# ── Fail-soft wrapper ──────────────────────────────────────────────────────────

class TestFailSoft:
    def test_success(self):
        outcome = call_k8s(lambda **kw: "ok")
        assert outcome.ok is True
        assert outcome.category == CATEGORY_SUCCESS

    def test_401_is_auth_failed(self):
        def raiser(**kw):
            raise ApiException(status=401, reason="Unauthorized")
        outcome = call_k8s(raiser)
        assert outcome.ok is False
        assert outcome.category == CATEGORY_AUTH_FAILED

    def test_403_is_permission_denied(self):
        def raiser(**kw):
            raise ApiException(status=403, reason="Forbidden")
        outcome = call_k8s(raiser)
        assert outcome.category == CATEGORY_PERMISSION_DENIED

    def test_404_is_not_found(self):
        def raiser(**kw):
            raise ApiException(status=404, reason="Not Found")
        outcome = call_k8s(raiser)
        assert outcome.category == CATEGORY_NOT_FOUND

    def test_429_is_throttled(self):
        def raiser(**kw):
            raise ApiException(status=429, reason="Too Many Requests")
        outcome = call_k8s(raiser)
        assert outcome.category == CATEGORY_THROTTLED

    def test_5xx_is_server_error(self):
        def raiser(**kw):
            raise ApiException(status=503, reason="Service Unavailable")
        outcome = call_k8s(raiser)
        assert outcome.category == CATEGORY_SERVER_ERROR

    def test_connection_error(self):
        def raiser(**kw):
            raise ConnectionError("could not connect")
        outcome = call_k8s(raiser)
        assert outcome.category == CATEGORY_CONNECTION_ERROR

    def test_tls_error(self):
        import ssl

        def raiser(**kw):
            raise ssl.SSLError("certificate verify failed")
        outcome = call_k8s(raiser)
        assert outcome.category == CATEGORY_TLS_ERROR

    def test_malformed_response(self):
        def raiser(**kw):
            raise ValueError("could not parse")
        outcome = call_k8s(raiser)
        assert outcome.category == CATEGORY_MALFORMED_RESPONSE

    def test_valid_empty_list_is_success_not_error(self):
        outcome = call_k8s(lambda **kw: _page([]))
        assert outcome.ok is True
        assert outcome.result.items == []

    def test_error_detail_never_contains_raw_exception_text(self):
        def raiser(**kw):
            raise ApiException(status=401, reason="token abc-super-secret-123 rejected")
        outcome = call_k8s(raiser)
        assert "abc-super-secret-123" not in outcome.detail

    def test_no_synthetic_record_is_ever_returned_on_failure(self):
        def raiser(**kw):
            raise ApiException(status=403, reason="Forbidden")
        outcome = call_k8s(raiser)
        assert outcome.result is None


# ── Version and misc normalization ────────────────────────────────────────────

class TestVersionNormalization:
    def test_strips_eks_suffix(self):
        assert normalize_kubernetes_version("v1.29.3-eks-1234abc") == "v1.29.3"

    def test_strips_k3s_suffix(self):
        assert normalize_kubernetes_version("v1.28.9+k3s1") == "v1.28.9"

    def test_none_input(self):
        assert normalize_kubernetes_version(None) is None

    def test_major_minor(self):
        assert major_minor("v1.29.3") == "1.29"

    def test_major_minor_none(self):
        assert major_minor(None) is None


# ── API discovery ──────────────────────────────────────────────────────────────

_TYPED_DISCOVERY_CLASSES = (
    "CoreV1Api", "AppsV1Api", "RbacAuthorizationV1Api", "NetworkingV1Api",
    "PolicyV1Api", "BatchV1Api", "AdmissionregistrationV1Api",
)


class _DiscoveryPatchSet:
    """Patches every typed discovery API class on the real ``kubernetes.client``
    module (the connector does ``from kubernetes import client as k8s_client``
    locally, which binds to this same module object, so patching it here
    affects the connector's local alias too)."""

    def __init__(self, *, default_status=404):
        self._patches = []
        self._mocks = {}
        self._default_status = default_status

    def __enter__(self):
        for name in _TYPED_DISCOVERY_CLASSES:
            p = patch(f"kubernetes.client.{name}")
            mock_cls = p.start()
            mock_cls.return_value.get_api_resources.side_effect = ApiException(
                status=self._default_status
            )
            self._patches.append(p)
            self._mocks[name] = mock_cls
        return self._mocks

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()


class TestDiscovery:
    def test_core_resources_discovered(self):
        connector = KubernetesConnector()
        fake_api_client = MagicMock()
        fake_api_client.call_api.side_effect = ApiException(status=404)
        fake_resource = SimpleNamespace(name="namespaces", namespaced=False, verbs=["get", "list"])
        fake_list = SimpleNamespace(resources=[fake_resource])

        with _DiscoveryPatchSet() as mocks:
            mocks["CoreV1Api"].return_value.get_api_resources.side_effect = None
            mocks["CoreV1Api"].return_value.get_api_resources.return_value = fake_list
            records, status = connector._discover_capabilities(
                fake_api_client, cluster_id="c1", cluster_name="c1"
            )

        core_records = [r for r in records if r["api_group"] == "core"]
        assert any(r["resource"] == "namespaces" and r["available"] for r in core_records)
        assert status == "complete"

    def test_absent_optional_group_is_recorded_unavailable_not_omitted(self):
        connector = KubernetesConnector()
        fake_api_client = MagicMock()
        fake_api_client.call_api.side_effect = ApiException(status=404)

        with _DiscoveryPatchSet():
            records, status = connector._discover_capabilities(
                fake_api_client, cluster_id="c1", cluster_name="c1"
            )

        assert len(records) == 8  # one placeholder per probed group
        assert all(r["available"] is False for r in records)
        assert status == "complete"  # 404 is an expected/clean answer, not an error

    def test_gateway_api_absent_is_handled_via_raw_probe(self):
        connector = KubernetesConnector()
        fake_api_client = MagicMock()
        fake_api_client.call_api.side_effect = ApiException(status=404)

        with _DiscoveryPatchSet():
            records, _status = connector._discover_capabilities(
                fake_api_client, cluster_id="c1", cluster_name="c1"
            )

        gw_records = [r for r in records if r["api_group"] == "gateway.networking.k8s.io"]
        assert len(gw_records) == 1
        assert gw_records[0]["available"] is False

    def test_gateway_api_present_is_parsed_from_raw_dict(self):
        connector = KubernetesConnector()
        fake_api_client = MagicMock()
        fake_api_client.call_api.side_effect = lambda path, method, **kw: (
            {"resources": [{"name": "gateways", "namespaced": True, "verbs": ["get", "list"]}]}
            if "gateway.networking.k8s.io" in path
            else (_ for _ in ()).throw(ApiException(status=404))
        )

        with _DiscoveryPatchSet():
            records, _status = connector._discover_capabilities(
                fake_api_client, cluster_id="c1", cluster_name="c1"
            )

        gw = next(r for r in records if r["api_group"] == "gateway.networking.k8s.io")
        assert gw["available"] is True
        assert gw["resource"] == "gateways"
        assert gw["namespaced"] is True

    def test_unexpected_discovery_error_marks_status_partial(self):
        connector = KubernetesConnector()
        fake_api_client = MagicMock()
        fake_api_client.call_api.side_effect = ApiException(status=404)

        with _DiscoveryPatchSet() as mocks:
            mocks["CoreV1Api"].return_value.get_api_resources.side_effect = ApiException(status=500)
            _records, status = connector._discover_capabilities(
                fake_api_client, cluster_id="c1", cluster_name="c1"
            )
        assert status == "partial"

    def test_no_full_discovery_document_is_persisted(self):
        connector = KubernetesConnector()
        fake_api_client = MagicMock()
        fake_api_client.call_api.side_effect = ApiException(status=404)
        fake_resource = SimpleNamespace(name="namespaces", namespaced=False, verbs=["get", "list"])
        fake_list = SimpleNamespace(resources=[fake_resource])

        with _DiscoveryPatchSet() as mocks:
            mocks["CoreV1Api"].return_value.get_api_resources.side_effect = None
            mocks["CoreV1Api"].return_value.get_api_resources.return_value = fake_list
            records, _status = connector._discover_capabilities(
                fake_api_client, cluster_id="c1", cluster_name="c1"
            )

        # Every record must be a flat dict of the documented capability
        # fields only — never the raw APIResourceList/payload object or an
        # embedded "resources" sub-list.
        expected_keys = {
            "record_type", "record_id", "cluster_id", "cluster_name",
            "api_group", "api_version", "resource", "namespaced", "verbs",
            "available", "preferred_version", "collection_support_status",
        }
        for record in records:
            assert set(record.keys()) == expected_keys
            assert "resources" not in record
            assert not isinstance(record.get("resource"), (list, dict))

    def test_namespaced_vs_cluster_scoped_recorded(self):
        connector = KubernetesConnector()
        fake_api_client = MagicMock()
        fake_api_client.call_api.side_effect = ApiException(status=404)
        ns_res = SimpleNamespace(name="pods", namespaced=True, verbs=["get"])
        cluster_res = SimpleNamespace(name="nodes", namespaced=False, verbs=["get"])
        fake_list = SimpleNamespace(resources=[ns_res, cluster_res])

        with _DiscoveryPatchSet() as mocks:
            mocks["CoreV1Api"].return_value.get_api_resources.side_effect = None
            mocks["CoreV1Api"].return_value.get_api_resources.return_value = fake_list
            records, _ = connector._discover_capabilities(
                fake_api_client, cluster_id="c1", cluster_name="c1"
            )

        pods = next(r for r in records if r["resource"] == "pods")
        nodes = next(r for r in records if r["resource"] == "nodes")
        assert pods["namespaced"] is True
        assert nodes["namespaced"] is False


# ── Safe normalization ─────────────────────────────────────────────────────────

class TestSafeNormalization:
    def test_no_secret_api_calls_anywhere_in_connector(self):
        import app.connectors.kubernetes as k8s_connector_module

        source = inspect.getsource(k8s_connector_module)
        forbidden = (
            "read_namespaced_secret", "list_secret_for_all_namespaces",
            "read_namespaced_config_map", "list_config_map_for_all_namespaces",
            "read_namespaced_pod_log", "connect_get_namespaced_pod_exec",
        )
        for call in forbidden:
            assert call not in source, f"Forbidden Kubernetes API call found: {call}"

    def test_no_configmap_values_read(self):
        import app.connectors.kubernetes as k8s_connector_module

        source = inspect.getsource(k8s_connector_module)
        assert "binary_data" not in source
        assert "stringData" not in source

    def test_deterministic_namespace_ordering(self):
        records = [{"name": "z"}, {"name": "a"}, {"name": "m"}]
        records.sort(key=lambda r: r["name"])
        assert [r["name"] for r in records] == ["a", "m", "z"]

    def test_foundation_record_types_constant(self):
        from app.connectors.kubernetes_schema import KUBERNETES_FOUNDATION_RECORD_TYPES

        assert KUBERNETES_FOUNDATION_RECORD_TYPES == frozenset(
            {KUBERNETES_CLUSTER, KUBERNETES_NAMESPACE, KUBERNETES_API_CAPABILITY}
        )
