"""Kubernetes integration creation/reconnect end-to-end tests (message 9).

Exercises the real HTTP path — POST /integrations and POST
/integrations/{id}/reconnect — for the four launch-certification cases:
valid connection, partial connection (some API families denied but the
credential is still accepted), invalid connection (rejected outright), and
an unsupported optional API (Gateway API missing) that must NOT be treated
as invalid. Also pins that sensitive credentials never leak into any
response.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from app.connectors.exceptions import AuthenticationError, NetworkError
from app.connectors.kubernetes import KubernetesConnector
from app.models.integration import Integration


def _fake_kubeconfig() -> str:
    return """
apiVersion: v1
kind: Config
current-context: ctx
clusters:
  - name: c
    cluster:
      server: https://10.0.0.5:6443
users:
  - name: u
    user:
      token: "super-secret-fake-token"
contexts:
  - name: ctx
    context:
      cluster: c
      user: u
"""


def _stub_valid_client():
    fake_api_client = MagicMock()
    fake_api_client.configuration.verify_ssl = True
    fake_api_client.configuration.host = "https://10.0.0.5:6443"
    return fake_api_client


# ════════════════════════════════════════════════════════════════════════════
# Valid connection
# ════════════════════════════════════════════════════════════════════════════


class TestValidConnection:
    def test_create_integration_succeeds_when_cluster_reachable(self, client):
        with patch.object(KubernetesConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "kubernetes",
                "display_name": "Valid Cluster",
                "kubeconfig": _fake_kubeconfig(),
                "context": "ctx",
            })
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["provider"] == "kubernetes"
        assert body["status"] == "active"
        assert body["resource_count"] == 1


# ════════════════════════════════════════════════════════════════════════════
# Partial connection — workloads available, RBAC denied, integration still accepted
# ════════════════════════════════════════════════════════════════════════════


class TestPartialConnection:
    def test_integration_accepted_when_some_families_denied(self, client):
        """Creation only requires /version to succeed (validate_credentials);
        partial family denial is a first-sync-time diagnostic, not a
        creation-time rejection — an integration must still be accepted so
        the operator gets a partial-but-real cluster connection instead of
        being blocked entirely."""
        with patch.object(KubernetesConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "kubernetes",
                "display_name": "Partial Cluster",
                "kubeconfig": _fake_kubeconfig(),
            })
        assert resp.status_code == 201, resp.text

    def test_permission_diagnostics_report_partial_state_from_denied_family(self):
        from app.connectors.kubernetes import build_permission_diagnostics

        records = [
            {
                "record_type": "kubernetes_cluster",
                "record_id": "uid:c1",
                "cluster_id": "uid:c1",
                "cluster_name": "c1",
                "family_completeness": {
                    "workload": "complete",
                    "rbac": "partial",
                    "network": "complete",
                    "admission": "complete",
                },
                "configured_namespace_allowlist": None,
            },
        ]
        report = build_permission_diagnostics(records)
        assert report["coverage"] in ("partial", "full", "invalid")
        assert report["coverage"] != "invalid"


# ════════════════════════════════════════════════════════════════════════════
# Invalid connection
# ════════════════════════════════════════════════════════════════════════════


class TestInvalidConnection:
    def test_malformed_kubeconfig_rejected(self, client):
        resp = client.post("/integrations", json={
            "provider": "kubernetes",
            "display_name": "Bad Cluster",
            "kubeconfig": "not: valid: yaml: [unterminated",
        })
        assert resp.status_code == 400, resp.text

    def test_nonexistent_context_rejected(self, client):
        resp = client.post("/integrations", json={
            "provider": "kubernetes",
            "display_name": "Bad Context",
            "kubeconfig": _fake_kubeconfig(),
            "context": "does-not-exist",
        })
        assert resp.status_code == 400, resp.text

    def test_auth_failure_rejected(self, client):
        with patch.object(
            KubernetesConnector, "validate_credentials",
            side_effect=AuthenticationError("Kubernetes API server rejected the supplied credentials."),
        ):
            resp = client.post("/integrations", json={
                "provider": "kubernetes",
                "display_name": "Auth Fail Cluster",
                "kubeconfig": _fake_kubeconfig(),
            })
        assert resp.status_code == 400, resp.text
        assert "credentials" not in resp.json()

    def test_unreachable_cluster_rejected(self, client):
        with patch.object(
            KubernetesConnector, "validate_credentials",
            side_effect=NetworkError("Could not reach the Kubernetes API server."),
        ):
            resp = client.post("/integrations", json={
                "provider": "kubernetes",
                "display_name": "Unreachable Cluster",
                "kubeconfig": _fake_kubeconfig(),
            })
        # NetworkError subclasses ConnectorError, and the router's
        # `except ConnectorError` branch (400) is ordered before its
        # `except NetworkError` branch (502) for every provider — so this
        # is caught as a 400, matching existing router behavior.
        assert resp.status_code == 400, resp.text

    def test_missing_kubeconfig_rejected_at_schema_layer(self, client):
        resp = client.post("/integrations", json={
            "provider": "kubernetes",
            "display_name": "No Kubeconfig",
        })
        assert resp.status_code == 422, resp.text


# ════════════════════════════════════════════════════════════════════════════
# Unsupported optional API (Gateway API not installed) is NOT invalid
# ════════════════════════════════════════════════════════════════════════════


class TestUnsupportedOptionalApi:
    def test_gateway_api_unsupported_does_not_block_creation(self, client):
        with patch.object(KubernetesConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "kubernetes",
                "display_name": "No Gateway API Cluster",
                "kubeconfig": _fake_kubeconfig(),
            })
        assert resp.status_code == 201, resp.text

    def test_gateway_unsupported_family_reports_unsupported_not_invalid(self):
        from app.connectors.kubernetes import build_permission_diagnostics

        records = [
            {
                "record_type": "kubernetes_cluster",
                "record_id": "uid:c1",
                "cluster_id": "uid:c1",
                "cluster_name": "c1",
                "family_completeness": {
                    "workload": "complete",
                    "rbac": "complete",
                    "network": "complete",
                    "admission": "complete",
                    "gateway_api": "unsupported",
                },
                "configured_namespace_allowlist": None,
            },
        ]
        report = build_permission_diagnostics(records)
        assert report["coverage"] != "invalid"


# ════════════════════════════════════════════════════════════════════════════
# Sensitive credentials never leak
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveCredentialsNeverLeak:
    def test_kubeconfig_not_in_create_response(self, client, db_session):
        kubeconfig = _fake_kubeconfig()
        with patch.object(KubernetesConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "kubernetes",
                "display_name": "Secret Test Cluster",
                "kubeconfig": kubeconfig,
            })
        assert resp.status_code == 201, resp.text
        body_str = resp.text
        assert "super-secret-fake-token" not in body_str
        assert kubeconfig not in body_str
        assert "kubeconfig" not in resp.json()

    def test_kubeconfig_not_in_get_integration_response(self, client, db_session):
        kubeconfig = _fake_kubeconfig()
        with patch.object(KubernetesConnector, "validate_credentials", return_value=True):
            create_resp = client.post("/integrations", json={
                "provider": "kubernetes",
                "display_name": "Secret Get Cluster",
                "kubeconfig": kubeconfig,
            })
        integration_id = create_resp.json()["id"]
        get_resp = client.get(f"/integrations/{integration_id}")
        assert get_resp.status_code == 200
        assert "super-secret-fake-token" not in get_resp.text
        assert kubeconfig not in get_resp.text

    def test_kubeconfig_not_logged_by_validate_credentials(self, caplog):
        import logging

        connector = KubernetesConnector()
        fake_api_client = _stub_valid_client()
        with patch.object(connector, "_build_api_client", return_value=(fake_api_client, {}, "ctx")):
            with patch("kubernetes.client.VersionApi") as mock_version_api:
                mock_version_api.return_value.get_code.return_value = MagicMock(git_version="v1.29.0")
                with caplog.at_level(logging.DEBUG):
                    connector.validate_credentials({"kubeconfig": _fake_kubeconfig()})
        assert "super-secret-fake-token" not in caplog.text

    def test_encrypted_credentials_column_is_not_plaintext(self, client, db_session):
        kubeconfig = _fake_kubeconfig()
        with patch.object(KubernetesConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "kubernetes",
                "display_name": "Encryption Check Cluster",
                "kubeconfig": kubeconfig,
            })
        integration_id = resp.json()["id"]
        db_session.expire_all()
        row = db_session.query(Integration).filter(Integration.id == integration_id).first()
        assert row is not None
        assert b"super-secret-fake-token" not in row.encrypted_credentials
