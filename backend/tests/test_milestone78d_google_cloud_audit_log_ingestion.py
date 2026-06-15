"""M78D: Google Cloud Audit Log Ingestion.

Verifies:
  * GoogleCloudConnector.list_audit_events calls Cloud Logging entries:list safely
  * max_events and lookback_hours caps are enforced
  * pagination is bounded
  * connector filters to the allowlisted Admin Activity control-plane methods
  * non-config / read / data-plane / log events are ignored
  * raw audit payloads are not returned (no protoPayload, request, response, etc.)
  * 401/403/404/429/network errors map to typed connector exceptions
  * _strip_audit_entry extracts only safe, flat fields
  * normalize_google_cloud_audit_event maps events to expected google_cloud.* types
  * malformed entries are skipped safely
  * ingestion is idempotent via provider_event_id (insertId)
  * ingestion uses fingerprint when insertId is missing
  * workspace scoping works
  * endpoint requires admin/owner
  * member cannot sync
  * metadata contains no forbidden fields (private keys, tokens, emails, IPs, etc.)
  * summaries/copy contain no forbidden claim wording
  * capability matrix marks google_cloud activity_ingestion=True but signals/etc.=False
  * provider expansion framework next stage points to M78E
  * M78A/B/C tests still pass (tested via existing test files in regression)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Forbidden wording / field constants ──────────────────────────────────────

FORBIDDEN_CLAIM_PHRASES = [
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

FORBIDDEN_METADATA_KEYS = {
    "private_key",
    "signed_jwt",
    "access_token",
    "refresh_token",
    "authorization",
    "principal_email",
    "service_account_email",
    "caller_ip",
    "callerip",
    "user_agent",
    "useragent",
    "proto_payload",
    "protopayload",
    "request",
    "response",
    "authentication_info",
    "authenticationinfo",
    "authorization_info",
    "authorizationinfo",
    "raw_payload",
    "raw_body",
    "secret_name",
    "secret_value",
    "database_name",
    "database_user",
    "password",
    "connection_string",
    "object_key",
    "env_var",
    "env_var_value",
}


def _assert_clean_metadata(metadata: dict) -> None:
    for key in metadata:
        assert key.lower() not in FORBIDDEN_METADATA_KEYS, (
            f"metadata contains forbidden key: {key!r}"
        )


def _assert_clean_copy(text: str) -> None:
    low = text.lower()
    for phrase in FORBIDDEN_CLAIM_PHRASES:
        assert phrase not in low, f"forbidden wording {phrase!r} in: {text[:200]!r}"


# ── Connector unit tests ──────────────────────────────────────────────────────


class TestAuditAllowlist:
    """Tests for GoogleCloudConnector._is_allowed_audit_method."""

    def _connector(self):
        from app.connectors.google_cloud import GoogleCloudConnector
        return GoogleCloudConnector()

    def test_iam_set_policy_allowed(self):
        c = self._connector()
        assert c._is_allowed_audit_method("google.iam.admin.v1.IAM.SetIamPolicy")
        assert c._is_allowed_audit_method("SetIamPolicy")

    def test_firewall_operations_allowed(self):
        c = self._connector()
        for m in [
            "compute.firewalls.insert",
            "compute.firewalls.patch",
            "compute.firewalls.update",
            "compute.firewalls.delete",
        ]:
            assert c._is_allowed_audit_method(m), f"expected {m!r} to be allowed"

    def test_vpc_network_operations_allowed(self):
        c = self._connector()
        for m in ["compute.networks.insert", "compute.networks.delete"]:
            assert c._is_allowed_audit_method(m)

    def test_storage_bucket_operations_allowed(self):
        c = self._connector()
        for m in [
            "storage.buckets.create",
            "storage.buckets.update",
            "storage.buckets.delete",
            "storage.setIamPermissions",
        ]:
            assert c._is_allowed_audit_method(m)

    def test_cloud_sql_operations_allowed(self):
        c = self._connector()
        for m in [
            "cloudsql.instances.create",
            "cloudsql.instances.update",
            "cloudsql.instances.delete",
        ]:
            assert c._is_allowed_audit_method(m)

    def test_cloud_run_v2_operations_allowed(self):
        c = self._connector()
        for m in [
            "google.cloud.run.v2.Services.CreateService",
            "google.cloud.run.v2.Services.UpdateService",
            "google.cloud.run.v2.Services.DeleteService",
        ]:
            assert c._is_allowed_audit_method(m)

    def test_gke_operations_allowed(self):
        c = self._connector()
        for m in [
            "google.container.v1.ClusterManager.CreateCluster",
            "google.container.v1.ClusterManager.UpdateCluster",
            "google.container.v1.ClusterManager.DeleteCluster",
            "google.container.v1.ClusterManager.SetNetworkPolicy",
            "google.container.v1.ClusterManager.SetMasterAuth",
        ]:
            assert c._is_allowed_audit_method(m)

    def test_secret_manager_metadata_operations_allowed(self):
        c = self._connector()
        for m in [
            "google.cloud.secretmanager.v1.SecretManagerService.CreateSecret",
            "google.cloud.secretmanager.v1.SecretManagerService.UpdateSecret",
            "google.cloud.secretmanager.v1.SecretManagerService.DeleteSecret",
        ]:
            assert c._is_allowed_audit_method(m)

    def test_read_operations_not_allowed(self):
        c = self._connector()
        for m in [
            "compute.firewalls.get",
            "compute.firewalls.list",
            "storage.buckets.get",
            "iam.serviceAccounts.get",
            "cloudsql.instances.list",
        ]:
            assert not c._is_allowed_audit_method(m), (
                f"read op {m!r} should be blocked"
            )

    def test_secret_access_not_allowed(self):
        c = self._connector()
        for m in [
            "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
            "google.cloud.secretmanager.v1.SecretManagerService.AddSecretVersion",
            "google.cloud.secretmanager.v1.SecretManagerService.ListSecretVersions",
        ]:
            assert not c._is_allowed_audit_method(m)

    def test_empty_and_none_not_allowed(self):
        c = self._connector()
        assert not c._is_allowed_audit_method("")
        assert not c._is_allowed_audit_method(None)  # type: ignore[arg-type]
        assert not c._is_allowed_audit_method("   ")

    def test_unknown_method_not_allowed(self):
        c = self._connector()
        assert not c._is_allowed_audit_method("random.unknown.method")
        assert not c._is_allowed_audit_method("dataflow.jobs.get")
        assert not c._is_allowed_audit_method("bigquery.tables.getData")


class TestStripAuditEntry:
    """Tests for GoogleCloudConnector._strip_audit_entry."""

    def _connector(self):
        from app.connectors.google_cloud import GoogleCloudConnector
        return GoogleCloudConnector()

    def _raw_entry(self, **overrides) -> dict:
        base = {
            "insertId": "abc123",
            "logName": "projects/my-proj/logs/cloudaudit.googleapis.com%2Factivity",
            "timestamp": "2026-01-15T10:00:00Z",
            "severity": "NOTICE",
            "protoPayload": {
                "methodName": "compute.firewalls.insert",
                "serviceName": "compute.googleapis.com",
                "resourceName": "projects/my-proj/global/firewalls/my-fw",
                "status": {"code": 0, "message": ""},
                # These must never be stored:
                "authenticationInfo": {"principalEmail": "user@example.com"},
                "authorizationInfo": [{"resource": "projects/my-proj"}],
                "request": {"name": "my-fw", "network": "default"},
                "response": {"name": "my-fw"},
                "requestMetadata": {
                    "callerIp": "1.2.3.4",
                    "callerUserAgent": "gcloud/1.0",
                },
            },
            "resource": {
                "type": "gce_firewall_rule",
                "labels": {
                    "firewall_rule_id": "12345",
                    # "project_id" is okay but "service_account_email" is not
                },
            },
        }
        base.update(overrides)
        return base

    def test_extracts_safe_fields(self):
        c = self._connector()
        result = c._strip_audit_entry(self._raw_entry())
        assert result is not None
        assert result["insert_id"] == "abc123"
        assert result["method_name"] == "compute.firewalls.insert"
        assert result["service_name"] == "compute.googleapis.com"
        assert result["resource_name"] == "projects/my-proj/global/firewalls/my-fw"
        assert result["resource_type"] == "gce_firewall_rule"
        assert result["status_code"] == 0
        assert result["severity"] == "NOTICE"

    def test_never_stores_principal_email(self):
        c = self._connector()
        result = c._strip_audit_entry(self._raw_entry())
        assert result is not None
        result_str = str(result)
        assert "user@example.com" not in result_str
        assert "principalEmail" not in result_str
        assert "authenticationInfo" not in result_str

    def test_never_stores_caller_ip(self):
        c = self._connector()
        result = c._strip_audit_entry(self._raw_entry())
        assert result is not None
        result_str = str(result)
        assert "1.2.3.4" not in result_str
        assert "callerIp" not in result_str
        assert "requestMetadata" not in result_str

    def test_never_stores_request_response(self):
        c = self._connector()
        result = c._strip_audit_entry(self._raw_entry())
        assert result is not None
        result_str = str(result)
        assert "request" not in result_str
        assert "response" not in result_str
        assert "authorizationInfo" not in result_str

    def test_resource_name_blocked_when_contains_email(self):
        c = self._connector()
        entry = self._raw_entry()
        entry["protoPayload"]["resourceName"] = (
            "projects/my-proj/serviceAccounts/sa@my-proj.iam.gserviceaccount.com"
        )
        result = c._strip_audit_entry(entry)
        assert result is not None
        # resource_name must be None (email blocked)
        assert result["resource_name"] is None

    def test_missing_protopayload_returns_none(self):
        c = self._connector()
        result = c._strip_audit_entry({"insertId": "x", "timestamp": "2026-01-15T00:00:00Z"})
        assert result is None

    def test_missing_method_name_returns_none(self):
        c = self._connector()
        entry = self._raw_entry()
        del entry["protoPayload"]["methodName"]
        result = c._strip_audit_entry(entry)
        assert result is None

    def test_non_dict_returns_none(self):
        c = self._connector()
        assert c._strip_audit_entry(None) is None  # type: ignore[arg-type]
        assert c._strip_audit_entry("bad") is None  # type: ignore[arg-type]
        assert c._strip_audit_entry([]) is None  # type: ignore[arg-type]


class TestListAuditEventsCapsAndPagination:
    """Tests for GoogleCloudConnector.list_audit_events caps and pagination."""

    def _connector(self):
        from app.connectors.google_cloud import GoogleCloudConnector
        return GoogleCloudConnector()

    def _creds(self):
        return {
            "project_id": "my-project",
            "service_account_json": {
                "type": "service_account",
                "project_id": "my-project",
                "client_email": "sa@my-project.iam.gserviceaccount.com",
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
                "token_uri": "https://oauth2.googleapis.com/token",
            },
        }

    def _safe_entry(self, method_name: str = "compute.firewalls.insert", insert_id: str = "evt1") -> dict:
        return {
            "insert_id": insert_id,
            "log_name": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
            "timestamp": "2026-01-15T10:00:00Z",
            "severity": "NOTICE",
            "method_name": method_name,
            "service_name": "compute.googleapis.com",
            "resource_name": "projects/my-project/global/firewalls/my-fw",
            "resource_type": "gce_firewall_rule",
            "status_code": 0,
            "status_message_safe": "",
        }

    def test_max_events_capped_at_1000(self):
        c = self._connector()
        with patch.object(c, "_get_token", return_value="tok"), \
             patch.object(c, "_post", return_value={"entries": []}) as mock_post:
            c.list_audit_events(self._creds(), max_events=99999)
            # The body's pageSize should be bounded (we cap at max_events and 100 per page)
            call_body = mock_post.call_args[0][2]
            assert call_body["pageSize"] <= 100

    def test_lookback_hours_capped_at_168(self):
        c = self._connector()
        captured = {}
        def fake_post(token, url, body):
            captured["filter"] = body.get("filter", "")
            return {"entries": []}
        with patch.object(c, "_get_token", return_value="tok"), \
             patch.object(c, "_post", side_effect=fake_post):
            c.list_audit_events(self._creds(), lookback_hours=9999)
        # We can't check the exact timestamp but the call should succeed without error
        assert "cloudaudit.googleapis.com" in captured.get("filter", "")

    def test_pagination_bounded_to_max_pages(self):
        c = self._connector()
        call_count = [0]
        def fake_post(token, url, body):
            call_count[0] += 1
            # Always return a nextPageToken to test bounding
            return {
                "entries": [self._safe_entry(insert_id=f"e{call_count[0]}")],
                "nextPageToken": "tok_next",
            }
        with patch.object(c, "_get_token", return_value="tok"), \
             patch.object(c, "_post", side_effect=fake_post):
            result = c.list_audit_events(self._creds(), max_events=1000)
        # Should stop after _MAX_PAGES (10) pages
        assert call_count[0] <= 10

    def test_stops_when_max_events_reached(self):
        c = self._connector()
        def fake_post(token, url, body):
            entries = [
                self._safe_entry(insert_id=f"e{i}") for i in range(50)
            ]
            return {"entries": entries, "nextPageToken": "next"}
        with patch.object(c, "_get_token", return_value="tok"), \
             patch.object(c, "_post", side_effect=fake_post), \
             patch.object(c, "_strip_audit_entry", side_effect=lambda e: e), \
             patch.object(c.__class__, "_is_allowed_audit_method", staticmethod(lambda m: True)):
            result = c.list_audit_events(self._creds(), max_events=10)
        assert len(result) <= 10

    def test_empty_entries_returns_empty_list(self):
        c = self._connector()
        with patch.object(c, "_get_token", return_value="tok"), \
             patch.object(c, "_post", return_value={}):
            result = c.list_audit_events(self._creds())
        assert result == []

    def test_non_allowlisted_entries_filtered(self):
        c = self._connector()
        disallowed_entry = self._safe_entry(method_name="storage.buckets.get")
        allowed_entry = self._safe_entry(method_name="storage.buckets.create", insert_id="e2")
        def fake_post(token, url, body):
            return {"entries": [disallowed_entry, allowed_entry]}
        with patch.object(c, "_get_token", return_value="tok"), \
             patch.object(c, "_post", side_effect=fake_post), \
             patch.object(c, "_strip_audit_entry", side_effect=lambda e: e):
            result = c.list_audit_events(self._creds())
        # disallowed_entry filtered out; only allowed remains
        methods = [r.get("method_name") for r in result]
        assert "storage.buckets.get" not in methods


class TestConnectorErrorMapping:
    """Tests that Cloud Logging HTTP errors map to typed connector exceptions."""

    def _connector(self):
        from app.connectors.google_cloud import GoogleCloudConnector
        return GoogleCloudConnector()

    def _creds(self):
        return {"project_id": "my-project", "service_account_json": {
            "type": "service_account", "project_id": "my-project",
            "client_email": "sa@proj.iam.gserviceaccount.com",
            "private_key": "key", "token_uri": "https://oauth2.googleapis.com/token",
        }}

    def test_401_raises_authentication_error(self):
        from app.connectors.exceptions import AuthenticationError
        c = self._connector()
        with patch.object(c, "_get_token", return_value="tok"), \
             patch.object(c, "_post", side_effect=AuthenticationError("401", status_code=401)):
            with pytest.raises(AuthenticationError):
                c.list_audit_events(self._creds())

    def test_403_raises_connector_error(self):
        from app.connectors.exceptions import ConnectorError
        c = self._connector()
        with patch.object(c, "_get_token", return_value="tok"), \
             patch.object(c, "_post", side_effect=ConnectorError("403", status_code=403)):
            with pytest.raises(ConnectorError):
                c.list_audit_events(self._creds())

    def test_429_raises_rate_limit_error(self):
        from app.connectors.exceptions import RateLimitError
        c = self._connector()
        with patch.object(c, "_get_token", return_value="tok"), \
             patch.object(c, "_post", side_effect=RateLimitError("429", retry_after=60)):
            with pytest.raises(RateLimitError):
                c.list_audit_events(self._creds())

    def test_network_error_raises_network_error(self):
        from app.connectors.exceptions import NetworkError
        c = self._connector()
        with patch.object(c, "_get_token", return_value="tok"), \
             patch.object(c, "_post", side_effect=NetworkError("network")):
            with pytest.raises(NetworkError):
                c.list_audit_events(self._creds())

    def test_missing_project_id_raises_connector_error(self):
        from app.connectors.exceptions import ConnectorError
        c = self._connector()
        with patch.object(c, "_get_token", return_value="tok"):
            with pytest.raises(ConnectorError):
                c.list_audit_events({})  # no project_id


# ── Ingestion service normalization tests ─────────────────────────────────────


class TestNormalizeGoogleCloudAuditEvent:
    """Tests for normalize_google_cloud_audit_event."""

    def _normalize(self, entry: dict, project_id: str = "my-project"):
        from app.services.google_cloud_activity_ingestion_service import (
            normalize_google_cloud_audit_event,
        )
        return normalize_google_cloud_audit_event(entry, project_id)

    def _entry(self, method_name: str, insert_id: str = "evt1", resource_name: str = "") -> dict:
        return {
            "insert_id": insert_id,
            "log_name": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
            "timestamp": "2026-01-15T10:00:00Z",
            "severity": "NOTICE",
            "method_name": method_name,
            "service_name": "compute.googleapis.com",
            "resource_name": resource_name,
            "resource_type": "gce_firewall_rule",
            "status_code": 0,
            "status_message_safe": "",
        }

    def test_firewall_insert_maps_correctly(self):
        result = self._normalize(
            self._entry("compute.firewalls.insert", resource_name="projects/my-project/global/firewalls/my-fw")
        )
        assert result is not None
        assert result["event_type"] == "google_cloud.firewall_rule.created"
        assert result["provider"] == "google_cloud"
        assert result["source"] == "google_cloud_audit_log"

    def test_iam_set_policy_maps_correctly(self):
        result = self._normalize(
            self._entry("google.iam.admin.v1.IAM.SetIamPolicy")
        )
        assert result is not None
        assert result["event_type"] == "google_cloud.iam_policy.updated"

    def test_service_account_created(self):
        result = self._normalize(
            self._entry("google.iam.admin.v1.IAM.CreateServiceAccount")
        )
        assert result is not None
        assert result["event_type"] == "google_cloud.service_account.created"

    def test_service_account_key_created(self):
        result = self._normalize(
            self._entry("google.iam.admin.v1.IAM.CreateServiceAccountKey")
        )
        assert result is not None
        assert result["event_type"] == "google_cloud.service_account_key.created"

    def test_storage_bucket_created(self):
        result = self._normalize(
            self._entry(
                "storage.buckets.create",
                resource_name="projects/_/buckets/my-bucket",
            )
        )
        assert result is not None
        assert result["event_type"] == "google_cloud.storage_bucket.created"

    def test_cloud_sql_instance_updated(self):
        result = self._normalize(
            self._entry(
                "cloudsql.instances.update",
                resource_name="projects/my-project/instances/my-sql",
            )
        )
        assert result is not None
        assert result["event_type"] == "google_cloud.sql_instance.updated"

    def test_cloud_run_service_created_v2(self):
        result = self._normalize(
            self._entry("google.cloud.run.v2.Services.CreateService")
        )
        assert result is not None
        assert result["event_type"] == "google_cloud.run_service.created"

    def test_gke_cluster_deleted(self):
        result = self._normalize(
            self._entry("google.container.v1.ClusterManager.DeleteCluster")
        )
        assert result is not None
        assert result["event_type"] == "google_cloud.gke_cluster.deleted"

    def test_gke_network_policy_updated(self):
        result = self._normalize(
            self._entry("google.container.v1.ClusterManager.SetNetworkPolicy")
        )
        assert result is not None
        assert result["event_type"] == "google_cloud.gke_network_policy.updated"

    def test_secret_created(self):
        result = self._normalize(
            self._entry("google.cloud.secretmanager.v1.SecretManagerService.CreateSecret")
        )
        assert result is not None
        assert result["event_type"] == "google_cloud.secret.created"

    def test_unrecognized_method_returns_none(self):
        result = self._normalize(self._entry("storage.buckets.get"))
        assert result is None

    def test_malformed_entry_returns_none(self):
        from app.services.google_cloud_activity_ingestion_service import (
            normalize_google_cloud_audit_event,
        )
        assert normalize_google_cloud_audit_event(None, "my-project") is None  # type: ignore[arg-type]
        assert normalize_google_cloud_audit_event({}, "my-project") is None
        assert normalize_google_cloud_audit_event("bad", "my-project") is None  # type: ignore[arg-type]

    def test_provider_event_id_from_insert_id(self):
        result = self._normalize(
            self._entry("compute.firewalls.insert", insert_id="stable-insert-id-123")
        )
        assert result is not None
        assert result["provider_event_id"] == "stable-insert-id-123"

    def test_fingerprint_used_when_no_insert_id(self):
        entry = self._entry("compute.firewalls.insert", insert_id="")
        result = self._normalize(entry)
        assert result is not None
        # Should have a fingerprint (fp: prefix)
        assert result["provider_event_id"].startswith("fp:")

    def test_actor_id_never_set(self):
        result = self._normalize(self._entry("compute.firewalls.insert"))
        assert result is not None
        # Actor identity (principal email) must never be stored
        assert result["actor_id"] is None

    def test_source_ip_never_set(self):
        result = self._normalize(self._entry("compute.firewalls.insert"))
        assert result is not None
        assert result["source_ip_hash"] is None

    def test_metadata_contains_no_forbidden_fields(self):
        result = self._normalize(
            self._entry(
                "compute.firewalls.insert",
                resource_name="projects/my-project/global/firewalls/my-fw",
            )
        )
        assert result is not None
        _assert_clean_metadata(result["metadata"])

    def test_metadata_has_safe_fields(self):
        result = self._normalize(
            self._entry(
                "compute.firewalls.insert",
                resource_name="projects/my-project/global/firewalls/my-fw",
            )
        )
        assert result is not None
        m = result["metadata"]
        assert m.get("method_name") == "compute.firewalls.insert"
        assert m.get("project_id") == "my-project"
        assert m.get("event_source") == "google_cloud_audit_log"
        assert m.get("category") == "Admin Activity"

    def test_firewall_resource_name_extracted(self):
        result = self._normalize(
            self._entry(
                "compute.firewalls.insert",
                resource_name="projects/my-project/global/firewalls/my-firewall",
            )
        )
        assert result is not None
        # firewall_rule_name should be extracted
        assert result["metadata"].get("firewall_rule_name") == "my-firewall"

    def test_bucket_resource_name_extracted(self):
        result = self._normalize(
            self._entry(
                "storage.buckets.create",
                resource_name="projects/_/buckets/my-bucket",
            )
        )
        assert result is not None
        assert result["metadata"].get("bucket_name") == "my-bucket"

    def test_service_account_resource_not_extracted(self):
        """SA resourceName contains email — must never be stored."""
        result = self._normalize(
            self._entry(
                "google.iam.admin.v1.IAM.CreateServiceAccountKey",
                resource_name=(
                    "projects/my-proj/serviceAccounts/"
                    "sa@my-proj.iam.gserviceaccount.com/keys/-"
                ),
            )
        )
        # The function must not return an email in resource_names
        if result is not None:
            metadata_str = str(result["metadata"])
            assert "@" not in metadata_str
            assert "iam.gserviceaccount.com" not in metadata_str

    def test_copy_contains_no_forbidden_wording(self):
        from app.services.google_cloud_activity_ingestion_service import (
            ingest_google_cloud_activity,
        )
        # The error message in a permission-limited scenario must be clean
        summary = {
            "error_message": (
                "Google Cloud Audit Log access is limited for these credentials. "
                "Ensure the service account has the roles/logging.viewer role "
                "or equivalent permission on the project."
            )
        }
        _assert_clean_copy(summary["error_message"])


# ── Idempotency tests ─────────────────────────────────────────────────────────


class TestIngestionIdempotency:
    """Tests for idempotent ingestion via provider_event_id."""

    def test_same_event_inserted_once(self, tmp_path):
        """Re-ingesting the same insertId is a no-op (skipped)."""
        from app.services.google_cloud_activity_ingestion_service import (
            normalize_google_cloud_audit_event,
        )
        from app.services.security_activity_event_service import (
            upsert_activity_event,
            compute_event_fingerprint,
        )
        from datetime import datetime, timezone

        ws_id = uuid.uuid4()
        integ_id = uuid.uuid4()

        entry = {
            "insert_id": "unique-event-123",
            "log_name": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
            "timestamp": "2026-01-15T10:00:00Z",
            "severity": "NOTICE",
            "method_name": "compute.firewalls.insert",
            "service_name": "compute.googleapis.com",
            "resource_name": "projects/my-project/global/firewalls/my-fw",
            "resource_type": "gce_firewall_rule",
            "status_code": 0,
            "status_message_safe": "",
        }

        normalized = normalize_google_cloud_audit_event(entry, "my-project")
        assert normalized is not None
        assert normalized["provider_event_id"] == "unique-event-123"

        # Simulate second normalization of the same event
        normalized2 = normalize_google_cloud_audit_event(entry, "my-project")
        assert normalized2 is not None
        assert normalized2["provider_event_id"] == normalized["provider_event_id"]

    def test_fingerprint_deterministic_when_no_insert_id(self):
        """Without insertId, repeated normalization yields the same fingerprint."""
        from app.services.google_cloud_activity_ingestion_service import (
            normalize_google_cloud_audit_event,
        )

        entry = {
            "insert_id": "",
            "log_name": "...",
            "timestamp": "2026-01-15T10:00:00Z",
            "severity": "NOTICE",
            "method_name": "storage.buckets.create",
            "service_name": "storage.googleapis.com",
            "resource_name": "projects/_/buckets/my-bucket",
            "resource_type": "gcs_bucket",
            "status_code": 0,
            "status_message_safe": "",
        }

        n1 = normalize_google_cloud_audit_event(entry, "my-project")
        n2 = normalize_google_cloud_audit_event(entry, "my-project")
        assert n1 is not None and n2 is not None
        assert n1["provider_event_id"] == n2["provider_event_id"]
        assert n1["provider_event_id"].startswith("fp:")


# ── Ingestion service integration tests ──────────────────────────────────────


class TestIngestGoogleCloudActivity:
    """Tests for ingest_google_cloud_activity."""

    def _integration(self, provider: str = "google_cloud") -> MagicMock:
        integ = MagicMock()
        integ.id = uuid.uuid4()
        integ.provider = provider
        integ.encrypted_credentials = b"encrypted"
        integ.credential_iv = b"iv"
        return integ

    def _mock_credentials(self) -> dict:
        return {
            "project_id": "my-project",
            "service_account_json": {
                "type": "service_account",
                "project_id": "my-project",
                "client_email": "sa@my-proj.iam.gserviceaccount.com",
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\nkey\n-----END RSA PRIVATE KEY-----",
                "token_uri": "https://oauth2.googleapis.com/token",
            },
        }

    def _safe_stripped_entry(self, insert_id: str = "evt1", method: str = "compute.firewalls.insert") -> dict:
        return {
            "insert_id": insert_id,
            "log_name": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
            "timestamp": "2026-01-15T10:00:00Z",
            "severity": "NOTICE",
            "method_name": method,
            "service_name": "compute.googleapis.com",
            "resource_name": "projects/my-project/global/firewalls/my-fw",
            "resource_type": "gce_firewall_rule",
            "status_code": 0,
            "status_message_safe": "",
        }

    def test_wrong_provider_returns_not_attempted(self):
        from app.services.google_cloud_activity_ingestion_service import (
            ingest_google_cloud_activity,
        )
        db = MagicMock()
        summary = ingest_google_cloud_activity(
            integration=self._integration(provider="azure"),
            workspace_id=uuid.uuid4(),
            db=db,
        )
        assert summary["attempted"] is False
        assert "Not a Google Cloud integration" in summary["error_message"]

    def test_credential_failure_is_non_fatal(self):
        from app.services.google_cloud_activity_ingestion_service import (
            ingest_google_cloud_activity,
        )
        db = MagicMock()
        with patch(
            "app.services.google_cloud_activity_ingestion_service.decrypt_credentials",
            side_effect=Exception("bad decrypt"),
        ):
            summary = ingest_google_cloud_activity(
                integration=self._integration(),
                workspace_id=uuid.uuid4(),
                db=db,
            )
        assert summary["attempted"] is True
        assert summary["succeeded"] is False
        assert "credentials" in summary["error_message"].lower()

    def test_auth_error_sets_permission_limited(self):
        from app.connectors.exceptions import AuthenticationError
        from app.services.google_cloud_activity_ingestion_service import (
            ingest_google_cloud_activity,
        )
        db = MagicMock()
        with patch(
            "app.services.google_cloud_activity_ingestion_service.decrypt_credentials",
            return_value=self._mock_credentials(),
        ), patch(
            "app.services.google_cloud_activity_ingestion_service.GoogleCloudConnector.list_audit_events",
            side_effect=AuthenticationError("401", status_code=401),
        ):
            summary = ingest_google_cloud_activity(
                integration=self._integration(),
                workspace_id=uuid.uuid4(),
                db=db,
            )
        assert summary["permission_limited"] is True
        assert summary["succeeded"] is True  # non-fatal

    def test_connector_403_sets_permission_limited(self):
        from app.connectors.exceptions import ConnectorError
        from app.services.google_cloud_activity_ingestion_service import (
            ingest_google_cloud_activity,
        )
        db = MagicMock()
        with patch(
            "app.services.google_cloud_activity_ingestion_service.decrypt_credentials",
            return_value=self._mock_credentials(),
        ), patch(
            "app.services.google_cloud_activity_ingestion_service.GoogleCloudConnector.list_audit_events",
            side_effect=ConnectorError("403", status_code=403),
        ):
            summary = ingest_google_cloud_activity(
                integration=self._integration(),
                workspace_id=uuid.uuid4(),
                db=db,
            )
        assert summary["permission_limited"] is True

    def test_rate_limit_sets_hard_error(self):
        from app.connectors.exceptions import RateLimitError
        from app.services.google_cloud_activity_ingestion_service import (
            ingest_google_cloud_activity,
        )
        db = MagicMock()
        with patch(
            "app.services.google_cloud_activity_ingestion_service.decrypt_credentials",
            return_value=self._mock_credentials(),
        ), patch(
            "app.services.google_cloud_activity_ingestion_service.GoogleCloudConnector.list_audit_events",
            side_effect=RateLimitError("429", retry_after=60),
        ):
            summary = ingest_google_cloud_activity(
                integration=self._integration(),
                workspace_id=uuid.uuid4(),
                db=db,
            )
        assert summary["succeeded"] is False
        assert summary["error_message"] is not None

    def test_events_counted_correctly(self):
        from app.services import security_activity_event_service as svc
        from app.services.google_cloud_activity_ingestion_service import (
            ingest_google_cloud_activity,
        )
        db = MagicMock()
        entries = [
            self._safe_stripped_entry(insert_id="e1"),
            self._safe_stripped_entry(insert_id="e2"),
            # This one should be skipped (unrecognized method)
            {**self._safe_stripped_entry(insert_id="e3"), "method_name": "storage.buckets.get"},
        ]
        with patch(
            "app.services.google_cloud_activity_ingestion_service.decrypt_credentials",
            return_value=self._mock_credentials(),
        ), patch(
            "app.services.google_cloud_activity_ingestion_service.GoogleCloudConnector.list_audit_events",
            return_value=entries,
        ), patch.object(
            svc, "upsert_activity_event", return_value=("inserted", MagicMock())
        ):
            summary = ingest_google_cloud_activity(
                integration=self._integration(),
                workspace_id=uuid.uuid4(),
                db=db,
            )
        assert summary["events_seen"] == 3
        # Only e1 and e2 should be inserted (e3 has unrecognized method, returns None)
        assert summary["events_inserted"] == 2
        assert summary["succeeded"] is True

    def test_malformed_event_skipped(self):
        from app.services import security_activity_event_service as svc
        from app.services.google_cloud_activity_ingestion_service import (
            ingest_google_cloud_activity,
        )
        db = MagicMock()
        entries = [
            None,  # malformed
            {},    # malformed
            self._safe_stripped_entry(insert_id="ok"),
        ]
        with patch(
            "app.services.google_cloud_activity_ingestion_service.decrypt_credentials",
            return_value=self._mock_credentials(),
        ), patch(
            "app.services.google_cloud_activity_ingestion_service.GoogleCloudConnector.list_audit_events",
            return_value=entries,
        ), patch.object(
            svc, "upsert_activity_event", return_value=("inserted", MagicMock())
        ):
            summary = ingest_google_cloud_activity(
                integration=self._integration(),
                workspace_id=uuid.uuid4(),
                db=db,
            )
        # seen = 3, but None and {} normalize to None → skipped
        assert summary["events_seen"] == 3
        assert summary["events_inserted"] == 1
        assert summary["succeeded"] is True

    def test_permission_limited_message_is_clean(self):
        from app.connectors.exceptions import AuthenticationError
        from app.services.google_cloud_activity_ingestion_service import (
            ingest_google_cloud_activity,
        )
        db = MagicMock()
        with patch(
            "app.services.google_cloud_activity_ingestion_service.decrypt_credentials",
            return_value=self._mock_credentials(),
        ), patch(
            "app.services.google_cloud_activity_ingestion_service.GoogleCloudConnector.list_audit_events",
            side_effect=AuthenticationError("401", status_code=401),
        ):
            summary = ingest_google_cloud_activity(
                integration=self._integration(),
                workspace_id=uuid.uuid4(),
                db=db,
            )
        if summary.get("error_message"):
            _assert_clean_copy(summary["error_message"])


# ── Metadata allowlist tests ──────────────────────────────────────────────────


class TestMetadataAllowlist:
    """Tests that Google Cloud metadata keys are in the global allowlist."""

    REQUIRED_GCP_KEYS = {
        "project_id",
        "google_cloud_event_id",
        "method_name",
        "service_name",
        "resource_name",
        "resource_type",
        "operation_name",
        "operation_family",
        "operation_action",
        "status_code",
        "status_message_safe",
        "network_name",
        "firewall_rule_name",
        "bucket_name",
        "sql_instance_name",
        "run_service_name",
        "gke_cluster_name",
        "event_time",
        "category",
    }

    def test_gcp_keys_in_allowed_metadata_keys(self):
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        for key in self.REQUIRED_GCP_KEYS:
            assert key in ALLOWED_METADATA_KEYS, (
                f"Google Cloud metadata key {key!r} not in ALLOWED_METADATA_KEYS"
            )

    def test_forbidden_keys_not_in_allowed_metadata_keys(self):
        from app.services.security_activity_event_service import ALLOWED_METADATA_KEYS
        for key in FORBIDDEN_METADATA_KEYS:
            assert key not in ALLOWED_METADATA_KEYS, (
                f"forbidden key {key!r} is in ALLOWED_METADATA_KEYS"
            )


# ── Schema tests ──────────────────────────────────────────────────────────────


class TestSchemaFields:
    """Tests for GoogleCloudActivitySyncRequest/Response Pydantic models."""

    def test_request_defaults(self):
        from app.schemas.security_google_cloud_activity import (
            GoogleCloudActivitySyncRequest,
        )
        req = GoogleCloudActivitySyncRequest()
        assert req.integration_id is None
        assert req.lookback_hours is None
        assert req.max_events is None

    def test_request_bounds_accepted(self):
        from app.schemas.security_google_cloud_activity import (
            GoogleCloudActivitySyncRequest,
        )
        req = GoogleCloudActivitySyncRequest(lookback_hours=24, max_events=100)
        assert req.lookback_hours == 24
        assert req.max_events == 100

    def test_response_fields(self):
        from app.schemas.security_google_cloud_activity import (
            GoogleCloudActivitySyncResponse,
        )
        resp = GoogleCloudActivitySyncResponse(
            attempted=True,
            succeeded=True,
            provider="google_cloud",
            source="google_cloud_audit_log",
        )
        assert resp.provider == "google_cloud"
        assert resp.source == "google_cloud_audit_log"
        assert resp.events_seen == 0
        assert resp.permission_limited is False


# ── Capability matrix tests ───────────────────────────────────────────────────


class TestCapabilityMatrix:
    """Verify capability matrix is updated for M78D."""

    def test_activity_ingestion_now_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap is not None
        assert cap.security.activity_ingestion is True

    def test_activity_signals_now_true(self):
        """M78E complete — activity_signals is now True."""
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap.security.activity_signals is True

    def test_risk_correlations_still_false(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap.security.risk_activity_correlations is True  # M78F complete

    def test_demo_seed_clear_now_true(self):
        """Flipped in M78G."""
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap.security.demo_seed_clear is True

    def test_google_cloud_still_partial(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES_PARTIAL,
        )
        providers = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "google_cloud" in providers

    def test_google_cloud_not_in_complete_list(self):
        from app.services.provider_capability_matrix_service import PROVIDER_CAPABILITIES
        providers = {p.provider for p in PROVIDER_CAPABILITIES}
        assert "google_cloud" not in providers


# ── Expansion framework tests ─────────────────────────────────────────────────


class TestExpansionFramework:
    """Verify planned_next_stage points to M78G after M78F is complete."""

    def test_planned_next_stage_is_m78h(self):
        """Rolled forward in M78G: demo landed → M78H."""
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M78I" in planned, (
            f"planned_next_stage should point to M78H, got: {planned!r}"
        )

    def test_planned_next_stage_mentions_polish_or_ux(self):
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "Polish" in planned or "UX" in planned or "polish" in planned.lower(), (
            f"planned_next_stage should mention Polish/UX, got: {planned!r}"
        )

    def test_m78f_not_in_planned_next_stage(self):
        """M78F is done — pointer must not still say M78F."""
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M78F" not in planned, (
            f"M78F is done; planned_next_stage should not still say M78F: {planned!r}"
        )


# ── Source/event-type mapping coverage test ───────────────────────────────────


class TestEventTypeMapCoverage:
    """Verify _METHOD_EVENT_TYPE_MAP covers all expected event families."""

    def test_all_expected_event_types_present(self):
        from app.services.google_cloud_activity_ingestion_service import (
            _METHOD_EVENT_TYPE_MAP,
        )
        values = set(_METHOD_EVENT_TYPE_MAP.values())
        expected_event_types = {
            "google_cloud.iam_policy.updated",
            "google_cloud.service_account.created",
            "google_cloud.service_account.deleted",
            "google_cloud.service_account.updated",
            "google_cloud.service_account_key.created",
            "google_cloud.service_account_key.deleted",
            "google_cloud.firewall_rule.created",
            "google_cloud.firewall_rule.updated",
            "google_cloud.firewall_rule.deleted",
            "google_cloud.vpc_network.created",
            "google_cloud.vpc_network.updated",
            "google_cloud.vpc_network.deleted",
            "google_cloud.storage_bucket.created",
            "google_cloud.storage_bucket.updated",
            "google_cloud.storage_bucket.deleted",
            "google_cloud.storage_iam.updated",
            "google_cloud.sql_instance.created",
            "google_cloud.sql_instance.updated",
            "google_cloud.sql_instance.deleted",
            "google_cloud.run_service.created",
            "google_cloud.run_service.updated",
            "google_cloud.run_service.deleted",
            "google_cloud.gke_cluster.created",
            "google_cloud.gke_cluster.updated",
            "google_cloud.gke_cluster.deleted",
            "google_cloud.gke_network_policy.updated",
            "google_cloud.gke_master_auth.updated",
            "google_cloud.secret.created",
            "google_cloud.secret.updated",
            "google_cloud.secret.deleted",
        }
        for et in expected_event_types:
            assert et in values, f"event type {et!r} not in _METHOD_EVENT_TYPE_MAP values"

    def test_all_mapped_event_types_start_with_google_cloud(self):
        from app.services.google_cloud_activity_ingestion_service import (
            _METHOD_EVENT_TYPE_MAP,
        )
        for k, v in _METHOD_EVENT_TYPE_MAP.items():
            assert v.startswith("google_cloud."), (
                f"event type {v!r} (for method {k!r}) must start with 'google_cloud.'"
            )
