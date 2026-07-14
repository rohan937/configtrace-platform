"""M78A — Google Cloud drift provider foundation.

Mirrors the M77A Azure foundation test scaffolding (89 tests) for Google
Cloud's five M78A surfaces:
  1. Project metadata
  2. IAM policy summary (counts only — principal identifiers NEVER stored)
  3. VPC network
  4. Firewall rule
  5. Cloud Storage bucket

GCP has no "resource group" equivalent (project is the top-level container);
no Key Vault analog (Secret Manager deferred to M78C); IAM policy summary
replaces the Azure role-assignment surface and surfaces ONLY counts.
"""

from __future__ import annotations

import inspect
import json
from typing import Any
from unittest.mock import MagicMock, patch

import httpx as httpx_mod
import pytest

from app.connectors.exceptions import (
    AuthenticationError, ConnectorError, NetworkError, RateLimitError,
)
from app.connectors.google_cloud import (
    GoogleCloudConnector, _iam_member_type_counts, _MAX_PAGES,
    _parse_network_from_self_link, _parse_project_from_self_link,
    _safe_label_keys, _trunc,
)
from app.connectors.google_cloud_schema import (
    GOOGLE_CLOUD_FIREWALL_RULE,
    GOOGLE_CLOUD_IAM_POLICY_SUMMARY,
    GOOGLE_CLOUD_PROJECT,
    GOOGLE_CLOUD_RECORD_TYPES,
    GOOGLE_CLOUD_STORAGE_BUCKET,
    GOOGLE_CLOUD_VPC_NETWORK,
)

# ── Forbidden claim wording ─────────────────────────────────────────────────
_FORBIDDEN = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

# ── Forbidden field names in any normalized record ──────────────────────────
_SENSITIVE_FIELD_NAMES = frozenset({
    "service_account_json", "private_key", "private_key_id",
    "access_token", "refresh_token", "bearer", "authorization",
    "client_secret", "connection_string", "secret_value", "password",
    "hmac_key", "hmac_secret", "kubeconfig", "etag",
    "members", "bindings", "condition", "customer_encryption_key",
    "service_account_emails",
})

# ── Forbidden value substrings ──────────────────────────────────────────────
_SENSITIVE_VALUE_SUBSTRINGS = (
    # Service-account / OAuth shapes
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "ya29.",  # Google OAuth access token prefix
    "1//",    # Google refresh token prefix
    # HMAC shapes
    "GOOG1E",
    # Member identifiers
    "alice@example.com", "bob@example.com",
    "owner@configtrace-test.iam.gserviceaccount.com",
    "deploy-bot@configtrace-test.iam.gserviceaccount.com",
    # Customer-supplied key fragments
    "csekCustomerEncryptionKey",
)

_PROJECT_ID = "configtrace-test-project"
_PROJECT_NUMBER = "123456789012"
_FAKE_TOKEN = "fake-access-token-not-real"


# ── Helper factories ────────────────────────────────────────────────────────


def _raw_project() -> dict:
    return {
        "name": f"projects/{_PROJECT_NUMBER}",
        "projectId": _PROJECT_ID,
        "displayName": "ConfigTrace Test",
        "state": "ACTIVE",
        "parent": "organizations/000000000001",
        "createTime": "2024-01-01T00:00:00Z",
        "labels": {
            "env": "test",
            "owner": "alice@example.com",  # value MUST NOT be stored
            "secret": "topsecret",           # value MUST NOT be stored
        },
        # Pollution — these MUST NOT survive normalization.
        "private_key": "-----BEGIN PRIVATE KEY-----\nshhhh\n-----END PRIVATE KEY-----",
    }


def _raw_iam_policy() -> dict:
    return {
        "version": 3,
        "etag": "BwYabc123secretetag",  # MUST NOT be stored
        "bindings": [
            {
                "role": "roles/owner",
                "members": [
                    "user:alice@example.com",
                    "user:bob@example.com",
                    "group:admins@example.com",
                    "serviceAccount:owner@configtrace-test.iam.gserviceaccount.com",
                    "domain:example.com",
                ],
            },
            {
                "role": "roles/editor",
                "members": [
                    "serviceAccount:deploy-bot@configtrace-test.iam.gserviceaccount.com",
                ],
            },
            {
                "role": "roles/storage.objectViewer",
                "members": ["allUsers"],  # public exposure sentinel
            },
            {
                "role": "roles/storage.objectAdmin",
                "members": ["allAuthenticatedUsers"],
                "condition": {
                    "title": "BucketScope",
                    "expression": "resource.name == 'projects/_/buckets/secret-bucket'",
                },
            },
        ],
    }


def _raw_vpc_network() -> dict:
    return {
        "id": "888777666555",
        "name": "test-network",
        "selfLink": f"https://www.googleapis.com/compute/v1/projects/{_PROJECT_ID}/global/networks/test-network",
        "autoCreateSubnetworks": False,
        "routingConfig": {"routingMode": "REGIONAL"},
        "mtu": 1460,
        "subnetworks": [
            f"https://www.googleapis.com/compute/v1/projects/{_PROJECT_ID}/regions/us-central1/subnetworks/subnet-1",
            f"https://www.googleapis.com/compute/v1/projects/{_PROJECT_ID}/regions/us-east1/subnetworks/subnet-2",
        ],
        "peerings": [{"name": "peer-1", "network": "other-project/global/networks/x"}],
    }


def _raw_firewall_rule() -> dict:
    return {
        "id": "555444333222",
        "name": "allow-ssh",
        "selfLink": f"https://www.googleapis.com/compute/v1/projects/{_PROJECT_ID}/global/firewalls/allow-ssh",
        "network": f"https://www.googleapis.com/compute/v1/projects/{_PROJECT_ID}/global/networks/test-network",
        "direction": "INGRESS",
        "priority": 1000,
        "disabled": False,
        "sourceRanges": ["0.0.0.0/0"],
        "destinationRanges": [],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
        "denied": [],
        "targetTags": ["web", "ssh"],
        "targetServiceAccounts": [
            "owner@configtrace-test.iam.gserviceaccount.com",  # MUST NOT survive
            "deploy-bot@configtrace-test.iam.gserviceaccount.com",
        ],
        "logConfig": {"enable": False},
    }


def _raw_storage_bucket() -> dict:
    return {
        "id": "configtrace-test-bucket",
        "name": "configtrace-test-bucket",
        "location": "US-CENTRAL1",
        "locationType": "region",
        "storageClass": "STANDARD",
        "iamConfiguration": {
            "uniformBucketLevelAccess": {"enabled": True},
            "publicAccessPrevention": "enforced",
        },
        "versioning": {"enabled": True},
        "retentionPolicy": {"retentionPeriod": "604800", "isLocked": False},
        "lifecycle": {"rule": [{"action": {"type": "Delete"}}, {"action": {"type": "SetStorageClass"}}]},
        "encryption": {"defaultKmsKeyName": "projects/test/locations/us/keyRings/r/cryptoKeys/k"},
        # Pollution that MUST NOT survive normalization.
        "hmacAccessId": "GOOG1ENHMACFAKE",
        "signedUrl": "https://storage.googleapis.com/?X-Goog-Signature=fake",
        "customerEncryptionKey": "csekCustomerEncryptionKey",
        "serviceAccountKey": "-----BEGIN PRIVATE KEY-----\nshhh\n-----END PRIVATE KEY-----",
    }


def _raw_firewall_with_many_protos() -> dict:
    """Used by edge-case caps tests."""
    return {
        "id": "1",
        "name": "wide-rule",
        "selfLink": f"https://www.googleapis.com/compute/v1/projects/{_PROJECT_ID}/global/firewalls/wide-rule",
        "network": f"https://www.googleapis.com/compute/v1/projects/{_PROJECT_ID}/global/networks/n",
        "direction": "INGRESS",
        "priority": 100,
        "sourceRanges": [f"10.0.{i}.0/24" for i in range(50)],  # 50 ranges
        "allowed": [{"IPProtocol": "tcp", "ports": [str(p)] } for p in range(50)],
    }


def _fake_get_token(*_args, **_kwargs) -> str:
    return _FAKE_TOKEN


# ══════════════════════════════════════════════════════════════════════════════
# 1. Schema constants
# ══════════════════════════════════════════════════════════════════════════════


class TestGoogleCloudSchemaConstants:
    def test_record_types_is_frozenset(self):
        assert isinstance(GOOGLE_CLOUD_RECORD_TYPES, frozenset)

    def test_record_types_has_at_least_five_members(self):
        # M78A introduced 5 record types; M78C expanded the set further.
        assert len(GOOGLE_CLOUD_RECORD_TYPES) >= 5

    def test_project_constant_value_and_membership(self):
        assert GOOGLE_CLOUD_PROJECT == "google_cloud_project"
        assert GOOGLE_CLOUD_PROJECT in GOOGLE_CLOUD_RECORD_TYPES

    def test_iam_summary_constant_value_and_membership(self):
        assert GOOGLE_CLOUD_IAM_POLICY_SUMMARY == "google_cloud_iam_policy_summary"
        assert GOOGLE_CLOUD_IAM_POLICY_SUMMARY in GOOGLE_CLOUD_RECORD_TYPES

    def test_vpc_network_constant_value_and_membership(self):
        assert GOOGLE_CLOUD_VPC_NETWORK == "google_cloud_vpc_network"
        assert GOOGLE_CLOUD_VPC_NETWORK in GOOGLE_CLOUD_RECORD_TYPES

    def test_firewall_constant_value_and_membership(self):
        assert GOOGLE_CLOUD_FIREWALL_RULE == "google_cloud_firewall_rule"
        assert GOOGLE_CLOUD_FIREWALL_RULE in GOOGLE_CLOUD_RECORD_TYPES

    def test_storage_bucket_constant_value_and_membership(self):
        assert GOOGLE_CLOUD_STORAGE_BUCKET == "google_cloud_storage_bucket"
        assert GOOGLE_CLOUD_STORAGE_BUCKET in GOOGLE_CLOUD_RECORD_TYPES

    def test_all_five_constants_in_set(self):
        # The M78A-introduced types must remain in the set; M78C adds more.
        m78a_types = {
            GOOGLE_CLOUD_PROJECT, GOOGLE_CLOUD_IAM_POLICY_SUMMARY,
            GOOGLE_CLOUD_VPC_NETWORK, GOOGLE_CLOUD_FIREWALL_RULE,
            GOOGLE_CLOUD_STORAGE_BUCKET,
        }
        assert m78a_types.issubset(set(GOOGLE_CLOUD_RECORD_TYPES))


# ══════════════════════════════════════════════════════════════════════════════
# 2. _normalize_project
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeProject:
    def setup_method(self):
        self.conn = GoogleCloudConnector()
        self.record = self.conn._normalize_project(_raw_project())

    def test_record_type(self):
        assert self.record["record_type"] == GOOGLE_CLOUD_PROJECT

    def test_record_id_format(self):
        assert self.record["record_id"] == f"gcp_project_{_PROJECT_ID}"

    def test_project_id(self):
        assert self.record["project_id"] == _PROJECT_ID

    def test_project_number(self):
        assert self.record["project_number"] == _PROJECT_NUMBER

    def test_parent_type_only_no_id(self):
        assert self.record["parent_type"] == "organizations"
        # The parent ID (000000000001) MUST NOT appear anywhere
        assert "000000000001" not in json.dumps(self.record)

    def test_label_keys_present_values_absent(self):
        assert set(self.record["label_keys"]) == {"env", "owner", "secret"}
        blob = json.dumps(self.record)
        # Label VALUES must NEVER survive — these would be PII / secrets.
        assert "alice@example.com" not in blob
        assert "topsecret" not in blob

    def test_no_private_key_in_record(self):
        blob = json.dumps(self.record)
        assert "BEGIN PRIVATE KEY" not in blob
        assert "shhhh" not in blob

    def test_no_forbidden_field_names(self):
        for k in self.record.keys():
            assert k not in _SENSITIVE_FIELD_NAMES, (
                f"forbidden field name {k!r} in project record"
            )


# ══════════════════════════════════════════════════════════════════════════════
# 3. _normalize_iam_policy_summary
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeIAMPolicySummary:
    def setup_method(self):
        self.conn = GoogleCloudConnector()
        self.record = self.conn._normalize_iam_policy_summary(
            _raw_iam_policy(), project_id=_PROJECT_ID,
        )

    def test_record_type(self):
        assert self.record["record_type"] == GOOGLE_CLOUD_IAM_POLICY_SUMMARY

    def test_provider_resource_id_format(self):
        assert self.record["provider_resource_id"] == f"projects/{_PROJECT_ID}/iamPolicy"

    def test_binding_count(self):
        assert self.record["binding_count"] == 4

    def test_role_count(self):
        assert self.record["role_count"] == 4  # all four roles are distinct

    def test_role_names_present(self):
        assert "roles/owner" in self.record["role_names"]
        assert "roles/editor" in self.record["role_names"]
        assert "roles/storage.objectViewer" in self.record["role_names"]
        assert "roles/storage.objectAdmin" in self.record["role_names"]

    def test_broad_role_count(self):
        # roles/owner and roles/editor are broad.
        assert self.record["broad_role_count"] == 2

    def test_member_type_counts(self):
        assert self.record["user_member_count"] == 2
        assert self.record["group_member_count"] == 1
        assert self.record["service_account_member_count"] == 2
        assert self.record["domain_member_count"] == 1

    def test_public_member_sentinels(self):
        assert self.record["allusers_binding_present"] is True
        assert self.record["allauthenticatedusers_binding_present"] is True

    def test_conditional_binding_count(self):
        assert self.record["conditional_binding_count"] == 1

    def test_no_principal_identifiers(self):
        blob = json.dumps(self.record)
        for forbidden in (
            "alice@example.com", "bob@example.com",
            "admins@example.com",
            "owner@configtrace-test.iam.gserviceaccount.com",
            "deploy-bot@configtrace-test.iam.gserviceaccount.com",
        ):
            assert forbidden not in blob, (
                f"IAM principal identifier {forbidden!r} leaked into record"
            )

    def test_no_etag_in_record(self):
        blob = json.dumps(self.record)
        assert "BwYabc123secretetag" not in blob
        # The key "etag" must not appear either.
        assert '"etag"' not in blob

    def test_no_condition_expression_in_record(self):
        # The CEL expression carries a resource name; MUST NOT survive.
        blob = json.dumps(self.record)
        assert "secret-bucket" not in blob
        assert "BucketScope" not in blob

    def test_no_raw_bindings_or_members(self):
        assert "bindings" not in self.record
        assert "members" not in self.record


# ══════════════════════════════════════════════════════════════════════════════
# 4. _normalize_vpc_network
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeVPCNetwork:
    def setup_method(self):
        self.conn = GoogleCloudConnector()
        self.record = self.conn._normalize_vpc_network(_raw_vpc_network())

    def test_record_type(self):
        assert self.record["record_type"] == GOOGLE_CLOUD_VPC_NETWORK

    def test_network_name(self):
        assert self.record["network_name"] == "test-network"

    def test_project_id_parsed_from_self_link(self):
        assert self.record["project_id"] == _PROJECT_ID

    def test_auto_create_subnetworks(self):
        assert self.record["auto_create_subnetworks"] is False

    def test_routing_mode(self):
        assert self.record["routing_mode"] == "REGIONAL"

    def test_mtu(self):
        assert self.record["mtu"] == 1460

    def test_subnet_count_only_no_subnet_list(self):
        assert self.record["subnet_count"] == 2
        blob = json.dumps(self.record)
        assert "subnet-1" not in blob
        assert "subnet-2" not in blob

    def test_peering_count_only(self):
        assert self.record["peering_count"] == 1
        blob = json.dumps(self.record)
        assert "peer-1" not in blob
        assert "other-project" not in blob


# ══════════════════════════════════════════════════════════════════════════════
# 5. _normalize_firewall_rule
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeFirewallRule:
    def setup_method(self):
        self.conn = GoogleCloudConnector()
        self.record = self.conn._normalize_firewall_rule(_raw_firewall_rule())

    def test_record_type(self):
        assert self.record["record_type"] == GOOGLE_CLOUD_FIREWALL_RULE

    def test_firewall_name(self):
        assert self.record["firewall_name"] == "allow-ssh"

    def test_network_name_parsed(self):
        assert self.record["network_name"] == "test-network"

    def test_direction(self):
        assert self.record["direction"] == "INGRESS"

    def test_priority(self):
        assert self.record["priority"] == 1000

    def test_disabled(self):
        assert self.record["disabled"] is False

    def test_source_ranges_summary(self):
        assert self.record["source_ranges_summary"] == ["0.0.0.0/0"]

    def test_allowed_summary_protocols_and_ports(self):
        assert len(self.record["allowed_summary"]) == 1
        entry = self.record["allowed_summary"][0]
        assert entry["protocol"] == "tcp"
        assert entry["ports"] == ["22"]

    def test_target_tag_count(self):
        assert self.record["target_tag_count"] == 2

    def test_target_service_account_count_only(self):
        assert self.record["target_service_account_count"] == 2

    def test_no_target_service_account_emails(self):
        blob = json.dumps(self.record)
        assert "owner@configtrace-test.iam.gserviceaccount.com" not in blob
        assert "deploy-bot@configtrace-test.iam.gserviceaccount.com" not in blob

    def test_has_log_config(self):
        assert self.record["has_log_config"] is False

    def test_many_protos_cap_safely(self):
        wide = self.conn._normalize_firewall_rule(_raw_firewall_with_many_protos())
        # source ranges cap is 20.
        assert len(wide["source_ranges_summary"]) == 20
        # allowed cap is 20 entries.
        assert len(wide["allowed_summary"]) == 20


# ══════════════════════════════════════════════════════════════════════════════
# 6. _normalize_storage_bucket
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeStorageBucket:
    def setup_method(self):
        self.conn = GoogleCloudConnector()
        self.record = self.conn._normalize_storage_bucket(_raw_storage_bucket())

    def test_record_type(self):
        assert self.record["record_type"] == GOOGLE_CLOUD_STORAGE_BUCKET

    def test_bucket_name(self):
        assert self.record["bucket_name"] == "configtrace-test-bucket"

    def test_location(self):
        assert self.record["location"] == "US-CENTRAL1"
        assert self.record["location_type"] == "region"

    def test_storage_class(self):
        assert self.record["storage_class"] == "STANDARD"

    def test_uniform_bucket_level_access(self):
        assert self.record["uniform_bucket_level_access_enabled"] is True

    def test_public_access_prevention(self):
        assert self.record["public_access_prevention"] == "enforced"

    def test_versioning_enabled(self):
        assert self.record["versioning_enabled"] is True

    def test_retention_policy_seconds(self):
        assert self.record["retention_policy_seconds"] == "604800"

    def test_retention_policy_locked(self):
        assert self.record["retention_policy_locked"] is False

    def test_lifecycle_rule_count(self):
        assert self.record["lifecycle_rule_count"] == 2

    def test_encryption_default_kms_key_present_only_bool(self):
        assert self.record["encryption_default_kms_key_present"] is True
        # The KMS key path itself must not be stored.
        blob = json.dumps(self.record)
        assert "keyRings/r/cryptoKeys/k" not in blob

    def test_no_hmac_key_in_record(self):
        blob = json.dumps(self.record)
        assert "GOOG1ENHMACFAKE" not in blob

    def test_no_signed_url_in_record(self):
        blob = json.dumps(self.record)
        assert "X-Goog-Signature" not in blob

    def test_no_customer_encryption_key(self):
        blob = json.dumps(self.record)
        assert "csekCustomerEncryptionKey" not in blob

    def test_no_service_account_private_key(self):
        blob = json.dumps(self.record)
        assert "BEGIN PRIVATE KEY" not in blob


# ══════════════════════════════════════════════════════════════════════════════
# 7. HTTP _get error mapping
# ══════════════════════════════════════════════════════════════════════════════


class TestGetErrorMapping:
    def test_401_raises_authentication_error(self):
        conn = GoogleCloudConnector()
        resp = MagicMock(status_code=401, headers={})
        with patch("httpx.get", return_value=resp):
            with pytest.raises(AuthenticationError) as exc:
                conn._get(_FAKE_TOKEN, "https://example.com/x")
            assert exc.value.status_code == 401

    def test_429_raises_rate_limit_error_with_retry_after(self):
        conn = GoogleCloudConnector()
        resp = MagicMock(status_code=429, headers={"Retry-After": "60"})
        with patch("httpx.get", return_value=resp):
            with pytest.raises(RateLimitError) as exc:
                conn._get(_FAKE_TOKEN, "https://example.com/x")
            assert exc.value.retry_after == 60.0

    @pytest.mark.parametrize("status", [403, 404, 422, 500, 502])
    def test_4xx_5xx_raise_connector_error(self, status: int):
        conn = GoogleCloudConnector()
        resp = MagicMock(status_code=status, headers={})
        with patch("httpx.get", return_value=resp):
            with pytest.raises(ConnectorError) as exc:
                conn._get(_FAKE_TOKEN, "https://example.com/x")
            assert exc.value.status_code == status

    def test_connect_error_raises_network_error(self):
        conn = GoogleCloudConnector()
        with patch("httpx.get", side_effect=httpx_mod.ConnectError("nope")):
            with pytest.raises(NetworkError):
                conn._get(_FAKE_TOKEN, "https://example.com/x")

    def test_timeout_raises_network_error(self):
        conn = GoogleCloudConnector()
        with patch("httpx.get", side_effect=httpx_mod.TimeoutException("slow")):
            with pytest.raises(NetworkError):
                conn._get(_FAKE_TOKEN, "https://example.com/x")

    def test_200_with_invalid_json_raises_connector_error(self):
        conn = GoogleCloudConnector()
        resp = MagicMock(status_code=200, headers={})
        resp.json.side_effect = ValueError("bad json")
        with patch("httpx.get", return_value=resp):
            with pytest.raises(ConnectorError):
                conn._get(_FAKE_TOKEN, "https://example.com/x")


# ══════════════════════════════════════════════════════════════════════════════
# 8. _get_token error mapping
# ══════════════════════════════════════════════════════════════════════════════


class TestGetTokenErrorMapping:
    _GOOD_CREDS = {
        "service_account_json": {
            "type": "service_account",
            "project_id": _PROJECT_ID,
            "client_email": "sa@configtrace-test.iam.gserviceaccount.com",
            "private_key": "fake-key-not-real-pem",
        }
    }

    def test_missing_client_email_raises_auth_error(self):
        conn = GoogleCloudConnector()
        creds = {"service_account_json": {"project_id": _PROJECT_ID, "private_key": "x"}}
        with pytest.raises(AuthenticationError):
            conn._get_token(creds)

    def test_missing_private_key_raises_auth_error(self):
        conn = GoogleCloudConnector()
        creds = {
            "service_account_json": {
                "project_id": _PROJECT_ID,
                "client_email": "sa@x.iam.gserviceaccount.com",
            }
        }
        with pytest.raises(AuthenticationError):
            conn._get_token(creds)

    def test_signing_failure_raises_auth_error_without_echoing_key(self):
        conn = GoogleCloudConnector()
        # python-jose will raise on a bogus PEM string.
        try:
            conn._get_token(self._GOOD_CREDS)
        except AuthenticationError as e:
            # Error message must not echo the private_key value.
            assert "fake-key-not-real-pem" not in str(e)
        except Exception as e:
            # If python-jose raises something else first, also no leak.
            assert "fake-key-not-real-pem" not in str(e)


# ══════════════════════════════════════════════════════════════════════════════
# 9. _paginate boundedness
# ══════════════════════════════════════════════════════════════════════════════


class TestPaginate:
    def test_paginate_stops_at_max_pages_with_unbounded_token(self):
        conn = GoogleCloudConnector()
        call_count = {"n": 0}

        def fake_get(self, token, url, params=None):
            call_count["n"] += 1
            return {"items": [{"id": call_count["n"]}], "nextPageToken": "more"}

        with patch.object(GoogleCloudConnector, "_get", fake_get):
            items = conn._paginate(_FAKE_TOKEN, "https://example.com/list", items_key="items")
        assert call_count["n"] == _MAX_PAGES
        assert len(items) == _MAX_PAGES

    def test_paginate_stops_when_token_absent(self):
        conn = GoogleCloudConnector()
        call_count = {"n": 0}

        def fake_get(self, token, url, params=None):
            call_count["n"] += 1
            return {"items": [{"id": 1}, {"id": 2}]}  # no nextPageToken

        with patch.object(GoogleCloudConnector, "_get", fake_get):
            items = conn._paginate(_FAKE_TOKEN, "https://example.com/list", items_key="items")
        assert call_count["n"] == 1
        assert len(items) == 2

    def test_paginate_returns_empty_on_non_dict(self):
        conn = GoogleCloudConnector()
        with patch.object(GoogleCloudConnector, "_get", lambda *a, **k: ["bad"]):
            items = conn._paginate(_FAKE_TOKEN, "https://example.com/list", items_key="items")
        assert items == []


# ══════════════════════════════════════════════════════════════════════════════
# 10. validate_credentials
# ══════════════════════════════════════════════════════════════════════════════


class TestValidateCredentials:
    def test_validate_calls_project_endpoint_and_returns_true(self):
        conn = GoogleCloudConnector()
        creds = {"project_id": _PROJECT_ID, "service_account_json": {"x": "y"}}
        with patch.object(GoogleCloudConnector, "_get_token", _fake_get_token):
            with patch.object(GoogleCloudConnector, "_get", return_value={"projectId": _PROJECT_ID}):
                assert conn.validate_credentials(creds) is True

    def test_validate_propagates_auth_error_from_token(self):
        conn = GoogleCloudConnector()
        with patch.object(
            GoogleCloudConnector, "_get_token",
            side_effect=AuthenticationError("nope", status_code=401),
        ):
            with pytest.raises(AuthenticationError):
                conn.validate_credentials({"project_id": _PROJECT_ID})


# ══════════════════════════════════════════════════════════════════════════════
# 11. fetch() — happy path with mocked HTTP
# ══════════════════════════════════════════════════════════════════════════════


class TestFetchReturnsSafeRecords:
    def _mock_responses(self):
        """Build per-URL responses for _get and httpx.post (IAM)."""
        responses = {}

        # CRM v3 project
        responses["/v3/projects/"] = _raw_project()
        # Compute v1 networks
        responses["/global/networks"] = {"items": [_raw_vpc_network()]}
        # Compute v1 firewalls
        responses["/global/firewalls"] = {"items": [_raw_firewall_rule()]}
        # Storage v1 buckets
        responses["/storage/v1/b"] = {"items": [_raw_storage_bucket()]}
        return responses

    def test_fetch_returns_all_five_record_types(self):
        conn = GoogleCloudConnector()
        creds = {"project_id": _PROJECT_ID, "service_account_json": {"x": "y"}}
        responses = self._mock_responses()

        def fake_get(self, token, url, params=None):
            for substr, body in responses.items():
                if substr in url:
                    return body
            return {}

        iam_response = MagicMock(status_code=200, headers={})
        iam_response.json.return_value = _raw_iam_policy()

        with patch.object(GoogleCloudConnector, "_get_token", _fake_get_token):
            with patch.object(GoogleCloudConnector, "_get", fake_get):
                with patch("httpx.post", return_value=iam_response):
                    records = conn.fetch(creds)

        types_in_records = {r["record_type"] for r in records}
        assert GOOGLE_CLOUD_PROJECT in types_in_records
        assert GOOGLE_CLOUD_IAM_POLICY_SUMMARY in types_in_records
        assert GOOGLE_CLOUD_VPC_NETWORK in types_in_records
        assert GOOGLE_CLOUD_FIREWALL_RULE in types_in_records
        assert GOOGLE_CLOUD_STORAGE_BUCKET in types_in_records

    def test_fetch_records_pass_privacy_denylist(self):
        conn = GoogleCloudConnector()
        creds = {"project_id": _PROJECT_ID, "service_account_json": {"x": "y"}}
        responses = self._mock_responses()

        def fake_get(self, token, url, params=None):
            for substr, body in responses.items():
                if substr in url:
                    return body
            return {}

        iam_response = MagicMock(status_code=200, headers={})
        iam_response.json.return_value = _raw_iam_policy()

        with patch.object(GoogleCloudConnector, "_get_token", _fake_get_token):
            with patch.object(GoogleCloudConnector, "_get", fake_get):
                with patch("httpx.post", return_value=iam_response):
                    records = conn.fetch(creds)

        blob = json.dumps(records)
        for forbidden in _SENSITIVE_VALUE_SUBSTRINGS:
            assert forbidden not in blob, (
                f"forbidden value substring {forbidden!r} in fetched records"
            )

    def test_fetch_records_have_no_forbidden_field_names(self):
        conn = GoogleCloudConnector()
        creds = {"project_id": _PROJECT_ID, "service_account_json": {"x": "y"}}
        responses = self._mock_responses()

        def fake_get(self, token, url, params=None):
            for substr, body in responses.items():
                if substr in url:
                    return body
            return {}

        iam_response = MagicMock(status_code=200, headers={})
        iam_response.json.return_value = _raw_iam_policy()

        with patch.object(GoogleCloudConnector, "_get_token", _fake_get_token):
            with patch.object(GoogleCloudConnector, "_get", fake_get):
                with patch("httpx.post", return_value=iam_response):
                    records = conn.fetch(creds)

        for r in records:
            for key in r.keys():
                assert key not in _SENSITIVE_FIELD_NAMES, (
                    f"forbidden field {key!r} in {r['record_type']!r} record"
                )

    def test_fetch_fail_soft_when_one_surface_403s(self):
        """If firewalls returns 403, project / vpc / iam / storage still return."""
        conn = GoogleCloudConnector()
        creds = {"project_id": _PROJECT_ID, "service_account_json": {"x": "y"}}

        def fake_get(self, token, url, params=None):
            if "firewalls" in url:
                raise ConnectorError("forbidden", status_code=403)
            if "networks" in url:
                return {"items": [_raw_vpc_network()]}
            if "/storage/v1/b" in url:
                return {"items": [_raw_storage_bucket()]}
            if "/v3/projects" in url:
                return _raw_project()
            return {}

        iam_response = MagicMock(status_code=200, headers={})
        iam_response.json.return_value = _raw_iam_policy()

        with patch.object(GoogleCloudConnector, "_get_token", _fake_get_token):
            with patch.object(GoogleCloudConnector, "_get", fake_get):
                with patch("httpx.post", return_value=iam_response):
                    records = conn.fetch(creds)

        types_in_records = {r["record_type"] for r in records}
        assert GOOGLE_CLOUD_FIREWALL_RULE not in types_in_records
        # Other four still come back.
        assert GOOGLE_CLOUD_PROJECT in types_in_records
        assert GOOGLE_CLOUD_VPC_NETWORK in types_in_records
        assert GOOGLE_CLOUD_IAM_POLICY_SUMMARY in types_in_records
        assert GOOGLE_CLOUD_STORAGE_BUCKET in types_in_records

    def test_fetch_records_are_json_serialisable(self):
        conn = GoogleCloudConnector()
        creds = {"project_id": _PROJECT_ID, "service_account_json": {"x": "y"}}
        responses = self._mock_responses()

        def fake_get(self, token, url, params=None):
            for substr, body in responses.items():
                if substr in url:
                    return body
            return {}

        iam_response = MagicMock(status_code=200, headers={})
        iam_response.json.return_value = _raw_iam_policy()

        with patch.object(GoogleCloudConnector, "_get_token", _fake_get_token):
            with patch.object(GoogleCloudConnector, "_get", fake_get):
                with patch("httpx.post", return_value=iam_response):
                    records = conn.fetch(creds)
        # Should not raise.
        json.dumps(records)


# ══════════════════════════════════════════════════════════════════════════════
# 12. Helper unit tests
# ══════════════════════════════════════════════════════════════════════════════


class TestHelpers:
    def test_trunc_truncates_strings(self):
        assert _trunc("x" * 300) == "x" * 200

    def test_trunc_passes_through_non_strings(self):
        assert _trunc(42) == 42
        assert _trunc(None) is None
        assert _trunc(True) is True

    def test_safe_label_keys_returns_key_names_only(self):
        assert sorted(_safe_label_keys({"env": "prod", "secret": "k"})) == ["env", "secret"]

    def test_safe_label_keys_handles_non_dict(self):
        assert _safe_label_keys(None) == []
        assert _safe_label_keys("not a dict") == []
        assert _safe_label_keys([1, 2]) == []

    def test_parse_project_from_self_link(self):
        link = "https://www.googleapis.com/compute/v1/projects/p1/global/networks/n1"
        assert _parse_project_from_self_link(link) == "p1"

    def test_parse_project_from_self_link_missing(self):
        assert _parse_project_from_self_link("https://example.com/foo") == ""

    def test_parse_network_from_self_link(self):
        link = "https://www.googleapis.com/compute/v1/projects/p1/global/networks/my-net"
        assert _parse_network_from_self_link(link) == "my-net"

    def test_iam_member_type_counts_buckets_correctly(self):
        counts = _iam_member_type_counts([
            "user:a@b.c", "user:c@d.e", "group:g@h.i",
            "serviceAccount:s@a.b.c", "domain:example.com",
            "allUsers", "allAuthenticatedUsers",
            "unknown:something",  # falls into other_count
        ])
        assert counts["user_count"] == 2
        assert counts["group_count"] == 1
        assert counts["service_account_count"] == 1
        assert counts["domain_count"] == 1
        assert counts["other_count"] == 1
        assert counts["allusers_present"] is True
        assert counts["allauthenticatedusers_present"] is True

    def test_iam_member_type_counts_on_non_list(self):
        counts = _iam_member_type_counts("not a list")
        assert counts["user_count"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# 13. Edge cases — empty / malformed input
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizerEdgeCases:
    def setup_method(self):
        self.conn = GoogleCloudConnector()

    def test_normalize_project_handles_empty_dict(self):
        r = self.conn._normalize_project({})
        assert r["record_type"] == GOOGLE_CLOUD_PROJECT
        assert r["project_id"] == ""

    def test_normalize_iam_policy_summary_with_no_bindings(self):
        r = self.conn._normalize_iam_policy_summary({}, project_id="p1")
        assert r["binding_count"] == 0
        assert r["role_count"] == 0
        assert r["broad_role_count"] == 0
        assert r["user_member_count"] == 0
        assert r["allusers_binding_present"] is False

    def test_normalize_iam_policy_caps_role_names(self):
        bindings = [
            {"role": f"roles/test.role{i}", "members": []}
            for i in range(50)
        ]
        r = self.conn._normalize_iam_policy_summary(
            {"bindings": bindings}, project_id="p1",
        )
        # role_names is capped at _MAX_IAM_ROLE_NAMES (=20).
        assert len(r["role_names"]) == 20

    def test_normalize_vpc_network_handles_missing_routing_config(self):
        r = self.conn._normalize_vpc_network({"name": "n", "selfLink": "x"})
        assert r["routing_mode"] == ""

    def test_normalize_firewall_rule_handles_missing_protocol_list(self):
        r = self.conn._normalize_firewall_rule({"name": "n", "selfLink": "x"})
        assert r["allowed_summary"] == []
        assert r["denied_summary"] == []
        assert r["target_tag_count"] == 0
        assert r["target_service_account_count"] == 0

    def test_normalize_storage_bucket_handles_missing_iam_config(self):
        r = self.conn._normalize_storage_bucket({"name": "b"})
        assert r["uniform_bucket_level_access_enabled"] is False
        assert r["public_access_prevention"] == ""


# ══════════════════════════════════════════════════════════════════════════════
# 14. Capability matrix wiring
# ══════════════════════════════════════════════════════════════════════════════


class TestCapabilityMatrix:
    def test_google_cloud_included(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("google_cloud")
        assert cap is not None
        assert cap.label == "Google Cloud"
        assert cap.category == "cloud"

    def test_maturity_is_partial(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("google_cloud")
        assert cap.maturity == "partial"

    def test_drift_snapshots_true(self):
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("google_cloud")
        assert cap.drift.drift_snapshots is True
        assert cap.drift.drift_diff is True
        assert cap.drift.drift_review_workflow is True

    def test_drift_risk_classification_flipped_in_m78b(self):
        """Flipped to True in M78B (core security foundation lit up)."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("google_cloud")
        assert cap.drift.drift_risk_classification is True

    def test_security_capabilities_partial_after_m78g(self):
        """M78G flips demo_seed_clear/case_report/evidence_timeline/evidence_graph."""
        from app.services.provider_capability_matrix_service import (
            get_provider_capability,
        )
        cap = get_provider_capability("google_cloud")
        assert cap.security.security_rules is True
        assert cap.security.activity_ingestion is True   # M78D complete
        assert cap.security.activity_signals is True  # M78E complete
        assert cap.security.risk_activity_correlations is True  # M78F complete
        assert cap.security.demo_seed_clear is True  # M78G complete
        assert cap.security.case_report is True  # M78G complete

    def test_google_cloud_in_partial_list(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES_PARTIAL,
        )
        providers = {p.provider for p in PROVIDER_CAPABILITIES_PARTIAL}
        assert "google_cloud" in providers

    def test_google_cloud_not_in_canonical_8(self):
        from app.services.provider_capability_matrix_service import (
            PROVIDER_CAPABILITIES,
        )
        providers = {p.provider for p in PROVIDER_CAPABILITIES}
        assert "google_cloud" not in providers


# ══════════════════════════════════════════════════════════════════════════════
# 15. sync_service registration
# ══════════════════════════════════════════════════════════════════════════════


def test_google_cloud_in_supported_providers_tuple():
    from app.services import sync_service
    src = inspect.getsource(sync_service)
    assert '"google_cloud"' in src
    assert "_SUPPORTED_PROVIDERS" in src


def test_worker_sync_task_dispatches_google_cloud():
    from app.workers import sync_task
    src = inspect.getsource(sync_task)
    assert 'integration.provider == "google_cloud"' in src
    assert "GoogleCloudConnector" in src


# ══════════════════════════════════════════════════════════════════════════════
# 16. security_coverage_service registration
# ══════════════════════════════════════════════════════════════════════════════


def test_google_cloud_in_security_coverage_providers():
    """M78A: google_cloud is registered in coverage PROVIDERS list (drift only;
    security rules deferred to M78B).
    """
    from app.services.security_coverage_service import PROVIDERS, PROVIDER_SURFACES
    assert "google_cloud" in PROVIDERS
    surfaces = PROVIDER_SURFACES["google_cloud"]
    assert "Project metadata" in surfaces
    assert "IAM policy bindings" in surfaces
    assert "Cloud Storage buckets" in surfaces
    assert "VPC firewall rules" in surfaces


# ══════════════════════════════════════════════════════════════════════════════
# 17. Provider expansion framework
# ══════════════════════════════════════════════════════════════════════════════


def test_expansion_framework_planned_next_stage_is_beyond_m78c():
    """The planned next stage has advanced to M89A: Kubernetes Drift Provider Foundation."""
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    stage = fw["summary"]["planned_next_stage"]
    # Kubernetes arc is open — next stage is M89A Kubernetes Drift Provider Foundation.
    assert "M89A" in stage
    assert "Kubernetes" in stage
    for done in ("M78C", "M78D", "M78E", "M78F", "M78G", "M78H", "M78I"):
        assert done not in stage, f"{done} is done; pointer has advanced past it"


def test_expansion_framework_no_longer_recommends_google_cloud():
    """Google Cloud launched in M78A and is no longer 'recommended' —
    it has moved into PROVIDER_CAPABILITIES_PARTIAL. Kubernetes is now the head
    of the recommended queue."""
    from app.services import provider_expansion_framework as svc
    fw = svc.get_framework()
    recs = fw["recommended_next_providers"]
    providers = [r["provider"] for r in recs]
    assert "google_cloud" not in providers
    assert recs[0]["provider"] == "kubernetes"


# ══════════════════════════════════════════════════════════════════════════════
# 18. Claim discipline — forbidden phrases
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("module_name", [
    "app.connectors.google_cloud",
    "app.connectors.google_cloud_schema",
    "app.services.risk_rules.google_cloud",
])
def test_no_forbidden_claims_in_google_cloud_modules(module_name):
    import importlib
    mod = importlib.import_module(module_name)
    src = inspect.getsource(mod)
    low = src.lower()
    for phrase in _FORBIDDEN:
        assert phrase not in low, (
            f"forbidden phrase {phrase!r} in {module_name}"
        )


def test_no_forbidden_claims_in_google_cloud_capability_notes():
    from app.services.provider_capability_matrix_service import (
        get_provider_capability,
    )
    cap = get_provider_capability("google_cloud")
    notes_low = (cap.notes or "").lower()
    for phrase in _FORBIDDEN:
        assert phrase not in notes_low


# ══════════════════════════════════════════════════════════════════════════════
# 19. Diff tracked fields and risk classification (QA pass)
# ══════════════════════════════════════════════════════════════════════════════
#
# Google Cloud previously had NO entry in diff_service.py's tracked-fields
# dispatch (every google_cloud_ record type fell through to the Cloudflare
# DNS default tuple, so compute_diff could never detect a modified field) and
# NO risk_rules/google_cloud.py module at all (risk_service.py had no
# google_cloud_ dispatch branch, so every Google Cloud change silently fell
# through to the Cloudflare DNS classifier) — despite the provider
# capability matrix already claiming drift_diff=True and
# drift_risk_classification=True. Both were built during this QA pass,
# making that pre-existing capability-matrix claim actually true.

GOOGLE_CLOUD_ALL_RECORD_TYPES = (
    "google_cloud_project",
    "google_cloud_iam_policy_summary",
    "google_cloud_vpc_network",
    "google_cloud_firewall_rule",
    "google_cloud_storage_bucket",
    "google_cloud_sql_instance",
    "google_cloud_run_service",
    "google_cloud_gke_cluster",
    "google_cloud_service_account_key_summary",
    "google_cloud_secret_manager_summary",
)


class TestGoogleCloudDiffTrackedFields:
    def test_all_ten_record_types_have_tracked_fields_entries(self):
        from app.services.diff_service import _GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE

        for record_type in GOOGLE_CLOUD_ALL_RECORD_TYPES:
            assert record_type in _GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE, (
                f"{record_type!r} has no tracked-fields entry — modified-field "
                "changes for this record type will never be detected by compute_diff"
            )

    def test_tracked_fields_dispatch_uses_google_cloud_table_not_cloudflare_default(self):
        from app.services.diff_service import _tracked_fields_for, _TRACKED_FIELDS

        for record_type in GOOGLE_CLOUD_ALL_RECORD_TYPES:
            fields = _tracked_fields_for({"record_type": record_type})
            assert fields != _TRACKED_FIELDS, (
                f"{record_type!r} is falling through to the Cloudflare DNS "
                "default tracked-fields tuple instead of its own Google Cloud fields"
            )
            assert fields, f"{record_type!r} resolved to an empty tracked-fields tuple"

    def test_firewall_source_ranges_change_produces_drift_change(self):
        """source_ranges_summary gaining 0.0.0.0/0 must surface as a Change."""
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        def _firewall_record(source_ranges: list) -> dict:
            return {
                "record_type": "google_cloud_firewall_rule",
                "provider": "google_cloud",
                "record_id": "gcp_firewall_fw1",
                "firewall_id": "fw1",
                "firewall_name": "test-fw",
                "network_name": "default",
                "project_id": "proj-1",
                "direction": "INGRESS",
                "priority": 1000,
                "disabled": False,
                "source_ranges_summary": source_ranges,
                "destination_ranges_summary": [],
                "allowed_summary": [{"protocol": "tcp", "ports": ["443"]}],
                "denied_summary": [],
                "target_tag_count": 1,
                "target_service_account_count": 0,
                "has_log_config": False,
            }

        prev = _mock_snapshot([_firewall_record(["10.0.0.0/8"])])
        new = _mock_snapshot([_firewall_record(["0.0.0.0/0"])])

        changes = compute_diff(prev, new)
        range_changes = [c for c in changes if c["field_path"] == "source_ranges_summary"]

        assert len(range_changes) == 1
        assert range_changes[0]["prev_value"] == ["10.0.0.0/8"]
        assert range_changes[0]["new_value"] == ["0.0.0.0/0"]

    def test_no_spurious_change_when_records_are_identical(self):
        from app.models.snapshot import Snapshot
        from app.services.diff_service import compute_diff

        def _mock_snapshot(state: list[dict]) -> MagicMock:
            snap = MagicMock(spec=Snapshot)
            snap.state = state
            return snap

        record = {
            "record_type": "google_cloud_storage_bucket",
            "provider": "google_cloud",
            "record_id": "gcp_storage_bucket1",
            "bucket_id": "bucket1",
            "bucket_name": "bucket1",
            "location": "US",
            "location_type": "multi-region",
            "storage_class": "STANDARD",
            "uniform_bucket_level_access_enabled": True,
            "public_access_prevention": "enforced",
            "versioning_enabled": True,
            "retention_policy_seconds": None,
            "retention_policy_locked": False,
            "lifecycle_rule_count": 0,
            "encryption_default_kms_key_present": False,
        }
        prev = _mock_snapshot([dict(record)])
        new = _mock_snapshot([dict(record)])

        assert compute_diff(prev, new) == []

    def test_every_tracked_field_classifies_without_error_or_invalid_severity(self):
        """Every field in _GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE must be
        classifiable: classify_google_cloud_change must not raise, and must
        return one of the four known severities, for a representative
        modified change on each tracked field of each record type."""
        from app.services.diff_service import _GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE
        from app.services.risk_rules.google_cloud import classify_google_cloud_change

        for record_type, fields in _GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE.items():
            for field in fields:
                change = {
                    "change_type": "modified",
                    "field_path": field,
                    "prev_value": 1,
                    "new_value": 2,
                    "provider_metadata": {"record_type": record_type},
                }
                level, reason = classify_google_cloud_change(change)
                assert level in ("low", "medium", "high", "critical"), (
                    f"{record_type}.{field} returned invalid severity {level!r}"
                )
                assert isinstance(reason, str) and reason, (
                    f"{record_type}.{field} returned an empty reason string"
                )


class TestGoogleCloudRiskClassifier:
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

    def test_risk_service_dispatches_google_cloud_to_google_cloud_classifier(self):
        """Regression guard: risk_service.py must route google_cloud_ record
        types to classify_google_cloud_change, not silently fall through to
        the Cloudflare DNS classifier (the exact bug this QA pass found and
        fixed)."""
        from app.services.risk_service import classify_change

        change = self._make_change(
            "google_cloud_iam_policy_summary", "allusers_binding_present",
            prev_value=False, new_value=True,
        )
        mock_change = MagicMock()
        mock_change.provider_metadata = change["provider_metadata"]
        mock_change.field_path = change["field_path"]
        mock_change.change_type = change["change_type"]
        mock_change.prev_value = change["prev_value"]
        mock_change.new_value = change["new_value"]
        level, reason = classify_change(mock_change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"
        assert "google cloud" in reason.lower()

    def test_iam_public_member_added_is_high(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_iam_policy_summary", "allusers_binding_present",
            prev_value=False, new_value=True,
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_iam_public_member_removed_is_low(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_iam_policy_summary", "allusers_binding_present",
            prev_value=True, new_value=False,
        )
        level, _ = classify_google_cloud_change(change)
        assert level == "low"

    def test_iam_high_severity_broad_role_added_is_high(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_iam_policy_summary", "role_names",
            prev_value=["roles/storage.objectViewer"],
            new_value=["roles/storage.objectViewer", "roles/owner"],
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_iam_medium_severity_broad_role_added_is_medium(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_iam_policy_summary", "role_names",
            prev_value=[],
            new_value=["roles/iam.serviceAccountAdmin"],
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_iam_broad_role_removed_is_low(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_iam_policy_summary", "role_names",
            prev_value=["roles/owner"],
            new_value=[],
        )
        level, _ = classify_google_cloud_change(change)
        assert level == "low"

    def test_firewall_public_source_range_added_is_high(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_firewall_rule", "source_ranges_summary",
            prev_value=["10.0.0.0/8"], new_value=["10.0.0.0/8", "0.0.0.0/0"],
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_firewall_public_source_range_removed_is_low(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_firewall_rule", "source_ranges_summary",
            prev_value=["10.0.0.0/8", "0.0.0.0/0"], new_value=["10.0.0.0/8"],
        )
        level, _ = classify_google_cloud_change(change)
        assert level == "low"

    def test_firewall_broad_port_entry_added_is_critical(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_firewall_rule", "allowed_summary",
            prev_value=[{"protocol": "tcp", "ports": ["443"]}],
            new_value=[{"protocol": "tcp", "ports": ["443"]}, {"protocol": "all", "ports": []}],
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "critical", f"Expected critical, got {level!r}: {reason}"

    def test_firewall_rdp_port_entry_added_is_critical(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_firewall_rule", "allowed_summary",
            prev_value=[],
            new_value=[{"protocol": "tcp", "ports": ["3389"]}],
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "critical", f"Expected critical, got {level!r}: {reason}"

    def test_firewall_ssh_port_entry_added_is_high(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_firewall_rule", "allowed_summary",
            prev_value=[],
            new_value=[{"protocol": "tcp", "ports": ["22"]}],
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_firewall_benign_port_entry_added_is_low(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_firewall_rule", "allowed_summary",
            prev_value=[],
            new_value=[{"protocol": "tcp", "ports": ["443"]}],
        )
        level, _ = classify_google_cloud_change(change)
        assert level == "low"

    def test_firewall_no_targets_gained_is_medium(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_firewall_rule", "target_tag_count",
            prev_value=2, new_value=0,
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_bucket_public_access_prevention_disabled_is_medium(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_storage_bucket", "public_access_prevention",
            prev_value="enforced", new_value="inherited",
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_bucket_uniform_access_disabled_is_medium(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_storage_bucket", "uniform_bucket_level_access_enabled",
            prev_value=True, new_value=False,
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_bucket_uniform_access_enabled_is_low(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_storage_bucket", "uniform_bucket_level_access_enabled",
            prev_value=False, new_value=True,
        )
        level, _ = classify_google_cloud_change(change)
        assert level == "low"

    def test_sql_public_ip_enabled_is_high(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_sql_instance", "public_ip_enabled",
            prev_value=False, new_value=True,
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_sql_backups_disabled_is_medium(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_sql_instance", "backup_enabled",
            prev_value=True, new_value=False,
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_run_public_invoker_enabled_is_high(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_run_service", "public_invoker_allowed",
            prev_value=False, new_value=True,
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_gke_legacy_abac_enabled_is_high(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_gke_cluster", "legacy_abac_enabled",
            prev_value=False, new_value=True,
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_gke_workload_identity_disabled_is_medium(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_gke_cluster", "workload_identity_enabled",
            prev_value=True, new_value=False,
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_sa_key_count_reaches_five_is_high(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_service_account_key_summary", "user_managed_key_count",
            prev_value=3, new_value=5,
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_sa_key_count_increase_below_five_is_medium(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_service_account_key_summary", "user_managed_key_count",
            prev_value=1, new_value=2,
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "medium", f"Expected medium, got {level!r}: {reason}"

    def test_sa_key_count_decrease_is_low(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change(
            "google_cloud_service_account_key_summary", "user_managed_key_count",
            prev_value=5, new_value=3,
        )
        level, _ = classify_google_cloud_change(change)
        assert level == "low"

    def test_unknown_record_type_is_low(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change
        change = self._make_change("google_cloud_unknown_surface", "some_field", prev_value=1, new_value=2)
        level, _ = classify_google_cloud_change(change)
        assert level == "low"

    def test_unknown_transitions_never_produce_high_or_critical(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change

        unknown_cases = [
            ("google_cloud_iam_policy_summary", "allusers_binding_present", False, None),
            ("google_cloud_storage_bucket", "uniform_bucket_level_access_enabled", True, None),
            ("google_cloud_sql_instance", "public_ip_enabled", False, None),
            ("google_cloud_run_service", "public_invoker_allowed", False, None),
            ("google_cloud_gke_cluster", "legacy_abac_enabled", False, None),
            ("google_cloud_service_account_key_summary", "user_managed_key_count", 3, None),
        ]
        for record_type, field, prev, new in unknown_cases:
            change = self._make_change(record_type, field, prev_value=prev, new_value=new)
            level, reason = classify_google_cloud_change(change)
            assert level not in ("high", "critical"), (
                f"{record_type}.{field} unknown transition produced {level!r}: {reason!r}"
            )

    def test_count_unknown_not_treated_as_zero(self):
        """A count field's unknown value must not be treated as an explicit
        zero — this is the exact bug fixed in PagerDuty's classification-QA
        pass, guarded against here from the start."""
        from app.services.risk_rules.google_cloud import classify_google_cloud_change

        change = self._make_change(
            "google_cloud_service_account_key_summary", "user_managed_key_count",
            prev_value=3, new_value=None,
        )
        level, reason = classify_google_cloud_change(change)
        assert level == "low", f"Expected low, got {level!r}: {reason}"
        assert "unknown or missing" in reason.lower()

    def test_classifier_reads_real_compute_diff_dict_shape_not_a_mock(self):
        """Regression guard against the exact old_value/prev_value bug class
        found in Terraform Cloud's first QA pass: builds a plain dict shaped
        EXACTLY like compute_diff's real output (prev_value/new_value/
        field_path/change_type/provider_metadata), not a MagicMock, to prove
        the classifier reads the real field name."""
        from app.services.risk_rules.google_cloud import classify_google_cloud_change

        real_shaped_change = {
            "change_type": "modified",
            "field_path": "allusers_binding_present",
            "prev_value": False,
            "new_value": True,
            "provider_metadata": {"record_type": "google_cloud_iam_policy_summary"},
        }
        level, reason = classify_google_cloud_change(real_shaped_change)
        assert level == "high", f"Expected high, got {level!r}: {reason}"

    def test_no_forbidden_wording_in_reasons(self):
        from app.services.risk_rules.google_cloud import classify_google_cloud_change

        FORBIDDEN = [
            "breach", "compromise", "attacker", "leaked", "unauthorized access",
            "bucket exposed", "buckets exposed", "state exposed",
            "secret exposed", "secrets exposed", "infrastructure exposed",
            "customer data exposed", "google cloud data exposed", "data exposed",
            "exfiltration", "stolen", "fraud", "attack detected",
        ]
        test_changes = [
            self._make_change("google_cloud_iam_policy_summary", "allusers_binding_present", prev_value=False, new_value=True),
            self._make_change("google_cloud_firewall_rule", "source_ranges_summary", prev_value=["10.0.0.0/8"], new_value=["0.0.0.0/0"]),
            self._make_change("google_cloud_storage_bucket", "uniform_bucket_level_access_enabled", prev_value=True, new_value=False),
            self._make_change("google_cloud_sql_instance", "public_ip_enabled", prev_value=False, new_value=True),
            self._make_change("google_cloud_run_service", "public_invoker_allowed", prev_value=False, new_value=True),
            self._make_change("google_cloud_gke_cluster", "legacy_abac_enabled", prev_value=False, new_value=True),
        ]
        for change in test_changes:
            _, reason = classify_google_cloud_change(change)
            reason_lower = reason.lower()
            for phrase in FORBIDDEN:
                assert phrase not in reason_lower, (
                    f"Forbidden phrase {phrase!r} found in risk reason: {reason!r}"
                )
