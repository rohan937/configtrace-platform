"""M78C: Google Cloud IAM / Network / Storage / Runtime Risk Expansion.

Verifies:
  * Connector normalizes new safe surfaces (Cloud SQL, Cloud Run, GKE,
    SA Key Summary, Secret Manager Summary).
  * Optional surfaces fail soft when permission-limited or unavailable.
  * All 13 new M78C security rules fire on risky configurations.
  * All M78B rules still pass.
  * Evidence contains no forbidden PII / secret fields.
  * Finding copy does not claim breach, compromise, unauthorized access,
    leaked secrets, or exposed data.
  * Rule keys are registered in registry / confidence / pack / coverage /
    frontend catalog.
  * Capability matrix keeps Google Cloud partial and does not mark
    activity/signals/correlations/demo complete.
  * Provider expansion framework next stage points to M78D.
"""

from __future__ import annotations

import pytest

# ── Helpers ──────────────────────────────────────────────────────────────────

FORBIDDEN_EVIDENCE_FIELDS = {
    "private_key",
    "private_key_data",
    "signed_jwt",
    "access_token",
    "refresh_token",
    "authorization",
    "service_account_email",
    "sa_email",
    "principal_email",
    "user_name",
    "group_name",
    "full_iam_bindings",
    "bindings",
    "database_name",
    "database_user",
    "password",
    "connection_string",
    "query_data",
    "env_var_name",
    "env_var_value",
    "secret_name",
    "secret_value",
    "secret_version_payload",
    "kubeconfig",
    "certificate",
    "node_name",
    "workload_data",
    "pod_spec",
    "logs",
    "customer_data",
}

FORBIDDEN_WORDING = [
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


def _assert_evidence_clean(evidence: dict) -> None:
    """Assert that the evidence dict contains no forbidden fields."""
    for key in evidence:
        assert key.lower() not in FORBIDDEN_EVIDENCE_FIELDS, (
            f"evidence contains forbidden field: {key!r}"
        )


def _assert_copy_clean(text: str) -> None:
    """Assert that a string contains none of the forbidden claim phrases."""
    lowered = text.lower()
    for phrase in FORBIDDEN_WORDING:
        assert phrase not in lowered, (
            f"forbidden wording found: {phrase!r} in {text[:200]!r}"
        )


# ── Connector normalizer tests ────────────────────────────────────────────────


class TestCloudSQLNormalizer:
    """Unit tests for _normalize_sql_instance."""

    def _get_connector(self):
        from app.connectors.google_cloud import GoogleCloudConnector
        return GoogleCloudConnector()

    def _sql_raw(self, **overrides):
        base = {
            "name": "my-sql-instance",
            "project": "my-project",
            "databaseVersion": "POSTGRES_15",
            "region": "us-central1",
            "state": "RUNNABLE",
            "settings": {
                "ipConfiguration": {
                    "ipv4Enabled": False,
                    "authorizedNetworks": [],
                    "requireSsl": True,
                    "sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
                },
                "backupConfiguration": {
                    "enabled": True,
                    "pointInTimeRecoveryEnabled": True,
                },
                "deletionProtectionEnabled": True,
                "availabilityType": "REGIONAL",
            },
        }
        base.update(overrides)
        return base

    def test_normalizes_safe_fields(self):
        connector = self._get_connector()
        raw = self._sql_raw()
        record = connector._normalize_sql_instance(raw)
        assert record["record_type"] == "google_cloud_sql_instance"
        assert record["instance_name"] == "my-sql-instance"
        assert record["project_id"] == "my-project"
        assert record["database_version"] == "POSTGRES_15"
        assert record["region"] == "us-central1"
        assert record["state"] == "RUNNABLE"
        assert record["public_ip_enabled"] is False
        assert record["authorized_network_count"] == 0
        assert record["require_ssl"] is True
        assert record["backup_enabled"] is True
        assert record["deletion_protection_enabled"] is True

    def test_public_ip_enabled(self):
        connector = self._get_connector()
        raw = self._sql_raw()
        raw["settings"]["ipConfiguration"]["ipv4Enabled"] = True
        raw["settings"]["ipConfiguration"]["authorizedNetworks"] = [
            {"value": "0.0.0.0/0"}
        ]
        record = connector._normalize_sql_instance(raw)
        assert record["public_ip_enabled"] is True
        assert record["authorized_network_count"] == 1

    def test_does_not_store_database_names_or_passwords(self):
        connector = self._get_connector()
        raw = self._sql_raw()
        # Add fields that should NOT be stored
        raw["databaseNames"] = ["secret_db"]
        raw["rootPassword"] = "hunter2"
        record = connector._normalize_sql_instance(raw)
        assert "databaseNames" not in record
        assert "rootPassword" not in record
        assert "password" not in record

    def test_record_id_is_safe(self):
        connector = self._get_connector()
        record = connector._normalize_sql_instance(self._sql_raw())
        assert "@" not in record["record_id"]  # no email in record id


class TestCloudRunNormalizer:
    """Unit tests for _normalize_run_service."""

    def _get_connector(self):
        from app.connectors.google_cloud import GoogleCloudConnector
        return GoogleCloudConnector()

    def _run_raw(self, **overrides):
        base = {
            "name": "projects/my-project/locations/us-central1/services/my-service",
            "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY",
            "launchStage": "GA",
            "template": {
                "containers": [
                    {
                        "env": [
                            {"name": "ENV_VAR", "value": "some_value"},
                            {
                                "name": "SECRET_VAR",
                                "valueSource": {
                                    "secretKeyRef": {
                                        "secret": "my-secret",
                                        "version": "latest",
                                    }
                                },
                            },
                        ]
                    }
                ]
            },
        }
        base.update(overrides)
        return base

    def test_normalizes_safe_fields(self):
        connector = self._get_connector()
        record = connector._normalize_run_service(self._run_raw(), None)
        assert record["record_type"] == "google_cloud_run_service"
        assert record["service_name"] == "my-service"
        assert record["project_id"] == "my-project"
        assert record["region"] == "us-central1"
        assert record["ingress"] == "INGRESS_TRAFFIC_INTERNAL_ONLY"
        assert record["environment_variable_count"] == 2
        assert record["secret_environment_variable_count"] == 1
        assert record["public_invoker_allowed"] is False

    def test_public_invoker_from_iam_policy(self):
        connector = self._get_connector()
        policy = {
            "bindings": [
                {
                    "role": "roles/run.invoker",
                    "members": ["allUsers"],
                }
            ]
        }
        record = connector._normalize_run_service(self._run_raw(), policy)
        assert record["public_invoker_allowed"] is True

    def test_no_env_var_names_or_values_stored(self):
        connector = self._get_connector()
        record = connector._normalize_run_service(self._run_raw(), None)
        # env var count is safe; names/values must not be stored
        assert "ENV_VAR" not in str(record)
        assert "some_value" not in str(record)
        assert "my-secret" not in str(record)

    def test_invoker_policy_none_is_safe(self):
        connector = self._get_connector()
        record = connector._normalize_run_service(self._run_raw(), None)
        assert record["public_invoker_allowed"] is False


class TestGKENormalizer:
    """Unit tests for _normalize_gke_cluster."""

    def _get_connector(self):
        from app.connectors.google_cloud import GoogleCloudConnector
        return GoogleCloudConnector()

    def _gke_raw(self, **overrides):
        base = {
            "name": "my-cluster",
            "location": "us-central1",
            "selfLink": (
                "https://container.googleapis.com/v1/projects/my-project/"
                "locations/us-central1/clusters/my-cluster"
            ),
            "privateClusterConfig": {
                "enablePrivateNodes": True,
                "enablePrivateEndpoint": True,
            },
            "masterAuthorizedNetworksConfig": {
                "enabled": True,
                "cidrBlocks": [
                    {"cidrBlock": "10.0.0.0/8", "displayName": "corp"},
                ],
            },
            "networkPolicy": {"enabled": True, "provider": "CALICO"},
            "workloadIdentityConfig": {"workloadPool": "my-project.svc.id.goog"},
            "shieldedNodes": {"enabled": True},
            "legacyAbac": {"enabled": False},
            "releaseChannel": {"channel": "REGULAR"},
        }
        base.update(overrides)
        return base

    def test_normalizes_safe_fields(self):
        connector = self._get_connector()
        record = connector._normalize_gke_cluster(self._gke_raw())
        assert record["record_type"] == "google_cloud_gke_cluster"
        assert record["cluster_name"] == "my-cluster"
        assert record["project_id"] == "my-project"
        assert record["location"] == "us-central1"
        assert record["private_cluster_enabled"] is True
        assert record["master_authorized_networks_count"] == 1
        assert record["network_policy_enabled"] is True
        assert record["workload_identity_enabled"] is True
        assert record["legacy_abac_enabled"] is False
        assert record["public_endpoint_enabled"] is False  # private endpoint
        assert record["release_channel"] == "REGULAR"

    def test_public_endpoint_when_no_private_config(self):
        connector = self._get_connector()
        raw = self._gke_raw()
        raw["privateClusterConfig"] = {}  # no enablePrivateEndpoint = public
        record = connector._normalize_gke_cluster(raw)
        assert record["public_endpoint_enabled"] is True

    def test_master_authorized_networks_zero_when_disabled(self):
        connector = self._get_connector()
        raw = self._gke_raw()
        raw["masterAuthorizedNetworksConfig"] = {"enabled": False}
        record = connector._normalize_gke_cluster(raw)
        assert record["master_authorized_networks_count"] == 0

    def test_no_kubeconfig_or_cert_stored(self):
        connector = self._get_connector()
        raw = self._gke_raw()
        raw["masterAuth"] = {"username": "admin", "password": "secret"}
        raw["masterAuth"]["clusterCaCertificate"] = "BASE64CERT=="
        record = connector._normalize_gke_cluster(raw)
        assert "username" not in record
        assert "password" not in record
        assert "clusterCaCertificate" not in record


class TestServiceAccountKeySummaryNormalizer:
    """Unit tests for _normalize_service_account_key_summary."""

    def _get_connector(self):
        from app.connectors.google_cloud import GoogleCloudConnector
        return GoogleCloudConnector()

    def test_aggregate_counts_only(self):
        connector = self._get_connector()
        keys = [
            # USER_MANAGED key — old
            {
                "keyType": "USER_MANAGED",
                "validAfterTime": "2020-01-01T00:00:00Z",
                "disabled": False,
            },
            # USER_MANAGED key — recent (within 90 days)
            {
                "keyType": "USER_MANAGED",
                "validAfterTime": "2026-05-15T00:00:00Z",
                "disabled": False,
            },
            # SYSTEM_MANAGED — should NOT be counted
            {
                "keyType": "SYSTEM_MANAGED",
                "validAfterTime": "2020-01-01T00:00:00Z",
            },
        ]
        record = connector._normalize_service_account_key_summary(
            "my-project", sa_count=3, disabled_sa_count=0, all_keys=keys
        )
        assert record["record_type"] == "google_cloud_service_account_key_summary"
        assert record["project_id"] == "my-project"
        assert record["service_account_count"] == 3
        assert record["user_managed_key_count"] == 2
        # The 2020 key is old (> 90 days)
        assert record["old_user_managed_key_count"] == 1
        assert record["oldest_key_age_days"] is not None
        assert record["oldest_key_age_days"] > 90

    def test_no_sa_emails_in_record(self):
        connector = self._get_connector()
        record = connector._normalize_service_account_key_summary(
            "my-project", sa_count=2, disabled_sa_count=0, all_keys=[]
        )
        record_str = str(record)
        assert "@" not in record_str
        assert "email" not in record_str.lower()

    def test_empty_key_list(self):
        connector = self._get_connector()
        record = connector._normalize_service_account_key_summary(
            "my-project", sa_count=0, disabled_sa_count=0, all_keys=[]
        )
        assert record["user_managed_key_count"] == 0
        assert record["old_user_managed_key_count"] == 0
        assert record["oldest_key_age_days"] is None


class TestSecretManagerSummaryNormalizer:
    """Unit tests for _normalize_secret_manager_summary."""

    def _get_connector(self):
        from app.connectors.google_cloud import GoogleCloudConnector
        return GoogleCloudConnector()

    def test_counts_replication_policies(self):
        connector = self._get_connector()
        secrets = [
            # Automatic without CMEK
            {"replication": {"automatic": {}}},
            # Automatic with CMEK
            {
                "replication": {
                    "automatic": {
                        "customerManagedEncryption": {"kmsKeyName": "projects/..."}
                    }
                }
            },
            # User-managed
            {"replication": {"userManaged": {"replicas": [{"location": "us-central1"}]}}},
        ]
        record = connector._normalize_secret_manager_summary("my-project", secrets)
        assert record["record_type"] == "google_cloud_secret_manager_summary"
        assert record["secret_count"] == 3
        assert record["automatic_replication_count"] == 2
        assert record["user_managed_replication_count"] == 1
        assert record["customer_managed_encryption_count"] == 1

    def test_no_secret_names_stored(self):
        connector = self._get_connector()
        secrets = [
            {"name": "projects/x/secrets/my-secret", "replication": {"automatic": {}}},
        ]
        record = connector._normalize_secret_manager_summary("my-project", secrets)
        # Secret name must NOT be stored
        record_str = str(record)
        assert "my-secret" not in record_str


# ── Security rule tests — Cloud SQL ──────────────────────────────────────────


class TestCloudSQLRules:
    """Unit tests for M78C Cloud SQL security rules."""

    def _evaluate(self, record: dict):
        from app.services.security_rules.google_cloud import evaluate
        return evaluate(record)

    def _sql_record(self, **kwargs):
        base = {
            "record_type": "google_cloud_sql_instance",
            "record_id": "gcp_sql_my-project_test-instance",
            "instance_name": "test-instance",
            "project_id": "my-project",
            "database_version": "POSTGRES_15",
            "region": "us-central1",
            "state": "RUNNABLE",
            "public_ip_enabled": False,
            "authorized_network_count": 0,
            "require_ssl": True,
            "ssl_mode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
            "backup_enabled": True,
            "deletion_protection_enabled": True,
        }
        base.update(kwargs)
        return base

    def test_public_network_access_high(self):
        record = self._sql_record(public_ip_enabled=True, authorized_network_count=2)
        findings = self._evaluate(record)
        rule_keys = [f.rule_key for f in findings]
        assert "google_cloud_sql_public_network_access" in rule_keys
        pna = next(f for f in findings if f.rule_key == "google_cloud_sql_public_network_access")
        assert pna.severity == "high"

    def test_public_network_access_medium_no_authorized_networks(self):
        record = self._sql_record(public_ip_enabled=True, authorized_network_count=0)
        findings = self._evaluate(record)
        rule_keys = [f.rule_key for f in findings]
        assert "google_cloud_sql_public_network_access" in rule_keys
        pna = next(f for f in findings if f.rule_key == "google_cloud_sql_public_network_access")
        assert pna.severity == "medium"

    def test_public_network_access_not_fired_when_private(self):
        record = self._sql_record(public_ip_enabled=False)
        findings = self._evaluate(record)
        assert not any(f.rule_key == "google_cloud_sql_public_network_access" for f in findings)

    def test_weak_tls_require_ssl_false(self):
        record = self._sql_record(require_ssl=False, ssl_mode="")
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_sql_weak_tls" for f in findings)

    def test_weak_tls_allow_unencrypted_mode(self):
        record = self._sql_record(
            require_ssl=True,
            ssl_mode="ALLOW_UNENCRYPTED_AND_ENCRYPTED",
        )
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_sql_weak_tls" for f in findings)

    def test_weak_tls_not_fired_when_strict(self):
        record = self._sql_record(
            require_ssl=True,
            ssl_mode="TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
        )
        findings = self._evaluate(record)
        assert not any(f.rule_key == "google_cloud_sql_weak_tls" for f in findings)

    def test_backups_disabled(self):
        record = self._sql_record(backup_enabled=False)
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_sql_backups_disabled" for f in findings)

    def test_backups_not_fired_when_enabled(self):
        record = self._sql_record(backup_enabled=True)
        findings = self._evaluate(record)
        assert not any(f.rule_key == "google_cloud_sql_backups_disabled" for f in findings)

    def test_deletion_protection_disabled(self):
        record = self._sql_record(deletion_protection_enabled=False)
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_sql_deletion_protection_disabled" for f in findings)

    def test_deletion_protection_not_fired_when_enabled(self):
        record = self._sql_record(deletion_protection_enabled=True)
        findings = self._evaluate(record)
        assert not any(
            f.rule_key == "google_cloud_sql_deletion_protection_disabled" for f in findings
        )

    def test_safe_record_no_findings(self):
        record = self._sql_record(
            public_ip_enabled=False,
            require_ssl=True,
            ssl_mode="TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
            backup_enabled=True,
            deletion_protection_enabled=True,
        )
        findings = self._evaluate(record)
        assert findings == []

    def test_evidence_privacy_sql(self):
        record = self._sql_record(public_ip_enabled=True, authorized_network_count=1)
        findings = self._evaluate(record)
        for f in findings:
            _assert_evidence_clean(f.evidence)
            _assert_copy_clean(f.description)
            _assert_copy_clean(f.title)


# ── Security rule tests — Cloud Run ──────────────────────────────────────────


class TestCloudRunRules:
    """Unit tests for M78C Cloud Run security rules."""

    def _evaluate(self, record: dict):
        from app.services.security_rules.google_cloud import evaluate
        return evaluate(record)

    def _run_record(self, **kwargs):
        base = {
            "record_type": "google_cloud_run_service",
            "record_id": "gcp_run_my-project_us-central1_my-service",
            "service_name": "my-service",
            "project_id": "my-project",
            "region": "us-central1",
            "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY",
            "launch_stage": "GA",
            "public_invoker_allowed": False,
            "invoker_policy_summary": {"invoker_binding_count": 0},
            "environment_variable_count": 2,
            "secret_environment_variable_count": 1,
        }
        base.update(kwargs)
        return base

    def test_public_invoker_fires(self):
        record = self._run_record(public_invoker_allowed=True)
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_run_public_invoker" for f in findings)

    def test_public_invoker_not_fired_when_false(self):
        record = self._run_record(public_invoker_allowed=False)
        findings = self._evaluate(record)
        assert not any(f.rule_key == "google_cloud_run_public_invoker" for f in findings)

    def test_all_ingress_fires(self):
        record = self._run_record(ingress="INGRESS_TRAFFIC_ALL")
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_run_all_ingress" for f in findings)

    def test_all_ingress_severity_high_when_also_public_invoker(self):
        record = self._run_record(
            ingress="INGRESS_TRAFFIC_ALL",
            public_invoker_allowed=True,
        )
        findings = self._evaluate(record)
        all_ingress = next(
            f for f in findings if f.rule_key == "google_cloud_run_all_ingress"
        )
        assert all_ingress.severity == "high"

    def test_all_ingress_severity_medium_when_no_public_invoker(self):
        record = self._run_record(
            ingress="INGRESS_TRAFFIC_ALL",
            public_invoker_allowed=False,
        )
        findings = self._evaluate(record)
        all_ingress = next(
            f for f in findings if f.rule_key == "google_cloud_run_all_ingress"
        )
        assert all_ingress.severity == "medium"

    def test_internal_ingress_not_fired(self):
        record = self._run_record(ingress="INGRESS_TRAFFIC_INTERNAL_ONLY")
        findings = self._evaluate(record)
        assert not any(f.rule_key == "google_cloud_run_all_ingress" for f in findings)

    def test_evidence_privacy_run(self):
        record = self._run_record(public_invoker_allowed=True, ingress="INGRESS_TRAFFIC_ALL")
        findings = self._evaluate(record)
        for f in findings:
            _assert_evidence_clean(f.evidence)
            _assert_copy_clean(f.description)


# ── Security rule tests — GKE ─────────────────────────────────────────────────


class TestGKERules:
    """Unit tests for M78C GKE security rules."""

    def _evaluate(self, record: dict):
        from app.services.security_rules.google_cloud import evaluate
        return evaluate(record)

    def _gke_record(self, **kwargs):
        base = {
            "record_type": "google_cloud_gke_cluster",
            "record_id": "gcp_gke_my-project_us-central1_my-cluster",
            "cluster_name": "my-cluster",
            "project_id": "my-project",
            "location": "us-central1",
            "private_cluster_enabled": True,
            "master_authorized_networks_count": 1,
            "network_policy_enabled": True,
            "workload_identity_enabled": True,
            "shielded_nodes_enabled": True,
            "legacy_abac_enabled": False,
            "public_endpoint_enabled": False,
            "release_channel": "REGULAR",
        }
        base.update(kwargs)
        return base

    def test_public_control_plane_fires(self):
        record = self._gke_record(
            public_endpoint_enabled=True,
            master_authorized_networks_count=0,
        )
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_gke_public_control_plane" for f in findings)

    def test_public_control_plane_not_fired_with_authorized_networks(self):
        record = self._gke_record(
            public_endpoint_enabled=True,
            master_authorized_networks_count=2,
        )
        findings = self._evaluate(record)
        assert not any(
            f.rule_key == "google_cloud_gke_public_control_plane" for f in findings
        )

    def test_public_control_plane_not_fired_with_private_endpoint(self):
        record = self._gke_record(
            public_endpoint_enabled=False,
            master_authorized_networks_count=0,
        )
        findings = self._evaluate(record)
        assert not any(
            f.rule_key == "google_cloud_gke_public_control_plane" for f in findings
        )

    def test_legacy_abac_fires(self):
        record = self._gke_record(legacy_abac_enabled=True)
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_gke_legacy_abac_enabled" for f in findings)

    def test_legacy_abac_not_fired_when_disabled(self):
        record = self._gke_record(legacy_abac_enabled=False)
        findings = self._evaluate(record)
        assert not any(f.rule_key == "google_cloud_gke_legacy_abac_enabled" for f in findings)

    def test_network_policy_disabled_fires(self):
        record = self._gke_record(network_policy_enabled=False)
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_gke_network_policy_disabled" for f in findings)

    def test_network_policy_not_fired_when_enabled(self):
        record = self._gke_record(network_policy_enabled=True)
        findings = self._evaluate(record)
        assert not any(
            f.rule_key == "google_cloud_gke_network_policy_disabled" for f in findings
        )

    def test_workload_identity_disabled_fires(self):
        record = self._gke_record(workload_identity_enabled=False)
        findings = self._evaluate(record)
        assert any(
            f.rule_key == "google_cloud_gke_workload_identity_disabled" for f in findings
        )

    def test_workload_identity_not_fired_when_enabled(self):
        record = self._gke_record(workload_identity_enabled=True)
        findings = self._evaluate(record)
        assert not any(
            f.rule_key == "google_cloud_gke_workload_identity_disabled" for f in findings
        )

    def test_safe_record_no_findings(self):
        record = self._gke_record(
            public_endpoint_enabled=False,
            master_authorized_networks_count=1,
            legacy_abac_enabled=False,
            network_policy_enabled=True,
            workload_identity_enabled=True,
        )
        findings = self._evaluate(record)
        assert findings == []

    def test_evidence_privacy_gke(self):
        record = self._gke_record(
            public_endpoint_enabled=True,
            master_authorized_networks_count=0,
            legacy_abac_enabled=True,
            network_policy_enabled=False,
            workload_identity_enabled=False,
        )
        findings = self._evaluate(record)
        for f in findings:
            _assert_evidence_clean(f.evidence)
            _assert_copy_clean(f.description)
            _assert_copy_clean(f.title)


# ── Security rule tests — Service account key summary ────────────────────────


class TestServiceAccountKeyRules:
    """Unit tests for M78C SA key security rules."""

    def _evaluate(self, record: dict):
        from app.services.security_rules.google_cloud import evaluate
        return evaluate(record)

    def _sa_key_summary(self, **kwargs):
        base = {
            "record_type": "google_cloud_service_account_key_summary",
            "record_id": "gcp_sa_key_summary_my-project",
            "project_id": "my-project",
            "service_account_count": 5,
            "disabled_service_account_count": 0,
            "user_managed_key_count": 0,
            "old_user_managed_key_count": 0,
            "oldest_key_age_days": None,
        }
        base.update(kwargs)
        return base

    def test_user_managed_keys_fires(self):
        record = self._sa_key_summary(user_managed_key_count=2)
        findings = self._evaluate(record)
        assert any(
            f.rule_key == "google_cloud_service_account_user_managed_keys" for f in findings
        )

    def test_user_managed_keys_high_severity_when_many(self):
        record = self._sa_key_summary(user_managed_key_count=5)
        findings = self._evaluate(record)
        f = next(
            f for f in findings
            if f.rule_key == "google_cloud_service_account_user_managed_keys"
        )
        assert f.severity == "high"

    def test_user_managed_keys_medium_severity_when_few(self):
        record = self._sa_key_summary(user_managed_key_count=2)
        findings = self._evaluate(record)
        f = next(
            f for f in findings
            if f.rule_key == "google_cloud_service_account_user_managed_keys"
        )
        assert f.severity == "medium"

    def test_user_managed_keys_not_fired_when_zero(self):
        record = self._sa_key_summary(user_managed_key_count=0)
        findings = self._evaluate(record)
        assert not any(
            f.rule_key == "google_cloud_service_account_user_managed_keys" for f in findings
        )

    def test_old_keys_fires(self):
        record = self._sa_key_summary(
            user_managed_key_count=2,
            old_user_managed_key_count=1,
            oldest_key_age_days=120,
        )
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_service_account_old_keys" for f in findings)

    def test_old_keys_fires_via_oldest_age_threshold(self):
        record = self._sa_key_summary(
            user_managed_key_count=1,
            old_user_managed_key_count=0,
            oldest_key_age_days=95,
        )
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_service_account_old_keys" for f in findings)

    def test_old_keys_not_fired_when_recent(self):
        record = self._sa_key_summary(
            user_managed_key_count=1,
            old_user_managed_key_count=0,
            oldest_key_age_days=30,
        )
        findings = self._evaluate(record)
        assert not any(f.rule_key == "google_cloud_service_account_old_keys" for f in findings)

    def test_evidence_privacy_sa_keys(self):
        record = self._sa_key_summary(user_managed_key_count=3, old_user_managed_key_count=1)
        findings = self._evaluate(record)
        for f in findings:
            _assert_evidence_clean(f.evidence)
            _assert_copy_clean(f.description)
            # must not assert that keys ARE leaked (only "does not confirm... were leaked" is safe)
            assert "keys are leaked" not in f.description.lower()
            assert "key leaked" not in f.description.lower()


# ── Security rule tests — Secret Manager ─────────────────────────────────────


class TestSecretManagerRules:
    """Unit tests for M78C Secret Manager security rules."""

    def _evaluate(self, record: dict):
        from app.services.security_rules.google_cloud import evaluate
        return evaluate(record)

    def _sm_summary(self, **kwargs):
        base = {
            "record_type": "google_cloud_secret_manager_summary",
            "record_id": "gcp_secret_mgr_summary_my-project",
            "project_id": "my-project",
            "secret_count": 5,
            "automatic_replication_count": 3,
            "user_managed_replication_count": 2,
            "customer_managed_encryption_count": 0,
        }
        base.update(kwargs)
        return base

    def test_auto_replication_without_cmek_fires(self):
        record = self._sm_summary(
            automatic_replication_count=3,
            customer_managed_encryption_count=0,
        )
        findings = self._evaluate(record)
        assert any(
            f.rule_key == "google_cloud_secret_manager_auto_replication_without_cmek"
            for f in findings
        )

    def test_auto_replication_without_cmek_not_fired_when_cmek_present(self):
        record = self._sm_summary(
            automatic_replication_count=3,
            customer_managed_encryption_count=3,
        )
        findings = self._evaluate(record)
        assert not any(
            f.rule_key == "google_cloud_secret_manager_auto_replication_without_cmek"
            for f in findings
        )

    def test_auto_replication_without_cmek_not_fired_when_no_secrets(self):
        record = self._sm_summary(
            automatic_replication_count=0,
            customer_managed_encryption_count=0,
        )
        findings = self._evaluate(record)
        assert not any(
            f.rule_key == "google_cloud_secret_manager_auto_replication_without_cmek"
            for f in findings
        )

    def test_evidence_privacy_sm(self):
        record = self._sm_summary()
        findings = self._evaluate(record)
        for f in findings:
            _assert_evidence_clean(f.evidence)
            _assert_copy_clean(f.description)
            # no secret names or values in evidence
            assert "secret_name" not in str(f.evidence)
            assert "secret_value" not in str(f.evidence)


# ── M78B regression tests ─────────────────────────────────────────────────────


class TestM78BRegression:
    """Verify all M78B rules still fire correctly after M78C changes."""

    def _evaluate(self, record):
        from app.services.security_rules.google_cloud import evaluate
        return evaluate(record)

    def test_iam_public_member_still_fires(self):
        record = {
            "record_type": "google_cloud_iam_policy_summary",
            "record_id": "gcp_iam_policy_my-project",
            "project_id": "my-project",
            "allusers_binding_present": True,
            "allauthenticatedusers_binding_present": False,
            "binding_count": 5,
            "role_names": [],
        }
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_iam_public_member" for f in findings)

    def test_iam_broad_role_still_fires(self):
        record = {
            "record_type": "google_cloud_iam_policy_summary",
            "record_id": "gcp_iam_policy_my-project",
            "project_id": "my-project",
            "allusers_binding_present": False,
            "allauthenticatedusers_binding_present": False,
            "binding_count": 2,
            "broad_role_count": 1,
            "role_names": ["roles/owner"],
        }
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_iam_broad_privileged_role" for f in findings)

    def test_firewall_public_admin_still_fires(self):
        record = {
            "record_type": "google_cloud_firewall_rule",
            "record_id": "gcp_firewall_x",
            "firewall_name": "allow-ssh",
            "network_name": "default",
            "project_id": "my-project",
            "direction": "INGRESS",
            "priority": 1000,
            "disabled": False,
            "source_ranges_summary": ["0.0.0.0/0"],
            "allowed_summary": [{"protocol": "tcp", "ports": ["22"]}],
            "denied_summary": [],
            "target_tag_count": 0,
            "target_service_account_count": 0,
        }
        findings = self._evaluate(record)
        assert any(f.rule_key == "google_cloud_firewall_public_admin_ingress" for f in findings)

    def test_storage_public_access_prevention_still_fires(self):
        record = {
            "record_type": "google_cloud_storage_bucket",
            "record_id": "gcp_storage_my-bucket",
            "bucket_name": "my-bucket",
            "location": "US",
            "storage_class": "STANDARD",
            "public_access_prevention": "inherited",
            "uniform_bucket_level_access_enabled": True,
            "versioning_enabled": True,
            "retention_policy_seconds": None,
            "retention_policy_locked": None,
            "lifecycle_rule_count": 0,
        }
        findings = self._evaluate(record)
        assert any(
            f.rule_key == "google_cloud_storage_public_access_prevention_disabled"
            for f in findings
        )


# ── Registry / confidence / pack / coverage integration tests ─────────────────


class TestRegistryIntegration:
    """Verify all new rule keys are properly registered."""

    NEW_RULE_KEYS = [
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
    ]

    def test_all_new_keys_in_known_rule_keys(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        for key in self.NEW_RULE_KEYS:
            assert key in KNOWN_RULE_KEYS, f"{key!r} not in KNOWN_RULE_KEYS"

    def test_all_new_keys_have_confidence_entry(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in self.NEW_RULE_KEYS:
            assert key in RULE_CONFIDENCE, f"{key!r} not in RULE_CONFIDENCE"

    def test_confidence_entries_are_high_or_medium(self):
        from app.services.security_rule_confidence import RULE_CONFIDENCE
        for key in self.NEW_RULE_KEYS:
            confidence, _ = RULE_CONFIDENCE[key]
            assert confidence in ("high", "medium"), (
                f"{key!r} has unexpected confidence: {confidence!r}"
            )

    def test_all_new_keys_in_rule_pack_meta(self):
        from app.services.security_rule_pack import _RULE_META
        for key in self.NEW_RULE_KEYS:
            assert key in _RULE_META, f"{key!r} not in _RULE_META"

    def test_pack_rule_meta_has_correct_provider(self):
        from app.services.security_rule_pack import _RULE_META
        for key in self.NEW_RULE_KEYS:
            provider, _, _ = _RULE_META[key]
            assert provider == "google_cloud", (
                f"{key!r} has wrong provider: {provider!r}"
            )

    def test_pack_and_registry_in_sync(self):
        from app.services.security_rule_pack import _RULE_META
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        assert set(_RULE_META) == set(KNOWN_RULE_KEYS), (
            "security_rule_pack._RULE_META and KNOWN_RULE_KEYS are out of sync"
        )

    def test_all_new_keys_in_rule_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        for key in self.NEW_RULE_KEYS:
            assert key in RULE_RECORD_TYPES, f"{key!r} not in RULE_RECORD_TYPES"

    def test_rule_record_types_reference_correct_record_types(self):
        from app.services.security_coverage_service import RULE_RECORD_TYPES
        expected = {
            "google_cloud_sql_public_network_access": "google_cloud_sql_instance",
            "google_cloud_sql_weak_tls": "google_cloud_sql_instance",
            "google_cloud_sql_backups_disabled": "google_cloud_sql_instance",
            "google_cloud_sql_deletion_protection_disabled": "google_cloud_sql_instance",
            "google_cloud_run_public_invoker": "google_cloud_run_service",
            "google_cloud_run_all_ingress": "google_cloud_run_service",
            "google_cloud_gke_public_control_plane": "google_cloud_gke_cluster",
            "google_cloud_gke_legacy_abac_enabled": "google_cloud_gke_cluster",
            "google_cloud_gke_network_policy_disabled": "google_cloud_gke_cluster",
            "google_cloud_gke_workload_identity_disabled": "google_cloud_gke_cluster",
            "google_cloud_service_account_user_managed_keys": (
                "google_cloud_service_account_key_summary"
            ),
            "google_cloud_service_account_old_keys": (
                "google_cloud_service_account_key_summary"
            ),
            "google_cloud_secret_manager_auto_replication_without_cmek": (
                "google_cloud_secret_manager_summary"
            ),
        }
        for rule_key, expected_rt in expected.items():
            rts = RULE_RECORD_TYPES.get(rule_key, ())
            assert expected_rt in rts, (
                f"{rule_key!r} should map to {expected_rt!r}, got {rts!r}"
            )


# ── Schema record type tests ──────────────────────────────────────────────────


class TestSchemaRecordTypes:
    """Verify all M78C record types are in GOOGLE_CLOUD_RECORD_TYPES."""

    def test_m78c_record_types_in_schema(self):
        from app.connectors.google_cloud_schema import GOOGLE_CLOUD_RECORD_TYPES
        m78c_types = [
            "google_cloud_sql_instance",
            "google_cloud_run_service",
            "google_cloud_gke_cluster",
            "google_cloud_service_account_key_summary",
            "google_cloud_secret_manager_summary",
        ]
        for rt in m78c_types:
            assert rt in GOOGLE_CLOUD_RECORD_TYPES, (
                f"{rt!r} not in GOOGLE_CLOUD_RECORD_TYPES"
            )

    def test_m78a_record_types_still_present(self):
        from app.connectors.google_cloud_schema import GOOGLE_CLOUD_RECORD_TYPES
        m78a_types = [
            "google_cloud_project",
            "google_cloud_iam_policy_summary",
            "google_cloud_vpc_network",
            "google_cloud_firewall_rule",
            "google_cloud_storage_bucket",
        ]
        for rt in m78a_types:
            assert rt in GOOGLE_CLOUD_RECORD_TYPES, (
                f"{rt!r} not in GOOGLE_CLOUD_RECORD_TYPES after M78C"
            )


# ── Capability matrix tests ───────────────────────────────────────────────────


class TestCapabilityMatrix:
    """Verify the provider capability matrix is correct after M78C."""

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

    def test_google_cloud_activity_ingestion_true(self):
        """M78D complete — activity_ingestion is now True."""
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap is not None
        assert cap.security.activity_ingestion is True

    def test_google_cloud_activity_signals_true(self):
        """M78E complete — activity_signals is now True."""
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap.security.activity_signals is True

    def test_google_cloud_risk_correlations_false(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap.security.risk_activity_correlations is True  # M78F complete

    def test_google_cloud_demo_seed_clear_now_true(self):
        """Flipped in M78G."""
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap.security.demo_seed_clear is True

    def test_google_cloud_security_rules_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap.security.security_rules is True

    def test_google_cloud_drift_snapshots_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap.drift.drift_snapshots is True


# ── Provider expansion framework tests ───────────────────────────────────────


class TestProviderExpansionFramework:
    """Verify the expansion framework next stage is beyond M78E (M78C is done)."""

    def test_planned_next_stage_is_beyond_m78g(self):
        """Planned next stage has advanced to M89A: Kubernetes Drift Provider Foundation."""
        from app.services.provider_expansion_framework import get_framework
        framework = get_framework()
        planned = framework["summary"]["planned_next_stage"]
        assert "M89A" in planned, (
            f"planned_next_stage should be in M89A arc (Kubernetes), got: {planned!r}"
        )
        for done in ("M78C", "M78D", "M78E", "M78F", "M78G", "M78H", "M78I"):
            assert done not in planned, f"{done} is done; pointer has advanced past it"

    def test_google_cloud_next_stage_is_m78h(self):
        """Planned next stage has advanced to M89A: Kubernetes Drift Provider Foundation."""
        from app.services.provider_expansion_framework import get_framework
        framework = get_framework()
        planned = framework["summary"]["planned_next_stage"]
        assert "M89A" in planned, (
            f"planned_next_stage should be M89A (Kubernetes arc open), got: {planned!r}"
        )
        assert "Kubernetes" in planned


# ── Coverage service provider surfaces ───────────────────────────────────────


class TestCoverageServiceSurfaces:
    """Verify PROVIDER_SURFACES includes M78C surfaces."""

    def test_google_cloud_surfaces_include_m78c(self):
        from app.services.security_coverage_service import PROVIDER_SURFACES
        surfaces = PROVIDER_SURFACES.get("google_cloud", [])
        assert "Cloud SQL instances" in surfaces
        assert "Cloud Run services" in surfaces
        assert "GKE clusters" in surfaces
        assert "Service account keys" in surfaces
        assert "Secret Manager" in surfaces


# ── Pack list_pack_rules integration ─────────────────────────────────────────


class TestPackRulesIntegration:
    """Verify list_pack_rules returns all M78C rules."""

    def test_pack_includes_all_new_rules(self):
        from app.services.security_rule_pack import list_pack_rules
        rules = list_pack_rules()
        rule_keys = {r["rule_key"] for r in rules}
        new_keys = [
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
        ]
        for key in new_keys:
            assert key in rule_keys, f"{key!r} not in pack rules"

    def test_pack_rules_all_have_active_status(self):
        from app.services.security_rule_pack import list_pack_rules
        rules = list_pack_rules()
        for rule in rules:
            assert rule["status"] == "active"


# ── Malformed record handling ─────────────────────────────────────────────────


class TestMalformedRecords:
    """Verify malformed records are handled gracefully."""

    def _evaluate(self, record):
        from app.services.security_rules.google_cloud import evaluate
        return evaluate(record)

    def test_malformed_sql_record(self):
        assert self._evaluate({"record_type": "google_cloud_sql_instance"}) == []

    def test_malformed_run_record(self):
        assert self._evaluate({"record_type": "google_cloud_run_service"}) == []

    def test_malformed_gke_record(self):
        assert self._evaluate({"record_type": "google_cloud_gke_cluster"}) == []

    def test_malformed_sa_key_record(self):
        assert self._evaluate(
            {"record_type": "google_cloud_service_account_key_summary"}
        ) == []

    def test_malformed_secret_manager_record(self):
        assert self._evaluate(
            {"record_type": "google_cloud_secret_manager_summary"}
        ) == []

    def test_non_dict_input(self):
        assert self._evaluate(None) == []
        assert self._evaluate("not a dict") == []

    def test_unknown_record_type(self):
        assert self._evaluate({"record_type": "unknown_type"}) == []


# ── Forbidden wording across all new rules ────────────────────────────────────


class TestForbiddenWording:
    """Verify no M78C rule emits forbidden claim phrases."""

    def _evaluate(self, record):
        from app.services.security_rules.google_cloud import evaluate
        return evaluate(record)

    def _all_risky_records(self):
        return [
            {
                "record_type": "google_cloud_sql_instance",
                "record_id": "r1",
                "instance_name": "inst",
                "project_id": "proj",
                "region": "us",
                "database_version": "MYSQL_8",
                "state": "RUNNABLE",
                "public_ip_enabled": True,
                "authorized_network_count": 1,
                "require_ssl": False,
                "ssl_mode": "",
                "backup_enabled": False,
                "deletion_protection_enabled": False,
            },
            {
                "record_type": "google_cloud_run_service",
                "record_id": "r2",
                "service_name": "svc",
                "project_id": "proj",
                "region": "us",
                "ingress": "INGRESS_TRAFFIC_ALL",
                "launch_stage": "GA",
                "public_invoker_allowed": True,
                "invoker_policy_summary": {},
                "environment_variable_count": 0,
                "secret_environment_variable_count": 0,
            },
            {
                "record_type": "google_cloud_gke_cluster",
                "record_id": "r3",
                "cluster_name": "cluster",
                "project_id": "proj",
                "location": "us",
                "private_cluster_enabled": False,
                "master_authorized_networks_count": 0,
                "network_policy_enabled": False,
                "workload_identity_enabled": False,
                "shielded_nodes_enabled": False,
                "legacy_abac_enabled": True,
                "public_endpoint_enabled": True,
                "release_channel": "",
            },
            {
                "record_type": "google_cloud_service_account_key_summary",
                "record_id": "r4",
                "project_id": "proj",
                "service_account_count": 5,
                "disabled_service_account_count": 0,
                "user_managed_key_count": 10,
                "old_user_managed_key_count": 5,
                "oldest_key_age_days": 200,
            },
            {
                "record_type": "google_cloud_secret_manager_summary",
                "record_id": "r5",
                "project_id": "proj",
                "secret_count": 10,
                "automatic_replication_count": 10,
                "user_managed_replication_count": 0,
                "customer_managed_encryption_count": 0,
            },
        ]

    def test_no_forbidden_wording_in_any_finding(self):
        for record in self._all_risky_records():
            findings = self._evaluate(record)
            for f in findings:
                _assert_copy_clean(f.title)
                _assert_copy_clean(f.description)

    def test_evidence_does_not_contain_forbidden_fields(self):
        for record in self._all_risky_records():
            findings = self._evaluate(record)
            for f in findings:
                _assert_evidence_clean(f.evidence)
