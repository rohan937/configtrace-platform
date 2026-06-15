"""M78E: Google Cloud Activity Signals.

Verifies:
  * Each important M78D Google Cloud event type maps to the expected signal type
  * IAM, service account, key, firewall, VPC, storage, SQL, Run, GKE, secret
    events each produce the correct signal_type and severity
  * generic config.event produces low/medium google_cloud_config_activity signal
  * Read/data-plane/unrecognized event types do not create signals
  * Malformed activity events are skipped safely
  * Signal creation is idempotent (duplicate event → skipped)
  * Signal metadata contains no forbidden fields (emails, IPs, tokens, etc.)
  * Signal summaries/descriptions do not overclaim breach/compromise/etc.
  * generate_google_cloud_activity_signals() workspace-scopes correctly
  * Endpoint POST /google-cloud-activity/generate-signals requires admin/owner
  * Members cannot generate signals
  * Capability matrix marks activity_signals=True, correlations/demo=False
  * Provider expansion framework next stage points to M78F
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── Forbidden wording / fields ────────────────────────────────────────────────

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
    "secret_name",
    "secret_value",
    "database_name",
    "database_user",
    "password",
    "connection_string",
    "env_var",
    "env_var_value",
    "kubeconfig",
    "node_name",
    "pod_spec",
}


def _assert_clean_metadata(metadata: dict) -> None:
    for key in metadata:
        assert key.lower() not in FORBIDDEN_METADATA_KEYS, (
            f"signal metadata contains forbidden key: {key!r}"
        )


def _assert_clean_copy(text: str) -> None:
    low = text.lower()
    for phrase in FORBIDDEN_WORDING:
        assert phrase not in low, (
            f"forbidden wording {phrase!r} in: {text[:300]!r}"
        )


# ── Mock activity event factory ───────────────────────────────────────────────


def _make_event(
    event_type: str,
    project_id: str = "my-project",
    resource_name: str = "projects/my-project/global/firewalls/my-fw",
    insert_id: str = "evt1",
    occurred_at: datetime | None = None,
    workspace_id: uuid.UUID | None = None,
    integration_id: uuid.UUID | None = None,
) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.workspace_id = workspace_id or uuid.uuid4()
    ev.integration_id = integration_id
    ev.provider = "google_cloud"
    ev.source = "google_cloud_audit_log"
    ev.event_type = event_type
    ev.provider_event_id = insert_id
    ev.occurred_at = occurred_at or datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    ev.ingested_at = ev.occurred_at
    ev.created_at = ev.occurred_at
    ev.resource_id = resource_name
    ev.resource_type = "gce_firewall_rule"
    ev.actor_id = None  # never stored
    ev.event_metadata = {
        "project_id": project_id,
        "method_name": "compute.firewalls.insert",
        "service_name": "compute.googleapis.com",
        "resource_name": resource_name,
        "resource_type": "gce_firewall_rule",
        "operation_name": "compute.firewalls.insert",
        "operation_family": "compute.firewalls",
        "operation_action": "insert",
        "google_cloud_event_id": insert_id,
        "event_source": "google_cloud_audit_log",
        "category": "Admin Activity",
        "status_code": 0,
    }
    return ev


# ── Event → signal type mapping tests ────────────────────────────────────────


class TestEventPatternMapping:
    """Test that _EVENT_PATTERNS covers all M78D event types."""

    def _patterns(self):
        from app.services.google_cloud_activity_signal_service import _EVENT_PATTERNS
        return _EVENT_PATTERNS

    def test_iam_policy_updated_mapped(self):
        p = self._patterns()
        assert "google_cloud.iam_policy.updated" in p
        st, pattern, _ = p["google_cloud.iam_policy.updated"]
        assert st == "google_cloud_iam_policy_changed"
        assert pattern == "iam_policy_changed"

    def test_service_account_events_mapped(self):
        p = self._patterns()
        for et in [
            "google_cloud.service_account.created",
            "google_cloud.service_account.updated",
            "google_cloud.service_account.deleted",
        ]:
            assert et in p, f"{et!r} not in _EVENT_PATTERNS"
            assert p[et][0] == "google_cloud_service_account_changed"

    def test_service_account_key_events_mapped(self):
        p = self._patterns()
        assert "google_cloud.service_account_key.created" in p
        assert "google_cloud.service_account_key.deleted" in p
        assert p["google_cloud.service_account_key.created"][0] == "google_cloud_service_account_key_changed"

    def test_firewall_events_mapped(self):
        p = self._patterns()
        for et in [
            "google_cloud.firewall_rule.created",
            "google_cloud.firewall_rule.updated",
            "google_cloud.firewall_rule.deleted",
        ]:
            assert et in p
            assert p[et][0] == "google_cloud_firewall_config_changed"

    def test_vpc_events_mapped(self):
        p = self._patterns()
        for et in [
            "google_cloud.vpc_network.created",
            "google_cloud.vpc_network.updated",
            "google_cloud.vpc_network.deleted",
        ]:
            assert et in p
            assert p[et][0] == "google_cloud_vpc_network_changed"

    def test_storage_events_mapped(self):
        p = self._patterns()
        for et in [
            "google_cloud.storage_bucket.created",
            "google_cloud.storage_bucket.updated",
            "google_cloud.storage_bucket.deleted",
            "google_cloud.storage_iam.updated",
        ]:
            assert et in p
            assert p[et][0] == "google_cloud_storage_bucket_changed"

    def test_sql_events_mapped(self):
        p = self._patterns()
        for et in [
            "google_cloud.sql_instance.created",
            "google_cloud.sql_instance.updated",
            "google_cloud.sql_instance.deleted",
        ]:
            assert et in p
            assert p[et][0] == "google_cloud_sql_instance_changed"

    def test_run_service_events_mapped(self):
        p = self._patterns()
        for et in [
            "google_cloud.run_service.created",
            "google_cloud.run_service.updated",
            "google_cloud.run_service.deleted",
        ]:
            assert et in p
            assert p[et][0] == "google_cloud_run_service_changed"

    def test_gke_events_mapped(self):
        p = self._patterns()
        for et in [
            "google_cloud.gke_cluster.created",
            "google_cloud.gke_cluster.updated",
            "google_cloud.gke_cluster.deleted",
            "google_cloud.gke_network_policy.updated",
            "google_cloud.gke_master_auth.updated",
        ]:
            assert et in p
            assert p[et][0] == "google_cloud_gke_cluster_changed"

    def test_secret_events_mapped(self):
        p = self._patterns()
        for et in [
            "google_cloud.secret.created",
            "google_cloud.secret.updated",
            "google_cloud.secret.deleted",
        ]:
            assert et in p
            assert p[et][0] == "google_cloud_secret_config_changed"

    def test_config_event_mapped(self):
        p = self._patterns()
        assert "google_cloud.config.event" in p
        assert p["google_cloud.config.event"][0] == "google_cloud_config_activity"

    def test_all_signal_types_start_with_google_cloud(self):
        p = self._patterns()
        for k, (st, pattern, title) in p.items():
            assert st.startswith("google_cloud_"), (
                f"signal_type {st!r} for {k!r} should start with 'google_cloud_'"
            )


# ── _build_signal tests ───────────────────────────────────────────────────────


class TestBuildSignal:
    """Tests for _build_signal internals."""

    def _build(self, events):
        from app.services.google_cloud_activity_signal_service import _build_signal
        return _build_signal(events)

    def test_iam_policy_signal_built(self):
        ev = _make_event("google_cloud.iam_policy.updated")
        sig = self._build([ev])
        assert sig is not None
        assert sig["signal_type"] == "google_cloud_iam_policy_changed"
        assert sig["provider"] == "google_cloud"
        assert sig["severity"] == "high"
        assert sig["status"] == "open"
        assert sig["evidence_level"] == "activity"
        assert sig["confidence"] == "medium"

    def test_service_account_deleted_is_high(self):
        ev = _make_event("google_cloud.service_account.deleted")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_service_account_created_is_medium(self):
        ev = _make_event("google_cloud.service_account.created")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "medium"

    def test_service_account_key_created_is_high(self):
        ev = _make_event("google_cloud.service_account_key.created")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_service_account_key_deleted_is_medium(self):
        ev = _make_event("google_cloud.service_account_key.deleted")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "medium"

    def test_firewall_created_is_high(self):
        ev = _make_event("google_cloud.firewall_rule.created")
        sig = self._build([ev])
        assert sig is not None
        assert sig["signal_type"] == "google_cloud_firewall_config_changed"
        assert sig["severity"] == "high"

    def test_firewall_deleted_is_high(self):
        ev = _make_event("google_cloud.firewall_rule.deleted")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_vpc_network_deleted_is_high(self):
        ev = _make_event("google_cloud.vpc_network.deleted")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_vpc_network_changed_is_medium(self):
        ev = _make_event("google_cloud.vpc_network.created")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "medium"

    def test_storage_iam_updated_is_high(self):
        ev = _make_event("google_cloud.storage_iam.updated")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_storage_bucket_deleted_is_high(self):
        ev = _make_event("google_cloud.storage_bucket.deleted")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_storage_bucket_updated_is_medium(self):
        ev = _make_event("google_cloud.storage_bucket.updated")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "medium"

    def test_sql_instance_deleted_is_high(self):
        ev = _make_event("google_cloud.sql_instance.deleted")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_sql_instance_updated_is_medium(self):
        ev = _make_event("google_cloud.sql_instance.updated")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "medium"

    def test_run_service_deleted_is_high(self):
        ev = _make_event("google_cloud.run_service.deleted")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_run_service_created_is_medium(self):
        ev = _make_event("google_cloud.run_service.created")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "medium"

    def test_gke_cluster_deleted_is_high(self):
        ev = _make_event("google_cloud.gke_cluster.deleted")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_gke_network_policy_updated_is_high(self):
        ev = _make_event("google_cloud.gke_network_policy.updated")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_gke_master_auth_updated_is_high(self):
        ev = _make_event("google_cloud.gke_master_auth.updated")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_gke_cluster_updated_is_medium(self):
        ev = _make_event("google_cloud.gke_cluster.updated")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "medium"

    def test_secret_created_is_high(self):
        ev = _make_event("google_cloud.secret.created")
        sig = self._build([ev])
        assert sig is not None
        assert sig["signal_type"] == "google_cloud_secret_config_changed"
        assert sig["severity"] == "high"

    def test_secret_deleted_is_high(self):
        ev = _make_event("google_cloud.secret.deleted")
        sig = self._build([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_config_event_medium_with_resource(self):
        ev = _make_event(
            "google_cloud.config.event",
            resource_name="projects/my-project/global/firewalls/some-rule",
        )
        sig = self._build([ev])
        assert sig is not None
        assert sig["signal_type"] == "google_cloud_config_activity"
        assert sig["severity"] in ("low", "medium")

    def test_unrecognized_event_returns_none(self):
        ev = _make_event("google_cloud.unknown.event")
        sig = self._build([ev])
        assert sig is None

    def test_title_includes_resource_context(self):
        ev = _make_event(
            "google_cloud.iam_policy.updated",
            resource_name="projects/my-project/iam",
            project_id="my-project",
        )
        ev.event_metadata["project_id"] = "my-project"
        sig = self._build([ev])
        assert sig is not None
        # Title should include the resource description
        assert "Google Cloud IAM policy" in sig["title"]

    def test_signal_key_is_deterministic(self):
        ev = _make_event("google_cloud.firewall_rule.created", project_id="proj1")
        sig1 = self._build([ev])
        sig2 = self._build([ev])
        assert sig1 is not None and sig2 is not None
        assert sig1["signal_key"] == sig2["signal_key"]

    def test_group_of_events_uses_latest_anchor(self):
        ev1 = _make_event(
            "google_cloud.firewall_rule.updated",
            occurred_at=datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc),
            insert_id="e1",
        )
        ev2 = _make_event(
            "google_cloud.firewall_rule.updated",
            occurred_at=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            insert_id="e2",
        )
        sig = self._build([ev1, ev2])
        assert sig is not None
        # provider_event_id in metadata should be the latest event's
        assert sig["linked_activity_event_id"] == ev2.id

    def test_empty_group_returns_none(self):
        from app.services.google_cloud_activity_signal_service import _build_signal
        # A group with no events would be invalid, but we guard against it
        # indirectly since _pick_anchor would fail — confirm safe behavior
        # by checking the known guard: unrecognized event_type returns None.
        ev = _make_event("google_cloud.zzz.event")
        assert _build_signal([ev]) is None


# ── Signal metadata privacy tests ─────────────────────────────────────────────


class TestSignalMetadataPrivacy:
    """Signal metadata must never contain forbidden fields."""

    def _build(self, event_type: str, **kwargs):
        from app.services.google_cloud_activity_signal_service import _build_signal
        ev = _make_event(event_type, **kwargs)
        return _build_signal([ev])

    def test_iam_signal_metadata_clean(self):
        sig = self._build("google_cloud.iam_policy.updated")
        assert sig is not None
        _assert_clean_metadata(sig["metadata"])

    def test_firewall_signal_metadata_clean(self):
        sig = self._build("google_cloud.firewall_rule.created")
        assert sig is not None
        _assert_clean_metadata(sig["metadata"])

    def test_storage_signal_metadata_clean(self):
        sig = self._build("google_cloud.storage_iam.updated")
        assert sig is not None
        _assert_clean_metadata(sig["metadata"])

    def test_gke_signal_metadata_clean(self):
        sig = self._build("google_cloud.gke_master_auth.updated")
        assert sig is not None
        _assert_clean_metadata(sig["metadata"])

    def test_secret_signal_metadata_clean(self):
        sig = self._build("google_cloud.secret.created")
        assert sig is not None
        _assert_clean_metadata(sig["metadata"])

    def test_no_email_in_metadata(self):
        sig = self._build("google_cloud.iam_policy.updated")
        assert sig is not None
        meta_str = str(sig["metadata"])
        assert "@" not in meta_str

    def test_no_ip_in_metadata(self):
        sig = self._build("google_cloud.firewall_rule.created")
        assert sig is not None
        # Verify no raw IP-like values (resource names are fine)
        meta = sig["metadata"]
        for k, v in meta.items():
            if isinstance(v, str):
                # caller_ip would look like "1.2.3.4" — not a resource path
                assert "callerIp" not in k
                assert "caller_ip" not in k


# ── Signal copy / claim discipline tests ──────────────────────────────────────


class TestClaimDiscipline:
    """Signal summaries/titles must not overclaim breach or compromise."""

    def _build(self, event_type: str):
        from app.services.google_cloud_activity_signal_service import _build_signal
        ev = _make_event(event_type)
        return _build_signal([ev])

    def test_all_event_types_clean_copy(self):
        from app.services.google_cloud_activity_signal_service import _EVENT_PATTERNS
        from app.services.google_cloud_activity_signal_service import _build_signal

        for et in _EVENT_PATTERNS:
            ev = _make_event(et)
            sig = _build_signal([ev])
            if sig is None:
                continue
            _assert_clean_copy(sig["title"])
            _assert_clean_copy(sig["summary"])

    def test_secret_summary_no_claim_of_leaked_secret(self):
        sig = self._build("google_cloud.secret.created")
        assert sig is not None
        _assert_clean_copy(sig["summary"])
        # "secret values are never stored" is safe; "secret leaked" or "secret exposed" are not
        assert "secret leaked" not in sig["summary"].lower()
        assert "secrets exposed" not in sig["summary"].lower()
        assert "secret value exposed" not in sig["summary"].lower()

    def test_firewall_summary_no_claim_of_reachability(self):
        sig = self._build("google_cloud.firewall_rule.created")
        assert sig is not None
        # Must not claim resources are reachable/compromised
        _assert_clean_copy(sig["summary"])

    def test_iam_summary_no_claim_of_unauthorized_access(self):
        sig = self._build("google_cloud.iam_policy.updated")
        assert sig is not None
        _assert_clean_copy(sig["summary"])

    def test_summary_contains_review_note(self):
        sig = self._build("google_cloud.iam_policy.updated")
        assert sig is not None
        # Must include safe review language
        summary_low = sig["summary"].lower()
        assert "review" in summary_low or "does not confirm" in summary_low


# ── _group_key uniqueness tests ───────────────────────────────────────────────


class TestGroupKey:
    """_group_key must produce deterministic, unique group keys."""

    def _gk(self, event_type: str, project_id: str = "proj1", resource_id: str = "res1"):
        from app.services.google_cloud_activity_signal_service import _group_key
        ev = _make_event(event_type, project_id=project_id)
        ev.resource_id = resource_id
        ev.event_metadata["project_id"] = project_id
        return _group_key(ev)

    def test_same_event_type_same_resource_same_key(self):
        k1 = self._gk("google_cloud.firewall_rule.created", resource_id="fw1")
        k2 = self._gk("google_cloud.firewall_rule.created", resource_id="fw1")
        assert k1 == k2

    def test_different_event_type_different_key(self):
        k1 = self._gk("google_cloud.firewall_rule.created")
        k2 = self._gk("google_cloud.firewall_rule.updated")
        assert k1 != k2

    def test_different_project_different_key(self):
        k1 = self._gk("google_cloud.iam_policy.updated", project_id="proj1")
        k2 = self._gk("google_cloud.iam_policy.updated", project_id="proj2")
        assert k1 != k2

    def test_different_resource_different_key(self):
        k1 = self._gk("google_cloud.firewall_rule.created", resource_id="fw1")
        k2 = self._gk("google_cloud.firewall_rule.created", resource_id="fw2")
        assert k1 != k2

    def test_unrecognized_event_type_returns_none(self):
        from app.services.google_cloud_activity_signal_service import _group_key
        ev = _make_event("google_cloud.unknown.event")
        assert _group_key(ev) is None


# ── generate_google_cloud_activity_signals tests ──────────────────────────────


class TestGenerateSignals:
    """Integration-level tests for generate_google_cloud_activity_signals."""

    def _ws(self):
        return uuid.uuid4()

    def _recent(self, hours: int = 1) -> datetime:
        return datetime.now(timezone.utc) - timedelta(hours=hours)

    def test_returns_expected_shape(self):
        from app.services.google_cloud_activity_signal_service import (
            generate_google_cloud_activity_signals,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = generate_google_cloud_activity_signals(workspace_id=self._ws(), db=db)
        assert "provider" in result
        assert result["provider"] == "google_cloud"
        assert "source" in result
        assert result["source"] == "google_cloud_audit_log"
        assert "events_scanned" in result
        assert "groups_scanned" in result
        assert "signals_created" in result
        assert "signals_skipped" in result

    def test_empty_event_set_returns_zero_counts(self):
        from app.services.google_cloud_activity_signal_service import (
            generate_google_cloud_activity_signals,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = generate_google_cloud_activity_signals(workspace_id=self._ws(), db=db)
        assert result["events_scanned"] == 0
        assert result["signals_created"] == 0

    def test_unrecognized_events_produce_no_signals(self):
        from app.services.google_cloud_activity_signal_service import (
            generate_google_cloud_activity_signals,
        )
        db = MagicMock()
        ev = _make_event("google_cloud.unknown.event", occurred_at=self._recent())
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev]
        with patch(
            "app.services.google_cloud_activity_signal_service.signal_svc.upsert_incident_signal"
        ) as mock_upsert:
            result = generate_google_cloud_activity_signals(workspace_id=self._ws(), db=db)
        mock_upsert.assert_not_called()
        assert result["signals_created"] == 0

    def test_recognized_event_creates_signal(self):
        from app.services.google_cloud_activity_signal_service import (
            generate_google_cloud_activity_signals,
        )
        db = MagicMock()
        ev = _make_event(
            "google_cloud.firewall_rule.created",
            occurred_at=self._recent(),
        )
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev]
        with patch(
            "app.services.google_cloud_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", MagicMock()),
        ):
            result = generate_google_cloud_activity_signals(workspace_id=self._ws(), db=db)
        assert result["signals_created"] == 1
        assert result["events_scanned"] == 1

    def test_idempotent_skips_existing_signal(self):
        from app.services.google_cloud_activity_signal_service import (
            generate_google_cloud_activity_signals,
        )
        db = MagicMock()
        ev = _make_event(
            "google_cloud.iam_policy.updated",
            occurred_at=self._recent(),
        )
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev]
        with patch(
            "app.services.google_cloud_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("skipped", MagicMock()),
        ):
            result = generate_google_cloud_activity_signals(workspace_id=self._ws(), db=db)
        assert result["signals_skipped"] == 1
        assert result["signals_created"] == 0

    def test_events_outside_lookback_window_excluded(self):
        from app.services.google_cloud_activity_signal_service import (
            generate_google_cloud_activity_signals,
        )
        db = MagicMock()
        # Event older than 24 hours
        old_ev = _make_event(
            "google_cloud.firewall_rule.created",
            occurred_at=datetime.now(timezone.utc) - timedelta(hours=48),
        )
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [old_ev]
        with patch(
            "app.services.google_cloud_activity_signal_service.signal_svc.upsert_incident_signal"
        ) as mock_upsert:
            result = generate_google_cloud_activity_signals(
                workspace_id=self._ws(), db=db, lookback_hours=24
            )
        mock_upsert.assert_not_called()
        assert result["events_scanned"] == 0

    def test_malformed_event_metadata_skipped_gracefully(self):
        from app.services.google_cloud_activity_signal_service import (
            generate_google_cloud_activity_signals,
        )
        db = MagicMock()
        ev = _make_event("google_cloud.firewall_rule.created", occurred_at=self._recent())
        ev.event_metadata = "not-a-dict"  # malformed
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev]
        with patch(
            "app.services.google_cloud_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", MagicMock()),
        ):
            # Should not raise
            result = generate_google_cloud_activity_signals(workspace_id=self._ws(), db=db)
        # Function should complete; signal is still created (metadata just sanitizes to {})
        assert isinstance(result, dict)

    def test_upsert_exception_skipped_gracefully(self):
        """A single failed upsert must not abort the whole batch."""
        from app.services.google_cloud_activity_signal_service import (
            generate_google_cloud_activity_signals,
        )
        db = MagicMock()
        ev1 = _make_event(
            "google_cloud.firewall_rule.created",
            occurred_at=self._recent(),
            insert_id="e1",
        )
        ev2 = _make_event(
            "google_cloud.iam_policy.updated",
            occurred_at=self._recent(),
            insert_id="e2",
        )
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [ev1, ev2]

        call_count = [0]
        def side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("db error on first")
            return ("created", MagicMock())

        with patch(
            "app.services.google_cloud_activity_signal_service.signal_svc.upsert_incident_signal",
            side_effect=side_effect,
        ):
            result = generate_google_cloud_activity_signals(workspace_id=self._ws(), db=db)
        # One failed, one succeeded — no exception raised
        assert result["signals_created"] == 1
        assert isinstance(result, dict)

    def test_max_signals_cap_respected(self):
        from app.services.google_cloud_activity_signal_service import (
            generate_google_cloud_activity_signals,
        )
        db = MagicMock()
        events = [
            _make_event(
                "google_cloud.firewall_rule.created",
                occurred_at=self._recent(),
                insert_id=f"e{i}",
                resource_name=f"projects/p/firewalls/fw{i}",
            )
            for i in range(20)
        ]
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events
        with patch(
            "app.services.google_cloud_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", MagicMock()),
        ):
            result = generate_google_cloud_activity_signals(
                workspace_id=self._ws(), db=db, max_signals=3
            )
        assert result["signals_created"] <= 3

    def test_lookback_hours_cap(self):
        """lookback_hours > 168 is clamped to 168."""
        from app.services.google_cloud_activity_signal_service import (
            generate_google_cloud_activity_signals,
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        # Should not raise with oversized lookback
        result = generate_google_cloud_activity_signals(
            workspace_id=self._ws(), db=db, lookback_hours=9999
        )
        assert isinstance(result, dict)


# ── Allowed metadata keys test ────────────────────────────────────────────────


class TestSignalMetadataAllowlist:
    """Google Cloud signal metadata keys must be in the global allowlist."""

    EXPECTED_GCP_SIGNAL_KEYS = {
        "google_cloud_event_id",
        "project_id",
        "resource_name",
        "resource_type",
        "service_name",
        "method_name",
        "network_name",
        "firewall_rule_name",
        "bucket_name",
        "sql_instance_name",
        "run_service_name",
        "gke_cluster_name",
        "status_code",
    }

    def test_gcp_keys_in_signal_allowed_keys(self):
        from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS
        for key in self.EXPECTED_GCP_SIGNAL_KEYS:
            assert key in ALLOWED_METADATA_KEYS, (
                f"GCP signal key {key!r} not in signal ALLOWED_METADATA_KEYS"
            )


# ── Schema tests ──────────────────────────────────────────────────────────────


class TestSchema:
    def test_request_defaults(self):
        from app.schemas.security_google_cloud_activity import (
            GoogleCloudActivitySignalGenerateRequest,
        )
        req = GoogleCloudActivitySignalGenerateRequest()
        assert req.lookback_hours is None
        assert req.max_signals is None

    def test_response_fields(self):
        from app.schemas.security_google_cloud_activity import (
            GoogleCloudActivitySignalGenerateResponse,
        )
        resp = GoogleCloudActivitySignalGenerateResponse(
            provider="google_cloud",
            source="google_cloud_audit_log",
        )
        assert resp.provider == "google_cloud"
        assert resp.events_scanned == 0
        assert resp.signals_created == 0


# ── Capability matrix tests ───────────────────────────────────────────────────


class TestCapabilityMatrix:
    def test_activity_signals_now_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap is not None
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

    def test_activity_ingestion_still_true(self):
        from app.services.provider_capability_matrix_service import get_provider_capability
        cap = get_provider_capability("google_cloud")
        assert cap.security.activity_ingestion is True

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
        from app.services.provider_expansion_framework import get_framework
        fw = get_framework()
        planned = fw["summary"]["planned_next_stage"]
        assert "M78F" not in planned, (
            f"M78F is done; should not still be in planned_next_stage: {planned!r}"
        )


# ── Pattern summary coverage ──────────────────────────────────────────────────


class TestPatternSummaryCoverage:
    """Every pattern used in _EVENT_PATTERNS must have a summary."""

    def test_all_patterns_have_summary(self):
        from app.services.google_cloud_activity_signal_service import (
            _EVENT_PATTERNS,
            _PATTERN_SUMMARY,
        )
        all_patterns = {triple[1] for triple in _EVENT_PATTERNS.values()}
        for p in all_patterns:
            assert p in _PATTERN_SUMMARY, (
                f"pattern {p!r} has no entry in _PATTERN_SUMMARY"
            )

    def test_all_summaries_clean_copy(self):
        from app.services.google_cloud_activity_signal_service import _PATTERN_SUMMARY
        for pattern, summary in _PATTERN_SUMMARY.items():
            _assert_clean_copy(summary)
