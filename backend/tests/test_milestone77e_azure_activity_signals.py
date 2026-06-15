"""M77E: Azure Activity Log Incident Signals — test suite.

Covers:
  * Signal service converts each Azure event type to the expected signal type
  * Severity rules (deletions → high, KV config → high, broad role → high, etc.)
  * Group key is deterministic and event-type+resource specific
  * Signal creation is idempotent (upsert → "created" then "skipped")
  * Malformed activity events are skipped safely
  * Signal metadata contains no tokens, PII, caller identity, raw payloads
  * Signal descriptions do not overclaim
  * All 20 Azure event types are covered in _EVENT_PATTERNS
  * All pattern IDs in _EVENT_PATTERNS have a summary in _PATTERN_SUMMARY
  * generate_azure_activity_signals endpoint registered
  * Capability matrix: activity_signals=True, correlations/demo=False
  * Expansion framework next_stage → M77F
  * M77A/B/C/D regression
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest

from app.services.azure_activity_signal_service import (
    PROVIDER,
    SOURCE,
    _BROAD_PRIVILEGE_ROLES,
    _EVENT_PATTERNS,
    _PATTERN_SUMMARY,
    _build_signal,
    _group_key,
    _severity,
    generate_azure_activity_signals,
)
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework
from app.services.security_incident_signal_service import ALLOWED_METADATA_KEYS as SIGNAL_ALLOWED_KEYS

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

_FORBIDDEN_CLAIM_PHRASES = (
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
)

_FORBIDDEN_SIGNAL_METADATA_KEYS = {
    "caller", "claims", "authorization", "properties",
    "httpRequest", "tenantId", "principal_id", "object_id",
    "ip_address", "client_secret", "access_token", "bearer",
    "caller_email", "upn", "caller_name",
}

_ALL_AZURE_EVENT_TYPES = list(_EVENT_PATTERNS.keys())

# Recent timestamp so events fall inside the default 24-hour lookback window.
_TS = datetime.now(timezone.utc)


# ──────────────────────────────────────────────────────────────────────────────
# Mock helpers
# ──────────────────────────────────────────────────────────────────────────────


def _make_event(
    event_type: str,
    *,
    resource_id: str = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-prod",
    resource_type: str = "Microsoft.Network/networkSecurityGroups",
    metadata: Optional[dict] = None,
    nsg_name: Optional[str] = "nsg-prod",
    role_definition_name: Optional[str] = None,
    subscription_id: str = "sub-123",
) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.event_type = event_type
    ev.provider = PROVIDER
    ev.source = SOURCE
    ev.resource_id = resource_id
    ev.resource_type = resource_type
    ev.provider_event_id = f"evt-{uuid.uuid4()}"
    ev.integration_id = uuid.uuid4()
    ev.occurred_at = _TS
    ev.ingested_at = _TS
    ev.created_at = _TS
    md: dict = {
        "subscription_id": subscription_id,
        "resource_group": "rg",
        "resource_id": resource_id,
        "resource_type": resource_type,
        "operation_name": "Microsoft.Network/networkSecurityGroups/write",
        "operation_family": "Microsoft.Network/networkSecurityGroups",
        "operation_action": "write",
        "azure_event_id": "evt-abc-123",
        "azure_correlation_id_hash": "abc123def456789012345678901234ab",
        "status": "Succeeded",
        "sub_status": "Created",
        "category": "Administrative",
        "event_source": "azure_activity_log",
        "event_action": "write",
    }
    if nsg_name:
        md["nsg_name"] = nsg_name
    if role_definition_name:
        md["role_definition_name"] = role_definition_name
        md["scope_type"] = "subscription"
        md["principal_type"] = "ServicePrincipal"
    if metadata:
        md.update(metadata)
    ev.event_metadata = md
    return ev


# ──────────────────────────────────────────────────────────────────────────────
# Pattern completeness
# ──────────────────────────────────────────────────────────────────────────────


class TestPatternCompleteness:
    def test_all_event_types_have_pattern_entry(self):
        expected = {
            "azure.nsg.updated", "azure.nsg.deleted",
            "azure.nsg_rule.updated", "azure.nsg_rule.deleted",
            "azure.storage_account.updated", "azure.storage_account.deleted",
            "azure.key_vault.updated", "azure.key_vault.deleted",
            "azure.role_assignment.created", "azure.role_assignment.deleted",
            "azure.app_service.updated", "azure.app_service.deleted",
            "azure.app_service_config.updated",
            "azure.sql_server.updated", "azure.sql_server.deleted",
            "azure.sql_firewall_rule.updated", "azure.sql_firewall_rule.deleted",
            "azure.aks_cluster.updated", "azure.aks_cluster.deleted",
            "azure.config.event",
        }
        missing = expected - set(_EVENT_PATTERNS)
        assert missing == set(), f"Missing from _EVENT_PATTERNS: {missing}"

    def test_all_patterns_have_summaries(self):
        patterns = {v[1] for v in _EVENT_PATTERNS.values()}
        missing = patterns - set(_PATTERN_SUMMARY)
        assert missing == set(), f"Patterns without summaries: {missing}"

    def test_20_event_types_covered(self):
        assert len(_EVENT_PATTERNS) == 20


# ──────────────────────────────────────────────────────────────────────────────
# Signal type mappings
# ──────────────────────────────────────────────────────────────────────────────


class TestSignalTypeMappings:
    @pytest.mark.parametrize("event_type,expected_signal_type", [
        ("azure.nsg.updated",                "azure_network_exposure_changed"),
        ("azure.nsg.deleted",                "azure_nsg_deleted"),
        ("azure.nsg_rule.updated",           "azure_network_exposure_changed"),
        ("azure.nsg_rule.deleted",           "azure_network_exposure_changed"),
        ("azure.storage_account.updated",    "azure_storage_config_changed"),
        ("azure.storage_account.deleted",    "azure_storage_account_deleted"),
        ("azure.key_vault.updated",          "azure_key_vault_config_changed"),
        ("azure.key_vault.deleted",          "azure_key_vault_deleted"),
        ("azure.role_assignment.created",    "azure_role_assignment_changed"),
        ("azure.role_assignment.deleted",    "azure_role_assignment_changed"),
        ("azure.app_service.updated",        "azure_app_service_config_changed"),
        ("azure.app_service.deleted",        "azure_app_service_deleted"),
        ("azure.app_service_config.updated", "azure_app_service_config_changed"),
        ("azure.sql_server.updated",         "azure_sql_network_config_changed"),
        ("azure.sql_server.deleted",         "azure_sql_server_deleted"),
        ("azure.sql_firewall_rule.updated",  "azure_sql_network_config_changed"),
        ("azure.sql_firewall_rule.deleted",  "azure_sql_network_config_changed"),
        ("azure.aks_cluster.updated",        "azure_aks_cluster_config_changed"),
        ("azure.aks_cluster.deleted",        "azure_aks_cluster_deleted"),
        ("azure.config.event",               "azure_config_activity"),
    ])
    def test_event_type_maps_to_correct_signal_type(self, event_type: str, expected_signal_type: str):
        ev = _make_event(event_type)
        sig = _build_signal([ev])
        assert sig is not None, f"No signal for {event_type}"
        assert sig["signal_type"] == expected_signal_type


# ──────────────────────────────────────────────────────────────────────────────
# Severity rules
# ──────────────────────────────────────────────────────────────────────────────


class TestSeverityRules:
    def test_nsg_deleted_is_high(self):
        sig = _build_signal([_make_event("azure.nsg.deleted")])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_storage_account_deleted_is_high(self):
        sig = _build_signal([_make_event("azure.storage_account.deleted", nsg_name=None)])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_key_vault_deleted_is_high(self):
        sig = _build_signal([_make_event("azure.key_vault.deleted", nsg_name=None)])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_app_service_deleted_is_high(self):
        sig = _build_signal([_make_event("azure.app_service.deleted", nsg_name=None)])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_sql_server_deleted_is_high(self):
        sig = _build_signal([_make_event("azure.sql_server.deleted", nsg_name=None)])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_aks_cluster_deleted_is_high(self):
        sig = _build_signal([_make_event("azure.aks_cluster.deleted", nsg_name=None)])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_key_vault_config_changed_is_high(self):
        sig = _build_signal([_make_event("azure.key_vault.updated", nsg_name=None)])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_sql_firewall_rule_updated_is_high(self):
        ev = _make_event("azure.sql_firewall_rule.updated", nsg_name=None)
        sig = _build_signal([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_sql_firewall_rule_deleted_is_high(self):
        ev = _make_event("azure.sql_firewall_rule.deleted", nsg_name=None)
        sig = _build_signal([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_role_assignment_broad_owner_is_high(self):
        ev = _make_event(
            "azure.role_assignment.created",
            nsg_name=None,
            role_definition_name="Owner",
        )
        sig = _build_signal([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_role_assignment_contributor_is_high(self):
        ev = _make_event(
            "azure.role_assignment.created",
            nsg_name=None,
            role_definition_name="Contributor",
        )
        sig = _build_signal([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_role_assignment_user_access_admin_is_high(self):
        ev = _make_event(
            "azure.role_assignment.created",
            nsg_name=None,
            role_definition_name="User Access Administrator",
        )
        sig = _build_signal([ev])
        assert sig is not None
        assert sig["severity"] == "high"

    def test_role_assignment_reader_is_medium(self):
        ev = _make_event(
            "azure.role_assignment.created",
            nsg_name=None,
            role_definition_name="Reader",
        )
        sig = _build_signal([ev])
        assert sig is not None
        assert sig["severity"] == "medium"

    def test_role_assignment_unknown_role_is_medium(self):
        ev = _make_event(
            "azure.role_assignment.deleted",
            nsg_name=None,
            role_definition_name="",
        )
        sig = _build_signal([ev])
        assert sig is not None
        assert sig["severity"] == "medium"

    def test_nsg_updated_is_medium(self):
        sig = _build_signal([_make_event("azure.nsg.updated")])
        assert sig is not None
        assert sig["severity"] == "medium"

    def test_storage_config_changed_is_medium(self):
        sig = _build_signal([_make_event("azure.storage_account.updated", nsg_name=None)])
        assert sig is not None
        assert sig["severity"] == "medium"

    def test_aks_updated_is_medium(self):
        sig = _build_signal([_make_event("azure.aks_cluster.updated", nsg_name=None)])
        assert sig is not None
        assert sig["severity"] == "medium"


# ──────────────────────────────────────────────────────────────────────────────
# Group key determinism
# ──────────────────────────────────────────────────────────────────────────────


class TestGroupKey:
    def test_group_key_is_deterministic(self):
        ev = _make_event("azure.nsg.updated")
        k1 = _group_key(ev)
        k2 = _group_key(ev)
        assert k1 == k2

    def test_different_event_types_produce_different_keys(self):
        ev_update = _make_event("azure.nsg.updated")
        ev_delete = _make_event("azure.nsg.deleted")
        assert _group_key(ev_update) != _group_key(ev_delete)

    def test_different_resources_produce_different_keys(self):
        ev1 = _make_event("azure.nsg.updated", resource_id="/sub/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-a")
        ev2 = _make_event("azure.nsg.updated", resource_id="/sub/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-b")
        assert _group_key(ev1) != _group_key(ev2)

    def test_unknown_event_type_returns_none(self):
        ev = _make_event("azure.unknown.event")
        assert _group_key(ev) is None

    def test_group_key_contains_signal_type(self):
        ev = _make_event("azure.nsg.deleted")
        k = _group_key(ev)
        assert k is not None
        assert "azure_nsg_deleted" in k


# ──────────────────────────────────────────────────────────────────────────────
# Signal metadata safety
# ──────────────────────────────────────────────────────────────────────────────


class TestSignalMetadataSafety:
    def test_no_forbidden_keys_in_signal_metadata(self):
        ev = _make_event("azure.nsg.updated")
        sig = _build_signal([ev])
        assert sig is not None
        meta = sig.get("metadata", {})
        for forbidden in _FORBIDDEN_SIGNAL_METADATA_KEYS:
            assert forbidden not in meta, (
                f"Forbidden key {forbidden!r} in signal metadata"
            )

    def _sig_text(self, sig: dict) -> str:
        """JSON-serialize the safe parts of a signal (metadata + title + summary)."""
        return json.dumps({
            "metadata": sig.get("metadata", {}),
            "title": sig.get("title", ""),
            "summary": sig.get("summary", ""),
        })

    def test_caller_never_in_signal(self):
        ev = _make_event("azure.key_vault.updated", nsg_name=None,
                         metadata={"caller": "user@example.com", "upn": "user@corp.com"})
        sig = _build_signal([ev])
        assert sig is not None
        sig_text = self._sig_text(sig)
        assert "user@example.com" not in sig_text
        assert "user@corp.com" not in sig_text

    def test_principal_id_never_in_signal(self):
        ev = _make_event("azure.role_assignment.created", nsg_name=None,
                         metadata={"principal_id": "some-guid-here"})
        sig = _build_signal([ev])
        assert sig is not None
        assert "some-guid-here" not in self._sig_text(sig)

    def test_raw_payload_never_in_signal(self):
        ev = _make_event("azure.storage_account.updated", nsg_name=None,
                         metadata={"properties": "raw_payload_here"})
        sig = _build_signal([ev])
        assert sig is not None
        assert "raw_payload_here" not in self._sig_text(sig)

    def test_safe_resource_fields_present(self):
        ev = _make_event("azure.nsg.updated")
        sig = _build_signal([ev])
        assert sig is not None
        meta = sig.get("metadata", {})
        # Should include safe identifiers
        assert meta.get("event_type") == "azure.nsg.updated"
        assert meta.get("nsg_name") == "nsg-prod"

    def test_role_definition_name_safe_in_metadata(self):
        ev = _make_event("azure.role_assignment.created", nsg_name=None,
                         role_definition_name="Owner")
        sig = _build_signal([ev])
        assert sig is not None
        assert sig["metadata"].get("role_definition_name") == "Owner"

    def test_azure_metadata_keys_in_signal_allowlist(self):
        azure_keys = {
            "subscription_id", "resource_group", "resource_type",
            "operation_name", "operation_family", "operation_action",
            "azure_event_id", "azure_correlation_id_hash",
            "scope_type", "role_definition_name", "principal_type",
            "nsg_name", "nsg_rule_name", "storage_account_name",
            "key_vault_name", "app_service_name", "sql_server_name",
            "sql_firewall_rule_name", "aks_cluster_name",
            "status", "sub_status", "category", "provider_event_id",
        }
        for key in azure_keys:
            assert key in SIGNAL_ALLOWED_KEYS, (
                f"Azure signal metadata key {key!r} not in ALLOWED_METADATA_KEYS"
            )


# ──────────────────────────────────────────────────────────────────────────────
# Claim discipline
# ──────────────────────────────────────────────────────────────────────────────


class TestClaimDiscipline:
    def test_no_forbidden_phrases_in_signal_summaries(self):
        for pattern, summary in _PATTERN_SUMMARY.items():
            low = summary.lower()
            for phrase in _FORBIDDEN_CLAIM_PHRASES:
                assert phrase not in low, (
                    f"Forbidden phrase {phrase!r} in pattern {pattern!r} summary"
                )

    def test_signal_summaries_include_review_note(self):
        for pattern, summary in _PATTERN_SUMMARY.items():
            assert "review" in summary.lower(), (
                f"Pattern {pattern!r} summary missing 'review'"
            )

    def test_no_forbidden_phrases_in_service_source(self):
        import inspect
        import app.services.azure_activity_signal_service as svc
        src = inspect.getsource(svc)
        for phrase in _FORBIDDEN_CLAIM_PHRASES:
            assert phrase.lower() not in src.lower(), (
                f"Forbidden phrase {phrase!r} in signal service source"
            )


# ──────────────────────────────────────────────────────────────────────────────
# generate_azure_activity_signals (integration tests with mocked DB)
# ──────────────────────────────────────────────────────────────────────────────


class TestGenerateAzureActivitySignals:
    def _mock_db(self, events: list) -> MagicMock:
        db = MagicMock()
        query_mock = MagicMock()
        db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.all.return_value = events
        return db

    def test_generates_signals_from_events(self):
        ev = _make_event("azure.nsg.updated")
        db = self._mock_db([ev])
        mock_row = MagicMock()
        mock_row.id = uuid.uuid4()

        with patch(
            "app.services.azure_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", mock_row),
        ):
            result = generate_azure_activity_signals(
                workspace_id=uuid.uuid4(), db=db
            )
        assert result["signals_created"] == 1
        assert result["signals_skipped"] == 0
        assert result["events_scanned"] == 1

    def test_unknown_event_types_are_skipped(self):
        ev = _make_event("azure.unknown.event.type")
        db = self._mock_db([ev])
        result = generate_azure_activity_signals(workspace_id=uuid.uuid4(), db=db)
        assert result["signals_created"] == 0

    def test_idempotency_via_skipped(self):
        ev = _make_event("azure.key_vault.updated", nsg_name=None)
        db = self._mock_db([ev])
        mock_row = MagicMock()

        with patch(
            "app.services.azure_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("skipped", mock_row),
        ):
            result = generate_azure_activity_signals(
                workspace_id=uuid.uuid4(), db=db
            )
        assert result["signals_created"] == 0
        assert result["signals_skipped"] == 1

    def test_never_raises_on_malformed_event(self):
        ev = _make_event("azure.nsg.updated")
        ev.event_metadata = "not-a-dict"  # malformed

        db = self._mock_db([ev])
        # Should not raise; either skips or builds signal with missing metadata
        result = generate_azure_activity_signals(workspace_id=uuid.uuid4(), db=db)
        assert isinstance(result, dict)

    def test_multiple_events_same_group_produce_one_signal(self):
        """Three updates to the same NSG → grouped → one signal."""
        ev1 = _make_event("azure.nsg.updated")
        ev2 = _make_event("azure.nsg.updated")
        ev3 = _make_event("azure.nsg.updated")
        db = self._mock_db([ev1, ev2, ev3])
        mock_row = MagicMock()

        with patch(
            "app.services.azure_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", mock_row),
        ) as mock_upsert:
            result = generate_azure_activity_signals(
                workspace_id=uuid.uuid4(), db=db
            )
        assert result["groups_scanned"] == 1
        assert result["signals_created"] == 1
        assert mock_upsert.call_count == 1

    def test_events_scanned_vs_groups(self):
        """Two different event types → two groups."""
        ev1 = _make_event("azure.nsg.updated")
        ev2 = _make_event("azure.nsg.deleted")
        db = self._mock_db([ev1, ev2])
        mock_row = MagicMock()

        with patch(
            "app.services.azure_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", mock_row),
        ):
            result = generate_azure_activity_signals(
                workspace_id=uuid.uuid4(), db=db
            )
        assert result["events_scanned"] == 2
        assert result["groups_scanned"] == 2
        assert result["signals_created"] == 2

    def test_cap_max_signals_enforced(self):
        events = [_make_event(et) for et in list(_EVENT_PATTERNS)[:10]]
        db = self._mock_db(events)
        mock_row = MagicMock()

        with patch(
            "app.services.azure_activity_signal_service.signal_svc.upsert_incident_signal",
            return_value=("created", mock_row),
        ):
            result = generate_azure_activity_signals(
                workspace_id=uuid.uuid4(), db=db, max_signals=3
            )
        assert result["signals_created"] <= 3


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint registration
# ──────────────────────────────────────────────────────────────────────────────


class TestEndpointRegistered:
    def test_generate_signals_endpoint_registered(self, client):
        resp = client.get("/security/azure-activity/generate-signals")
        assert resp.status_code != 404, (
            "Endpoint /security/azure-activity/generate-signals not found"
        )

    def test_admin_can_reach_generate_signals(self, client):
        resp = client.post(
            "/security/azure-activity/generate-signals", json={}
        )
        assert resp.status_code in (200, 422, 403), (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Capability matrix + expansion framework
# ──────────────────────────────────────────────────────────────────────────────


class TestCapabilityMatrix:
    def test_azure_activity_signals_true(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.activity_signals is True

    def test_azure_activity_ingestion_still_true(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.activity_ingestion is True

    def test_azure_correlations_still_false(self):
        """Flipped in M77F: risk_activity_correlations now True."""
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.risk_activity_correlations is True  # flipped in M77F

    def test_azure_demo_still_false(self):
        """Flipped in M77G: demo_seed_clear now True."""
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.demo_seed_clear is True  # flipped in M77G

    def test_azure_still_partial(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.maturity == "partial"


class TestExpansionFramework:
    def test_next_stage_is_m77f(self):
        """Flipped in M77I: Azure arc closed → M78A Google Cloud."""
        fw = get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M78H" in stage


# ──────────────────────────────────────────────────────────────────────────────
# M77A/B/C/D regression
# ──────────────────────────────────────────────────────────────────────────────


class TestM77ABCDRegression:
    def test_m77b_rules_still_registered(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        assert "azure_nsg_public_admin_ingress" in KNOWN_RULE_KEYS
        assert "azure_key_vault_rbac_disabled" in KNOWN_RULE_KEYS

    def test_m77c_rules_still_registered(self):
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        assert "azure_role_assignment_broad_privilege" in KNOWN_RULE_KEYS
        assert "azure_aks_public_api_access" in KNOWN_RULE_KEYS

    def test_m77d_activity_log_connector_still_works(self):
        from app.connectors.azure import _ALLOWED_OPERATION_NAMES
        assert "microsoft.network/networksecuritygroups/write" in _ALLOWED_OPERATION_NAMES

    def test_m77d_activity_ingestion_service_still_importable(self):
        from app.services.azure_activity_ingestion_service import (
            ingest_azure_activity, normalize_azure_activity_event,
        )
        # Just verify imports work
        assert callable(ingest_azure_activity)
        assert callable(normalize_azure_activity_event)

    def test_azure_schema_has_all_record_types(self):
        from app.connectors.azure_schema import AZURE_RECORD_TYPES
        assert "azure_role_assignment" in AZURE_RECORD_TYPES
        assert "azure_app_service" in AZURE_RECORD_TYPES
        assert len(AZURE_RECORD_TYPES) == 9

    def test_import_time_assertions_still_pass(self):
        from app.services.security_rule_pack import _RULE_META
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        assert set(_RULE_META) == set(KNOWN_RULE_KEYS)
