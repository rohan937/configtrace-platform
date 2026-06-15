"""M77F — Azure configuration-risk × Azure Activity Log correlations.

Correlates ACTIVE Azure configuration-risk findings (provider="azure", from
M77B/M77C rules) with Azure Activity Log events (source="azure_activity_log",
from M77D ingestion) on the SAME Azure resource within the finding's review
window.

Matching rules tested:
  - Resource-name match: finding.evidence[name_field] == event.metadata[event_name_field]
    for NSG / Storage Account / Key Vault / App Service / SQL Server / AKS
  - Resource_group agreement (defense-in-depth) — if both sides expose it
  - Role assignment match: role_definition_name + scope_type, only for broad roles
  - NEVER provider-only, NEVER subscription-only, NEVER different objects, NEVER
    different roles, NEVER different scope types

Privacy + claim discipline also asserted:
  - No principal IDs / emails / names anywhere in metadata
  - No raw correlationId (only the hash)
  - No raw API payloads / properties / claims / authorization / httpRequest
  - No forbidden phrases in summaries / titles
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest.mock import MagicMock

import pytest

from app.services.security_signal_correlation_service import (
    AZURE_CORRELATION_RULES,
    _AZURE_BROAD_ROLES,
    _az_match_resource,
    _az_match_role_assignment,
    _az_resource_label,
    build_azure_correlation,
    generate_azure_correlations,
    sanitize_correlation_metadata,
    ALLOWED_METADATA_KEYS as CORR_ALLOWED_KEYS,
)
from app.services.provider_capability_matrix_service import get_provider_capability
from app.services.provider_expansion_framework import get_framework

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

_FORBIDDEN_CLAIM_PHRASES = (
    "compromise confirmed", "secret leaked", "data leaked",
    "customer data leaked", "payment fraud detected", "attacker found",
    "someone has access", "unauthorized access confirmed", "breach detected",
    "attack detected", "orders exposed", "card data exposed",
)

_FORBIDDEN_METADATA_KEYS = {
    "caller", "claims", "authorization", "properties", "httpRequest",
    "tenantId", "principal_id", "object_id", "ip_address",
    "client_secret", "access_token", "bearer", "caller_email", "upn",
    "caller_name", "principal_email",
}

# Use a recent timestamp so events fall inside the default 24-hour window.
_NOW = datetime.now(timezone.utc)


# ──────────────────────────────────────────────────────────────────────────────
# Mock helpers
# ──────────────────────────────────────────────────────────────────────────────


def _mock_finding(
    *,
    finding_key: str,
    evidence: dict,
    severity: str = "high",
    title: Optional[str] = None,
    first_detected_at: Optional[datetime] = None,
    last_seen_at: Optional[datetime] = None,
) -> MagicMock:
    f = MagicMock()
    f.id = uuid.uuid4()
    f.finding_key = finding_key
    f.severity = severity
    f.title = title or f"Azure finding: {finding_key}"
    f.provider = "azure"
    f.status = "active"
    f.evidence = evidence
    f.first_detected_at = first_detected_at or (_NOW - timedelta(hours=1))
    f.last_seen_at = last_seen_at or _NOW
    f.linked_change_id = None
    f.integration_id = uuid.uuid4()
    f.resource_id = uuid.uuid4()
    return f


def _mock_event(
    *,
    event_type: str,
    metadata: dict,
    occurred_at: Optional[datetime] = None,
) -> MagicMock:
    ev = MagicMock()
    ev.id = uuid.uuid4()
    ev.provider = "azure"
    ev.source = "azure_activity_log"
    ev.event_type = event_type
    ev.event_metadata = metadata
    ev.occurred_at = occurred_at or _NOW
    ev.actor_id = None
    return ev


# ──────────────────────────────────────────────────────────────────────────────
# Rule completeness
# ──────────────────────────────────────────────────────────────────────────────


class TestRuleCompleteness:
    def test_all_m77b_rules_have_correlation_entry(self):
        m77b = {
            "azure_nsg_public_admin_ingress",
            "azure_nsg_public_broad_ingress",
            "azure_storage_public_blob_access",
            "azure_storage_public_network_access",
            "azure_storage_weak_tls",
            "azure_storage_shared_key_enabled",
            "azure_key_vault_public_network_access",
            "azure_key_vault_purge_protection_disabled",
            "azure_key_vault_soft_delete_disabled",
            "azure_key_vault_rbac_disabled",
        }
        missing = m77b - set(AZURE_CORRELATION_RULES)
        assert missing == set(), f"M77B rules without correlation: {missing}"

    def test_all_m77c_rules_have_correlation_entry(self):
        m77c = {
            "azure_role_assignment_broad_privilege",
            "azure_app_service_https_disabled",
            "azure_app_service_ftp_enabled",
            "azure_app_service_weak_tls",
            "azure_app_service_public_network_access",
            "azure_sql_public_network_access",
            "azure_sql_weak_tls",
            "azure_aks_local_accounts_enabled",
            "azure_aks_public_api_access",
            "azure_aks_network_policy_missing",
        }
        missing = m77c - set(AZURE_CORRELATION_RULES)
        assert missing == set(), f"M77C rules without correlation: {missing}"

    def test_20_finding_rules_covered(self):
        assert len(AZURE_CORRELATION_RULES) == 20

    def test_7_distinct_correlation_types(self):
        types = {r["correlation_type"] for r in AZURE_CORRELATION_RULES.values()}
        assert len(types) == 7


# ──────────────────────────────────────────────────────────────────────────────
# Resource matching
# ──────────────────────────────────────────────────────────────────────────────


class TestResourceMatching:
    def _nsg_finding(self, nsg_name="nsg-prod", rg="rg-prod"):
        return _mock_finding(
            finding_key=f"azure_nsg_public_admin_ingress:{nsg_name}",
            evidence={"nsg_name": nsg_name, "resource_group": rg, "rule": "azure_nsg_public_admin_ingress"},
        )

    def _nsg_event(self, nsg_name="nsg-prod", rg="rg-prod", event_type="azure.nsg.updated"):
        return _mock_event(
            event_type=event_type,
            metadata={"nsg_name": nsg_name, "resource_group": rg},
        )

    def test_nsg_name_and_rg_match_high_confidence(self):
        f = self._nsg_finding()
        ev = self._nsg_event()
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        matched = _az_match_resource(f, ev, rule)
        assert matched == "nsg_name+resource_group"

    def test_nsg_name_only_match_medium_confidence(self):
        f = _mock_finding(
            finding_key="azure_nsg_public_admin_ingress:nsg-prod",
            evidence={"nsg_name": "nsg-prod"},  # no resource_group
        )
        ev = _mock_event(event_type="azure.nsg.updated", metadata={"nsg_name": "nsg-prod"})
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        matched = _az_match_resource(f, ev, rule)
        assert matched == "nsg_name"

    def test_nsg_name_mismatch_returns_none(self):
        f = self._nsg_finding(nsg_name="nsg-a")
        ev = self._nsg_event(nsg_name="nsg-b")
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        assert _az_match_resource(f, ev, rule) is None

    def test_rg_mismatch_returns_none(self):
        """Same NSG name in different resource groups must not correlate."""
        f = self._nsg_finding(nsg_name="nsg-prod", rg="rg-a")
        ev = self._nsg_event(nsg_name="nsg-prod", rg="rg-b")
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        assert _az_match_resource(f, ev, rule) is None

    def test_storage_account_match(self):
        f = _mock_finding(
            finding_key="azure_storage_public_blob_access:acct1",
            evidence={"account_name": "acct1", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.storage_account.updated",
            metadata={"storage_account_name": "acct1", "resource_group": "rg-prod"},
        )
        rule = AZURE_CORRELATION_RULES["azure_storage_public_blob_access"]
        assert _az_match_resource(f, ev, rule) == "storage_account_name+resource_group"

    def test_key_vault_match(self):
        f = _mock_finding(
            finding_key="azure_key_vault_public_network_access:kv-prod",
            evidence={"vault_name": "kv-prod", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.key_vault.updated",
            metadata={"key_vault_name": "kv-prod", "resource_group": "rg-prod"},
        )
        rule = AZURE_CORRELATION_RULES["azure_key_vault_public_network_access"]
        assert _az_match_resource(f, ev, rule) == "key_vault_name+resource_group"

    def test_app_service_match(self):
        f = _mock_finding(
            finding_key="azure_app_service_https_disabled:app-prod",
            evidence={"app_name": "app-prod", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.app_service.updated",
            metadata={"app_service_name": "app-prod", "resource_group": "rg-prod"},
        )
        rule = AZURE_CORRELATION_RULES["azure_app_service_https_disabled"]
        assert _az_match_resource(f, ev, rule) == "app_service_name+resource_group"

    def test_sql_server_match(self):
        f = _mock_finding(
            finding_key="azure_sql_public_network_access:sql-prod",
            evidence={"server_name": "sql-prod", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.sql_server.updated",
            metadata={"sql_server_name": "sql-prod", "resource_group": "rg-prod"},
        )
        rule = AZURE_CORRELATION_RULES["azure_sql_public_network_access"]
        assert _az_match_resource(f, ev, rule) == "sql_server_name+resource_group"

    def test_aks_cluster_match(self):
        f = _mock_finding(
            finding_key="azure_aks_public_api_access:aks-prod",
            evidence={"cluster_name": "aks-prod", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.aks_cluster.updated",
            metadata={"aks_cluster_name": "aks-prod", "resource_group": "rg-prod"},
        )
        rule = AZURE_CORRELATION_RULES["azure_aks_public_api_access"]
        assert _az_match_resource(f, ev, rule) == "aks_cluster_name+resource_group"


# ──────────────────────────────────────────────────────────────────────────────
# Role-assignment matching
# ──────────────────────────────────────────────────────────────────────────────


class TestRoleAssignmentMatching:
    def _role_finding(self, role="Owner", scope="subscription"):
        return _mock_finding(
            finding_key=f"azure_role_assignment_broad_privilege:assignment-1",
            evidence={
                "role_definition_name": role,
                "scope_type": scope,
                "principal_type": "ServicePrincipal",
            },
        )

    def _role_event(self, role="Owner", scope="subscription",
                    event_type="azure.role_assignment.created"):
        return _mock_event(
            event_type=event_type,
            metadata={
                "role_definition_name": role,
                "scope_type": scope,
                "principal_type": "ServicePrincipal",
            },
        )

    def test_owner_at_subscription_matches(self):
        f = self._role_finding(role="Owner", scope="subscription")
        ev = self._role_event(role="Owner", scope="subscription")
        matched = _az_match_role_assignment(f, ev)
        assert matched == "role_definition_name+scope_type"

    def test_contributor_at_resource_group_matches(self):
        f = self._role_finding(role="Contributor", scope="resource_group")
        ev = self._role_event(role="Contributor", scope="resource_group")
        matched = _az_match_role_assignment(f, ev)
        assert matched == "role_definition_name+scope_type"

    def test_different_roles_do_not_match(self):
        f = self._role_finding(role="Owner")
        ev = self._role_event(role="Contributor")
        assert _az_match_role_assignment(f, ev) is None

    def test_different_scopes_do_not_match(self):
        f = self._role_finding(role="Owner", scope="subscription")
        ev = self._role_event(role="Owner", scope="resource_group")
        assert _az_match_role_assignment(f, ev) is None

    def test_non_broad_role_does_not_match(self):
        f = self._role_finding(role="Reader", scope="subscription")
        ev = self._role_event(role="Reader", scope="subscription")
        # Reader isn't in _AZURE_BROAD_ROLES → no match
        assert _az_match_role_assignment(f, ev) is None

    def test_principal_id_never_used_in_match(self):
        """Match must succeed without principal_id, and event/finding can include
        a principal_id without the matcher reading it."""
        f = _mock_finding(
            finding_key="azure_role_assignment_broad_privilege:assignment-1",
            evidence={
                "role_definition_name": "Owner",
                "scope_type": "subscription",
                "principal_id": "REDACTED-GUID-1",
            },
        )
        ev = _mock_event(
            event_type="azure.role_assignment.created",
            metadata={
                "role_definition_name": "Owner",
                "scope_type": "subscription",
                "principal_id": "REDACTED-GUID-2",  # different — would invalidate match
            },
        )
        # Should still match — matcher ignores principal_id entirely
        matched = _az_match_role_assignment(f, ev)
        assert matched == "role_definition_name+scope_type"


# ──────────────────────────────────────────────────────────────────────────────
# Cross-resource / negative correlations
# ──────────────────────────────────────────────────────────────────────────────


class TestNegativeCorrelations:
    def test_nsg_finding_does_not_match_storage_event(self):
        f = _mock_finding(
            finding_key="azure_nsg_public_admin_ingress:nsg-prod",
            evidence={"nsg_name": "nsg-prod", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.storage_account.updated",
            metadata={"storage_account_name": "nsg-prod", "resource_group": "rg-prod"},
        )
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        # NSG rule looks for nsg_name on event side → no match
        assert _az_match_resource(f, ev, rule) is None

    def test_storage_finding_does_not_match_keyvault_event(self):
        f = _mock_finding(
            finding_key="azure_storage_public_blob_access:acct1",
            evidence={"account_name": "acct1", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.key_vault.updated",
            metadata={"key_vault_name": "acct1", "resource_group": "rg-prod"},
        )
        rule = AZURE_CORRELATION_RULES["azure_storage_public_blob_access"]
        assert _az_match_resource(f, ev, rule) is None

    def test_finding_without_name_field_does_not_match(self):
        """A NSG finding with no nsg_name in evidence must not match."""
        f = _mock_finding(
            finding_key="azure_nsg_public_admin_ingress",
            evidence={"resource_group": "rg-prod"},  # no nsg_name
        )
        ev = _mock_event(
            event_type="azure.nsg.updated",
            metadata={"nsg_name": "nsg-prod", "resource_group": "rg-prod"},
        )
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        assert _az_match_resource(f, ev, rule) is None

    def test_event_without_name_field_does_not_match(self):
        f = _mock_finding(
            finding_key="azure_nsg_public_admin_ingress:nsg-prod",
            evidence={"nsg_name": "nsg-prod", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.nsg.updated",
            metadata={"resource_group": "rg-prod"},  # no nsg_name
        )
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        assert _az_match_resource(f, ev, rule) is None


# ──────────────────────────────────────────────────────────────────────────────
# Built correlation shape and metadata
# ──────────────────────────────────────────────────────────────────────────────


class TestBuildCorrelation:
    def _make_pair(self):
        f = _mock_finding(
            finding_key="azure_nsg_public_admin_ingress:nsg-prod",
            evidence={"nsg_name": "nsg-prod", "resource_group": "rg-prod"},
            severity="high",
        )
        ev = _mock_event(
            event_type="azure.nsg.updated",
            metadata={
                "nsg_name": "nsg-prod",
                "resource_group": "rg-prod",
                "subscription_id": "sub-123",
                "azure_event_id": "evt-abc",
                "azure_correlation_id_hash": "abc123" * 5,
                "operation_name": "Microsoft.Network/networkSecurityGroups/write",
                "operation_action": "write",
                "category": "Administrative",
                "status": "Succeeded",
                "event_source": "azure_activity_log",
            },
        )
        return f, ev

    def test_correlation_has_required_fields(self):
        f, ev = self._make_pair()
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        c = build_azure_correlation(
            finding=f, event=ev, rule=rule,
            matched_on="nsg_name+resource_group",
            resource_label='NSG "nsg-prod"',
        )
        assert c["provider"] == "azure"
        assert c["correlation_type"] == "azure_nsg_exposure_activity_correlation"
        assert c["severity"] == "high"
        assert c["confidence"] == "high"
        assert c["linked_finding_id"] == f.id
        assert c["linked_activity_event_id"] == ev.id
        assert c["status"] == "open"

    def test_high_confidence_when_rg_matches(self):
        f, ev = self._make_pair()
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        c = build_azure_correlation(
            finding=f, event=ev, rule=rule,
            matched_on="nsg_name+resource_group",
            resource_label='NSG "nsg-prod"',
        )
        assert c["confidence"] == "high"
        assert c["metadata"]["match_confidence"] == "high"

    def test_medium_confidence_when_only_name_matches(self):
        f, ev = self._make_pair()
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        c = build_azure_correlation(
            finding=f, event=ev, rule=rule,
            matched_on="nsg_name",
            resource_label='NSG "nsg-prod"',
        )
        assert c["confidence"] == "medium"
        assert c["metadata"]["match_confidence"] == "medium"

    def test_metadata_only_includes_allowlisted_keys(self):
        f, ev = self._make_pair()
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        c = build_azure_correlation(
            finding=f, event=ev, rule=rule,
            matched_on="nsg_name+resource_group",
            resource_label='NSG "nsg-prod"',
        )
        for k in c["metadata"]:
            assert k in CORR_ALLOWED_KEYS, f"non-allowlisted metadata key: {k}"

    def test_metadata_contains_safe_resource_identity(self):
        f, ev = self._make_pair()
        rule = AZURE_CORRELATION_RULES["azure_nsg_public_admin_ingress"]
        c = build_azure_correlation(
            finding=f, event=ev, rule=rule,
            matched_on="nsg_name+resource_group",
            resource_label='NSG "nsg-prod"',
        )
        md = c["metadata"]
        assert md["nsg_name"] == "nsg-prod"
        assert md["resource_group"] == "rg-prod"
        assert md["subscription_id"] == "sub-123"
        assert md["operation_name"].startswith("Microsoft.Network/")


# ──────────────────────────────────────────────────────────────────────────────
# Privacy / claim discipline
# ──────────────────────────────────────────────────────────────────────────────


class TestPrivacyAndClaimDiscipline:
    def _build_with_pollution(self):
        """A finding/event with PII-like keys that the matcher/sanitizer must drop."""
        f = _mock_finding(
            finding_key="azure_role_assignment_broad_privilege:assignment-1",
            evidence={
                "role_definition_name": "Owner",
                "scope_type": "subscription",
                "principal_type": "ServicePrincipal",
                # Polluted (must never appear in correlation):
                "principal_id": "REDACTED-OBJECT-ID",
                "caller": "user@example.com",
                "claims": {"oid": "abc"},
            },
        )
        ev = _mock_event(
            event_type="azure.role_assignment.created",
            metadata={
                "role_definition_name": "Owner",
                "scope_type": "subscription",
                "principal_type": "ServicePrincipal",
                "subscription_id": "sub-x",
                "azure_correlation_id_hash": "h" * 32,
                # Polluted:
                "caller": "user@evil.example",
                "principal_id": "REDACTED-OBJECT-ID-2",
                "properties": "raw_payload_should_not_appear",
                "authorization": "Bearer SECRET",
            },
        )
        rule = AZURE_CORRELATION_RULES["azure_role_assignment_broad_privilege"]
        return build_azure_correlation(
            finding=f, event=ev, rule=rule,
            matched_on="role_definition_name+scope_type",
            resource_label='role assignment "Owner"',
        )

    def test_no_forbidden_metadata_keys(self):
        c = self._build_with_pollution()
        for forbidden in _FORBIDDEN_METADATA_KEYS:
            assert forbidden not in c["metadata"], (
                f"Forbidden metadata key {forbidden!r} in correlation"
            )

    def test_no_pii_strings_anywhere(self):
        c = self._build_with_pollution()
        # Re-build a json-safe representation (skip UUIDs)
        text = json.dumps({
            "metadata": c["metadata"],
            "title": c["title"],
            "summary": c["summary"],
        })
        assert "user@example.com" not in text
        assert "user@evil.example" not in text
        assert "REDACTED-OBJECT-ID" not in text
        assert "raw_payload_should_not_appear" not in text
        assert "Bearer SECRET" not in text

    def test_no_overclaim_in_summary_or_title(self):
        c = self._build_with_pollution()
        text = (c["title"] + " " + c["summary"]).lower()
        for phrase in _FORBIDDEN_CLAIM_PHRASES:
            assert phrase not in text, f"Forbidden phrase: {phrase!r}"

    def test_review_note_present(self):
        c = self._build_with_pollution()
        assert "may require review" in c["summary"].lower()
        assert "does not confirm" in c["summary"].lower()

    def test_no_forbidden_phrases_in_service_source(self):
        import inspect
        import app.services.security_signal_correlation_service as svc
        src = inspect.getsource(svc)
        # Find "AZURE" section
        azure_start = src.find("AZURE — M77F")
        if azure_start < 0:
            azure_start = src.find("def generate_azure_correlations")
        azure_src = src[azure_start:]
        for phrase in _FORBIDDEN_CLAIM_PHRASES:
            assert phrase.lower() not in azure_src.lower(), (
                f"Forbidden phrase in Azure correlation source: {phrase!r}"
            )


# ──────────────────────────────────────────────────────────────────────────────
# generate_azure_correlations (driver with mocked DB)
# ──────────────────────────────────────────────────────────────────────────────


class TestGenerateAzureCorrelations:
    def _mock_db(self, findings: list, events: list) -> MagicMock:
        db = MagicMock()

        # Build two distinct query chains: one for SecurityFinding, one for
        # SecurityActivityEvent. We dispatch by the model class passed to
        # db.query() and return different mocks.
        from app.models.security_activity_event import SecurityActivityEvent
        from app.models.security_finding import SecurityFinding

        def query_dispatch(model):
            q = MagicMock()
            q.filter.return_value = q
            q.limit.return_value = q
            if model is SecurityFinding:
                q.all.return_value = findings
            elif model is SecurityActivityEvent:
                q.all.return_value = events
            else:
                q.all.return_value = []
            return q

        db.query.side_effect = query_dispatch
        return db

    def test_one_finding_one_event_creates_one_correlation(self, monkeypatch):
        f = _mock_finding(
            finding_key="azure_nsg_public_admin_ingress:nsg-prod",
            evidence={"nsg_name": "nsg-prod", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.nsg.updated",
            metadata={"nsg_name": "nsg-prod", "resource_group": "rg-prod"},
        )
        db = self._mock_db([f], [ev])
        mock_row = MagicMock()
        monkeypatch.setattr(
            "app.services.security_signal_correlation_service.upsert_correlation",
            lambda *, workspace_id, correlation, db: ("created", mock_row),
        )
        summary = generate_azure_correlations(workspace_id=uuid.uuid4(), db=db)
        assert summary["correlations_created"] == 1
        assert summary["correlations_skipped"] == 0
        assert summary["findings_scanned"] == 1
        assert summary["events_scanned"] == 1
        assert summary["provider"] == "azure"

    def test_finding_outside_window_does_not_correlate(self, monkeypatch):
        old_finding_time = _NOW - timedelta(hours=200)
        f = _mock_finding(
            finding_key="azure_nsg_public_admin_ingress:nsg-prod",
            evidence={"nsg_name": "nsg-prod", "resource_group": "rg-prod"},
            first_detected_at=old_finding_time,
            last_seen_at=old_finding_time,
        )
        # Event is "now" — outside the finding's [old-24h, old+24h] window
        ev = _mock_event(
            event_type="azure.nsg.updated",
            metadata={"nsg_name": "nsg-prod", "resource_group": "rg-prod"},
            occurred_at=_NOW,
        )
        db = self._mock_db([f], [ev])
        called = []
        monkeypatch.setattr(
            "app.services.security_signal_correlation_service.upsert_correlation",
            lambda *, workspace_id, correlation, db: (called.append(1), ("created", MagicMock()))[1],
        )
        summary = generate_azure_correlations(workspace_id=uuid.uuid4(), db=db)
        assert summary["correlations_created"] == 0
        assert called == []

    def test_provider_only_match_is_not_created(self, monkeypatch):
        """Finding and event for the same provider but different resource names → no correlation."""
        f = _mock_finding(
            finding_key="azure_nsg_public_admin_ingress:nsg-a",
            evidence={"nsg_name": "nsg-a", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.nsg.updated",
            metadata={"nsg_name": "nsg-b", "resource_group": "rg-prod"},
        )
        db = self._mock_db([f], [ev])
        called = []
        monkeypatch.setattr(
            "app.services.security_signal_correlation_service.upsert_correlation",
            lambda *, workspace_id, correlation, db: (called.append(1), ("created", MagicMock()))[1],
        )
        summary = generate_azure_correlations(workspace_id=uuid.uuid4(), db=db)
        assert summary["correlations_created"] == 0
        assert called == []

    def test_subscription_only_match_is_not_created(self, monkeypatch):
        """Same subscription but different resources → no correlation."""
        f = _mock_finding(
            finding_key="azure_storage_public_blob_access:acct-a",
            evidence={"account_name": "acct-a", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.storage_account.updated",
            metadata={
                "storage_account_name": "acct-b",  # different
                "resource_group": "rg-prod",
                "subscription_id": "sub-1",
            },
        )
        db = self._mock_db([f], [ev])
        called = []
        monkeypatch.setattr(
            "app.services.security_signal_correlation_service.upsert_correlation",
            lambda *, workspace_id, correlation, db: (called.append(1), ("created", MagicMock()))[1],
        )
        summary = generate_azure_correlations(workspace_id=uuid.uuid4(), db=db)
        assert summary["correlations_created"] == 0

    def test_idempotent_via_skipped(self, monkeypatch):
        f = _mock_finding(
            finding_key="azure_key_vault_public_network_access:kv-prod",
            evidence={"vault_name": "kv-prod", "resource_group": "rg-prod"},
        )
        ev = _mock_event(
            event_type="azure.key_vault.updated",
            metadata={"key_vault_name": "kv-prod", "resource_group": "rg-prod"},
        )
        db = self._mock_db([f], [ev])
        mock_row = MagicMock()
        monkeypatch.setattr(
            "app.services.security_signal_correlation_service.upsert_correlation",
            lambda *, workspace_id, correlation, db: ("skipped", mock_row),
        )
        summary = generate_azure_correlations(workspace_id=uuid.uuid4(), db=db)
        assert summary["correlations_created"] == 0
        assert summary["correlations_skipped"] == 1

    def test_unrelated_finding_rule_is_filtered(self, monkeypatch):
        f = _mock_finding(
            finding_key="some_other_rule:resource",
            evidence={"nsg_name": "nsg-prod"},
        )
        ev = _mock_event(
            event_type="azure.nsg.updated",
            metadata={"nsg_name": "nsg-prod"},
        )
        db = self._mock_db([f], [ev])
        summary = generate_azure_correlations(workspace_id=uuid.uuid4(), db=db)
        # finding_key not in AZURE_CORRELATION_RULES → filtered out
        assert summary["findings_scanned"] == 0
        assert summary["correlations_created"] == 0

    def test_role_assignment_creates_correlation(self, monkeypatch):
        f = _mock_finding(
            finding_key="azure_role_assignment_broad_privilege:assignment-1",
            evidence={
                "role_definition_name": "Owner",
                "scope_type": "subscription",
                "principal_type": "ServicePrincipal",
            },
        )
        ev = _mock_event(
            event_type="azure.role_assignment.created",
            metadata={
                "role_definition_name": "Owner",
                "scope_type": "subscription",
                "principal_type": "ServicePrincipal",
            },
        )
        db = self._mock_db([f], [ev])
        monkeypatch.setattr(
            "app.services.security_signal_correlation_service.upsert_correlation",
            lambda *, workspace_id, correlation, db: ("created", MagicMock()),
        )
        summary = generate_azure_correlations(workspace_id=uuid.uuid4(), db=db)
        assert summary["correlations_created"] == 1


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint
# ──────────────────────────────────────────────────────────────────────────────


class TestEndpointRouting:
    def test_correlations_generate_endpoint_accepts_azure_provider(self, client):
        resp = client.post(
            "/security/correlations/generate", json={"provider": "azure"}
        )
        # Either 200 (workspace setup ok) or auth-related; never 404
        assert resp.status_code != 404, "Generic correlations endpoint missing"


# ──────────────────────────────────────────────────────────────────────────────
# Capability matrix + expansion framework
# ──────────────────────────────────────────────────────────────────────────────


class TestCapabilityMatrix:
    def test_azure_correlations_true(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.risk_activity_correlations is True

    def test_azure_demo_still_false(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.security.demo_seed_clear is False

    def test_azure_still_partial(self):
        cap = get_provider_capability("azure")
        assert cap is not None
        assert cap.maturity == "partial"


class TestExpansionFramework:
    def test_next_stage_is_m77g(self):
        fw = get_framework()
        stage = fw["summary"]["planned_next_stage"]
        assert "M77G" in stage


# ──────────────────────────────────────────────────────────────────────────────
# M77A/B/C/D/E regression smoke
# ──────────────────────────────────────────────────────────────────────────────


class TestRegression:
    def test_azure_security_rules_still_true(self):
        cap = get_provider_capability("azure")
        assert cap.security.security_rules is True

    def test_azure_activity_ingestion_still_true(self):
        cap = get_provider_capability("azure")
        assert cap.security.activity_ingestion is True

    def test_azure_activity_signals_still_true(self):
        cap = get_provider_capability("azure")
        assert cap.security.activity_signals is True

    def test_m77e_signal_service_still_importable(self):
        from app.services.azure_activity_signal_service import (
            generate_azure_activity_signals, _EVENT_PATTERNS,
        )
        assert callable(generate_azure_activity_signals)
        assert len(_EVENT_PATTERNS) == 20

    def test_m77d_connector_still_importable(self):
        from app.connectors.azure import _ALLOWED_OPERATION_NAMES
        assert "microsoft.network/networksecuritygroups/write" in _ALLOWED_OPERATION_NAMES

    def test_import_time_assertions_still_pass(self):
        from app.services.security_rule_pack import _RULE_META
        from app.services.security_rule_registry import KNOWN_RULE_KEYS
        assert set(_RULE_META) == set(KNOWN_RULE_KEYS)
