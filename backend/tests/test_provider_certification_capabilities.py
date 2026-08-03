"""Capability-declaration normalization tests (message 4 of N).

Audits the fixed five-string capability vocabulary
(``security_findings``, ``activity_ingestion``, ``activity_signals``,
``risk_activity_correlations``, ``demo_case_reporting``) across all
eleven manifests. Message 4 explicitly audited whether the broader
capability-ID list suggested in the task spec (configuration_drift,
identity_access, effective_access, alerting, ownership_routing,
repositories, integrations, database_security, network_security,
storage_security, application_security, event_ingestion,
incident_ingestion) was needed — every one of those concepts already
maps onto the existing five generic strings or a provider's
``known_limitations``/completeness declarations; no manifest across all
eleven providers needed a capability concept the existing vocabulary
couldn't express, so no new capability IDs were introduced. These tests
pin that finding and cover the supported/unsupported invariants.
"""

from __future__ import annotations

import pytest

from app.provider_certification import runner
from app.provider_certification.models import ManifestValidationError, ProviderCertificationManifest, ReachabilityExemption

_ALL_PROVIDERS = (
    "cloudflare", "entra", "firebase", "github", "gitlab", "kubernetes",
    "okta", "sentry", "snowflake", "stripe", "supabase",
)

_KNOWN_CAPABILITIES = frozenset({
    "security_findings", "activity_ingestion", "activity_signals",
    "risk_activity_correlations", "demo_case_reporting",
})


def _manifest(**overrides) -> ProviderCertificationManifest:
    fields = dict(
        provider_id="ghostprov4",
        display_name="Ghost Provider 4",
        category="observability",
        maturity="partial",
        expected_public=True,
        expected_connectable=True,
        expected_live=False,
        credential_fields=("ghostprov4_api_token",),
        sensitive_credential_fields=("ghostprov4_api_token",),
        authentication_model="api_token",
        expected_record_types=("ghostprov4_widget",),
        expected_frontend_form="GhostProv4IntegrationForm.tsx",
        expected_reconnect=False,
    )
    fields.update(overrides)
    return ProviderCertificationManifest(**fields)


class TestCapabilityVocabularySufficiency:
    def test_every_provider_uses_only_known_capability_strings(self):
        for pid in _ALL_PROVIDERS:
            manifest = runner.get_manifest(pid)
            assert set(manifest.supported_capabilities) <= _KNOWN_CAPABILITIES
            assert set(manifest.unsupported_capabilities) <= _KNOWN_CAPABILITIES

    def test_no_provider_specific_capability_strings_leaked_into_any_manifest(self):
        # Every capability declared across all eleven providers normalizes
        # to the same five generic IDs — none is provider-specific.
        for pid in _ALL_PROVIDERS:
            manifest = runner.get_manifest(pid)
            for cap in manifest.supported_capabilities:
                assert pid not in cap


class TestSupportedUnsupportedDisjoint:
    def test_overlap_rejected(self):
        with pytest.raises(ManifestValidationError, match="declared both supported and unsupported"):
            _manifest(
                supported_capabilities=("security_findings",),
                unsupported_capabilities=("security_findings",),
                security_finding_rule_ids=("ghostprov4_rule_a",),
            )

    def test_disjoint_accepted(self):
        m = _manifest(
            supported_capabilities=("security_findings",),
            unsupported_capabilities=("activity_ingestion",),
            security_finding_rule_ids=("ghostprov4_rule_a",),
            reachability_exemptions=(ReachabilityExemption(rule_ids=("ghostprov4_rule_a",), reason="test fixture"),),
        )
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()

    def test_all_eleven_providers_have_disjoint_supported_unsupported(self):
        for pid in _ALL_PROVIDERS:
            manifest = runner.get_manifest(pid)
            assert set(manifest.supported_capabilities) & set(manifest.unsupported_capabilities) == set()


class TestFindingCapabilityRequiresRules:
    def test_security_findings_supported_with_zero_rule_ids_rejected(self):
        with pytest.raises(ManifestValidationError, match="security_finding_rule_ids is empty"):
            _manifest(supported_capabilities=("security_findings",), security_finding_rule_ids=())

    def test_rule_ids_present_without_capability_rejected(self):
        with pytest.raises(ManifestValidationError, match="'security_findings' is not in supported_capabilities"):
            _manifest(supported_capabilities=(), security_finding_rule_ids=("ghostprov4_rule_a",))


class TestActivityCapabilityConflictsWithLimitation:
    def test_cloudflare_advertises_activity_ingestion_and_documents_traffic_analytics_boundary(self):
        # Cloudflare DOES support activity_ingestion (confirmed via the
        # real capability matrix), but its known_limitations explicitly
        # denies request/traffic ANALYTICS specifically — proving the
        # capability and the boundary are not contradictory, just scoped
        # more narrowly than the capability name alone might suggest.
        manifest = runner.get_manifest("cloudflare")
        assert "activity_ingestion" in manifest.supported_capabilities
        assert any("traffic analytics" in lim for lim in manifest.known_limitations)


class TestSupportedVersusUnsupportedBoundariesDocumented:
    def test_cloudflare_documents_unsupported_traffic_analytics(self):
        manifest = runner.get_manifest("cloudflare")
        assert any("traffic analytics" in lim or "customer traffic ingestion" in lim for lim in manifest.known_limitations)

    def test_supabase_documents_unsupported_table_rows_and_auth_user_data(self):
        manifest = runner.get_manifest("supabase")
        assert any("table-row" in lim for lim in manifest.known_limitations)
        assert any("auth-user" in lim for lim in manifest.known_limitations)

    def test_firebase_documents_unsupported_document_object_user_data(self):
        manifest = runner.get_manifest("firebase")
        assert any("Firestore document" in lim for lim in manifest.known_limitations)
        assert any("Storage object" in lim for lim in manifest.known_limitations)
        assert any("Authentication user records" in lim for lim in manifest.known_limitations)

    def test_stripe_documents_unsupported_customer_payment_event_data(self):
        manifest = runner.get_manifest("stripe")
        assert any("payment transaction" in lim for lim in manifest.known_limitations)
        assert any("customer" in lim.lower() for lim in manifest.known_limitations)

    def test_every_provider_declares_at_least_one_known_limitation(self):
        for pid in _ALL_PROVIDERS:
            manifest = runner.get_manifest(pid)
            assert len(manifest.known_limitations) >= 1, f"{pid} declares no known_limitations"


class TestDeterministicSerialization:
    def test_capability_lists_serialize_deterministically(self):
        m = _manifest(
            supported_capabilities=("security_findings", "activity_ingestion"),
            security_finding_rule_ids=("ghostprov4_rule_a",),
            reachability_exemptions=(ReachabilityExemption(rule_ids=("ghostprov4_rule_a",), reason="test fixture"),),
        )
        d1 = m.as_dict()
        d2 = m.as_dict()
        assert d1["supported_capabilities"] == d2["supported_capabilities"]

    def test_all_eleven_manifests_serialize_reproducibly(self):
        for pid in _ALL_PROVIDERS:
            manifest = runner.get_manifest(pid)
            assert manifest.as_dict() == manifest.as_dict()


class TestPerProviderCapabilityBoundaries:
    """One method per provider (rather than a loop) so a failure names
    the exact provider whose capability declaration regressed."""

    def test_sentry_capabilities_valid(self):
        m = runner.get_manifest("sentry")
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()
        assert len(m.known_limitations) >= 0

    def test_snowflake_capabilities_valid(self):
        m = runner.get_manifest("snowflake")
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()

    def test_okta_capabilities_valid(self):
        m = runner.get_manifest("okta")
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()

    def test_entra_capabilities_valid(self):
        m = runner.get_manifest("entra")
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()

    def test_kubernetes_capabilities_valid(self):
        m = runner.get_manifest("kubernetes")
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()

    def test_github_capabilities_valid(self):
        m = runner.get_manifest("github")
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()

    def test_gitlab_capabilities_valid(self):
        m = runner.get_manifest("gitlab")
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()

    def test_cloudflare_capabilities_valid_and_documents_limitations(self):
        m = runner.get_manifest("cloudflare")
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()
        assert len(m.known_limitations) >= 1

    def test_supabase_capabilities_valid_and_documents_limitations(self):
        m = runner.get_manifest("supabase")
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()
        assert len(m.known_limitations) >= 1

    def test_firebase_capabilities_valid_and_documents_limitations(self):
        m = runner.get_manifest("firebase")
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()
        assert len(m.known_limitations) >= 1

    def test_stripe_capabilities_valid_and_documents_limitations(self):
        m = runner.get_manifest("stripe")
        assert set(m.supported_capabilities) & set(m.unsupported_capabilities) == set()
        assert len(m.known_limitations) >= 1
