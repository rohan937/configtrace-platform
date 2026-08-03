"""Cross-manifest global gate tests (message 2 of N).

Covers the invariants that only make sense across all four registered
pilot manifests at once: unique provider IDs, no alias collisions, valid
maturity/capability combinations, absence from future-provider queues, no
unmarked secret fields, every expected frontend form/reconnect path
present, and schema-version compatibility.
"""

from __future__ import annotations

from app.provider_certification import cross_manifest
from app.provider_certification import discovery as disc
from app.provider_certification import runner
from app.provider_certification.manifests.entra import ENTRA_MANIFEST
from app.provider_certification.manifests.okta import OKTA_MANIFEST
from app.provider_certification.manifests.sentry import SENTRY_MANIFEST
from app.provider_certification.manifests.snowflake import SNOWFLAKE_MANIFEST

_ALL = (ENTRA_MANIFEST, OKTA_MANIFEST, SENTRY_MANIFEST, SNOWFLAKE_MANIFEST)


class TestFourUniquePilotIds:
    def test_four_manifests_registered(self):
        runner._ensure_manifests_loaded()
        assert set(runner.known_provider_ids()) == {"entra", "okta", "sentry", "snowflake"}

    def test_identity_gate_passes_for_real_manifests(self):
        gate = cross_manifest.gate_cross_manifest_identity(_ALL)
        assert gate.status == "pass"

    def test_identity_gate_fails_on_duplicate_provider_id(self):
        gate = cross_manifest.gate_cross_manifest_identity(_ALL + (SENTRY_MANIFEST,))
        assert gate.status == "fail"
        assert "sentry" in gate.details


class TestNoAliasCollisions:
    def test_no_provider_uses_a_hyphen_or_case_variant_of_another(self):
        gate = cross_manifest.gate_cross_manifest_identity(_ALL)
        assert gate.status == "pass"

    def test_entra_has_no_registered_alias(self):
        assert "microsoft_entra_id" not in {m.provider_id for m in _ALL}
        assert "azure_ad" not in {m.provider_id for m in _ALL}


class TestMaturityCapabilityConsistency:
    def test_capability_consistency_gate_passes(self):
        gate = cross_manifest.gate_cross_manifest_capability_consistency(_ALL)
        assert gate.status == "pass"

    def test_all_four_pilots_declare_partial_maturity(self):
        assert {m.maturity for m in _ALL} == {"partial"}

    def test_capability_gate_fails_when_capability_matrix_maturity_disagrees(self, monkeypatch):
        from types import SimpleNamespace

        real = disc.discover_capability_entry("okta")
        mutated = SimpleNamespace(provider=real.provider, category=real.category, maturity="complete", security=real.security)
        monkeypatch.setattr(
            cross_manifest.disc, "discover_capability_entry", lambda pid: mutated if pid == "okta" else real
        )
        gate = cross_manifest.gate_cross_manifest_capability_consistency(_ALL)
        assert gate.status == "fail"
        assert "okta" in gate.details


class TestNoFutureQueuePresence:
    def test_live_freeze_gate_passes(self):
        gate = cross_manifest.gate_cross_manifest_live_freeze(_ALL)
        assert gate.status == "pass"

    def test_live_freeze_gate_fails_when_a_pilot_reappears_in_backend_queue(self, monkeypatch):
        monkeypatch.setattr(cross_manifest.disc, "discover_recommended_next_providers", lambda: frozenset({"okta"}))
        gate = cross_manifest.gate_cross_manifest_live_freeze(_ALL)
        assert gate.status == "fail"
        assert "okta" in gate.details


class TestNoSecretFieldLeftUnmarked:
    def test_every_manifest_marks_its_secret_looking_fields_sensitive(self):
        markers = ("token", "secret", "password", "key", "pat", "dsn")
        for m in _ALL:
            secret_looking = {f for f in m.credential_fields if any(mk in f.lower() for mk in markers)}
            assert secret_looking <= set(m.sensitive_credential_fields), m.provider_id


class TestExpectedFrontendFormsAndReconnectPaths:
    def test_every_connectable_manifest_declares_a_frontend_form(self):
        for m in _ALL:
            if m.expected_connectable:
                assert m.expected_frontend_form

    def test_every_live_manifest_requires_reconnect(self):
        for m in _ALL:
            if m.expected_live:
                assert m.expected_reconnect

    def test_every_declared_frontend_form_file_exists(self):
        if disc.frontend_root() is None:
            import pytest
            pytest.skip("frontend tree not mounted")
        for m in _ALL:
            if m.expected_frontend_form:
                assert disc.discover_frontend_form_file_exists(m.expected_frontend_form), m.provider_id


class TestSchemaVersionCompatibility:
    def test_every_manifest_declares_version_1(self):
        for m in _ALL:
            assert m.manifest_version == 1


class TestCatalogConsistency:
    def test_catalog_consistency_gate_passes(self):
        gate = cross_manifest.gate_cross_manifest_catalog_consistency(_ALL)
        assert gate.status == "pass"

    def test_catalog_consistency_fails_when_provider_missing_from_sync_service(self, monkeypatch):
        monkeypatch.setattr(cross_manifest.disc, "discover_backend_sync_provider_ids", lambda: frozenset({"entra", "sentry", "snowflake"}))
        gate = cross_manifest.gate_cross_manifest_catalog_consistency(_ALL)
        assert gate.status == "fail"
        assert "okta" in gate.details


class TestFindingUniqueness:
    def test_finding_uniqueness_gate_passes(self):
        gate = cross_manifest.gate_cross_manifest_finding_uniqueness(_ALL)
        assert gate.status == "pass"

    def test_finding_uniqueness_fails_on_cross_provider_duplicate(self):
        from types import SimpleNamespace

        # The real ProviderCertificationManifest dataclass validates that
        # every rule ID starts with "<provider_id>_" at construction time
        # (proving that scenario structurally can't happen for a real
        # manifest) — so this test uses a minimal stand-in exposing only
        # the two attributes gate_cross_manifest_finding_uniqueness reads,
        # to exercise the CROSS-manifest duplicate-detection logic itself
        # in isolation from that per-manifest validation.
        duplicated_okta = SimpleNamespace(
            provider_id="okta",
            security_finding_rule_ids=OKTA_MANIFEST.security_finding_rule_ids + ("sentry_active_organization_admin",),
        )
        gate = cross_manifest.gate_cross_manifest_finding_uniqueness((duplicated_okta, SENTRY_MANIFEST))
        assert gate.status == "fail"
        assert "sentry_active_organization_admin" in gate.details


class TestCrossManifestGatesAttachedToEveryResult:
    def test_every_provider_result_includes_all_cross_manifest_gates(self):
        for pid in ("sentry", "snowflake", "okta", "entra"):
            result = runner.certify_provider(pid)
            gate_ids = {g.gate_id for g in result.gates}
            for expected in (
                "cross_manifest_identity",
                "cross_manifest_capability_consistency",
                "cross_manifest_finding_uniqueness",
                "cross_manifest_catalog_consistency",
                "cross_manifest_live_freeze",
            ):
                assert expected in gate_ids, f"{pid} missing {expected}"

    def test_cross_manifest_gate_status_identical_across_providers(self):
        results = {pid: runner.certify_provider(pid) for pid in ("sentry", "okta")}
        for gate_id in ("cross_manifest_identity", "cross_manifest_catalog_consistency"):
            statuses = {next(g for g in r.gates if g.gate_id == gate_id).status for r in results.values()}
            assert len(statuses) == 1
