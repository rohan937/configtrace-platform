"""Discovery-adapter mechanism tests (message 2 of N).

No pilot provider (Sentry, Snowflake, Okta, Entra) currently needs a
discovery adapter — generic discovery already handles all four correctly
(see the four providers' own certification test files). These tests
exercise the ADAPTER MECHANISM itself with synthetic adapters so a future
provider that genuinely needs one has a proven, typed extension point
rather than an untested one.
"""

from __future__ import annotations

from app.provider_certification import adapters as adapt
from app.provider_certification import gates
from app.provider_certification import runner
from app.provider_certification.manifests.sentry import SENTRY_MANIFEST


class TestResolveSetGenericOnly:
    def test_no_hook_returns_generic_unchanged(self):
        generic = frozenset({"a", "b"})
        resolved = adapt.resolve_set(generic, None)
        assert resolved.value == generic
        assert resolved.agreement is True
        assert resolved.augmented is False
        assert resolved.contradiction_note is None

    def test_hook_returning_none_defers_to_generic(self):
        generic = frozenset({"a", "b"})
        resolved = adapt.resolve_set(generic, lambda: None)
        assert resolved.value == generic
        assert resolved.agreement is True


class TestResolveSetAgreement:
    def test_hook_matching_generic_is_agreement(self):
        generic = frozenset({"a", "b"})
        resolved = adapt.resolve_set(generic, lambda: frozenset({"a", "b"}))
        assert resolved.value == generic
        assert resolved.agreement is True
        assert resolved.augmented is False
        assert resolved.contradiction_note is None


class TestResolveSetAugmentation:
    def test_hook_superset_is_augmentation_not_silent_override(self):
        generic = frozenset({"a", "b"})
        resolved = adapt.resolve_set(generic, lambda: frozenset({"a", "b", "c"}))
        assert resolved.value == frozenset({"a", "b", "c"})
        assert resolved.agreement is False
        assert resolved.augmented is True
        assert resolved.contradiction_note is not None
        assert "'c'" in resolved.contradiction_note


class TestResolveSetContradiction:
    def test_hook_missing_a_generic_symbol_is_contradiction(self):
        generic = frozenset({"a", "b"})
        resolved = adapt.resolve_set(generic, lambda: frozenset({"a"}))
        assert resolved.value == generic, "contradiction must keep the safe generic result, never silently trust the adapter"
        assert resolved.agreement is False
        assert resolved.augmented is False
        assert resolved.contradiction_note is not None
        assert "CONTRADICTION" in resolved.contradiction_note

    def test_hook_with_unrelated_extra_and_missing_symbols_is_contradiction(self):
        generic = frozenset({"a", "b"})
        resolved = adapt.resolve_set(generic, lambda: frozenset({"a", "z"}))
        assert resolved.value == generic
        assert resolved.contradiction_note is not None
        assert "CONTRADICTION" in resolved.contradiction_note
        assert "'b'" in resolved.contradiction_note
        assert "'z'" in resolved.contradiction_note

    def test_hook_returning_empty_set_when_generic_nonempty_is_contradiction(self):
        generic = frozenset({"a"})
        resolved = adapt.resolve_set(generic, lambda: frozenset())
        assert resolved.value == generic
        assert resolved.contradiction_note is not None


class TestAdapterRegistry:
    def test_unregistered_provider_has_no_adapter(self):
        assert adapt.get_adapter("nonexistent_provider_xyz") is None

    def test_register_and_retrieve_adapter(self):
        adapter = adapt.ProviderDiscoveryAdapter(provider_id="_test_adapter_provider")
        adapt.register_adapter(adapter)
        try:
            assert adapt.get_adapter("_test_adapter_provider") is adapter
            assert "_test_adapter_provider" in adapt.registered_adapter_provider_ids()
        finally:
            del adapt._ADAPTERS["_test_adapter_provider"]

    def test_deterministic_provider_id_listing(self):
        a1 = adapt.ProviderDiscoveryAdapter(provider_id="_zzz_test")
        a2 = adapt.ProviderDiscoveryAdapter(provider_id="_aaa_test")
        adapt.register_adapter(a1)
        adapt.register_adapter(a2)
        try:
            ids = adapt.registered_adapter_provider_ids()
            assert ids == tuple(sorted(ids))
        finally:
            del adapt._ADAPTERS["_zzz_test"]
            del adapt._ADAPTERS["_aaa_test"]


class TestNoPilotAdapterNeeded:
    """Confirms generic discovery is sufficient for nine of the eleven
    pilots. Kubernetes (message 3) and Cloudflare (message 4) are the
    exceptions — each registers a real adapter for genuinely different
    architectural patterns (unprefixed credential fields for both;
    grouped classifier dispatch for Kubernetes, a split-across-two-
    modules classifier for Cloudflare) — see ``manifests/kubernetes.py``
    and ``manifests/cloudflare.py``."""

    def test_no_adapter_registered_for_non_kubernetes_pilots(self):
        runner._ensure_manifests_loaded()
        for pid in runner.known_provider_ids():
            if pid in ("kubernetes", "cloudflare"):
                continue
            assert adapt.get_adapter(pid) is None

    def test_kubernetes_has_a_registered_adapter(self):
        runner._ensure_manifests_loaded()
        assert adapt.get_adapter("kubernetes") is not None

    def test_cloudflare_has_a_registered_adapter(self):
        runner._ensure_manifests_loaded()
        assert adapt.get_adapter("cloudflare") is not None


class TestGateAdapterConsistency:
    def test_not_applicable_when_no_adapter_registered(self):
        gate = gates.gate_adapter_consistency(SENTRY_MANIFEST)
        assert gate.status == "not_applicable"

    def test_pass_when_adapter_agrees_with_generic(self):
        adapter = adapt.ProviderDiscoveryAdapter(
            provider_id="sentry",
            discover_record_types=lambda: frozenset(SENTRY_MANIFEST.expected_record_types),
        )
        adapt.register_adapter(adapter)
        try:
            gate = gates.gate_adapter_consistency(SENTRY_MANIFEST)
            assert gate.status == "pass"
        finally:
            del adapt._ADAPTERS["sentry"]

    def test_pass_when_adapter_augments_generic(self):
        augmented = frozenset(SENTRY_MANIFEST.expected_record_types) | {"sentry_extra_alias_type"}
        adapter = adapt.ProviderDiscoveryAdapter(
            provider_id="sentry",
            discover_record_types=lambda: augmented,
        )
        adapt.register_adapter(adapter)
        try:
            gate = gates.gate_adapter_consistency(SENTRY_MANIFEST)
            assert gate.status == "pass"
            assert "augmented" in gate.details
        finally:
            del adapt._ADAPTERS["sentry"]

    def test_fail_when_adapter_contradicts_generic(self):
        contradicted = frozenset(SENTRY_MANIFEST.expected_record_types) - {"sentry_organization"}
        adapter = adapt.ProviderDiscoveryAdapter(
            provider_id="sentry",
            discover_record_types=lambda: contradicted,
        )
        adapt.register_adapter(adapter)
        try:
            gate = gates.gate_adapter_consistency(SENTRY_MANIFEST)
            assert gate.status == "fail"
            assert "CONTRADICTION" in gate.details
        finally:
            del adapt._ADAPTERS["sentry"]


class TestDeterministicOutput:
    def test_resolve_set_is_deterministic_across_calls(self):
        generic = frozenset({"a", "b", "c"})
        hook = lambda: frozenset({"a", "b", "c", "d"})
        r1 = adapt.resolve_set(generic, hook)
        r2 = adapt.resolve_set(generic, hook)
        assert r1 == r2
