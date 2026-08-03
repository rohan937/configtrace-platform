"""Provider-expansion freeze — global certification gate tests.

This is a repository-wide invariant, not owned by any single provider:
RECOMMENDED_NEXT_PROVIDERS must be empty, no frontend future-provider
queue may recommend an unlaunched provider, Sentry (the final planned
provider) must not be presented as future work, and the framework's own
summary text must say expansion is frozen.
"""

from __future__ import annotations

from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification import runner


class TestFreezeGateCurrentState:
    def test_backend_queue_is_empty(self):
        assert disc.discover_recommended_next_providers() == frozenset()

    def test_planned_next_stage_says_frozen(self):
        assert "frozen" in disc.discover_planned_next_stage_text().lower()

    def test_frontend_future_queue_empty_or_absent(self):
        queue = disc.discover_frontend_future_provider_queue()
        if queue is not None:
            assert queue == frozenset()

    def test_global_gate_passes(self):
        gate = gates.gate_provider_expansion_freeze()
        assert gate.status == "pass"
        assert gate.dimension == "provider_expansion_freeze"
        assert gate.blocking is True


class TestFreezeGateIsAttachedToEveryProviderResult:
    def test_sentry_result_includes_freeze_gate(self):
        result = runner.certify_provider("sentry")
        assert any(g.gate_id == "provider_expansion_freeze" for g in result.gates)

    def test_snowflake_result_includes_freeze_gate(self):
        result = runner.certify_provider("snowflake")
        assert any(g.gate_id == "provider_expansion_freeze" for g in result.gates)

    def test_freeze_gate_status_identical_across_providers(self):
        """The freeze gate is a global fact — it must resolve identically
        regardless of which provider is being certified."""
        sentry_gate = next(g for g in runner.certify_provider("sentry").gates if g.gate_id == "provider_expansion_freeze")
        snowflake_gate = next(g for g in runner.certify_provider("snowflake").gates if g.gate_id == "provider_expansion_freeze")
        assert sentry_gate.status == snowflake_gate.status == "pass"


class TestFreezeGateNegativeMutations:
    def test_fails_if_backend_queue_gains_an_entry(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_recommended_next_providers", lambda: frozenset({"some_future_provider"}))
        gate = gates.gate_provider_expansion_freeze()
        assert gate.status == "fail"

    def test_fails_if_sentry_reappears_in_backend_queue(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_recommended_next_providers", lambda: frozenset({"sentry"}))
        gate = gates.gate_provider_expansion_freeze()
        assert gate.status == "fail"
        assert "sentry" in gate.details

    def test_fails_if_planned_next_stage_stops_saying_frozen(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_planned_next_stage_text", lambda: "M91A: Next Provider Foundation")
        gate = gates.gate_provider_expansion_freeze()
        assert gate.status == "fail"

    def test_fails_if_frontend_future_queue_gains_sentry(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_frontend_future_provider_queue", lambda: frozenset({"Sentry"}))
        gate = gates.gate_provider_expansion_freeze()
        assert gate.status == "fail"
        assert "Sentry" in gate.details

    def test_fails_if_frontend_future_queue_gains_any_provider(self, monkeypatch):
        monkeypatch.setattr(disc, "discover_frontend_future_provider_queue", lambda: frozenset({"SomeNewProvider"}))
        gate = gates.gate_provider_expansion_freeze()
        assert gate.status == "fail"

    def test_certify_provider_fails_overall_if_freeze_gate_fails(self, monkeypatch):
        """The freeze gate is blocking — if it fails, the provider's
        overall certification must also fail, even if every per-provider
        gate passes."""
        monkeypatch.setattr(disc, "discover_recommended_next_providers", lambda: frozenset({"sentry"}))
        result = runner.certify_provider("sentry")
        assert result.overall_status == "fail"
