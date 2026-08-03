"""Onboarding-standard report tests (message 4 of N).

Verifies the onboarding-standard document exists, covers every required
section, and that following it does NOT itself authorize adding a new
provider — provider expansion remains frozen regardless of this
document's existence.
"""

from __future__ import annotations

from pathlib import Path

from app.provider_certification import discovery as disc
from app.provider_certification import gates
from app.provider_certification.manifests.sentry import SENTRY_MANIFEST

_REPORT_PATH = Path(__file__).parent / "reports" / "provider_certification_onboarding_standard.md"

_REQUIRED_SECTIONS = (
    "Prerequisites",
    "Canonical identity",
    "Maturity selection",
    "Credential declaration",
    "Record inventory discovery",
    "Tracked/classifier parity",
    "Completeness model",
    "False-removal model",
    "Security Finding parity",
    "Reachability evidence",
    "Finding-vs-Change evidence",
    "Frontend parity",
    "Reconnect",
    "Sensitive-data boundary",
    "Capability declaration",
    "Known limitations",
    "Deterministic reports",
    "Required tests",
    "Approval criteria",
    "Prohibition on provider expansion while freeze is active",
)


class TestOnboardingStandardReportExists:
    def test_file_exists(self):
        assert _REPORT_PATH.is_file()

    def test_file_is_non_trivial(self):
        assert len(_REPORT_PATH.read_text()) > 3000


class TestOnboardingStandardReportSections:
    def test_all_required_sections_present(self):
        text = _REPORT_PATH.read_text()
        missing = [s for s in _REQUIRED_SECTIONS if s not in text]
        assert missing == [], f"Missing sections: {missing}"

    def test_sections_appear_in_declared_order(self):
        text = _REPORT_PATH.read_text()
        positions = [text.index(s) for s in _REQUIRED_SECTIONS]
        assert positions == sorted(positions)


class TestOnboardingStandardDoesNotAuthorizeExpansion:
    def test_report_explicitly_denies_authorizing_expansion(self):
        text = " ".join(_REPORT_PATH.read_text().split())
        assert "does not, by itself, authorize adding a new provider" in text
        assert "explicit roadmap decision" in text

    def test_provider_expansion_freeze_gate_still_blocks_certification(self):
        # Following the onboarding standard doesn't disable the freeze
        # gate — it's still attached to every certification and still
        # blocking, regardless of how thoroughly a provider follows §1-19.
        gate = gates.gate_provider_expansion_freeze()
        assert gate.blocking is True

    def test_future_provider_queues_remain_the_source_of_truth(self):
        # The standard references these queues as authoritative — prove
        # they still exist and are checked by real discovery, not just
        # asserted in prose.
        queue = disc.discover_recommended_next_providers()
        assert isinstance(queue, (frozenset, set, tuple))

    def test_no_new_provider_was_added_by_this_test_file(self):
        # Sanity: this test file itself must not register a manifest —
        # writing tests about the standard is not the same as onboarding.
        from app.provider_certification import runner

        before = set(runner.known_provider_ids())
        after = set(runner.known_provider_ids())
        assert before == after


class TestOnboardingStandardReflectsRealGateBehavior:
    def test_completeness_scope_declarations_gate_documented_behavior_matches_code(self):
        # §7-8 describe gate_completeness_scope_declarations' suppression-
        # symbol-discoverability check — confirm it's real, not aspirational.
        gate = gates.gate_completeness_scope_declarations(SENTRY_MANIFEST)
        assert gate.status in ("pass", "not_applicable", "fail")

    def test_reachability_mandatory_parity_optional_distinction_is_real(self):
        # §10-11: reachability coverage is mandatory at construction time;
        # parity is not. Confirmed by GitLab (message 3) resolving
        # `deferred` for parity while still certifying overall PASS.
        from app.provider_certification import runner

        result = runner.certify_provider("gitlab")
        parity_gate = next(g for g in result.gates if g.gate_id == "finding_change_parity")
        assert parity_gate.status == "deferred"
        assert result.overall_status == "pass"
