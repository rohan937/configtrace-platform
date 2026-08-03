"""Message-1 report existence/shape tests (Commercial Infrastructure message 1)."""

from __future__ import annotations

from pathlib import Path

_REPORTS_DIR = Path(__file__).parent / "reports"

_REQUIRED_REPORTS = (
    "commercial_infrastructure_message1.md",
    "commercial_infrastructure_stripe_inventory.md",
    "commercial_infrastructure_deployment_inventory.md",
    "commercial_infrastructure_paddle_cutover.md",
    "commercial_infrastructure_pricing_matrix.md",
    "commercial_infrastructure_test_matrix.md",
)


class TestAllRequiredReportsExist:
    def test_every_required_report_file_exists(self):
        missing = [name for name in _REQUIRED_REPORTS if not (_REPORTS_DIR / name).is_file()]
        assert missing == [], f"missing reports: {missing}"

    def test_every_report_is_non_trivial(self):
        for name in _REQUIRED_REPORTS:
            text = (_REPORTS_DIR / name).read_text()
            assert len(text) > 500, f"{name} looks too short to be genuine"


class TestStripeInventoryReport:
    def test_mentions_provider_neutral_scope_distinction(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_stripe_inventory.md").read_text()
        assert "security-monitoring" in text.lower() or "security monitoring" in text.lower()

    def test_documents_actual_current_team_price_not_the_spec_assumption(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_stripe_inventory.md").read_text()
        assert "$40" in text  # the real current price, honestly documented


class TestDeploymentInventoryReport:
    def test_documents_paddle_env_vars_planned_not_deployed(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_deployment_inventory.md").read_text()
        for var in ("PADDLE_API_KEY", "PADDLE_WEBHOOK_SECRET", "PADDLE_BASE_PRICE_ID"):
            assert var in text

    def test_documents_existing_stripe_env_vars(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_deployment_inventory.md").read_text()
        assert "STRIPE_SECRET_KEY" in text
        assert "STRIPE_WEBHOOK_SECRET" in text


class TestPaddleCutoverReport:
    def test_has_all_five_phases(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_paddle_cutover.md").read_text()
        for phase in ("Phase A", "Phase B", "Phase C", "Phase D", "Phase E"):
            assert phase in text

    def test_documents_rollback_strategy(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_paddle_cutover.md").read_text()
        assert "Rollback" in text or "rollback" in text


class TestMessage1Report:
    def test_states_provider_neutral_architecture(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_message1.md").read_text()
        assert "provider-neutral" in text.lower()

    def test_documents_zero_member_decision(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_message1.md").read_text()
        assert "zero" in text.lower()

    def test_does_not_claim_paddle_api_was_called(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_message1.md").read_text()
        assert "zero external calls" in text.lower() or "no external" in text.lower() or "0 external" in text.lower()


class TestPricingMatrixReport:
    def test_has_at_least_boundary_rows(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_pricing_matrix.md").read_text()
        for boundary in ("20", "21", "$30", "$35"):
            assert boundary in text


class TestTestMatrixReport:
    def test_has_at_least_180_rows(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_test_matrix.md").read_text()
        # Count markdown table data rows (lines starting with "| " that are
        # not header/separator rows) across the whole document.
        row_count = sum(
            1 for line in text.splitlines()
            if line.strip().startswith("|")
            and not line.strip().startswith("|---")
            and "Case" not in line
            and "---" not in line
        )
        assert row_count >= 180, f"only {row_count} test-matrix rows found, need >= 180"
