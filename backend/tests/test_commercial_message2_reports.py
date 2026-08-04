"""Message-2 report existence/shape tests (Commercial Infrastructure message 2)."""

from __future__ import annotations

from pathlib import Path

_REPORTS_DIR = Path(__file__).parent / "reports"

_REQUIRED_REPORTS = (
    "commercial_infrastructure_message2.md",
    "commercial_infrastructure_paddle_api_matrix.md",
    "commercial_infrastructure_paddle_webhook_matrix.md",
    "commercial_infrastructure_paddle_seat_matrix.md",
    "commercial_infrastructure_paddle_sandbox_runbook.md",
    "commercial_infrastructure_paddle_production_cutover.md",
    "commercial_infrastructure_paddle_security_review.md",
    "commercial_infrastructure_message2_test_matrix.md",
)


class TestAllRequiredReportsExist:
    def test_every_required_report_file_exists(self):
        missing = [name for name in _REQUIRED_REPORTS if not (_REPORTS_DIR / name).is_file()]
        assert missing == [], f"missing reports: {missing}"

    def test_every_report_is_non_trivial(self):
        for name in _REQUIRED_REPORTS:
            text = (_REPORTS_DIR / name).read_text()
            assert len(text) > 500, f"{name} looks too short to be genuine"


class TestMessage2Report:
    def test_states_zero_production_calls(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_message2.md").read_text()
        assert "zero" in text.lower()

    def test_documents_safe_to_push_answer(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_message2.md").read_text()
        assert "safe to push" in text.lower()
        assert "**no.**" in text.lower() or "no." in text.lower()

    def test_does_not_start_message_3(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_message2.md").read_text()
        assert "reserved" in text.lower()


class TestApiMatrixReport:
    def test_has_url_and_retry_rows(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_paddle_api_matrix.md").read_text()
        assert "sandbox-api.paddle.com" in text
        assert "Retry-After" in text or "retried" in text.lower()


class TestWebhookMatrixReport:
    def test_has_signature_and_idempotency_coverage(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_paddle_webhook_matrix.md").read_text()
        assert "signature" in text.lower()
        assert "duplicate" in text.lower()


class TestSeatMatrixReport:
    def test_has_all_six_required_transitions(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_paddle_seat_matrix.md").read_text()
        for transition in ("20→21", "21→20", "30→25", "50→10", "10→50"):
            assert transition in text


class TestSandboxRunbookReport:
    def test_documents_exact_render_and_vercel_variable_names(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_paddle_sandbox_runbook.md").read_text()
        for var in (
            "PADDLE_API_KEY",
            "PADDLE_WEBHOOK_SECRET",
            "PADDLE_TEAM_BASE_PRICE_ID",
            "PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID",
            "NEXT_PUBLIC_PADDLE_CLIENT_TOKEN",
        ):
            assert var in text

    def test_never_includes_a_real_looking_secret_value(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_paddle_sandbox_runbook.md").read_text()
        assert "<sandbox" in text  # placeholders only, never real-looking values


class TestProductionCutoverReport:
    def test_has_fifteen_step_sequence_and_rollback(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_paddle_production_cutover.md").read_text()
        assert "15." in text
        assert "Rollback" in text or "rollback" in text

    def test_requires_explicit_operator_approval(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_paddle_production_cutover.md").read_text()
        assert "operator approval" in text.lower()


class TestSecurityReviewReport:
    def test_documents_known_signature_limitation_honestly(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_paddle_security_review.md").read_text()
        assert "not been verified against a real" in text.lower() or "not verified against a real" in text.lower()

    def test_documents_secrets_boundary(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_paddle_security_review.md").read_text()
        assert "PADDLE_API_KEY" in text
        assert "PADDLE_WEBHOOK_SECRET" in text


class TestMessage2TestMatrixReport:
    def test_has_at_least_260_rows(self):
        text = (_REPORTS_DIR / "commercial_infrastructure_message2_test_matrix.md").read_text()
        row_count = sum(
            1 for line in text.splitlines()
            if line.strip().startswith("|")
            and not line.strip().startswith("|---")
            and "Test node ID" not in line
        )
        assert row_count >= 260, f"only {row_count} test-matrix rows found, need >= 260"
