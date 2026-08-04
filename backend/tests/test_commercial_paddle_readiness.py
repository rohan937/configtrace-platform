"""Paddle configuration validation + production-readiness tests
(Commercial Infrastructure message 2)."""

from __future__ import annotations

from app.billing.paddle_config import requires_paddle_settings, requires_stripe_settings, validate_paddle_configuration
from app.billing.readiness import check_production_readiness
from app.config import Settings


def _settings(**overrides) -> Settings:
    base = {
        "PADDLE_ENVIRONMENT": None, "PADDLE_API_KEY": None, "PADDLE_WEBHOOK_SECRET": None,
        "PADDLE_TEAM_BASE_PRICE_ID": None, "PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID": None,
        "BILLING_PROVIDER": "stripe", "BILLING_GRACE_PERIOD_DAYS": 7,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


class TestEnvironmentValidation:
    def test_missing_environment_is_invalid(self):
        result = validate_paddle_configuration(_settings())
        assert result.valid is False
        assert any(i.field == "PADDLE_ENVIRONMENT" for i in result.issues)

    def test_sandbox_is_valid_value(self):
        result = validate_paddle_configuration(_settings(PADDLE_ENVIRONMENT="sandbox"))
        assert not any(i.field == "PADDLE_ENVIRONMENT" for i in result.issues)

    def test_production_is_valid_value(self):
        result = validate_paddle_configuration(_settings(PADDLE_ENVIRONMENT="production"))
        assert not any(i.field == "PADDLE_ENVIRONMENT" for i in result.issues)

    def test_invalid_environment_string_rejected(self):
        result = validate_paddle_configuration(_settings(PADDLE_ENVIRONMENT="staging"))
        assert any(i.field == "PADDLE_ENVIRONMENT" for i in result.issues)


class TestSandboxTokenPrefixHandling:
    def test_live_looking_key_in_sandbox_flagged(self):
        result = validate_paddle_configuration(
            _settings(PADDLE_ENVIRONMENT="sandbox", PADDLE_API_KEY="apikey_live_something")
        )
        assert any(i.field == "PADDLE_API_KEY" for i in result.issues)

    def test_sandbox_looking_key_in_sandbox_not_flagged(self):
        result = validate_paddle_configuration(
            _settings(PADDLE_ENVIRONMENT="sandbox", PADDLE_API_KEY="apikey_sandbox_something")
        )
        assert not any(i.field == "PADDLE_API_KEY" for i in result.issues)

    def test_sandbox_looking_key_in_production_flagged(self):
        result = validate_paddle_configuration(
            _settings(PADDLE_ENVIRONMENT="production", PADDLE_API_KEY="apikey_sandbox_something")
        )
        assert any(i.field == "PADDLE_API_KEY" for i in result.issues)

    def test_ambiguous_key_not_flagged_either_way(self):
        result = validate_paddle_configuration(
            _settings(PADDLE_ENVIRONMENT="sandbox", PADDLE_API_KEY="apikey_abcdef123456")
        )
        assert not any(i.field == "PADDLE_API_KEY" and "credential" in i.message for i in result.issues)


class TestPriceIdConsistency:
    def test_missing_base_price_flagged(self):
        result = validate_paddle_configuration(_settings(PADDLE_ENVIRONMENT="sandbox"))
        assert any(i.field == "PADDLE_TEAM_BASE_PRICE_ID" for i in result.issues)

    def test_identical_base_and_additional_price_flagged(self):
        result = validate_paddle_configuration(
            _settings(
                PADDLE_ENVIRONMENT="sandbox", PADDLE_TEAM_BASE_PRICE_ID="pri_same",
                PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID="pri_same",
            )
        )
        assert any("must not equal" in i.message for i in result.issues)

    def test_fully_valid_configuration_passes(self):
        result = validate_paddle_configuration(
            _settings(
                PADDLE_ENVIRONMENT="sandbox", PADDLE_API_KEY="apikey_sandbox_x", PADDLE_WEBHOOK_SECRET="whsec_x",
                PADDLE_TEAM_BASE_PRICE_ID="pri_base", PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID="pri_seat",
            )
        )
        assert result.valid is True


class TestNoSecretInValidationErrors:
    def test_api_key_value_never_appears_in_issue_message(self):
        secret_value = "apikey_live_super_secret_value_123"
        result = validate_paddle_configuration(
            _settings(PADDLE_ENVIRONMENT="sandbox", PADDLE_API_KEY=secret_value)
        )
        for issue in result.issues:
            assert secret_value not in issue.message

    def test_webhook_secret_value_never_appears_anywhere(self):
        secret_value = "whsec_super_secret_do_not_leak"
        result = validate_paddle_configuration(_settings(PADDLE_WEBHOOK_SECRET=secret_value))
        for issue in result.issues:
            assert secret_value not in issue.message
            assert secret_value not in issue.field


class TestStripeSettingsNotRequiredWhenPaddleActive:
    def test_stripe_not_required_when_billing_provider_paddle(self):
        assert requires_stripe_settings(_settings(BILLING_PROVIDER="paddle")) is False

    def test_paddle_not_required_when_billing_provider_stripe(self):
        assert requires_paddle_settings(_settings(BILLING_PROVIDER="stripe")) is False

    def test_paddle_required_when_active(self):
        assert requires_paddle_settings(_settings(BILLING_PROVIDER="paddle")) is True

    def test_stripe_required_when_active(self):
        assert requires_stripe_settings(_settings(BILLING_PROVIDER="stripe")) is True


class TestProductionReadinessReport:
    def test_unconfigured_settings_report_unsafe(self):
        report = check_production_readiness(_settings())
        assert report.all_safe is False
        assert report.exit_code == 1

    def test_fully_configured_settings_report_safe(self):
        report = check_production_readiness(
            _settings(
                PADDLE_ENVIRONMENT="sandbox", PADDLE_API_KEY="apikey_sandbox_x", PADDLE_WEBHOOK_SECRET="whsec_x",
                PADDLE_TEAM_BASE_PRICE_ID="pri_base", PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID="pri_seat",
            )
        )
        assert report.all_safe is True
        assert report.exit_code == 0

    def test_report_never_includes_secret_value(self):
        secret_value = "apikey_super_secret_do_not_leak_9999"
        report = check_production_readiness(
            _settings(
                PADDLE_ENVIRONMENT="sandbox", PADDLE_API_KEY=secret_value, PADDLE_WEBHOOK_SECRET="whsec_x",
                PADDLE_TEAM_BASE_PRICE_ID="pri_base", PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID="pri_seat",
            )
        )
        assert secret_value not in str(report.as_dict())

    def test_report_as_dict_is_json_serializable(self):
        import json

        report = check_production_readiness(_settings())
        json.dumps(report.as_dict())

    def test_report_never_calls_a_live_paddle_api(self, monkeypatch):
        """Guard against a future regression: readiness must remain a pure
        offline function — patch httpx to explode if ever called."""
        import httpx

        def _boom(*args, **kwargs):
            raise AssertionError("check_production_readiness must never make an HTTP call")

        monkeypatch.setattr(httpx.Client, "request", _boom)
        check_production_readiness(_settings())  # must not raise
