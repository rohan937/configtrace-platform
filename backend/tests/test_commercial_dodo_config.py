"""Dodo configuration + readiness tests (Dodo Payments message 1)."""

from __future__ import annotations

import httpx
import pytest

from app.billing.dodo_config import (
    check_dodo_readiness,
    requires_dodo_settings,
    validate_dodo_configuration,
)


def _configure(monkeypatch, **overrides):
    from app import config

    defaults = dict(
        DODO_ENVIRONMENT="test",
        DODO_API_KEY="apikey_test_dummy",
        DODO_WEBHOOK_SECRET="whsec_dGVzdHNlY3JldA==",
        DODO_PRO_PRODUCT_ID="prod_pro_test",
        DODO_TEAM_PRODUCT_ID="prod_team_test",
        DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID="addon_seat_test",
        BILLING_GRACE_PERIOD_DAYS=7,
    )
    defaults.update(overrides)
    for key, value in defaults.items():
        monkeypatch.setattr(config.settings, key, value)
    return config.settings


class TestEnvironmentValidation:
    def test_missing_environment_is_invalid(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_ENVIRONMENT=None)
        result = validate_dodo_configuration(settings)
        assert result.valid is False
        assert any(i.field == "DODO_ENVIRONMENT" for i in result.issues)

    def test_test_is_valid_value(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_ENVIRONMENT="test")
        assert settings.dodo_environment_normalized == "test"

    def test_live_is_valid_value(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_ENVIRONMENT="live")
        assert settings.dodo_environment_normalized == "live"

    def test_invalid_environment_string_rejected(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_ENVIRONMENT="sandbox")
        assert settings.dodo_environment_normalized == "not_configured"

    def test_dodo_official_test_mode_value_accepted_and_normalized(self, monkeypatch):
        """Post-implementation audit finding: Dodo's own official Python
        and Node.js SDKs use environment="test_mode"/"live_mode" as their
        canonical values, not "test"/"live". ConfigTrace must accept an
        operator pasting Dodo's own documented example value."""
        settings = _configure(monkeypatch, DODO_ENVIRONMENT="test_mode")
        assert settings.dodo_environment_normalized == "test"

    def test_dodo_official_live_mode_value_accepted_and_normalized(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_ENVIRONMENT="live_mode")
        assert settings.dodo_environment_normalized == "live"

    def test_test_mode_value_is_case_insensitive(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_ENVIRONMENT="TEST_MODE")
        assert settings.dodo_environment_normalized == "test"

    def test_live_mode_value_is_case_insensitive(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_ENVIRONMENT="Live_Mode")
        assert settings.dodo_environment_normalized == "live"

    def test_test_mode_configuration_passes_full_validation(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_ENVIRONMENT="test_mode")
        result = validate_dodo_configuration(settings)
        assert result.valid is True

    def test_dodo_environment_normalized_never_returns_raw_test_mode_string(self, monkeypatch):
        """The normalized value must always be the short canonical form
        ("test"/"live"), never the raw "test_mode"/"live_mode" input —
        every other module in this codebase (dodo_client base-url
        selection, registry.py's catalog mapping) depends on receiving
        exactly "test" or "live"."""
        settings = _configure(monkeypatch, DODO_ENVIRONMENT="test_mode")
        assert settings.dodo_environment_normalized in ("test", "live")
        assert settings.dodo_environment_normalized != "test_mode"


class TestWebhookSecretFormat:
    def test_missing_secret_flagged(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_WEBHOOK_SECRET=None)
        result = validate_dodo_configuration(settings)
        assert any(i.field == "DODO_WEBHOOK_SECRET" for i in result.issues)

    def test_secret_without_whsec_prefix_flagged(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_WEBHOOK_SECRET="not_the_right_prefix")
        result = validate_dodo_configuration(settings)
        assert any(i.field == "DODO_WEBHOOK_SECRET" for i in result.issues)

    def test_secret_with_whsec_prefix_passes(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_WEBHOOK_SECRET="whsec_dGVzdHNlY3JldA==")
        result = validate_dodo_configuration(settings)
        assert not any(i.field == "DODO_WEBHOOK_SECRET" for i in result.issues)


class TestCatalogIdConsistency:
    def test_missing_pro_product_flagged(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_PRO_PRODUCT_ID=None)
        result = validate_dodo_configuration(settings)
        assert any(i.field == "DODO_PRO_PRODUCT_ID" for i in result.issues)

    def test_missing_team_product_flagged(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_TEAM_PRODUCT_ID=None)
        result = validate_dodo_configuration(settings)
        assert any(i.field == "DODO_TEAM_PRODUCT_ID" for i in result.issues)

    def test_missing_addon_flagged(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID=None)
        result = validate_dodo_configuration(settings)
        assert any(i.field == "DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID" for i in result.issues)

    def test_identical_pro_and_team_product_flagged(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_TEAM_PRODUCT_ID="prod_same", DODO_PRO_PRODUCT_ID="prod_same")
        result = validate_dodo_configuration(settings)
        assert any(i.field == "DODO_PRO_PRODUCT_ID" for i in result.issues)

    def test_fully_valid_configuration_passes(self, monkeypatch):
        settings = _configure(monkeypatch)
        result = validate_dodo_configuration(settings)
        assert result.valid is True
        assert result.issues == ()


class TestNoSecretInValidationErrors:
    def test_api_key_value_never_appears_in_issue_message(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_API_KEY=None)
        result = validate_dodo_configuration(settings)
        for issue in result.issues:
            assert "apikey_test_dummy" not in issue.message

    def test_webhook_secret_value_never_appears_anywhere(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_WEBHOOK_SECRET="whsec_badformat")
        result = validate_dodo_configuration(settings)
        for issue in result.issues:
            assert "badformat" not in issue.message
            assert "whsec_" not in issue.message or issue.field == "DODO_WEBHOOK_SECRET"


class TestRequiresDodoSettings:
    def test_not_required_when_billing_provider_stripe(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")
        assert requires_dodo_settings(config.settings) is False

    def test_required_when_billing_provider_dodo(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "dodo")
        assert requires_dodo_settings(config.settings) is True


class TestReadinessReport:
    def test_unconfigured_settings_report_unsafe(self, monkeypatch):
        settings = _configure(monkeypatch, DODO_API_KEY=None, DODO_WEBHOOK_SECRET=None)
        report = check_dodo_readiness(settings)
        assert report.all_present is False
        assert report.exit_code == 1

    def test_fully_configured_settings_report_safe(self, monkeypatch):
        settings = _configure(monkeypatch)
        report = check_dodo_readiness(settings)
        assert report.all_present is True
        assert report.exit_code == 0

    def test_report_never_includes_a_secret_value(self, monkeypatch):
        settings = _configure(monkeypatch)
        report = check_dodo_readiness(settings)
        as_text = str(report.as_dict())
        assert "apikey_test_dummy" not in as_text
        assert "dGVzdHNlY3JldA" not in as_text

    def test_report_as_dict_is_json_serializable(self, monkeypatch):
        import json

        settings = _configure(monkeypatch)
        report = check_dodo_readiness(settings)
        json.dumps(report.as_dict())  # raises if not serializable

    def test_report_never_calls_a_live_dodo_api(self, monkeypatch):
        settings = _configure(monkeypatch)

        def _boom(*args, **kwargs):
            raise AssertionError("check_dodo_readiness must never make an HTTP call")

        monkeypatch.setattr(httpx.Client, "request", _boom)
        check_dodo_readiness(settings)  # must not raise the AssertionError above

    def test_readiness_confirms_not_routing_to_dodo_by_default(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "BILLING_PROVIDER", "stripe")
        settings = _configure(monkeypatch)
        report = check_dodo_readiness(settings)
        not_routing_check = next(c for c in report.checks if c.name == "not_routing_production_to_dodo")
        assert not_routing_check.present is True


class TestRegistryEndToEndWithOfficialEnvironmentValues:
    """Post-implementation audit: prove the "test_mode"/"live_mode" fix
    actually propagates all the way to the constructed client's base URL,
    not just the settings property in isolation."""

    def test_registry_builds_test_base_url_from_official_test_mode_value(self, monkeypatch):
        from app import config
        from app.billing.registry import _build_dodo_adapter

        settings = _configure(monkeypatch, DODO_ENVIRONMENT="test_mode")
        adapter = _build_dodo_adapter()
        assert adapter.is_configured is True
        assert adapter._client._config.base_url == "https://test.dodopayments.com"

    def test_registry_builds_live_base_url_from_official_live_mode_value(self, monkeypatch):
        from app import config
        from app.billing.registry import _build_dodo_adapter

        settings = _configure(monkeypatch, DODO_ENVIRONMENT="live_mode")
        adapter = _build_dodo_adapter()
        assert adapter.is_configured is True
        assert adapter._client._config.base_url == "https://live.dodopayments.com"
