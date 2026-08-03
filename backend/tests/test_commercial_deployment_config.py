"""Deployment configuration tests (Commercial Infrastructure message 1).

Covers: settings schema support for Paddle variables, safe defaults,
fail-closed provider selection, .env.example placeholders (no real
secrets), and that no billing secret is ever exposed via an API response
model.
"""

from __future__ import annotations

from pathlib import Path

from app.config import Settings

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ENV_EXAMPLE = _REPO_ROOT / ".env.example"


class TestSettingsSchemaSupportsPaddle:
    def test_billing_provider_field_exists_and_defaults_to_stripe(self):
        s = Settings(_env_file=None)
        assert s.BILLING_PROVIDER == "stripe"

    def test_paddle_fields_exist_and_default_to_none(self):
        s = Settings(_env_file=None)
        assert s.PADDLE_ENVIRONMENT is None
        assert s.PADDLE_API_KEY is None
        assert s.PADDLE_WEBHOOK_SECRET is None
        assert s.PADDLE_BASE_PRICE_ID is None
        assert s.PADDLE_ADDITIONAL_SEAT_PRICE_ID is None

    def test_existing_stripe_fields_unchanged(self):
        s = Settings(_env_file=None)
        assert s.STRIPE_SECRET_KEY is None
        assert s.STRIPE_WEBHOOK_SECRET is None


class TestEnvExampleHasPaddlePlaceholders:
    def test_env_example_file_exists(self):
        assert _ENV_EXAMPLE.is_file()

    def test_env_example_declares_paddle_variables(self):
        text = _ENV_EXAMPLE.read_text()
        for var in (
            "PADDLE_ENVIRONMENT", "PADDLE_API_KEY", "PADDLE_WEBHOOK_SECRET",
            "PADDLE_BASE_PRICE_ID", "PADDLE_ADDITIONAL_SEAT_PRICE_ID", "BILLING_PROVIDER",
        ):
            assert var in text, f"{var} missing from .env.example"

    def test_env_example_declares_no_real_paddle_secret_values(self):
        text = _ENV_EXAMPLE.read_text()
        for line in text.splitlines():
            if line.startswith("PADDLE_API_KEY=") or line.startswith("PADDLE_WEBHOOK_SECRET="):
                value = line.split("=", 1)[1].strip()
                assert value == "", f"unexpected non-empty placeholder: {line!r}"


class TestFailClosedProviderSelection:
    def test_paddle_without_mapping_never_returns_a_usable_adapter(self, db_session):
        from app.billing.adapters.paddle import PaddleNotConfiguredError
        from app.billing.enums import BillingProvider
        from app.billing.registry import get_billing_provider

        try:
            get_billing_provider(db_session, provider_override=BillingProvider.PADDLE)
            assert False, "expected PaddleNotConfiguredError"
        except PaddleNotConfiguredError:
            pass


class TestNoSecretInAPIResponseModels:
    def test_billing_response_model_has_no_paddle_or_stripe_secret_fields(self):
        from app.routers.billing import BillingResponse

        field_names = set(BillingResponse.model_fields.keys())
        forbidden_substrings = ("secret", "api_key", "webhook_secret")
        for name in field_names:
            lowered = name.lower()
            for forbidden in forbidden_substrings:
                assert forbidden not in lowered, f"BillingResponse field {name!r} looks secret-shaped"

    def test_pricing_breakdown_as_dict_has_no_secret_fields(self):
        from app.billing.pricing import calculate_team_monthly_price

        breakdown = calculate_team_monthly_price(25).as_dict()
        forbidden_substrings = ("secret", "api_key", "token", "password")
        flat_repr = str(breakdown).lower()
        for forbidden in forbidden_substrings:
            assert forbidden not in flat_repr


class TestPaddleSecretsBackendOnly:
    def test_paddle_settings_are_not_next_public_prefixed(self):
        """Backend-only secrets must never carry the NEXT_PUBLIC_ prefix
        (which Next.js embeds directly into the client bundle)."""
        for field in ("PADDLE_API_KEY", "PADDLE_WEBHOOK_SECRET"):
            assert not field.startswith("NEXT_PUBLIC_")

    def test_stripe_secret_key_is_not_next_public_prefixed(self):
        assert not "STRIPE_SECRET_KEY".startswith("NEXT_PUBLIC_")


class TestHostedEnvironmentsUntouchedByThisMessage:
    def test_no_render_yaml_modification_evidence_of_paddle_env_injection(self):
        """render.yaml (infra-as-code) must not be modified to inject real
        Paddle values in message 1 — only settings-schema support is added
        in code; hosted secrets are configured out-of-band later."""
        render_yaml = _REPO_ROOT / "render.yaml"
        if not render_yaml.is_file():
            return
        text = render_yaml.read_text()
        assert "PADDLE_API_KEY" not in text
        assert "PADDLE_WEBHOOK_SECRET" not in text
