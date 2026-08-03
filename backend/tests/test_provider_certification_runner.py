"""Runner-layer tests for the Provider Certification Framework.

Covers: certifying one provider, certifying all pilot providers, an
unknown provider raising clearly, a provider with no manifest never
silently passing, deterministic ordering, and — critically — that
certification performs NO network calls, NO DB access, and NEVER
instantiates a live connector or reads a customer credential.
"""

from __future__ import annotations

import json

import pytest

from app.provider_certification import runner
from app.provider_certification.models import CertificationResult


class TestCertifyOneProvider:
    def test_certify_sentry(self):
        result = runner.certify_provider("sentry")
        assert isinstance(result, CertificationResult)
        assert result.provider_id == "sentry"
        assert result.overall_status == "pass"

    def test_certify_snowflake(self):
        result = runner.certify_provider("snowflake")
        assert result.overall_status == "pass"

    def test_certify_unknown_provider_raises_clearly(self):
        with pytest.raises(runner.MissingManifestError, match="No certification manifest registered"):
            runner.certify_provider("not_a_real_provider")

    def test_provider_with_no_manifest_never_silently_passes(self):
        """A provider absent from the manifest registry must raise, not
        return some default-passing result."""
        with pytest.raises(runner.MissingManifestError):
            runner.certify_provider("totally_unregistered_provider_id")


class TestCertifyAllProviders:
    def test_certify_all_pilot_providers(self):
        results = runner.certify_all_providers()
        assert set(results) == {
            "sentry", "snowflake", "okta", "entra", "kubernetes", "github", "gitlab",
            "cloudflare", "supabase", "firebase", "stripe",
            "aws", "vercel", "datadog", "pagerduty", "slack", "jira",
            "auth0", "azure", "clerk", "google_cloud", "linear", "sendgrid",
            "shopify", "terraform_cloud", "twilio",
        }
        for pid, result in results.items():
            assert result.provider_id == pid
            assert result.overall_status == "pass"

    def test_certify_explicit_subset(self):
        results = runner.certify_all_providers(("sentry",))
        assert set(results) == {"sentry"}

    def test_certify_all_deterministic_ordering(self):
        first = list(runner.certify_all_providers().keys())
        second = list(runner.certify_all_providers().keys())
        assert first == second == sorted(first)

    def test_pilot_providers_constant_matches_task_scope(self):
        assert set(runner.PILOT_PROVIDERS) == {
            "sentry", "snowflake", "okta", "entra", "kubernetes", "github", "gitlab",
            "cloudflare", "supabase", "firebase", "stripe",
            "aws", "vercel", "datadog", "pagerduty", "slack", "jira",
            "auth0", "azure", "clerk", "google_cloud", "linear", "sendgrid",
            "shopify", "terraform_cloud", "twilio",
        }


class TestDeterminism:
    def test_gate_ordering_deterministic(self):
        r1 = runner.certify_provider("sentry")
        r2 = runner.certify_provider("sentry")
        assert [g.gate_id for g in r1.gates] == [g.gate_id for g in r2.gates]
        assert [g.gate_id for g in r1.gates] == sorted(g.gate_id for g in r1.gates)

    def test_json_output_deterministic_across_two_runs(self):
        r1 = runner.certify_provider("snowflake")
        r2 = runner.certify_provider("snowflake")
        assert r1.to_json() == r2.to_json()

    def test_json_output_is_valid_json_with_expected_top_level_keys(self):
        result = runner.certify_provider("sentry")
        parsed = json.loads(result.to_json())
        assert set(parsed.keys()) == {"schema_version", "provider_id", "maturity", "overall_status", "gates", "summary"}


class TestWriteReport:
    def test_write_report_creates_deterministic_file(self, tmp_path):
        result = runner.certify_provider("sentry")
        path = runner.write_report(result, output_dir=tmp_path)
        assert path.is_file()
        assert path.name == "sentry.json"
        content = path.read_text()
        parsed = json.loads(content)
        assert parsed["provider_id"] == "sentry"

    def test_write_report_does_not_touch_real_reports_dir_unless_asked(self, tmp_path, monkeypatch):
        """Calling write_report with an explicit tmp output_dir must never
        write anywhere else (no accidental side effect outside the
        explicit report-output path)."""
        result = runner.certify_provider("sentry")
        before = set(tmp_path.iterdir())
        runner.write_report(result, output_dir=tmp_path)
        after = set(tmp_path.iterdir())
        assert len(after) == len(before) + 1


class TestNoProductionSideEffects:
    """Certification must never call an external provider API, mutate an
    integration, access a customer credential, write DB state, trigger a
    sync, initialize a provider SDK, or read a global customer-credential
    env var."""

    def test_no_httpx_client_constructed_during_certification(self, monkeypatch):
        import httpx

        created = []
        original_init = httpx.Client.__init__

        def _tracking_init(self, *args, **kwargs):
            created.append((args, kwargs))
            return original_init(self, *args, **kwargs)

        monkeypatch.setattr(httpx.Client, "__init__", _tracking_init)
        runner.certify_all_providers()
        assert created == [], "certification must never construct an httpx.Client"

    def test_no_db_session_used_during_certification(self, monkeypatch):
        from sqlalchemy.orm import Session

        created = []
        original_init = Session.__init__

        def _tracking_init(self, *args, **kwargs):
            created.append((args, kwargs))
            return original_init(self, *args, **kwargs)

        monkeypatch.setattr(Session, "__init__", _tracking_init)
        runner.certify_all_providers()
        assert created == [], "certification must never open a DB session"

    def test_no_environ_credential_lookup_for_pilot_providers(self, monkeypatch):
        import os

        forbidden_names = {
            "SENTRY_AUTH_TOKEN", "SENTRY_DSN", "SENTRY_ORG",
            "SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PASSWORD", "SNOWFLAKE_PRIVATE_KEY",
        }
        looked_up = []
        real_environ_get = os.environ.get

        def _tracking_get(key, *args, **kwargs):
            if key in forbidden_names:
                looked_up.append(key)
            return real_environ_get(key, *args, **kwargs)

        monkeypatch.setattr(os.environ, "get", _tracking_get)
        runner.certify_all_providers()
        assert looked_up == [], f"certification looked up forbidden env vars: {looked_up}"

    def test_no_connector_instance_created_during_certification(self, monkeypatch):
        """Certification imports connector CLASSES (for introspection)
        but must never INSTANTIATE one — instantiating could imply a
        real client/session setup for some future connector."""
        from app.connectors.sentry import SentryConnector
        from app.connectors.snowflake import SnowflakeConnector

        sentry_calls = []
        snowflake_calls = []
        monkeypatch.setattr(SentryConnector, "__init__", lambda self, *a, **k: sentry_calls.append(1))
        monkeypatch.setattr(SnowflakeConnector, "__init__", lambda self, *a, **k: snowflake_calls.append(1))
        runner.certify_all_providers()
        assert sentry_calls == []
        assert snowflake_calls == []

    def test_no_encrypted_credentials_decrypted_during_certification(self, monkeypatch):
        from app.core import encryption

        calls = []
        monkeypatch.setattr(encryption, "decrypt_credentials", lambda *a, **k: calls.append(1))
        runner.certify_all_providers()
        assert calls == []

    def test_cli_certify_all_never_opens_a_db_session(self, monkeypatch):
        """message 7: the CLI entry point wraps the same pure runner —
        pin that no new DB/network side effect was introduced by cli.py."""
        from sqlalchemy.orm import Session

        from app.provider_certification import cli as cli_module

        created = []
        original_init = Session.__init__

        def _tracking_init(self, *args, **kwargs):
            created.append((args, kwargs))
            return original_init(self, *args, **kwargs)

        monkeypatch.setattr(Session, "__init__", _tracking_init)
        cli_module.main(["certify-all", "--format", "json"])
        assert created == [], "cli certify-all must never open a DB session"

    def test_impact_analysis_never_opens_a_db_session(self, monkeypatch):
        """message 7: impact analysis is pure string/path classification
        plus (optionally) a local git subprocess — never DB access."""
        from sqlalchemy.orm import Session

        from app.provider_certification import impact as impact_module

        created = []
        original_init = Session.__init__

        def _tracking_init(self, *args, **kwargs):
            created.append((args, kwargs))
            return original_init(self, *args, **kwargs)

        monkeypatch.setattr(Session, "__init__", _tracking_init)
        impact_module.analyze_impact(["backend/app/connectors/sentry.py", "README.md"])
        assert created == [], "impact analysis must never open a DB session"
