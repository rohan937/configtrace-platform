"""Sentry integration creation/reconnect end-to-end tests (message 8).

Exercises the real HTTP path — POST /integrations and POST
/integrations/{id}/reconnect — for the launch-certification cases: valid
(Full) connection, partial connection (some extended family denied but
core monitoring still works), invalid connection (rejected outright —
malformed slug, auth failure, unreachable organization, or zero core
families reachable), and reconnect (same-organization token rotation and
slug rename succeed, different-organization rejected). Also pins that
sensitive credentials never leak into any response.

``SentryConnector.probe_coverage`` is patched directly for most cases
(mirrors patching ``probe_coverage``/``validate_credentials`` in the
Snowflake/Okta/Entra precedent) — it is the single synchronous call the
creation/reconnect paths make.
"""

from __future__ import annotations

from unittest.mock import patch

from app.connectors.exceptions import AuthenticationError, ConnectorError, NetworkError
from app.connectors.sentry import SentryConnector
from app.connectors.sentry_schema import COVERAGE_FULL, COVERAGE_INVALID, COVERAGE_PARTIAL
from app.models.integration import Integration

_ORGANIZATION_SLUG = "my-organization"
_TOKEN = "super-secret-fake-sentry-token"


def _full_result(organization_id: str = "id:1001") -> dict:
    return {
        "coverage": COVERAGE_FULL,
        "organization_id": organization_id,
        "slug": _ORGANIZATION_SLUG,
        "name": "My Organization",
        "family_status": {},
        "diagnostics": {
            "Projects and teams": "Available",
            "Members and access": "Available",
            "Alert rules": "Available",
            "Integrations": "Available",
            "Repositories": "Available",
            "Releases": "Available",
        },
    }


def _partial_result(organization_id: str = "id:1001") -> dict:
    result = _full_result(organization_id)
    result["coverage"] = COVERAGE_PARTIAL
    result["diagnostics"]["Integrations"] = "Permission denied"
    result["diagnostics"]["Repositories"] = "Permission denied"
    return result


def _create_payload(**overrides) -> dict:
    payload = {
        "provider": "sentry",
        "display_name": "Test Sentry Organization",
        "sentry_organization_slug": _ORGANIZATION_SLUG,
        "sentry_auth_token": _TOKEN,
    }
    payload.update(overrides)
    return payload


# ════════════════════════════════════════════════════════════════════════════
# Valid (Full) connection
# ════════════════════════════════════════════════════════════════════════════


class TestValidConnection:
    def test_create_integration_succeeds_with_full_coverage(self, client):
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post("/integrations", json=_create_payload())
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["provider"] == "sentry"
        assert body["status"] == "active"
        assert body["resource_count"] == 1


# ════════════════════════════════════════════════════════════════════════════
# Partial connection — some extended family denied, still accepted
# ════════════════════════════════════════════════════════════════════════════


class TestPartialConnection:
    def test_integration_accepted_when_extended_families_denied(self, client):
        """Integrations/repositories visibility denied but core families
        (projects/teams/members) are readable — Partial coverage, still
        accepted."""
        with patch.object(SentryConnector, "probe_coverage", return_value=_partial_result()):
            resp = client.post("/integrations", json=_create_payload(display_name="Partial Org"))
        assert resp.status_code == 201, resp.text

    def test_compute_coverage_state_partial_when_one_extended_family_denied(self):
        from app.connectors.sentry_schema import (
            PROBED_CAPABILITY_FAMILIES,
            CAPABILITY_AVAILABLE,
            CAPABILITY_DENIED,
            compute_coverage_state,
        )

        family_status = {f: CAPABILITY_AVAILABLE for f in PROBED_CAPABILITY_FAMILIES}
        family_status["releases"] = CAPABILITY_DENIED
        assert compute_coverage_state(family_status) == COVERAGE_PARTIAL


# ════════════════════════════════════════════════════════════════════════════
# Invalid connection
# ════════════════════════════════════════════════════════════════════════════


class TestInvalidConnection:
    def test_malformed_organization_slug_rejected(self, client):
        resp = client.post("/integrations", json=_create_payload(
            sentry_organization_slug="not a valid slug!!",
        ))
        assert resp.status_code == 400, resp.text

    def test_auth_failure_rejected(self, client):
        with patch.object(
            SentryConnector, "probe_coverage",
            side_effect=AuthenticationError("sentry: token rejected", status_code=401),
        ):
            resp = client.post("/integrations", json=_create_payload(display_name="Auth Fail Org"))
        assert resp.status_code == 400, resp.text
        assert _TOKEN not in resp.text

    def test_unreachable_organization_rejected(self, client):
        with patch.object(
            SentryConnector, "probe_coverage",
            side_effect=NetworkError("sentry: could not reach the organization"),
        ):
            resp = client.post("/integrations", json=_create_payload(display_name="Unreachable Org"))
        assert resp.status_code == 400, resp.text

    def test_zero_core_capability_rejected(self, client):
        zero_result = _full_result()
        zero_result["coverage"] = COVERAGE_INVALID
        with patch.object(SentryConnector, "probe_coverage", return_value=zero_result):
            resp = client.post("/integrations", json=_create_payload(display_name="Zero Capability Org"))
        assert resp.status_code == 400, resp.text
        assert "core families" in resp.text

    def test_missing_organization_slug_rejected_at_schema_layer(self, client):
        payload = _create_payload()
        del payload["sentry_organization_slug"]
        resp = client.post("/integrations", json=payload)
        assert resp.status_code == 422, resp.text

    def test_missing_token_rejected_at_schema_layer(self, client):
        payload = _create_payload()
        del payload["sentry_auth_token"]
        resp = client.post("/integrations", json=payload)
        assert resp.status_code == 422, resp.text


# ════════════════════════════════════════════════════════════════════════════
# Extended family denied is NOT invalid
# ════════════════════════════════════════════════════════════════════════════


class TestExtendedFamilyDeniedNotInvalid:
    def test_releases_denied_does_not_block_creation(self, client):
        result = _full_result()
        result["coverage"] = COVERAGE_PARTIAL
        result["diagnostics"]["Releases"] = "Permission denied"
        with patch.object(SentryConnector, "probe_coverage", return_value=result):
            resp = client.post("/integrations", json=_create_payload(display_name="No Releases Org"))
        assert resp.status_code == 201, resp.text


# ════════════════════════════════════════════════════════════════════════════
# Reconnect — same-organization rotation succeeds, different-org rejected
# ════════════════════════════════════════════════════════════════════════════


class TestReconnect:
    def _create_integration(self, client) -> str:
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post("/integrations", json=_create_payload(display_name="Reconnect Test Org"))
        assert resp.status_code == 201, resp.text
        return resp.json()["id"]

    def test_same_organization_new_token_accepted(self, client):
        integration_id = self._create_integration(client)
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "new-rotated-token"},
            )
        assert resp.status_code == 200, resp.text

    def test_same_organization_renamed_slug_accepted(self, client):
        integration_id = self._create_integration(client)
        renamed = _full_result()
        renamed["slug"] = "my-organization-renamed"
        with patch.object(SentryConnector, "probe_coverage", return_value=renamed):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={
                    "sentry_organization_slug": "my-organization-renamed",
                    "sentry_auth_token": "new-rotated-token",
                },
            )
        assert resp.status_code == 200, resp.text

    def test_different_organization_rejected(self, client):
        integration_id = self._create_integration(client)
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result(organization_id="id:9999")):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "token-for-a-different-organization"},
            )
        assert resp.status_code == 400, resp.text

    def test_invalid_token_rejected(self, client):
        integration_id = self._create_integration(client)
        with patch.object(
            SentryConnector, "probe_coverage",
            side_effect=AuthenticationError("sentry: token rejected", status_code=401),
        ):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "invalid-token"},
            )
        assert resp.status_code == 400, resp.text

    def test_revoked_token_rejected_with_sanitized_error(self, client):
        integration_id = self._create_integration(client)
        with patch.object(
            SentryConnector, "probe_coverage",
            side_effect=AuthenticationError("sentry: TOKEN_REVOKED", status_code=401),
        ):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "revoked-token"},
            )
        assert resp.status_code == 400, resp.text
        assert "revoked-token" not in resp.text

    def test_partial_permissions_accepted_with_partial_diagnostics(self, client):
        integration_id = self._create_integration(client)
        with patch.object(SentryConnector, "probe_coverage", return_value=_partial_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "new-token-reduced-visibility"},
            )
        assert resp.status_code == 200, resp.text

    def test_reconnect_missing_token_rejected_at_schema_layer(self, client):
        integration_id = self._create_integration(client)
        resp = client.post(f"/integrations/{integration_id}/reconnect", json={})
        assert resp.status_code == 422, resp.text

    def test_old_token_not_reused(self, client, db_session):
        """After reconnect, the encrypted credentials column reflects only
        the NEW token — the old token is fully overwritten, never
        retained alongside it."""
        from app.core.encryption import decrypt_credentials

        integration_id = self._create_integration(client)
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "brand-new-token-value"},
            )
        assert resp.status_code == 200, resp.text

        db_session.expire_all()
        row = db_session.query(Integration).filter(Integration.id == integration_id).first()
        creds = decrypt_credentials(row.encrypted_credentials, row.credential_iv)
        assert creds["auth_token"] == "brand-new-token-value"
        assert creds["auth_token"] != _TOKEN

    def test_reconnect_clears_needs_reconnect_status(self, client, db_session):
        integration_id = self._create_integration(client)
        row = db_session.query(Integration).filter(Integration.id == integration_id).first()
        row.status = "needs_reconnect"
        db_session.commit()

        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "recovery-token"},
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "active"


# ════════════════════════════════════════════════════════════════════════════
# Sensitive credentials never leak
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveCredentialsNeverLeak:
    def test_token_not_in_create_response(self, client):
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post("/integrations", json=_create_payload(display_name="Secret Test Org"))
        assert resp.status_code == 201, resp.text
        assert _TOKEN not in resp.text
        assert "auth_token" not in resp.json()
        assert "sentry_auth_token" not in resp.json()

    def test_token_not_in_get_integration_response(self, client):
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            create_resp = client.post("/integrations", json=_create_payload(display_name="Secret Get Org"))
        integration_id = create_resp.json()["id"]
        get_resp = client.get(f"/integrations/{integration_id}")
        assert get_resp.status_code == 200
        assert _TOKEN not in get_resp.text

    def test_encrypted_credentials_column_is_not_plaintext(self, client, db_session):
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post("/integrations", json=_create_payload(display_name="Encryption Check Org"))
        integration_id = resp.json()["id"]
        db_session.expire_all()
        row = db_session.query(Integration).filter(Integration.id == integration_id).first()
        assert row is not None
        assert _TOKEN.encode() not in row.encrypted_credentials
