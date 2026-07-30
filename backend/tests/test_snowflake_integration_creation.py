"""Snowflake integration creation/reconnect end-to-end tests (message 8).

Exercises the real HTTP path — POST /integrations and POST
/integrations/{id}/reconnect — for the launch-certification cases: valid
(Full) connection, partial connection (some optional/elevated-visibility
families denied but core monitoring still works), invalid connection
(rejected outright — malformed credentials, auth failure, unreachable
account, or zero meaningful monitored families), and reconnect (same-
account PAT/user/role rotation succeeds, different-account rejected).
Also pins that sensitive credentials never leak into any response.

``SnowflakeConnector.probe_coverage`` is patched directly for most cases
(mirrors patching ``validate_credentials`` in the Okta/Entra precedent) —
it is the single synchronous call the creation/reconnect paths make.
"""

from __future__ import annotations

from unittest.mock import patch

from app.connectors.exceptions import AuthenticationError, ConnectorError, NetworkError
from app.connectors.snowflake import SnowflakeConnector
from app.connectors.snowflake_schema import COVERAGE_FULL, COVERAGE_INVALID, COVERAGE_PARTIAL
from app.models.integration import Integration

_ACCOUNT_IDENTIFIER = "myorg-myaccount"
_USERNAME = "CONFIGTRACE_MONITOR"
_TOKEN = "super-secret-fake-snowflake-pat"
_ROLE = "CONFIGTRACE_MONITOR"


def _full_result(account_id: str = "id:myorg-myaccount") -> dict:
    return {
        "coverage": COVERAGE_FULL,
        "account_id": account_id,
        "session_role": _ROLE,
        "family_status": {},
        "diagnostics": {
            "Identity and roles": "Available",
            "Data objects and grants": "Available",
            "Warehouses and shares": "Available",
            "Network policies": "Available",
            "Authentication policies": "Available",
            "Security integrations": "Available",
            "Storage integrations": "Available",
            "External access integrations": "Available",
        },
    }


def _partial_result(account_id: str = "id:myorg-myaccount") -> dict:
    result = _full_result(account_id)
    result["coverage"] = COVERAGE_PARTIAL
    result["diagnostics"]["Authentication policies"] = "Permission denied"
    result["diagnostics"]["Security integrations"] = "Permission denied"
    return result


def _create_payload(**overrides) -> dict:
    payload = {
        "provider": "snowflake",
        "display_name": "Test Snowflake Account",
        "snowflake_account_identifier": _ACCOUNT_IDENTIFIER,
        "snowflake_username": _USERNAME,
        "snowflake_programmatic_access_token": _TOKEN,
        "snowflake_role": _ROLE,
    }
    payload.update(overrides)
    return payload


# ════════════════════════════════════════════════════════════════════════════
# Valid (Full) connection
# ════════════════════════════════════════════════════════════════════════════


class TestValidConnection:
    def test_create_integration_succeeds_with_full_coverage(self, client):
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post("/integrations", json=_create_payload())
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["provider"] == "snowflake"
        assert body["status"] == "active"
        assert body["resource_count"] == 1


# ════════════════════════════════════════════════════════════════════════════
# Partial connection — some optional families denied, still accepted
# ════════════════════════════════════════════════════════════════════════════


class TestPartialConnection:
    def test_integration_accepted_when_optional_families_denied(self, client):
        """Authentication/security-integration visibility denied but core
        families (users/roles/grants/databases/schemas/warehouses/shares)
        are readable — Partial coverage, still accepted."""
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_partial_result()):
            resp = client.post("/integrations", json=_create_payload(display_name="Partial Account"))
        assert resp.status_code == 201, resp.text

    def test_compute_coverage_state_partial_when_one_extended_family_denied(self):
        from app.connectors.snowflake_schema import CAPABILITY_FAMILIES, CAPABILITY_AVAILABLE, CAPABILITY_DENIED, compute_coverage_state

        family_status = {f: CAPABILITY_AVAILABLE for f in CAPABILITY_FAMILIES}
        family_status["authentication_policies"] = CAPABILITY_DENIED
        assert compute_coverage_state(family_status) == COVERAGE_PARTIAL


# ════════════════════════════════════════════════════════════════════════════
# Invalid connection
# ════════════════════════════════════════════════════════════════════════════


class TestInvalidConnection:
    def test_malformed_account_identifier_rejected(self, client):
        resp = client.post("/integrations", json=_create_payload(
            snowflake_account_identifier="not a valid identifier!!",
        ))
        assert resp.status_code == 400, resp.text

    def test_auth_failure_rejected(self, client):
        with patch.object(
            SnowflakeConnector, "probe_coverage",
            side_effect=AuthenticationError("snowflake: PAT rejected", status_code=401),
        ):
            resp = client.post("/integrations", json=_create_payload(display_name="Auth Fail Account"))
        assert resp.status_code == 400, resp.text
        assert _TOKEN not in resp.text

    def test_unreachable_account_rejected(self, client):
        with patch.object(
            SnowflakeConnector, "probe_coverage",
            side_effect=NetworkError("snowflake: could not reach the account"),
        ):
            resp = client.post("/integrations", json=_create_payload(display_name="Unreachable Account"))
        assert resp.status_code == 400, resp.text

    def test_zero_meaningful_capability_rejected(self, client):
        zero_result = _full_result()
        zero_result["coverage"] = COVERAGE_INVALID
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=zero_result):
            resp = client.post("/integrations", json=_create_payload(display_name="Zero Capability Account"))
        assert resp.status_code == 400, resp.text
        assert "core families" in resp.text

    def test_missing_account_identifier_rejected_at_schema_layer(self, client):
        payload = _create_payload()
        del payload["snowflake_account_identifier"]
        resp = client.post("/integrations", json=payload)
        assert resp.status_code == 422, resp.text

    def test_missing_username_rejected_at_schema_layer(self, client):
        payload = _create_payload()
        del payload["snowflake_username"]
        resp = client.post("/integrations", json=payload)
        assert resp.status_code == 422, resp.text

    def test_missing_token_rejected_at_schema_layer(self, client):
        payload = _create_payload()
        del payload["snowflake_programmatic_access_token"]
        resp = client.post("/integrations", json=payload)
        assert resp.status_code == 422, resp.text

    def test_missing_role_rejected_at_schema_layer(self, client):
        payload = _create_payload()
        del payload["snowflake_role"]
        resp = client.post("/integrations", json=payload)
        assert resp.status_code == 422, resp.text


# ════════════════════════════════════════════════════════════════════════════
# Optional family denied is NOT invalid
# ════════════════════════════════════════════════════════════════════════════


class TestOptionalFamilyDeniedNotInvalid:
    def test_network_policies_denied_does_not_block_creation(self, client):
        result = _full_result()
        result["coverage"] = COVERAGE_PARTIAL
        result["diagnostics"]["Network policies"] = "Permission denied"
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=result):
            resp = client.post("/integrations", json=_create_payload(display_name="No Network Policy Account"))
        assert resp.status_code == 201, resp.text


# ════════════════════════════════════════════════════════════════════════════
# Reconnect — same-account rotation succeeds, different-account rejected
# ════════════════════════════════════════════════════════════════════════════


class TestReconnect:
    def _create_integration(self, client) -> str:
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post("/integrations", json=_create_payload(display_name="Reconnect Test Account"))
        assert resp.status_code == 201, resp.text
        return resp.json()["id"]

    def test_same_account_new_pat_accepted(self, client):
        integration_id = self._create_integration(client)
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"snowflake_programmatic_access_token": "new-rotated-pat"},
            )
        assert resp.status_code == 200, resp.text

    def test_same_account_new_username_accepted(self, client):
        integration_id = self._create_integration(client)
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={
                    "snowflake_username": "NEW_SERVICE_USER",
                    "snowflake_programmatic_access_token": "new-rotated-pat",
                },
            )
        assert resp.status_code == 200, resp.text

    def test_same_account_new_role_accepted_after_validation(self, client):
        integration_id = self._create_integration(client)
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={
                    "snowflake_role": "NEW_MONITOR_ROLE",
                    "snowflake_programmatic_access_token": "new-rotated-pat",
                },
            )
        assert resp.status_code == 200, resp.text

    def test_different_account_rejected(self, client):
        integration_id = self._create_integration(client)
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_full_result(account_id="id:otherorg-otheraccount")):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"snowflake_programmatic_access_token": "pat-for-a-different-account"},
            )
        assert resp.status_code == 400, resp.text

    def test_invalid_pat_rejected(self, client):
        integration_id = self._create_integration(client)
        with patch.object(
            SnowflakeConnector, "probe_coverage",
            side_effect=AuthenticationError("snowflake: PAT rejected", status_code=401),
        ):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"snowflake_programmatic_access_token": "invalid-pat"},
            )
        assert resp.status_code == 400, resp.text

    def test_revoked_pat_rejected_with_sanitized_error(self, client):
        integration_id = self._create_integration(client)
        with patch.object(
            SnowflakeConnector, "probe_coverage",
            side_effect=AuthenticationError("snowflake: PAT_INVALID", status_code=401),
        ):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"snowflake_programmatic_access_token": "revoked-pat"},
            )
        assert resp.status_code == 400, resp.text
        assert "revoked-pat" not in resp.text

    def test_role_restriction_mismatch_rejected(self, client):
        integration_id = self._create_integration(client)
        with patch.object(
            SnowflakeConnector, "probe_coverage",
            side_effect=AuthenticationError("snowflake: role not permitted for this token", status_code=401),
        ):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={
                    "snowflake_role": "DISALLOWED_ROLE",
                    "snowflake_programmatic_access_token": "pat-restricted-to-another-role",
                },
            )
        assert resp.status_code == 400, resp.text

    def test_partial_permissions_accepted_with_partial_diagnostics(self, client):
        integration_id = self._create_integration(client)
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_partial_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"snowflake_programmatic_access_token": "new-pat-reduced-visibility"},
            )
        assert resp.status_code == 200, resp.text

    def test_reconnect_missing_token_rejected_at_schema_layer(self, client):
        integration_id = self._create_integration(client)
        resp = client.post(f"/integrations/{integration_id}/reconnect", json={})
        assert resp.status_code == 422, resp.text

    def test_old_pat_not_reused(self, client, db_session):
        """After reconnect, the encrypted credentials column reflects only
        the NEW PAT — the old PAT is fully overwritten, never retained
        alongside it."""
        from app.core.encryption import decrypt_credentials

        integration_id = self._create_integration(client)
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"snowflake_programmatic_access_token": "brand-new-pat-value"},
            )
        assert resp.status_code == 200, resp.text

        db_session.expire_all()
        row = db_session.query(Integration).filter(Integration.id == integration_id).first()
        creds = decrypt_credentials(row.encrypted_credentials, row.credential_iv)
        assert creds["programmatic_access_token"] == "brand-new-pat-value"
        assert creds["programmatic_access_token"] != _TOKEN


# ════════════════════════════════════════════════════════════════════════════
# Sensitive credentials never leak
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveCredentialsNeverLeak:
    def test_pat_not_in_create_response(self, client):
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post("/integrations", json=_create_payload(display_name="Secret Test Account"))
        assert resp.status_code == 201, resp.text
        assert _TOKEN not in resp.text
        assert "programmatic_access_token" not in resp.json()
        assert "snowflake_programmatic_access_token" not in resp.json()

    def test_pat_not_in_get_integration_response(self, client):
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_full_result()):
            create_resp = client.post("/integrations", json=_create_payload(display_name="Secret Get Account"))
        integration_id = create_resp.json()["id"]
        get_resp = client.get(f"/integrations/{integration_id}")
        assert get_resp.status_code == 200
        assert _TOKEN not in get_resp.text

    def test_encrypted_credentials_column_is_not_plaintext(self, client, db_session):
        with patch.object(SnowflakeConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post("/integrations", json=_create_payload(display_name="Encryption Check Account"))
        integration_id = resp.json()["id"]
        db_session.expire_all()
        row = db_session.query(Integration).filter(Integration.id == integration_id).first()
        assert row is not None
        assert _TOKEN.encode() not in row.encrypted_credentials
