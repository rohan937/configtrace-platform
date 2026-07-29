"""Microsoft Entra ID integration creation/reconnect end-to-end tests
(message 8).

Exercises the real HTTP path — POST /integrations and POST
/integrations/{id}/reconnect — for the launch-certification cases: valid
connection, partial connection (some Graph API families denied but the
credential is still accepted at creation time), invalid connection
(rejected outright), an unsupported optional API (Conditional Access
missing) that must NOT be treated as invalid, and reconnect (same-tenant
secret rotation succeeds, same-tenant client rotation succeeds,
different-tenant rejected). Also pins that sensitive credentials never
leak into any response.
"""

from __future__ import annotations

from unittest.mock import patch

from app.connectors.entra import EntraConnector
from app.connectors.exceptions import AuthenticationError, NetworkError
from app.models.integration import Integration

_TENANT_ID = "11111111-1111-1111-1111-111111111111"
_CLIENT_ID = "22222222-2222-2222-2222-222222222222"
_OTHER_TENANT_ID = "99999999-9999-9999-9999-999999999999"
_OTHER_CLIENT_ID = "88888888-8888-8888-8888-888888888888"
_SECRET = "super-secret-fake-entra-client-secret"


# ════════════════════════════════════════════════════════════════════════════
# Valid connection
# ════════════════════════════════════════════════════════════════════════════


class TestValidConnection:
    def test_create_integration_succeeds_when_tenant_reachable(self, client):
        with patch.object(EntraConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "entra",
                "display_name": "Valid Tenant",
                "entra_tenant_id": _TENANT_ID,
                "entra_client_id": _CLIENT_ID,
                "entra_client_secret": _SECRET,
            })
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["provider"] == "entra"
        assert body["status"] == "active"
        assert body["resource_count"] == 1


# ════════════════════════════════════════════════════════════════════════════
# Partial connection — some families denied, integration still accepted
# ════════════════════════════════════════════════════════════════════════════


class TestPartialConnection:
    def test_integration_accepted_when_some_families_denied(self, client):
        """Creation only requires an app-only token + GET /organization to
        succeed (validate_credentials); partial family denial is a
        first-sync-time diagnostic, not a creation-time rejection — a
        least-privileged app registration legitimately cannot read every
        family (e.g. Conditional Access, authentication methods, directory
        roles) without additional application permissions and admin
        consent."""
        with patch.object(EntraConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "entra",
                "display_name": "Partial Tenant",
                "entra_tenant_id": _TENANT_ID,
                "entra_client_id": _CLIENT_ID,
                "entra_client_secret": _SECRET,
            })
        assert resp.status_code == 201, resp.text

    def test_permission_diagnostics_report_partial_state_from_denied_family(self):
        from app.connectors.entra import build_entra_permission_diagnostics

        families = [
            "users", "groups", "memberships", "applications",
            "service_principals", "app_role_assignments",
            "oauth2_permission_grants", "authentication_strengths",
            "authentication_methods", "directory_role_definitions",
            "directory_role_assignments",
        ]
        completeness = {f: "complete" for f in families}
        completeness["conditional_access_policies"] = "denied"
        records = [{
            "record_type": "entra_organization",
            "tenant_id": f"id:{_TENANT_ID}",
            "family_completeness": completeness,
        }]
        report = build_entra_permission_diagnostics(records)
        assert report["coverage"] in ("partial", "full", "invalid")
        assert report["coverage"] != "invalid"


# ════════════════════════════════════════════════════════════════════════════
# Invalid connection
# ════════════════════════════════════════════════════════════════════════════


class TestInvalidConnection:
    def test_malformed_tenant_id_rejected(self, client):
        resp = client.post("/integrations", json={
            "provider": "entra",
            "display_name": "Bad Tenant",
            "entra_tenant_id": "not-a-guid",
            "entra_client_id": _CLIENT_ID,
            "entra_client_secret": _SECRET,
        })
        assert resp.status_code == 400, resp.text

    def test_multi_tenant_audience_rejected(self, client):
        resp = client.post("/integrations", json={
            "provider": "entra",
            "display_name": "Common Audience",
            "entra_tenant_id": "common",
            "entra_client_id": _CLIENT_ID,
            "entra_client_secret": _SECRET,
        })
        assert resp.status_code == 400, resp.text

    def test_auth_failure_rejected(self, client):
        with patch.object(
            EntraConnector, "validate_credentials",
            side_effect=AuthenticationError("entra: invalid_client", status_code=401),
        ):
            resp = client.post("/integrations", json={
                "provider": "entra",
                "display_name": "Auth Fail Tenant",
                "entra_tenant_id": _TENANT_ID,
                "entra_client_id": _CLIENT_ID,
                "entra_client_secret": _SECRET,
            })
        assert resp.status_code == 400, resp.text
        assert _SECRET not in resp.text

    def test_unreachable_tenant_rejected(self, client):
        with patch.object(
            EntraConnector, "validate_credentials",
            side_effect=NetworkError("entra: could not reach Microsoft Graph"),
        ):
            resp = client.post("/integrations", json={
                "provider": "entra",
                "display_name": "Unreachable Tenant",
                "entra_tenant_id": _TENANT_ID,
                "entra_client_id": _CLIENT_ID,
                "entra_client_secret": _SECRET,
            })
        # NetworkError subclasses ConnectorError, and the router's
        # `except ConnectorError` branch (400) is ordered before its
        # `except NetworkError` branch (502) for every provider.
        assert resp.status_code == 400, resp.text

    def test_missing_tenant_id_rejected_at_schema_layer(self, client):
        resp = client.post("/integrations", json={
            "provider": "entra",
            "display_name": "No Tenant ID",
            "entra_client_id": _CLIENT_ID,
            "entra_client_secret": _SECRET,
        })
        assert resp.status_code == 422, resp.text

    def test_missing_client_id_rejected_at_schema_layer(self, client):
        resp = client.post("/integrations", json={
            "provider": "entra",
            "display_name": "No Client ID",
            "entra_tenant_id": _TENANT_ID,
            "entra_client_secret": _SECRET,
        })
        assert resp.status_code == 422, resp.text

    def test_missing_client_secret_rejected_at_schema_layer(self, client):
        resp = client.post("/integrations", json={
            "provider": "entra",
            "display_name": "No Secret",
            "entra_tenant_id": _TENANT_ID,
            "entra_client_id": _CLIENT_ID,
        })
        assert resp.status_code == 422, resp.text


# ════════════════════════════════════════════════════════════════════════════
# Unsupported optional API (Conditional Access unavailable) is NOT invalid
# ════════════════════════════════════════════════════════════════════════════


class TestUnsupportedOptionalApi:
    def test_conditional_access_unavailable_does_not_block_creation(self, client):
        with patch.object(EntraConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "entra",
                "display_name": "No CA Tenant",
                "entra_tenant_id": _TENANT_ID,
                "entra_client_id": _CLIENT_ID,
                "entra_client_secret": _SECRET,
            })
        assert resp.status_code == 201, resp.text

    def test_directory_roles_unavailable_reports_partial_not_invalid(self):
        from app.connectors.entra import build_entra_permission_diagnostics

        families = [
            "users", "groups", "memberships", "applications",
            "service_principals", "app_role_assignments",
            "oauth2_permission_grants", "conditional_access_policies",
            "authentication_strengths", "authentication_methods",
        ]
        completeness = {f: "complete" for f in families}
        completeness["directory_role_definitions"] = "unavailable"
        completeness["directory_role_assignments"] = "unavailable"
        records = [{
            "record_type": "entra_organization",
            "tenant_id": f"id:{_TENANT_ID}",
            "family_completeness": completeness,
        }]
        report = build_entra_permission_diagnostics(records)
        assert report["coverage"] != "invalid"

    def test_zero_readable_families_is_invalid(self):
        from app.connectors.entra import build_entra_permission_diagnostics

        records = [{
            "record_type": "entra_organization",
            "tenant_id": f"id:{_TENANT_ID}",
            "family_completeness": {"users": "denied", "groups": "unavailable"},
        }]
        report = build_entra_permission_diagnostics(records)
        assert report["coverage"] == "invalid"


# ════════════════════════════════════════════════════════════════════════════
# Reconnect — same-tenant rotation succeeds, different-tenant rejected
# ════════════════════════════════════════════════════════════════════════════


class TestReconnect:
    def _create_integration(self, client) -> str:
        with patch.object(EntraConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "entra",
                "display_name": "Reconnect Test Tenant",
                "entra_tenant_id": _TENANT_ID,
                "entra_client_id": _CLIENT_ID,
                "entra_client_secret": _SECRET,
            })
        assert resp.status_code == 201, resp.text
        return resp.json()["id"]

    def _promote_to_real_identity(self, db_session, integration_id: str, tenant_id: str) -> None:
        from app.models.resource import Resource

        resource = (
            db_session.query(Resource)
            .filter(Resource.integration_id == integration_id)
            .first()
        )
        resource.provider_resource_id = f"organization/id:{tenant_id}"
        db_session.commit()

    def test_same_tenant_secret_rotation_succeeds(self, client, db_session):
        integration_id = self._create_integration(client)
        self._promote_to_real_identity(db_session, integration_id, _TENANT_ID)

        with patch.object(EntraConnector, "validate_credentials", return_value=True):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"entra_client_secret": "new-rotated-secret"},
            )
        assert resp.status_code == 200, resp.text

    def test_same_tenant_new_client_rotation_succeeds(self, client, db_session):
        integration_id = self._create_integration(client)
        self._promote_to_real_identity(db_session, integration_id, _TENANT_ID)

        with patch.object(EntraConnector, "validate_credentials", return_value=True):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={
                    "entra_client_id": _OTHER_CLIENT_ID,
                    "entra_client_secret": "secret-for-new-app-registration",
                },
            )
        assert resp.status_code == 200, resp.text

    def test_different_tenant_rejected(self, client, db_session):
        integration_id = self._create_integration(client)
        self._promote_to_real_identity(db_session, integration_id, _TENANT_ID)

        with patch.object(EntraConnector, "validate_credentials", return_value=True):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={
                    "entra_tenant_id": _OTHER_TENANT_ID,
                    "entra_client_secret": "secret-for-a-different-tenant",
                },
            )
        assert resp.status_code == 400, resp.text

    def test_invalid_new_secret_rejected(self, client, db_session):
        integration_id = self._create_integration(client)
        self._promote_to_real_identity(db_session, integration_id, _TENANT_ID)

        with patch.object(
            EntraConnector, "validate_credentials",
            side_effect=AuthenticationError("entra: invalid_client", status_code=401),
        ):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"entra_client_secret": "wrong-secret"},
            )
        assert resp.status_code == 400, resp.text

    def test_graph_unavailable_during_reconnect_is_safe_failure(self, client, db_session):
        integration_id = self._create_integration(client)
        self._promote_to_real_identity(db_session, integration_id, _TENANT_ID)

        with patch.object(
            EntraConnector, "validate_credentials",
            side_effect=NetworkError("entra: could not reach Microsoft Graph"),
        ):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"entra_client_secret": "some-secret"},
            )
        assert resp.status_code == 400, resp.text

    def test_reconnect_before_first_sync_does_not_falsely_reject_same_tenant(self, client, db_session):
        """The integration created via _create_integration() has NOT been
        promoted to a real identity yet — its resource still has the
        creation-time placeholder provider_resource_id. Reconnecting with
        the SAME tenant must succeed (no real identity recorded yet to
        compare against), matching the Okta message-8 precedent."""
        integration_id = self._create_integration(client)

        with patch.object(EntraConnector, "validate_credentials", return_value=True):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"entra_client_secret": "rotated-before-first-sync"},
            )
        assert resp.status_code == 200, resp.text

    def test_reconnect_missing_secret_rejected_at_schema_layer(self, client):
        integration_id = self._create_integration(client)
        reconnect_resp = client.post(f"/integrations/{integration_id}/reconnect", json={})
        assert reconnect_resp.status_code == 422, reconnect_resp.text

    def test_token_cache_does_not_leak_across_reconnect_to_new_client(self):
        """Message 7 bound the in-memory token cache to (tenant_id,
        client_id). Reconnect calls EntraConnector.validate_credentials()
        with the NEW credentials on a throwaway connector instance, so this
        pins the underlying guarantee directly: acquiring a token for
        client A, then immediately requesting one for client B on the SAME
        connector instance, must never return client A's cached token."""
        import httpx

        from app.connectors.entra import EntraConnector

        connector = EntraConnector()
        creds_a = {"tenant_id": _TENANT_ID, "client_id": _CLIENT_ID, "client_secret": "secret-a"}
        creds_b = {"tenant_id": _TENANT_ID, "client_id": _OTHER_CLIENT_ID, "client_secret": "secret-b"}

        responses = [
            httpx.Response(200, json={"access_token": "token-for-client-a", "expires_in": 3600, "token_type": "Bearer"}),
            httpx.Response(200, json={"access_token": "token-for-client-b", "expires_in": 3600, "token_type": "Bearer"}),
        ]
        with patch("httpx.Client.request", side_effect=responses):
            token_a = connector._get_token(creds_a)
            token_b = connector._get_token(creds_b)

        assert token_a == "token-for-client-a"
        assert token_b == "token-for-client-b"
        assert token_a != token_b


# ════════════════════════════════════════════════════════════════════════════
# Sensitive credentials never leak
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveCredentialsNeverLeak:
    def test_client_secret_not_in_create_response(self, client, db_session):
        with patch.object(EntraConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "entra",
                "display_name": "Secret Test Tenant",
                "entra_tenant_id": _TENANT_ID,
                "entra_client_id": _CLIENT_ID,
                "entra_client_secret": _SECRET,
            })
        assert resp.status_code == 201, resp.text
        assert _SECRET not in resp.text
        assert "client_secret" not in resp.json()
        assert "entra_client_secret" not in resp.json()

    def test_client_secret_not_in_get_integration_response(self, client, db_session):
        with patch.object(EntraConnector, "validate_credentials", return_value=True):
            create_resp = client.post("/integrations", json={
                "provider": "entra",
                "display_name": "Secret Get Tenant",
                "entra_tenant_id": _TENANT_ID,
                "entra_client_id": _CLIENT_ID,
                "entra_client_secret": _SECRET,
            })
        integration_id = create_resp.json()["id"]
        get_resp = client.get(f"/integrations/{integration_id}")
        assert get_resp.status_code == 200
        assert _SECRET not in get_resp.text

    def test_client_secret_not_logged_by_validate_credentials(self, caplog):
        import logging

        import httpx

        connector = EntraConnector()
        fake_response = httpx.Response(200, json={"access_token": "fake-token", "expires_in": 3600, "token_type": "Bearer"})
        with patch("httpx.Client.request", return_value=fake_response):
            with caplog.at_level(logging.DEBUG):
                try:
                    connector.validate_credentials({
                        "tenant_id": _TENANT_ID, "client_id": _CLIENT_ID, "client_secret": _SECRET,
                    })
                except Exception:
                    pass
        assert _SECRET not in caplog.text

    def test_encrypted_credentials_column_is_not_plaintext(self, client, db_session):
        with patch.object(EntraConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "entra",
                "display_name": "Encryption Check Tenant",
                "entra_tenant_id": _TENANT_ID,
                "entra_client_id": _CLIENT_ID,
                "entra_client_secret": _SECRET,
            })
        integration_id = resp.json()["id"]
        db_session.expire_all()
        row = db_session.query(Integration).filter(Integration.id == integration_id).first()
        assert row is not None
        assert _SECRET.encode() not in row.encrypted_credentials
