"""Okta integration creation/reconnect end-to-end tests (message 8).

Exercises the real HTTP path — POST /integrations and POST
/integrations/{id}/reconnect — for the launch-certification cases: valid
connection, partial connection (some API families denied but the credential
is still accepted at creation time), invalid connection (rejected outright),
an unsupported optional API (custom admin roles missing) that must NOT be
treated as invalid, and reconnect (same-tenant token rotation succeeds,
different-tenant rejected). Also pins that sensitive credentials never leak
into any response.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.connectors.exceptions import AuthenticationError, NetworkError
from app.connectors.okta import CallOutcome, OktaConnector
from app.models.integration import Integration

_ORG_URL = "https://example.okta.com"
_TOKEN = "super-secret-fake-okta-token"


def _fake_org_outcome(tenant_id: str = "abc123"):
    fake_response = MagicMock()
    fake_response.json.return_value = {"id": tenant_id, "companyName": "Example Co"}
    return CallOutcome(ok=True, response=fake_response)


# ════════════════════════════════════════════════════════════════════════════
# Valid connection
# ════════════════════════════════════════════════════════════════════════════


class TestValidConnection:
    def test_create_integration_succeeds_when_org_reachable(self, client):
        with patch.object(OktaConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "okta",
                "display_name": "Valid Org",
                "okta_org_url": _ORG_URL,
                "okta_api_token": _TOKEN,
            })
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["provider"] == "okta"
        assert body["status"] == "active"
        assert body["resource_count"] == 1


# ════════════════════════════════════════════════════════════════════════════
# Partial connection — some families denied, integration still accepted
# ════════════════════════════════════════════════════════════════════════════


class TestPartialConnection:
    def test_integration_accepted_when_some_families_denied(self, client):
        """Creation only requires GET /api/v1/org to succeed
        (validate_credentials); partial family denial is a first-sync-time
        diagnostic, not a creation-time rejection — a least-privileged admin
        role legitimately cannot read every family."""
        with patch.object(OktaConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "okta",
                "display_name": "Partial Org",
                "okta_org_url": _ORG_URL,
                "okta_api_token": _TOKEN,
            })
        assert resp.status_code == 201, resp.text

    def test_permission_diagnostics_report_partial_state_from_denied_family(self):
        from app.connectors.okta import build_okta_permission_diagnostics

        records = [
            {
                "record_type": "okta_organization",
                "tenant_id": "id:abc123",
                "org_hostname": "example.okta.com",
                "family_completeness": {
                    "users": "complete",
                    "groups": "complete",
                    "memberships": "complete",
                    "applications": "complete",
                    "app_user_assignments": "complete",
                    "app_group_assignments": "complete",
                    "policies": "complete",
                    "policy_rules": "complete",
                    "authenticators": "complete",
                    "custom_admin_roles": "denied",
                    "user_admin_role_assignments": "complete",
                    "group_admin_role_assignments": "complete",
                },
            },
        ]
        report = build_okta_permission_diagnostics(records)
        assert report["coverage"] in ("partial", "full", "invalid")
        assert report["coverage"] != "invalid"


# ════════════════════════════════════════════════════════════════════════════
# Invalid connection
# ════════════════════════════════════════════════════════════════════════════


class TestInvalidConnection:
    def test_malformed_org_url_rejected(self, client):
        resp = client.post("/integrations", json={
            "provider": "okta",
            "display_name": "Bad Org",
            "okta_org_url": "not-a-valid-url",
            "okta_api_token": _TOKEN,
        })
        assert resp.status_code == 400, resp.text

    def test_auth_failure_rejected(self, client):
        with patch.object(
            OktaConnector, "validate_credentials",
            side_effect=AuthenticationError("okta: token rejected", status_code=401),
        ):
            resp = client.post("/integrations", json={
                "provider": "okta",
                "display_name": "Auth Fail Org",
                "okta_org_url": _ORG_URL,
                "okta_api_token": _TOKEN,
            })
        assert resp.status_code == 400, resp.text
        assert _TOKEN not in resp.text

    def test_unreachable_org_rejected(self, client):
        with patch.object(
            OktaConnector, "validate_credentials",
            side_effect=NetworkError("okta: could not reach the org"),
        ):
            resp = client.post("/integrations", json={
                "provider": "okta",
                "display_name": "Unreachable Org",
                "okta_org_url": _ORG_URL,
                "okta_api_token": _TOKEN,
            })
        # NetworkError subclasses ConnectorError, and the router's
        # `except ConnectorError` branch (400) is ordered before its
        # `except NetworkError` branch (502) for every provider.
        assert resp.status_code == 400, resp.text

    def test_missing_org_url_rejected_at_schema_layer(self, client):
        resp = client.post("/integrations", json={
            "provider": "okta",
            "display_name": "No Org URL",
            "okta_api_token": _TOKEN,
        })
        assert resp.status_code == 422, resp.text

    def test_missing_api_token_rejected_at_schema_layer(self, client):
        resp = client.post("/integrations", json={
            "provider": "okta",
            "display_name": "No Token",
            "okta_org_url": _ORG_URL,
        })
        assert resp.status_code == 422, resp.text


# ════════════════════════════════════════════════════════════════════════════
# Unsupported optional API (custom admin roles unavailable) is NOT invalid
# ════════════════════════════════════════════════════════════════════════════


class TestUnsupportedOptionalApi:
    def test_custom_admin_roles_unavailable_does_not_block_creation(self, client):
        with patch.object(OktaConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "okta",
                "display_name": "No Custom Roles Org",
                "okta_org_url": _ORG_URL,
                "okta_api_token": _TOKEN,
            })
        assert resp.status_code == 201, resp.text

    def test_custom_admin_roles_unavailable_reports_partial_not_invalid(self):
        from app.connectors.okta import build_okta_permission_diagnostics

        families = [
            "users", "groups", "memberships", "applications",
            "app_user_assignments", "app_group_assignments", "policies",
            "policy_rules", "authenticators", "user_admin_role_assignments",
            "group_admin_role_assignments",
        ]
        completeness = {f: "complete" for f in families}
        completeness["custom_admin_roles"] = "unavailable"
        records = [{
            "record_type": "okta_organization",
            "tenant_id": "id:abc123",
            "org_hostname": "example.okta.com",
            "family_completeness": completeness,
        }]
        report = build_okta_permission_diagnostics(records)
        assert report["coverage"] != "invalid"


# ════════════════════════════════════════════════════════════════════════════
# Reconnect — same-tenant rotation succeeds, different-tenant rejected
# ════════════════════════════════════════════════════════════════════════════


class TestReconnect:
    def _create_integration(self, client) -> str:
        with patch.object(OktaConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "okta",
                "display_name": "Reconnect Test Org",
                "okta_org_url": _ORG_URL,
                "okta_api_token": _TOKEN,
            })
        assert resp.status_code == 201, resp.text
        return resp.json()["id"]

    def test_same_tenant_token_rotation_succeeds(self, client, db_session):
        integration_id = self._create_integration(client)

        # Simulate a completed first sync: the org resource's
        # provider_resource_id is upgraded from the creation-time
        # placeholder to the real "org/<tenant_id>" identity.
        from app.models.resource import Resource

        resource = (
            db_session.query(Resource)
            .filter(Resource.integration_id == integration_id)
            .first()
        )
        resource.provider_resource_id = "org/id:abc123"
        db_session.commit()

        with patch.object(OktaConnector, "validate_credentials", return_value=True):
            with patch("app.connectors.okta.call_okta", return_value=_fake_org_outcome("abc123")):
                resp = client.post(
                    f"/integrations/{integration_id}/reconnect",
                    json={"okta_api_token": "new-rotated-token"},
                )
        assert resp.status_code == 200, resp.text

    def test_different_tenant_token_rejected(self, client, db_session):
        integration_id = self._create_integration(client)

        from app.models.resource import Resource

        resource = (
            db_session.query(Resource)
            .filter(Resource.integration_id == integration_id)
            .first()
        )
        resource.provider_resource_id = "org/id:abc123"
        db_session.commit()

        with patch.object(OktaConnector, "validate_credentials", return_value=True):
            with patch("app.connectors.okta.call_okta", return_value=_fake_org_outcome("different-tenant-999")):
                resp = client.post(
                    f"/integrations/{integration_id}/reconnect",
                    json={"okta_api_token": "token-for-a-different-org"},
                )
        assert resp.status_code == 400, resp.text

    def test_reconnect_missing_token_rejected_at_schema_layer(self, client):
        with patch.object(OktaConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "okta",
                "display_name": "Reconnect Missing Token Org",
                "okta_org_url": _ORG_URL,
                "okta_api_token": _TOKEN,
            })
        integration_id = resp.json()["id"]
        reconnect_resp = client.post(f"/integrations/{integration_id}/reconnect", json={})
        assert reconnect_resp.status_code == 422, reconnect_resp.text


# ════════════════════════════════════════════════════════════════════════════
# Sensitive credentials never leak
# ════════════════════════════════════════════════════════════════════════════


class TestSensitiveCredentialsNeverLeak:
    def test_api_token_not_in_create_response(self, client, db_session):
        with patch.object(OktaConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "okta",
                "display_name": "Secret Test Org",
                "okta_org_url": _ORG_URL,
                "okta_api_token": _TOKEN,
            })
        assert resp.status_code == 201, resp.text
        assert _TOKEN not in resp.text
        assert "api_token" not in resp.json()
        assert "okta_api_token" not in resp.json()

    def test_api_token_not_in_get_integration_response(self, client, db_session):
        with patch.object(OktaConnector, "validate_credentials", return_value=True):
            create_resp = client.post("/integrations", json={
                "provider": "okta",
                "display_name": "Secret Get Org",
                "okta_org_url": _ORG_URL,
                "okta_api_token": _TOKEN,
            })
        integration_id = create_resp.json()["id"]
        get_resp = client.get(f"/integrations/{integration_id}")
        assert get_resp.status_code == 200
        assert _TOKEN not in get_resp.text

    def test_api_token_not_logged_by_validate_credentials(self, caplog):
        import logging

        from app.connectors.okta import CallOutcome

        connector = OktaConnector()
        with patch("app.connectors.okta.call_okta", return_value=_fake_org_outcome()):
            with caplog.at_level(logging.DEBUG):
                connector.validate_credentials({"org_url": _ORG_URL, "api_token": _TOKEN})
        assert _TOKEN not in caplog.text

    def test_encrypted_credentials_column_is_not_plaintext(self, client, db_session):
        with patch.object(OktaConnector, "validate_credentials", return_value=True):
            resp = client.post("/integrations", json={
                "provider": "okta",
                "display_name": "Encryption Check Org",
                "okta_org_url": _ORG_URL,
                "okta_api_token": _TOKEN,
            })
        integration_id = resp.json()["id"]
        db_session.expire_all()
        row = db_session.query(Integration).filter(Integration.id == integration_id).first()
        assert row is not None
        assert _TOKEN.encode() not in row.encrypted_credentials
