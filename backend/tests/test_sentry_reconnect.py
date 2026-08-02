"""Sentry reconnect / token-rotation deep-dive tests (message 8 of 8).

Complements the end-to-end HTTP-path reconnect cases in
``test_sentry_integration_creation.py::TestReconnect`` with focused
unit-level coverage of ``reconnect_credentials_sentry()`` itself: organization-
identity mismatch protection (using the stable ``organization_id``, never
the mutable ``organization_slug``), reconnect-before-first-sync, and the
guarantee that no prior connector/session/pagination/capability state is
reused across a reconnect — every reconnect builds a fresh
``SentryConnector()`` bound only to the newly supplied credentials.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

from app.connectors.exceptions import AuthenticationError, ConnectorError
from app.connectors.sentry import SentryConnector
from app.connectors.sentry_schema import COVERAGE_FULL
from app.core.encryption import decrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.services import integration_service

_ORGANIZATION_SLUG = "my-organization"
_TOKEN = "super-secret-fake-sentry-token"


def _full_result(organization_id: str = "id:1001", slug: str = _ORGANIZATION_SLUG) -> dict:
    return {
        "coverage": COVERAGE_FULL,
        "organization_id": organization_id,
        "slug": slug,
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


def _create_payload(**overrides) -> dict:
    payload = {
        "provider": "sentry",
        "display_name": "Reconnect Unit Test Org",
        "sentry_organization_slug": _ORGANIZATION_SLUG,
        "sentry_auth_token": _TOKEN,
    }
    payload.update(overrides)
    return payload


def _create_integration(client) -> str:
    with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
        resp = client.post("/integrations", json=_create_payload())
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ════════════════════════════════════════════════════════════════════════════
# Organization-identity mismatch protection — stable ID, never raw slug
# ════════════════════════════════════════════════════════════════════════════


class TestOrganizationIdentityMismatch:
    def test_same_stable_id_different_slug_accepted(self, client):
        """A slug rename for the SAME organization (same stable
        organization_id) is a legitimate reconnect, not a mismatch."""
        integration_id = _create_integration(client)
        with patch.object(
            SentryConnector, "probe_coverage",
            return_value=_full_result(organization_id="id:1001", slug="renamed-org"),
        ):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={
                    "sentry_organization_slug": "renamed-org",
                    "sentry_auth_token": "new-token",
                },
            )
        assert resp.status_code == 200, resp.text

    def test_same_slug_different_stable_id_rejected(self, client):
        """Same slug string but a DIFFERENT underlying organization id
        (e.g. the org was deleted and slug re-registered by someone else)
        must be rejected — identity is the stable id, not the slug."""
        integration_id = _create_integration(client)
        with patch.object(
            SentryConnector, "probe_coverage",
            return_value=_full_result(organization_id="id:9999", slug=_ORGANIZATION_SLUG),
        ):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "token-for-different-org-same-slug"},
            )
        assert resp.status_code == 400, resp.text

    def test_mismatch_error_never_exposes_organization_ids(self, client):
        integration_id = _create_integration(client)
        with patch.object(
            SentryConnector, "probe_coverage",
            return_value=_full_result(organization_id="id:9999"),
        ):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "token-for-different-org"},
            )
        assert resp.status_code == 400, resp.text
        assert "id:1001" not in resp.text
        assert "id:9999" not in resp.text

    def test_unit_reconnect_raises_connector_error_on_mismatch(self, client, db_session):
        integration_id = _create_integration(client)
        with patch.object(
            SentryConnector, "probe_coverage",
            return_value=_full_result(organization_id="id:different"),
        ):
            try:
                integration_service.reconnect_credentials_sentry(
                    integration_id=uuid.UUID(integration_id),
                    user_id=_user_id_for(client, db_session, integration_id),
                    new_organization_slug=None,
                    new_auth_token="mismatched-token",
                    db=db_session,
                )
                raised = False
            except ConnectorError:
                raised = True
        assert raised


def _user_id_for(client, db_session, integration_id: str):
    row = db_session.query(Integration).filter(Integration.id == integration_id).first()
    return row.user_id


# ════════════════════════════════════════════════════════════════════════════
# No prior connector/session/pagination/capability/cache state is reused
# ════════════════════════════════════════════════════════════════════════════


class TestNoStateReuseAcrossReconnect:
    def test_reconnect_builds_fresh_connector_instance(self, client):
        """Each reconnect calls ``SentryConnector()`` fresh — no shared
        client/session/cache carried over from the original connection or
        a prior reconnect attempt."""
        integration_id = _create_integration(client)
        seen_instances = []
        original_probe = SentryConnector.probe_coverage

        def _tracking_probe(self, credentials):
            seen_instances.append(id(self))
            return _full_result()

        with patch.object(SentryConnector, "probe_coverage", _tracking_probe):
            client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "first-rotation"},
            )
            client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "second-rotation"},
            )
        assert len(seen_instances) == 2
        assert seen_instances[0] != seen_instances[1]

    def test_reconnect_probe_receives_only_new_credentials(self, client):
        """The credentials dict passed to probe_coverage on reconnect
        contains only the new token/slug — never a merged or leftover
        value from the original connection's credential dict identity."""
        integration_id = _create_integration(client)
        captured = {}

        def _capture_probe(self, credentials):
            captured.update(credentials)
            return _full_result()

        with patch.object(SentryConnector, "probe_coverage", _capture_probe):
            client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "isolated-rotation-token"},
            )
        assert captured["auth_token"] == "isolated-rotation-token"


# ════════════════════════════════════════════════════════════════════════════
# Token rotation identity — old token discarded, encrypted storage updated
# ════════════════════════════════════════════════════════════════════════════


class TestTokenRotationIdentity:
    def test_rotated_token_replaces_stored_credentials(self, client, db_session):
        integration_id = _create_integration(client)
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "rotated-token-final"},
            )
        assert resp.status_code == 200, resp.text
        db_session.expire_all()
        row = db_session.query(Integration).filter(Integration.id == integration_id).first()
        creds = decrypt_credentials(row.encrypted_credentials, row.credential_iv)
        assert creds["auth_token"] == "rotated-token-final"

    def test_reconnect_omitting_slug_reuses_existing_slug(self, client, db_session):
        integration_id = _create_integration(client)
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "token-only-rotation"},
            )
        assert resp.status_code == 200, resp.text
        db_session.expire_all()
        row = db_session.query(Integration).filter(Integration.id == integration_id).first()
        creds = decrypt_credentials(row.encrypted_credentials, row.credential_iv)
        assert creds["organization_slug"] == _ORGANIZATION_SLUG

    def test_resource_row_updated_with_new_stable_organization_id(self, client, db_session):
        integration_id = _create_integration(client)
        with patch.object(
            SentryConnector, "probe_coverage",
            return_value=_full_result(organization_id="id:1001", slug="new-slug-same-org"),
        ):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={
                    "sentry_organization_slug": "new-slug-same-org",
                    "sentry_auth_token": "token-for-rename",
                },
            )
        assert resp.status_code == 200, resp.text
        db_session.expire_all()
        resource = (
            db_session.query(Resource)
            .filter(
                Resource.integration_id == integration_id,
                Resource.provider_resource_type == "sentry_organization",
            )
            .first()
        )
        assert resource is not None
        assert resource.provider_resource_id == "organization/id:1001"


# ════════════════════════════════════════════════════════════════════════════
# Reconnect before first sync — no fabricated historical Changes
# ════════════════════════════════════════════════════════════════════════════


class TestReconnectBeforeFirstSync:
    def test_reconnect_immediately_after_creation_succeeds(self, client):
        """An integration that has never synced can still be reconnected
        — reconnect does not depend on any prior sync run existing."""
        integration_id = _create_integration(client)
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            resp = client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "pre-first-sync-rotation"},
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "active"

    def test_reconnect_does_not_create_sync_run(self, client, db_session):
        from app.models.sync_run import SyncRun

        integration_id = _create_integration(client)
        with patch.object(SentryConnector, "probe_coverage", return_value=_full_result()):
            client.post(
                f"/integrations/{integration_id}/reconnect",
                json={"sentry_auth_token": "no-sync-run-token"},
            )
        run_count = (
            db_session.query(SyncRun)
            .filter(SyncRun.integration_id == integration_id)
            .count()
        )
        assert run_count == 0
