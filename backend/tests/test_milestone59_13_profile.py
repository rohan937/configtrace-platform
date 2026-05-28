"""M59.13 — User profile (first_name + last_name) tests.

Covers:
  * ProfileUpdateRequest validation (trim + max-length + empty → None)
  * Computed-display-name policy
  * GET /me/profile and PATCH /me/profile via the TestClient
  * Authentication is required (no anonymous access)
  * One user cannot mutate another user's profile (the route has no
    user-id path param so this is structurally enforced — verified)
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.core.auth import get_current_user
from app.database import get_db
from app.main import app
from app.models.user import User
from app.routers.me import _computed_display_name
from app.schemas.profile import ProfileUpdateRequest


# ─────────────────────────────────────────────────────────────────────────────
# A. Schema validation
# ─────────────────────────────────────────────────────────────────────────────


class TestProfileUpdateRequest:

    def test_A1_trims_whitespace(self):
        r = ProfileUpdateRequest(first_name="  Rohan  ", last_name="\tShah\n")
        assert r.first_name == "Rohan"
        assert r.last_name == "Shah"

    def test_A2_empty_string_becomes_none(self):
        r = ProfileUpdateRequest(first_name="", last_name="   ")
        assert r.first_name is None
        assert r.last_name is None

    def test_A3_omitted_fields_are_none(self):
        r = ProfileUpdateRequest()
        assert r.first_name is None
        assert r.last_name is None
        # Critically, ``model_dump(exclude_unset=True)`` is empty so the
        # router will NOT overwrite either field.
        assert r.model_dump(exclude_unset=True) == {}

    def test_A4_long_names_rejected(self):
        with pytest.raises(Exception):
            ProfileUpdateRequest(first_name="x" * 101)
        with pytest.raises(Exception):
            ProfileUpdateRequest(last_name="x" * 200)

    def test_A5_accepts_unicode_names(self):
        r = ProfileUpdateRequest(first_name="Élise", last_name="Müller")
        assert r.first_name == "Élise"
        assert r.last_name == "Müller"


# ─────────────────────────────────────────────────────────────────────────────
# B. Computed-display-name policy
# ─────────────────────────────────────────────────────────────────────────────


def _user(**kw) -> User:
    """Build a User stub with sensible defaults."""
    u = User(
        clerk_id=kw.get("clerk_id", "clerk_x"),
        email=kw.get("email", "user@example.com"),
        display_name=kw.get("display_name"),
        first_name=kw.get("first_name"),
        last_name=kw.get("last_name"),
    )
    return u


class TestComputedDisplayName:

    def test_B1_first_and_last_used(self):
        assert _computed_display_name(_user(first_name="Rohan", last_name="Shah")) == "Rohan Shah"

    def test_B2_first_only(self):
        assert _computed_display_name(_user(first_name="Rohan")) == "Rohan"

    def test_B3_last_only(self):
        assert _computed_display_name(_user(last_name="Shah")) == "Shah"

    def test_B4_falls_back_to_display_name(self):
        u = _user(display_name="Imported Clerk Name", first_name=None, last_name=None)
        assert _computed_display_name(u) == "Imported Clerk Name"

    def test_B5_ignores_placeholder_display_name(self):
        u = _user(display_name="ConfigTrace User", email="alice@example.com")
        assert _computed_display_name(u) == "alice@example.com"

    def test_B6_falls_back_to_email_when_nothing_set(self):
        u = _user(email="solo@example.com")
        assert _computed_display_name(u) == "solo@example.com"

    def test_B7_first_last_take_priority_over_display_name(self):
        u = _user(
            first_name="Rohan", last_name="Shah",
            display_name="Clerk-Imported Name",
            email="rohan@example.com",
        )
        assert _computed_display_name(u) == "Rohan Shah"


# ─────────────────────────────────────────────────────────────────────────────
# C. Router behaviour via TestClient (mocked DB + auth dependency)
# ─────────────────────────────────────────────────────────────────────────────


def _make_test_user(**kw) -> User:
    u = _user(**kw)
    u.id = kw.get("id", uuid.uuid4())  # type: ignore[assignment]
    return u


def _client_with(user: User) -> TestClient:
    """Yield a TestClient whose get_current_user returns *user* and whose
    get_db returns a MagicMock session.  Caller is responsible for
    clearing dependency overrides via ``app.dependency_overrides.clear()``
    after the test."""
    mock_db = MagicMock()
    # PATCH path calls db.add, db.commit, db.refresh — all no-ops on mock.
    mock_db.add = MagicMock()
    mock_db.commit = MagicMock()
    mock_db.refresh = MagicMock(side_effect=lambda u: None)

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=True)


class TestProfileRouter:

    def teardown_method(self) -> None:
        app.dependency_overrides.clear()

    def test_C1_get_returns_email_when_nothing_set(self):
        u = _make_test_user(email="solo@example.com")
        client = _client_with(u)
        resp = client.get("/me/profile")
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "solo@example.com"
        assert data["first_name"] is None
        assert data["last_name"] is None
        assert data["computed_display_name"] == "solo@example.com"

    def test_C2_get_returns_full_name_when_set(self):
        u = _make_test_user(
            email="r@example.com", first_name="Rohan", last_name="Shah",
        )
        client = _client_with(u)
        resp = client.get("/me/profile")
        data = resp.json()
        assert data["computed_display_name"] == "Rohan Shah"

    def test_C3_patch_updates_both_names(self):
        u = _make_test_user(email="r@example.com")
        client = _client_with(u)
        resp = client.patch(
            "/me/profile",
            json={"first_name": "Rohan", "last_name": "Shah"},
        )
        assert resp.status_code == 200
        assert u.first_name == "Rohan"
        assert u.last_name == "Shah"
        assert resp.json()["computed_display_name"] == "Rohan Shah"

    def test_C4_patch_trims_whitespace(self):
        u = _make_test_user(email="r@example.com")
        client = _client_with(u)
        client.patch(
            "/me/profile",
            json={"first_name": "  Rohan  ", "last_name": "  Shah  "},
        )
        assert u.first_name == "Rohan"
        assert u.last_name == "Shah"

    def test_C5_patch_empty_string_clears_field(self):
        u = _make_test_user(
            email="r@example.com", first_name="Rohan", last_name="Shah",
        )
        client = _client_with(u)
        resp = client.patch("/me/profile", json={"first_name": ""})
        assert resp.status_code == 200
        assert u.first_name is None
        # last_name unchanged
        assert u.last_name == "Shah"
        assert resp.json()["computed_display_name"] == "Shah"

    def test_C6_patch_omitted_field_unchanged(self):
        u = _make_test_user(
            email="r@example.com", first_name="Rohan", last_name="Shah",
        )
        client = _client_with(u)
        resp = client.patch("/me/profile", json={"last_name": "Smith"})
        assert resp.status_code == 200
        assert u.first_name == "Rohan"  # unchanged
        assert u.last_name == "Smith"

    def test_C7_patch_long_name_rejected_with_422(self):
        u = _make_test_user(email="r@example.com")
        client = _client_with(u)
        resp = client.patch("/me/profile", json={"first_name": "x" * 101})
        assert resp.status_code == 422

    def test_C8_get_requires_authentication(self):
        """When the auth dependency is not overridden the request fails."""
        # Don't override get_current_user.
        app.dependency_overrides.clear()
        mock_db = MagicMock()
        app.dependency_overrides[get_db] = lambda: mock_db
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/me/profile")
        # Without dev mode set up, the real get_current_user dependency
        # rejects unauthenticated requests with 401 / 503.  Either is
        # acceptable here — what matters is that it does NOT succeed (200).
        assert resp.status_code != 200

    def test_C9_no_user_id_path_param_means_cross_user_attack_is_structural_impossible(self):
        """The route has no ``user_id`` path parameter, so a malicious
        client cannot target another user's profile by URL.  Document
        this structurally with an introspection check."""
        from app.routers.me import router as me_router

        for r in me_router.routes:
            assert "user_id" not in r.path  # type: ignore[attr-defined]
            assert "{id}" not in r.path     # type: ignore[attr-defined]
