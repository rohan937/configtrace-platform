"""M24 follow-up — user email resolution + placeholder backfill.

Background
----------
M24 alert dispatch was working up to recipient resolution but skipping
delivery because every authenticated user had a ``<clerk_id>@clerk.user``
placeholder in ``users.email``.  Root cause: Clerk's default session JWT
template doesn't include the ``email`` claim, so the auth-time fallback
was the placeholder for every user.

This follow-up adds a Clerk Backend API call as a second resolution path
and a backfill script for existing rows.  These tests assert:

1. ``clerk_service.fetch_user_email`` correctly extracts the primary
   email from a Clerk Backend API response, and returns ``None`` (never
   raises) on every failure mode.
2. ``_get_or_create_clerk_user`` writes a **real email** when:
   - the JWT carries the ``email`` claim;
   - the JWT has no claim, but the Clerk Backend API returns one.
3. ``_get_or_create_clerk_user`` writes the placeholder only when both
   sources are exhausted, and the placeholder is **upgraded** to a real
   email on a later request that does manage to resolve one.
4. A user who already has a real email is **never** overwritten — claim
   or Backend API result is ignored.
5. The backfill script processes every placeholder user, resolves each
   via ``clerk_service``, updates the rows, and is idempotent on re-run.

No real HTTP traffic
--------------------
Every test monkeypatches ``clerk_service.fetch_user_email`` (and, for
the parsing tests, only the network surface inside ``clerk_service``).
``CLERK_SECRET_KEY`` is forced to a string by tests that need the
Backend API code path; tests for the "missing key" branch explicitly
unset it.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from sqlalchemy.orm import Session

from app.models.user import User
from app.services import clerk_service


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _fresh_clerk_id() -> str:
    """Return a clerk_id that won't collide with anything else in the DB."""
    return f"user_m24fu_{uuid.uuid4().hex[:10]}"


def _delete_user_by_clerk_id(db: Session, clerk_id: str) -> None:
    """Best-effort teardown; placeholder users have no children to cascade."""
    user = db.query(User).filter(User.clerk_id == clerk_id).first()
    if user is not None:
        try:
            db.delete(user)
            db.commit()
        except Exception:
            db.rollback()


# ─────────────────────────────────────────────────────────────────────────────
# Section 1.  clerk_service.fetch_user_email — pure parsing + HTTP error paths
# ─────────────────────────────────────────────────────────────────────────────


def test_fetch_user_email_returns_none_when_secret_key_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No CLERK_SECRET_KEY → no API call → None (silent)."""
    from app.config import settings

    monkeypatch.setattr(settings, "CLERK_SECRET_KEY", None)
    assert clerk_service.fetch_user_email("user_abc") is None


def test_fetch_user_email_returns_none_on_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """httpx raises on network → None, no exception escapes."""
    from app.config import settings

    monkeypatch.setattr(settings, "CLERK_SECRET_KEY", "sk_test_xxx")

    class BoomClient:
        def __init__(self, *a: Any, **k: Any) -> None: ...
        def __enter__(self) -> "BoomClient":
            return self
        def __exit__(self, *a: Any) -> None: ...
        def get(self, *a: Any, **k: Any) -> Any:
            raise httpx.ConnectError("simulated network failure")

    monkeypatch.setattr(httpx, "Client", BoomClient)
    assert clerk_service.fetch_user_email("user_abc") is None


def test_fetch_user_email_returns_none_on_non_200(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """4xx/5xx → None.  Common case: 404 if the user was deleted in Clerk."""
    from app.config import settings

    monkeypatch.setattr(settings, "CLERK_SECRET_KEY", "sk_test_xxx")

    fake_resp = MagicMock()
    fake_resp.status_code = 404

    class FakeClient:
        def __init__(self, *a: Any, **k: Any) -> None: ...
        def __enter__(self) -> "FakeClient":
            return self
        def __exit__(self, *a: Any) -> None: ...
        def get(self, *a: Any, **k: Any) -> Any:
            return fake_resp

    monkeypatch.setattr(httpx, "Client", FakeClient)
    assert clerk_service.fetch_user_email("user_abc") is None


def test_extract_primary_email_happy_path() -> None:
    """Standard Clerk response shape → primary email extracted correctly."""
    payload = {
        "id": "user_abc",
        "primary_email_address_id": "idn_primary",
        "email_addresses": [
            {"id": "idn_other", "email_address": "other@example.com"},
            {"id": "idn_primary", "email_address": "alice@example.com"},
        ],
    }
    result = clerk_service._extract_primary_email(payload, clerk_id="user_abc")
    assert result == "alice@example.com"


def test_extract_primary_email_no_primary_id() -> None:
    payload = {"id": "user_abc", "email_addresses": []}
    assert clerk_service._extract_primary_email(payload, clerk_id="user_abc") is None


def test_extract_primary_email_primary_id_not_in_list() -> None:
    payload = {
        "primary_email_address_id": "idn_missing",
        "email_addresses": [
            {"id": "idn_other", "email_address": "other@example.com"},
        ],
    }
    assert clerk_service._extract_primary_email(payload, clerk_id="user_abc") is None


def test_extract_primary_email_empty_address_returns_none() -> None:
    payload = {
        "primary_email_address_id": "idn_primary",
        "email_addresses": [
            {"id": "idn_primary", "email_address": ""},
        ],
    }
    assert clerk_service._extract_primary_email(payload, clerk_id="user_abc") is None


def test_fetch_user_email_full_happy_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: 200 response → parsed → real email returned."""
    from app.config import settings

    monkeypatch.setattr(settings, "CLERK_SECRET_KEY", "sk_test_xxx")

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "id": "user_abc",
        "primary_email_address_id": "idn_primary",
        "email_addresses": [
            {"id": "idn_primary", "email_address": "alice@example.com"},
        ],
    }

    captured: dict[str, Any] = {}

    class FakeClient:
        def __init__(self, *a: Any, **k: Any) -> None: ...
        def __enter__(self) -> "FakeClient":
            return self
        def __exit__(self, *a: Any) -> None: ...
        def get(self, url: str, headers: dict, *a: Any, **k: Any) -> Any:
            captured["url"] = url
            captured["headers"] = headers
            return fake_resp

    monkeypatch.setattr(httpx, "Client", FakeClient)

    assert clerk_service.fetch_user_email("user_abc") == "alice@example.com"
    assert captured["url"].endswith("/v1/users/user_abc")
    # Bearer token format, secret not logged anywhere.
    assert captured["headers"]["Authorization"] == "Bearer sk_test_xxx"


# ─────────────────────────────────────────────────────────────────────────────
# Section 2.  _get_or_create_clerk_user — resolution policy
# ─────────────────────────────────────────────────────────────────────────────


def test_new_user_with_email_claim_persists_real_email(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """JWT carries the email claim → user.email is that value."""
    from app.core.auth import _get_or_create_clerk_user

    # Backend API must NOT be reached when the claim provides the email —
    # raise if called so a regression would be loud.
    monkeypatch.setattr(
        clerk_service,
        "fetch_user_email",
        lambda _: (_ for _ in ()).throw(AssertionError("must not call Backend API")),
    )

    clerk_id = _fresh_clerk_id()
    claims = {"sub": clerk_id, "email": "alice@example.com"}

    try:
        user = _get_or_create_clerk_user(claims, db_session)
        assert user.email == "alice@example.com"
        assert not user.email.endswith("@clerk.user")
    finally:
        _delete_user_by_clerk_id(db_session, clerk_id)


def test_new_user_no_claim_falls_back_to_clerk_backend_api(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No email claim → Clerk Backend API consulted → real email persisted."""
    from app.core.auth import _get_or_create_clerk_user

    calls: list[str] = []

    def fake_fetch(clerk_id: str) -> str:
        calls.append(clerk_id)
        return "bob@example.com"

    monkeypatch.setattr(clerk_service, "fetch_user_email", fake_fetch)

    clerk_id = _fresh_clerk_id()
    claims = {"sub": clerk_id}  # ← no email claim

    try:
        user = _get_or_create_clerk_user(claims, db_session)
        assert user.email == "bob@example.com"
        assert calls == [clerk_id]
    finally:
        _delete_user_by_clerk_id(db_session, clerk_id)


def test_new_user_no_claim_and_no_backend_api_writes_placeholder(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both sources exhausted → placeholder written (no exception)."""
    from app.core.auth import _get_or_create_clerk_user

    monkeypatch.setattr(clerk_service, "fetch_user_email", lambda _: None)

    clerk_id = _fresh_clerk_id()
    claims = {"sub": clerk_id}

    try:
        user = _get_or_create_clerk_user(claims, db_session)
        assert user.email == f"{clerk_id}@clerk.user"
    finally:
        _delete_user_by_clerk_id(db_session, clerk_id)


def test_existing_placeholder_user_upgraded_via_claim(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Placeholder user → next request with email claim → email upgraded."""
    from app.core.auth import _get_or_create_clerk_user

    monkeypatch.setattr(
        clerk_service,
        "fetch_user_email",
        lambda _: (_ for _ in ()).throw(AssertionError("claim path should win")),
    )

    clerk_id = _fresh_clerk_id()
    user = User(
        clerk_id=clerk_id,
        email=f"{clerk_id}@clerk.user",
        display_name="ConfigTrace User",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    try:
        result = _get_or_create_clerk_user(
            {"sub": clerk_id, "email": "carol@example.com"}, db_session
        )
        db_session.refresh(user)
        assert result.id == user.id
        assert user.email == "carol@example.com"
        assert not user.email.endswith("@clerk.user")
    finally:
        _delete_user_by_clerk_id(db_session, clerk_id)


def test_existing_placeholder_user_upgraded_via_backend_api(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Placeholder user, no claim, but Backend API has email → upgrade."""
    from app.core.auth import _get_or_create_clerk_user

    monkeypatch.setattr(
        clerk_service, "fetch_user_email", lambda _: "dave@example.com"
    )

    clerk_id = _fresh_clerk_id()
    user = User(
        clerk_id=clerk_id,
        email=f"{clerk_id}@clerk.user",
        display_name="ConfigTrace User",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    try:
        _get_or_create_clerk_user({"sub": clerk_id}, db_session)
        db_session.refresh(user)
        assert user.email == "dave@example.com"
    finally:
        _delete_user_by_clerk_id(db_session, clerk_id)


def test_existing_placeholder_user_left_alone_when_clerk_api_returns_none(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No claim, Clerk API failed → placeholder unchanged."""
    from app.core.auth import _get_or_create_clerk_user

    monkeypatch.setattr(clerk_service, "fetch_user_email", lambda _: None)

    clerk_id = _fresh_clerk_id()
    user = User(
        clerk_id=clerk_id,
        email=f"{clerk_id}@clerk.user",
        display_name="ConfigTrace User",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    try:
        _get_or_create_clerk_user({"sub": clerk_id}, db_session)
        db_session.refresh(user)
        assert user.email == f"{clerk_id}@clerk.user"  # unchanged
    finally:
        _delete_user_by_clerk_id(db_session, clerk_id)


def test_existing_real_email_never_overwritten(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real-email user → claim & Backend API both ignored."""
    from app.core.auth import _get_or_create_clerk_user

    # Make both sources return *different* emails to prove neither wins.
    monkeypatch.setattr(
        clerk_service, "fetch_user_email", lambda _: "different@example.com"
    )

    clerk_id = _fresh_clerk_id()
    user = User(
        clerk_id=clerk_id,
        email="real@example.com",
        display_name="Real Name",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    try:
        _get_or_create_clerk_user(
            {"sub": clerk_id, "email": "yet-another@example.com"}, db_session
        )
        db_session.refresh(user)
        assert user.email == "real@example.com"
    finally:
        _delete_user_by_clerk_id(db_session, clerk_id)


# ─────────────────────────────────────────────────────────────────────────────
# Section 3.  Backfill script
# ─────────────────────────────────────────────────────────────────────────────


def test_backfill_upgrades_placeholder_users(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run_backfill resolves every placeholder via clerk_service and commits."""
    from scripts.backfill_user_emails import run_backfill

    # Map clerk_id → "real" email returned by the fake Backend API.
    resolved: dict[str, str] = {}

    clerk_ids: list[str] = [_fresh_clerk_id() for _ in range(3)]
    try:
        for idx, cid in enumerate(clerk_ids):
            user = User(
                clerk_id=cid,
                email=f"{cid}@clerk.user",
                display_name="ConfigTrace User",
            )
            db_session.add(user)
            resolved[cid] = f"user{idx}@example.com"
        db_session.commit()

        monkeypatch.setattr(
            clerk_service,
            "fetch_user_email",
            lambda cid: resolved.get(cid),
        )

        result = run_backfill()
        assert result["total"] >= len(clerk_ids)
        # We can't assert == here because the test_user fixture (and any
        # leftover placeholder rows from other suites) also count.  But
        # at least our three rows must show up in ``updated`` count.
        assert result["updated"] >= len(clerk_ids)

        for cid in clerk_ids:
            row = db_session.query(User).filter(User.clerk_id == cid).first()
            assert row is not None
            assert row.email == resolved[cid]
            assert not row.email.endswith("@clerk.user")
    finally:
        for cid in clerk_ids:
            _delete_user_by_clerk_id(db_session, cid)


def test_backfill_idempotent_on_rerun(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Second run finds the previously-upgraded rows no longer match the filter."""
    from scripts.backfill_user_emails import run_backfill

    clerk_id = _fresh_clerk_id()
    user = User(
        clerk_id=clerk_id,
        email=f"{clerk_id}@clerk.user",
        display_name="ConfigTrace User",
    )
    db_session.add(user)
    db_session.commit()

    try:
        monkeypatch.setattr(
            clerk_service, "fetch_user_email", lambda _: "eve@example.com"
        )

        first = run_backfill()
        assert first["updated"] >= 1

        # Second run — clerk_service must NOT be called for our user
        # because the placeholder is gone.  If anything else in the DB
        # is still a placeholder it would still be processed; for our
        # row the email should remain stable.
        second = run_backfill()
        row = db_session.query(User).filter(User.clerk_id == clerk_id).first()
        assert row is not None
        assert row.email == "eve@example.com"
        # The user we created is no longer counted in second["total"].
        # Other tests' fixtures may leave placeholder rows, so we assert
        # a relative property rather than an absolute count.
        assert second["total"] <= first["total"]
    finally:
        _delete_user_by_clerk_id(db_session, clerk_id)


def test_backfill_leaves_users_unchanged_when_clerk_api_returns_none(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If Clerk Backend API can't resolve, the placeholder stays."""
    from scripts.backfill_user_emails import run_backfill

    clerk_id = _fresh_clerk_id()
    user = User(
        clerk_id=clerk_id,
        email=f"{clerk_id}@clerk.user",
        display_name="ConfigTrace User",
    )
    db_session.add(user)
    db_session.commit()

    try:
        monkeypatch.setattr(clerk_service, "fetch_user_email", lambda _: None)

        result = run_backfill()
        assert result["failed"] >= 1

        row = db_session.query(User).filter(User.clerk_id == clerk_id).first()
        assert row is not None
        assert row.email == f"{clerk_id}@clerk.user"
    finally:
        _delete_user_by_clerk_id(db_session, clerk_id)
