"""Email provider abstraction — Milestone 24.

Public surface
--------------
:func:`send_email(to, subject, body)` — the only function callers should use.

Why a thin wrapper
------------------
* The Resend HTTP call is hidden behind a single function so tests can
  monkeypatch ``email_service.send_email`` without mocking ``httpx``.
* Swapping providers later is a one-file change: replace
  :func:`_send_via_resend` and keep the public signature identical.
* Settings access is centralised here — callers never read ``RESEND_API_KEY``
  directly, so an unconfigured environment fails closed in exactly one place.

Failure semantics
-----------------
* ``send_email`` raises :class:`EmailSendError` on any failure.
* Callers (specifically :mod:`app.services.alert_service`) catch this and
  record a ``failed`` Alert row.  The sync itself never raises because of
  email problems — see ``alert_service.dispatch_alerts_for_sync``.

Configuration
-------------
Required env vars in production:

* ``RESEND_API_KEY``        — token from https://resend.com → API Keys
* ``ALERTS_FROM_EMAIL``     — "From" header, must be on a verified domain
* ``APP_BASE_URL``          — used by the alert templater, not this module

When :attr:`Settings.is_email_alerting_configured` is False, ``send_email``
raises :class:`EmailNotConfigured`.  The dispatcher catches this and logs
a single warning per sync instead of stack traces.
"""

from __future__ import annotations

import logging
from typing import Final

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

_RESEND_ENDPOINT: Final[str] = "https://api.resend.com/emails"
_HTTP_TIMEOUT: Final[float] = 8.0  # seconds


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────


class EmailServiceError(Exception):
    """Base class for all email-service errors."""


class EmailNotConfigured(EmailServiceError):
    """Raised when ``RESEND_API_KEY`` / ``ALERTS_FROM_EMAIL`` are missing.

    Treated as a non-fatal condition by the alert dispatcher: a warning is
    logged once per sync, and the sync completes normally.
    """


class EmailSendError(EmailServiceError):
    """Raised when the provider call fails (network, 4xx/5xx, parse).

    Caught by the alert dispatcher, which records a ``failed`` Alert row
    with the exception message in ``error_message``.
    """


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def send_email(*, to: str, subject: str, body: str) -> dict:
    """Send a plain-text email to *to* and return provider metadata.

    Args:
        to:      Recipient address.  Must be a real deliverable address —
                 the caller is responsible for filtering placeholder users
                 such as ``user_xxx@clerk.user``.
        subject: Plain-text subject line.  Should be short (<78 chars).
        body:    Plain-text body.  No HTML — keep it readable and not
                 dependent on rendering.

    Returns:
        Provider response dict (parsed JSON).  For Resend, this includes
        an ``id`` field that uniquely identifies the dispatched message.

    Raises:
        EmailNotConfigured: When ``RESEND_API_KEY`` / ``ALERTS_FROM_EMAIL``
            are missing or placeholder.
        EmailSendError:     Any network, HTTP, or parsing failure.
    """
    if not settings.is_email_alerting_configured:
        raise EmailNotConfigured(
            "Email alerting is not configured "
            "(RESEND_API_KEY and/or ALERTS_FROM_EMAIL missing)."
        )

    # Guarded by is_email_alerting_configured — these are guaranteed non-None
    # here, but the cast keeps mypy / pyright happy and survives refactors.
    api_key = settings.RESEND_API_KEY or ""
    from_addr = settings.ALERTS_FROM_EMAIL or ""

    return _send_via_resend(
        api_key=api_key,
        from_addr=from_addr,
        to=to,
        subject=subject,
        body=body,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Provider: Resend
# ─────────────────────────────────────────────────────────────────────────────


def _send_via_resend(
    *,
    api_key: str,
    from_addr: str,
    to: str,
    subject: str,
    body: str,
) -> dict:
    """POST to Resend's ``/emails`` endpoint and return the parsed response.

    Resend's API docs: https://resend.com/docs/api-reference/emails/send-email

    We send a plain-text body using the ``text`` field.  Resend also accepts
    ``html`` — intentionally not used in M24 to keep the surface small and
    avoid rendering-related deliverability issues.
    """
    payload = {
        "from": from_addr,
        "to": [to],
        "subject": subject,
        "text": body,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
            resp = client.post(_RESEND_ENDPOINT, json=payload, headers=headers)
    except httpx.HTTPError as exc:
        # Transport-level failure (DNS, connection, timeout).
        raise EmailSendError(f"Resend HTTP transport failure: {exc!r}") from exc

    if resp.status_code >= 400:
        # Surface the response body (provider error messages are useful in logs).
        # We do NOT log the request payload — that would include the recipient
        # address and subject, which is fine, but never the API key.
        raise EmailSendError(
            f"Resend returned HTTP {resp.status_code}: {resp.text[:500]!r}"
        )

    try:
        return resp.json()
    except ValueError as exc:
        raise EmailSendError(
            f"Resend returned non-JSON response (status {resp.status_code}): "
            f"{resp.text[:200]!r}"
        ) from exc
