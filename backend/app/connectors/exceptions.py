"""Connector exception hierarchy.

All exceptions raised by a connector's ``fetch()`` or
``validate_credentials()`` are subclasses of ``ConnectorError``.  Callers can
catch the base class for a single blanket handler, or catch the specific
subclass when they need to distinguish causes (e.g. to surface a 401 as an
integration-setup error vs a transient 500 as a sync error).
"""

from __future__ import annotations


class ConnectorError(Exception):
    """Base exception for all connector errors.

    Attributes:
        status_code: The HTTP status code returned by the provider, if any.
            ``None`` for non-HTTP errors (e.g. credential validation).
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class AuthenticationError(ConnectorError):
    """Raised when the provider rejects the supplied credentials.

    Corresponds to HTTP 401 (Unauthorized) or 403 (Forbidden).  This error
    means the stored credentials are stale or lack the required permissions —
    the integration should be marked as needing re-authentication.
    """


class RateLimitError(ConnectorError):
    """Raised when the rate limit was hit and all retries were exhausted.

    Attributes:
        retry_after: The last ``Retry-After`` value seen (seconds).  ``None``
            if the header was absent on the final 429 response.
    """

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, status_code=429)
        self.retry_after = retry_after


class NetworkError(ConnectorError):
    """Raised when a network-level failure prevents the request from completing.

    Examples: connection timeout, DNS resolution failure, SSL handshake error.
    The ``status_code`` attribute is always ``None`` because no HTTP response
    was received.
    """
