"""Abstract base class for all ConfigTrace provider connectors."""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseConnector(ABC):
    """Abstract interface that every provider connector must implement.

    Design constraints
    ------------------
    A connector is **stateless** and **database-independent**:

    - Credentials are passed in at call time.  The caller (typically a Celery
      sync task) is responsible for decrypting them from the ``Integration``
      row before passing them here.
    - Results are returned as plain Python dicts that are JSON-serialisable.
      They are written verbatim into ``Snapshot.state`` (a JSONB array).
    - A connector must **not** import SQLAlchemy models, access the database,
      enqueue Celery tasks, or perform snapshot/diff/risk logic.

    Implementing a new connector
    ----------------------------
    Subclass ``BaseConnector``, implement ``fetch`` and ``validate_credentials``,
    and register the class in ``app/connectors/__init__.py``.
    """

    @abstractmethod
    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all resources from the provider and return normalised records.

        Args:
            credentials: Provider-specific credential dict.  The expected keys
                vary per connector — see each subclass docstring for the
                required shape.

        Returns:
            A list of normalised record dicts.  Every dict must be
            JSON-serialisable and must contain at minimum a ``record_id``
            key that is stable across syncs (used by the diff service to
            correlate records between consecutive snapshots).

        Raises:
            AuthenticationError: Credentials are invalid or lack the required
                permissions.
            ConnectorError: The provider API returned an unexpected error.
            RateLimitError: Rate limits were hit and all retries exhausted.
            NetworkError: A network-level failure occurred.
        """

    @abstractmethod
    def validate_credentials(self, credentials: dict) -> bool:
        """Verify credentials without fetching the full dataset.

        Implementations should make the smallest possible API call that
        confirms the token has the required permissions (e.g. a single
        ``per_page=1`` listing request).

        Args:
            credentials: Same shape as ``fetch``.

        Returns:
            ``True`` if credentials are valid.

        Raises:
            AuthenticationError: Credentials are invalid.
            ConnectorError: The provider returned an unexpected error.
        """
