"""Cloudflare DNS connector.

Fetches all DNS records for a given zone, handles pagination and rate-limit
backoff, and returns a list of normalised ``CloudflareDNSRecord`` dicts.

Usage
-----
    from app.connectors.cloudflare import CloudflareConnector

    connector = CloudflareConnector()
    records = connector.fetch({"api_token": "...", "zone_id": "..."})
    # records → [{"record_id": "abc123", "record_type": "A", ...}, ...]

Credentials dict
----------------
    api_token : str
        A Cloudflare API token with **Zone.DNS:Read** permission scoped to the
        target zone (or to all zones).  Never use a Global API Key here.
    zone_id : str
        The 32-character hexadecimal Zone ID found on the Cloudflare dashboard
        overview page for the domain.
"""

from __future__ import annotations

import logging
import time

import httpx

from app.connectors.base import BaseConnector
from app.connectors.cloudflare_schema import CloudflareDNSRecord
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)

logger = logging.getLogger(__name__)

# ── Module-level constants ───────────────────────────────────────────────────

# Cloudflare Zones REST API base URL (no trailing slash)
_BASE_URL = "https://api.cloudflare.com/client/v4"

# Maximum number of records per page (Cloudflare cap)
_PER_PAGE = 100

# Number of 429-retry attempts before giving up.  The first request is
# attempt 0; the last allowed retry is attempt _MAX_RETRIES.
_MAX_RETRIES = 3

# Per-request HTTP timeout in seconds
_TIMEOUT = 30.0


# ── Normalisation helper ─────────────────────────────────────────────────────

def _normalize(raw: dict) -> CloudflareDNSRecord:
    """Map a raw Cloudflare API record dict to a ``CloudflareDNSRecord``.

    Only the fields defined in ``CloudflareDNSRecord`` are kept; all other
    Cloudflare-specific fields (zone_id, zone_name, locked, meta, etc.) are
    discarded to keep the stored state compact and provider-agnostic.
    """
    return {
        "record_id":   raw["id"],
        "record_type": raw["type"],
        "name":        raw["name"],
        "content":     raw["content"],
        "ttl":         raw["ttl"],
        "proxied":     raw.get("proxied", False),
        "priority":    raw.get("priority"),    # int for MX/SRV; None otherwise
        "comment":     raw.get("comment"),     # str or None
        "modified_on": raw.get("modified_on", ""),
    }


# ── Connector class ──────────────────────────────────────────────────────────

class CloudflareConnector(BaseConnector):
    """Connector for Cloudflare DNS records via the Zones API.

    This class is stateless.  Create a new instance per fetch operation or
    reuse a single instance freely — there is no shared mutable state.
    """

    # ── Public API ───────────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all DNS records for the zone and return normalised dicts.

        Paginates through every page of results using the ``result_info``
        envelope until ``total_count`` records have been retrieved.

        Rate-limit responses (HTTP 429) are retried up to ``_MAX_RETRIES``
        times.  The delay between retries is read from the ``Retry-After``
        response header; if the header is absent, 60 seconds is used as a
        conservative default.

        Args:
            credentials: Must contain ``api_token`` and ``zone_id``.

        Returns:
            A list of ``CloudflareDNSRecord`` dicts (plain dicts, not TypedDict
            instances — they are directly JSON-serialisable into
            ``Snapshot.state``).

        Raises:
            ConnectorError:      Missing or malformed credentials, or the
                                 Cloudflare API returned ``success=false``.
            AuthenticationError: HTTP 401 or 403.
            RateLimitError:      HTTP 429 after all retries are exhausted.
            NetworkError:        Timeout or transport-level failure.
        """
        api_token, zone_id = self._extract_credentials(credentials)
        headers = self._auth_headers(api_token)
        url = f"{_BASE_URL}/zones/{zone_id}/dns_records"

        records: list[dict] = []
        page = 1

        with httpx.Client(timeout=_TIMEOUT) as client:
            while True:
                response = self._get(
                    client,
                    url,
                    headers,
                    params={"page": page, "per_page": _PER_PAGE},
                )
                body = response.json()

                if not body.get("success"):
                    errors = body.get("errors", [])
                    raise ConnectorError(
                        f"Cloudflare API returned success=false: {errors}",
                        status_code=response.status_code,
                    )

                for raw in body.get("result", []):
                    records.append(_normalize(raw))

                result_info: dict = body.get("result_info", {})
                total_count: int = result_info.get("total_count", 0)
                per_page: int = result_info.get("per_page", _PER_PAGE)

                logger.debug(
                    "cloudflare_connector zone=%s page=%d fetched=%d total=%d",
                    zone_id,
                    page,
                    len(records),
                    total_count,
                )

                # Stop when we have retrieved at least total_count records.
                # Using page * per_page rather than len(records) so that a
                # partially-filled last page also terminates the loop.
                if page * per_page >= total_count:
                    break
                page += 1

        return records

    def validate_credentials(self, credentials: dict) -> bool:
        """Verify that the token has Zone.DNS:Read access to the zone.

        Issues a single ``GET /zones/{zone_id}/dns_records?per_page=1`` call
        — the lightest possible probe that exercises both authentication and
        zone-scoped permission.

        Args:
            credentials: Must contain ``api_token`` and ``zone_id``.

        Returns:
            ``True`` if the credentials are valid.

        Raises:
            AuthenticationError: HTTP 401 or 403 response.
            ConnectorError:      Any other API error.
            NetworkError:        Timeout or transport failure.
        """
        api_token, zone_id = self._extract_credentials(credentials)
        headers = self._auth_headers(api_token)
        url = f"{_BASE_URL}/zones/{zone_id}/dns_records"

        with httpx.Client(timeout=_TIMEOUT) as client:
            self._get(client, url, headers, params={"page": 1, "per_page": 1})

        return True

    # ── Private helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_credentials(credentials: dict) -> tuple[str, str]:
        """Return ``(api_token, zone_id)`` or raise ``ConnectorError``."""
        api_token = credentials.get("api_token", "")
        zone_id = credentials.get("zone_id", "")
        if not api_token or not zone_id:
            raise ConnectorError(
                "Cloudflare credentials must include 'api_token' and 'zone_id'"
            )
        return api_token, zone_id

    @staticmethod
    def _auth_headers(api_token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }

    def _get(
        self,
        client: httpx.Client,
        url: str,
        headers: dict[str, str],
        params: dict,
    ) -> httpx.Response:
        """Issue a GET request with 429 retry-backoff logic.

        Retries up to ``_MAX_RETRIES`` times on HTTP 429.  The inter-retry
        delay is taken from the ``Retry-After`` response header (defaults to
        60 s if the header is absent or non-numeric).

        Raises:
            AuthenticationError: HTTP 401 or 403.
            RateLimitError:      HTTP 429 after retries are exhausted.
            ConnectorError:      Any other non-2xx response.
            NetworkError:        ``httpx.TimeoutException`` or
                                 ``httpx.RequestError``.
        """
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = client.get(url, headers=headers, params=params)
            except httpx.TimeoutException as exc:
                raise NetworkError(f"Request timed out: {exc}") from exc
            except httpx.RequestError as exc:
                raise NetworkError(f"Network error: {exc}") from exc

            if response.status_code == 429:
                if attempt >= _MAX_RETRIES:
                    raise RateLimitError(
                        f"Cloudflare rate limit exceeded after {_MAX_RETRIES} "
                        "retries. Try again later."
                    )
                try:
                    retry_after = float(response.headers.get("Retry-After", "60"))
                except ValueError:
                    retry_after = 60.0

                logger.warning(
                    "Rate limited by Cloudflare (attempt %d/%d). "
                    "Sleeping %.1f s before retry.",
                    attempt + 1,
                    _MAX_RETRIES,
                    retry_after,
                )
                time.sleep(retry_after)
                continue  # retry

            if response.status_code in (401, 403):
                raise AuthenticationError(
                    f"Cloudflare authentication failed (HTTP {response.status_code}). "
                    "Verify that the API token has Zone.DNS:Read permission and "
                    "is scoped to the correct zone.",
                    status_code=response.status_code,
                )

            if not response.is_success:
                raise ConnectorError(
                    f"Cloudflare API error (HTTP {response.status_code}): "
                    f"{response.text[:500]}",
                    status_code=response.status_code,
                )

            return response

        # The loop always raises or returns — this line is unreachable.
        raise ConnectorError("Unexpected end of retry loop")  # pragma: no cover
