"""Normalised schema for Cloudflare DNS records.

``CloudflareDNSRecord`` is ConfigTrace's canonical representation of a single
Cloudflare DNS record.  Instances of this dict are stored verbatim inside
``Snapshot.state`` (a JSONB array) and are keyed by ``record_id`` when the
diff service compares two consecutive snapshots.

Field mapping from the raw Cloudflare API response
---------------------------------------------------
    ``id``    → ``record_id``
    ``type``  → ``record_type``
    All other fields map directly.
"""

from __future__ import annotations

from typing import Optional

try:
    from typing import TypedDict
except ImportError:  # Python < 3.8 — not expected in this project
    from typing_extensions import TypedDict  # type: ignore[assignment]


class CloudflareDNSRecord(TypedDict):
    """Normalised Cloudflare DNS record stored in ``Snapshot.state``.

    This TypedDict is the authoritative schema for Cloudflare records in
    ConfigTrace.  Do not rename or remove fields once records have been
    written to the database — doing so constitutes a breaking schema change
    that requires a migration plan.

    Fields
    ------
    record_id
        Cloudflare's stable unique identifier for this record (hex string).
        Used as the join key by the diff service.
    record_type
        DNS record type (e.g. ``"A"``, ``"AAAA"``, ``"CNAME"``, ``"MX"``).
    name
        Fully-qualified domain name for the record (e.g. ``"api.example.com"``).
    content
        Record value — an IP address for A/AAAA, a hostname for CNAME/MX, etc.
    ttl
        Time-to-live in seconds.  Cloudflare uses ``1`` to mean "automatic"
        (proxied records always have ``ttl=1``).
    proxied
        ``True`` if the record is proxied through Cloudflare (orange cloud).
    priority
        Numeric priority for MX and SRV records.  ``None`` for all other types.
    comment
        Optional user-supplied comment string.  ``None`` if not set.
    modified_on
        ISO 8601 timestamp of the last modification, as returned by Cloudflare.
    """

    record_id: str
    record_type: str
    name: str
    content: str
    ttl: int
    proxied: bool
    priority: Optional[int]
    comment: Optional[str]
    modified_on: str
