"""ConfigTrace connector package.

Connectors are pure fetch-and-normalise modules.  Each connector accepts a
credentials dict, calls a provider's API, and returns a list of normalised
record dicts.  Connectors have no knowledge of the database, Celery tasks,
snapshots, diffs, or risk classification.

Available connectors
--------------------
CloudflareConnector
    Fetches DNS records from the Cloudflare Zones API.
FirebaseConnector
    Fetches Firebase/Google Cloud project metadata, Auth config, Security Rules,
    Storage bucket metadata, Hosting sites, and Cloud Functions metadata.
    Customer data (Firestore documents, Storage objects, Auth users) is NEVER read.
SupabaseConnector
    Fetches Supabase project configuration, Auth settings, database/storage/API
    config, Edge Function metadata, RLS status, and network restrictions via the
    Supabase Management API.
    Row data, Auth user PII, secret values, and file contents are NEVER read.

Exceptions
----------
AuthenticationError
    Raised on HTTP 401 / 403 responses — invalid token or missing permissions.
RateLimitError
    Raised when HTTP 429 retries are exhausted.
ConnectorError
    Base class for all connector errors; also raised for unexpected API errors.
NetworkError
    Raised for transport-level failures (timeout, connection error).
"""

from app.connectors.cloudflare import CloudflareConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.firebase import FirebaseConnector
from app.connectors.supabase import SupabaseConnector

__all__ = [
    "CloudflareConnector",
    "FirebaseConnector",
    "SupabaseConnector",
    "AuthenticationError",
    "ConnectorError",
    "NetworkError",
    "RateLimitError",
]
