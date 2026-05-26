"""Firebase connector — M53: Firebase Provider MVP.

Fetches metadata-only configuration from Firebase/Google APIs using service
account credentials.  Customer data, secrets, and raw file/document contents
are NEVER fetched or stored.

APIs used (metadata-only)
--------------------------
firebase.googleapis.com/v1beta1/projects/{project_id}
    Firebase project metadata: display name, lifecycle state, enabled surfaces.

identitytoolkit.googleapis.com/admin/v2/projects/{project_id}/config
    Firebase Auth configuration: enabled sign-in methods, MFA state,
    authorized domain list, provider counts.

identitytoolkit.googleapis.com/admin/v2/projects/{project_id}/oauthIdpConfigs
identitytoolkit.googleapis.com/admin/v2/projects/{project_id}/defaultSupportedIdpConfigs
    OIDC/OAuth provider configs — enabled state only, no secrets.

firebaserules.googleapis.com/v1/projects/{project_id}/releases
    Which ruleset is the active deployment for Firestore / Storage.

firebaserules.googleapis.com/v1/{ruleset_name}
    Ruleset source for analysis.  Only a SHA-256 hash is stored; the source
    is discarded immediately after analysis.

storage.googleapis.com/storage/v1/b?project={project_id}
    GCS bucket metadata: location, storage class, access controls.
    Objects are NEVER listed or read.

firebasehosting.googleapis.com/v1beta1/projects/{project_id}/sites
    Firebase Hosting site list and custom domain metadata.

cloudfunctions.googleapis.com/v1/projects/{project_id}/locations/-/functions
    Cloud Function metadata: name, region, runtime, trigger type, status.
    Environment variable VALUES are NEVER stored or fetched.

Absolute forbidden behavior
---------------------------
The following Google/Firebase API calls are NEVER made:
  - Firestore document reads (firestore.googleapis.com/v1/.../documents/*)
  - Firestore collection queries
  - Cloud Storage object reads/downloads (storage.googleapis.com/storage/v1/b/{b}/o/*)
  - Firebase Auth user exports (identitytoolkit.googleapis.com/v1/projects/.../accounts:query)
  - Cloud Function GetFunction with environment variable values
  - Secret Manager GetSecretVersion
  - Any write/mutate API

Authentication
--------------
Uses service account JSON credentials.  A short-lived OAuth2 access token is
minted using the service account's private key via the standard JWT bearer flow
(RFC 7523).  The private key is NEVER logged, returned in API responses, or
included in any snapshot record.

SECURITY
--------
- credentials["private_key"] is used ONLY to sign the OAuth2 assertion JWT.
- The access token is cached for the duration of a single fetch() call only.
- project_number is stored only as a SHA-256[:16] hash.
- Ruleset names are stored only as SHA-256[:16] hashes.
- Raw rules source is discarded immediately; only SHA-256[:16] hash is stored.
- Storage bucket names are stored (they are infrastructure identifiers, not
  customer data); a hash is also stored for diffing convenience.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from typing import Any, Optional

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.firebase_schema import (
    FIREBASE_APP_CHECK_CONFIG,
    FIREBASE_AUTH_CONFIG,
    FIREBASE_AUTH_PROVIDER,
    FIREBASE_AUTHORIZED_DOMAIN,
    FIREBASE_FIRESTORE_RULESET,
    FIREBASE_FUNCTION_METADATA,
    FIREBASE_HOSTING_DOMAIN,
    FIREBASE_HOSTING_SITE,
    FIREBASE_PROJECT,
    FIREBASE_REMOTE_CONFIG_TEMPLATE,
    FIREBASE_STORAGE_BUCKET,
    FIREBASE_STORAGE_RULESET,
    REQUIRED_SA_FIELDS,
)

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_TIMEOUT = 20.0           # seconds
_MAX_RETRIES = 3
_RETRY_BACKOFF = (1.0, 2.0, 4.0)

_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# OAuth scopes requested.  cloud-platform.read-only covers GCS, Functions,
# Rules, Hosting.  firebase.readonly covers Firebase-specific management APIs.
_SCOPES = (
    "https://www.googleapis.com/auth/cloud-platform.read-only",
    "https://www.googleapis.com/auth/firebase.readonly",
)

# Default Firebase hosting domains — NOT customer-sensitive infrastructure IDs
_FIREBASE_DEFAULT_DOMAINS = {
    "firebaseapp.com",
    "web.app",
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _sha256_prefix(value: str) -> str:
    """Return the first 16 hex chars of SHA-256(value). Non-reversible."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _classify_trigger(trigger_data: dict) -> str:
    """Return a human-readable trigger type for a Cloud Function."""
    if "httpsTrigger" in trigger_data:
        return "HTTP"
    if "eventTrigger" in trigger_data:
        event_type = trigger_data["eventTrigger"].get("eventType", "")
        if "schedule" in event_type.lower():
            return "SCHEDULED"
        return "EVENT"
    if "scheduleTrigger" in trigger_data:
        return "SCHEDULED"
    return "OTHER"


# ── Rules analysis ────────────────────────────────────────────────────────────

# Dangerous patterns: allow [op]: if true
_RE_PUBLIC_WRITE = re.compile(
    r"\ballow\s+"
    r"(?:write|create|update|delete|read\s*,\s*write|write\s*,\s*read)"
    r"[^:;{]*:\s*if\s+true\b",
    re.IGNORECASE,
)
_RE_PUBLIC_READ = re.compile(
    r"\ballow\s+(?:read|get|list)[^:;{]*:\s*if\s+true\b",
    re.IGNORECASE,
)
# allow read, write: if true  (catches the combo in one pattern)
_RE_PUBLIC_COMBO = re.compile(
    r"\ballow\s+(?:read\s*,\s*write|write\s*,\s*read)[^:;{]*:\s*if\s+true\b",
    re.IGNORECASE,
)
# allow read; (without any condition — older syntax, public by default)
_RE_NO_COND_WRITE = re.compile(
    r"\ballow\s+(?:write|create|update|delete)\s*;",
    re.IGNORECASE,
)
_RE_NO_COND_READ = re.compile(
    r"\ballow\s+(?:read|get|list)\s*;",
    re.IGNORECASE,
)
# Safe: requires authentication
_RE_AUTH_CHECK = re.compile(
    r"request\.auth\s*!=\s*null|request\.auth\.uid\b",
    re.IGNORECASE,
)


def _analyze_rules(source: str) -> dict:
    """Conservatively analyse Firebase Security Rules source for public-access patterns.

    SECURITY: The raw source is never stored — only a truncated SHA-256 hash.
    The source is discarded after this function returns.

    Returns a dict with keys suitable for direct merge into a record:
      rules_hash, public_read_detected, public_write_detected,
      authenticated_only_detected, rule_summary, parser_confidence.
    """
    if not source or not source.strip():
        return {
            "rules_hash": None,
            "public_read_detected": False,
            "public_write_detected": False,
            "authenticated_only_detected": False,
            "rule_summary": "No rules source available.",
            "parser_confidence": "low",
        }

    # Hash first; source is discarded after analysis.
    rules_hash = _sha256_prefix(source)

    # Remove inline comments to avoid false negatives from commented-out rules.
    src_no_comments = re.sub(r"//[^\n]*", " ", source)
    src_no_comments = re.sub(r"/\*.*?\*/", " ", src_no_comments, flags=re.DOTALL)

    public_write = bool(_RE_PUBLIC_WRITE.search(src_no_comments))
    public_read  = bool(_RE_PUBLIC_READ.search(src_no_comments))

    if _RE_PUBLIC_COMBO.search(src_no_comments):
        public_write = True
        public_read  = True

    if _RE_NO_COND_WRITE.search(src_no_comments):
        public_write = True
    if _RE_NO_COND_READ.search(src_no_comments):
        public_read = True

    has_auth_check = bool(_RE_AUTH_CHECK.search(src_no_comments))

    # Conservative: if rules contain BOTH public access AND auth checks, lower
    # confidence — the auth checks may be on other paths.
    if public_read or public_write:
        confidence = "high" if not has_auth_check else "medium"
    else:
        confidence = "medium"

    # authenticated_only: auth checks present, no public access detected
    authenticated_only = has_auth_check and not (public_read or public_write)

    if public_write and public_read:
        summary = (
            "Rules may allow public read and write access without authentication. "
            "Verify this is intentional."
        )
    elif public_write:
        summary = (
            "Rules may allow public write access without authentication. "
            "Verify this is intentional."
        )
    elif public_read:
        summary = (
            "Rules may allow public read access without authentication. "
            "Verify this is intentional."
        )
    elif authenticated_only:
        summary = "Rules appear to require authentication for access."
    else:
        summary = "Rules detected; no obvious public access patterns found."

    return {
        "rules_hash": rules_hash,
        "public_read_detected": public_read,
        "public_write_detected": public_write,
        "authenticated_only_detected": authenticated_only,
        "rule_summary": summary,
        "parser_confidence": confidence,
    }


# ── Main connector ─────────────────────────────────────────────────────────────


class FirebaseConnector(BaseConnector):
    """Metadata-only Firebase/Google Cloud connector.

    Connects with a service account JSON.  Credential dict keys:
        type            — "service_account"
        project_id      — Firebase/GCP project ID
        private_key_id  — Key ID (for auditing)
        private_key     — RSA private key PEM (NEVER logged)
        client_email    — Service account email
        token_uri       — Token exchange URL (default: Google OAuth2 endpoint)

    SECURITY: The private_key is only used to sign the OAuth2 JWT assertion.
    It is NEVER logged, NEVER stored in snapshot records, and NEVER returned
    to the frontend.
    """

    # ── Authentication ────────────────────────────────────────────────────────

    def _validate_sa_fields(self, credentials: dict) -> None:
        """Raise ValueError if required service account fields are missing."""
        missing = [f for f in REQUIRED_SA_FIELDS if not credentials.get(f)]
        if missing:
            raise ValueError(
                f"Service account JSON is missing required fields: {missing}"
            )
        sa_type = credentials.get("type", "")
        if sa_type != "service_account":
            raise ValueError(
                f"Expected service account type 'service_account', got {sa_type!r}. "
                "Paste the full service account JSON from the Google Cloud Console."
            )

    def _get_access_token(self, credentials: dict) -> str:
        """Exchange service account credentials for a short-lived access token.

        Uses the standard JWT bearer grant (RFC 7523).

        SECURITY: credentials["private_key"] is NEVER logged here or anywhere
        in the call chain.  The returned access_token is also NEVER logged.
        """
        from jose import jwt as jose_jwt  # python-jose[cryptography]

        token_uri = credentials.get("token_uri") or _GOOGLE_TOKEN_URL
        now = int(time.time())
        claims = {
            "iss": credentials["client_email"],
            "sub": credentials["client_email"],
            "aud": token_uri,
            "iat": now,
            "exp": now + 3600,
            "scope": " ".join(_SCOPES),
        }

        # SECURITY: private_key is never logged — only referenced here.
        try:
            assertion = jose_jwt.encode(
                claims,
                credentials["private_key"],
                algorithm="RS256",
            )
        except Exception as exc:
            raise AuthenticationError(
                "Failed to sign the service account JWT. "
                "Ensure the private_key in the service account JSON is valid "
                "and has not been truncated.",
                status_code=None,
            ) from exc

        try:
            resp = httpx.post(
                token_uri,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": assertion,
                },
                timeout=_TIMEOUT,
            )
        except httpx.TimeoutException as exc:
            raise NetworkError(
                f"Timeout contacting Google OAuth2 token endpoint: {token_uri}"
            ) from exc
        except httpx.RequestError as exc:
            raise NetworkError(
                f"Network error reaching Google OAuth2 token endpoint: {exc}"
            ) from exc

        if resp.status_code in (400, 401):
            try:
                detail = resp.json().get("error_description") or resp.json().get("error", resp.text)
            except Exception:
                detail = resp.text
            raise AuthenticationError(
                f"Firebase service account authentication failed: {detail}. "
                "Verify the service account JSON is valid, the key has not been "
                "revoked, and the service account has the required IAM permissions.",
                status_code=resp.status_code,
            )
        if not resp.is_success:
            raise ConnectorError(
                f"Google OAuth2 token endpoint returned HTTP {resp.status_code}",
                status_code=resp.status_code,
            )

        try:
            return resp.json()["access_token"]
        except (KeyError, Exception) as exc:
            raise ConnectorError(
                "Google OAuth2 token endpoint returned an unexpected response "
                "(no access_token).",
                status_code=resp.status_code,
            ) from exc

    # ── HTTP transport ─────────────────────────────────────────────────────────

    def _get(
        self,
        access_token: str,
        url: str,
        params: dict | None = None,
    ) -> Any:
        """Authenticated GET with retry/back-off.

        SECURITY: access_token is NEVER logged.

        Raises
        ------
        AuthenticationError  — HTTP 401 (token expired / revoked)
        ConnectorError       — HTTP 403 (permission denied) or other 4xx/5xx
        RateLimitError       — HTTP 429 after retries
        NetworkError         — transport failure
        """
        logger.debug("firebase._get url=%s", url)

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                resp = httpx.get(
                    url,
                    params=params,
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=_TIMEOUT,
                )
            except httpx.TimeoutException as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF[attempt])
                    continue
                raise NetworkError(f"Firebase API timed out: {url}") from exc
            except httpx.RequestError as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF[attempt])
                    continue
                raise NetworkError(f"Network error reaching Firebase API: {exc}") from exc

            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", _RETRY_BACKOFF[attempt]))
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(retry_after)
                    continue
                raise RateLimitError(
                    f"Firebase API rate limit hit for {url}. Retry after {retry_after}s."
                )
            if resp.status_code == 401:
                raise AuthenticationError(
                    "Firebase API authentication failed: the access token was rejected. "
                    "The service account credentials may be revoked or expired.",
                    status_code=401,
                )
            if resp.status_code == 403:
                try:
                    message = resp.json().get("error", {}).get("message", "permission denied")
                except Exception:
                    message = "permission denied"
                raise ConnectorError(
                    f"Firebase API permission denied for {url}: {message}. "
                    "Grant the service account the required read-only IAM roles.",
                    status_code=403,
                )
            if resp.status_code >= 500:
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF[attempt])
                    continue
                raise ConnectorError(
                    f"Firebase API returned HTTP {resp.status_code} for {url}",
                    status_code=resp.status_code,
                )
            if not resp.is_success:
                try:
                    detail = resp.json().get("error", {}).get("message", resp.text)
                except Exception:
                    detail = resp.text
                raise ConnectorError(
                    f"Firebase API returned HTTP {resp.status_code} for {url}: {detail}",
                    status_code=resp.status_code,
                )
            return resp.json()

        raise NetworkError(f"Firebase API request failed after {_MAX_RETRIES} retries: {url}")

    def _get_paginated(
        self,
        access_token: str,
        url: str,
        items_key: str,
        params: dict | None = None,
        page_token_param: str = "pageToken",
        page_token_field: str = "nextPageToken",
    ) -> list[dict]:
        """Paginated GET that follows nextPageToken until exhausted."""
        params = dict(params or {})
        results: list[dict] = []
        while True:
            data = self._get(access_token, url, params)
            results.extend(data.get(items_key) or [])
            next_token = data.get(page_token_field)
            if not next_token:
                break
            params[page_token_param] = next_token
        return results

    # ── Surface fetchers ───────────────────────────────────────────────────────

    def _fetch_project_metadata(
        self,
        access_token: str,
        project_id: str,
    ) -> dict:
        """Fetch Firebase project metadata.

        GET https://firebase.googleapis.com/v1beta1/projects/{project_id}
        """
        url = f"https://firebase.googleapis.com/v1beta1/projects/{project_id}"
        data = self._get(access_token, url)

        project_number = str(data.get("projectNumber") or "")
        resources = data.get("resources") or {}

        return {
            "record_type":            FIREBASE_PROJECT,
            "record_id":              project_id,
            "name":                   project_id,
            "project_id":             project_id,
            "display_name":           data.get("displayName"),
            "project_number_hash":    _sha256_prefix(project_number) if project_number else "",
            "lifecycle_state":        data.get("state"),
            "hosting_site":           resources.get("hostingSite"),
            "has_realtime_db":        bool(resources.get("realtimeDatabaseInstance")),
            "has_storage":            bool(resources.get("storageBucket")),
            "config_fetch_warnings":  [],
        }

    def _fetch_auth_config(
        self,
        access_token: str,
        project_id: str,
        warnings: list[str],
    ) -> list[dict]:
        """Fetch Firebase Auth configuration and authorized domains.

        GET https://identitytoolkit.googleapis.com/admin/v2/projects/{project_id}/config

        Returns a list of normalised records:
          [auth_config_record, ...authorized_domain_records]

        SECURITY: Auth user data is NEVER requested.  The endpoint
        /accounts:query and /accounts:lookup are NEVER called.
        """
        url = f"https://identitytoolkit.googleapis.com/admin/v2/projects/{project_id}/config"
        try:
            data = self._get(access_token, url)
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append(
                    "firebase_auth_config: permission denied — "
                    "grant roles/identitytoolkit.viewer to the service account."
                )
                logger.info("firebase: auth_config skipped (403)")
                return []
            raise

        sign_in = data.get("signIn") or {}
        email_cfg = sign_in.get("email") or {}
        phone_cfg = sign_in.get("phoneNumber") or {}
        anon_cfg  = sign_in.get("anonymous") or {}
        mfa_cfg   = data.get("mfa") or {}

        authorized_domains: list[str] = data.get("authorizedDomains") or []

        # Count SAML/OIDC providers without fetching their secrets.
        saml_count = 0
        oidc_count = 0
        try:
            saml_url = (
                f"https://identitytoolkit.googleapis.com/admin/v2/projects/{project_id}/inboundSamlConfigs"
            )
            saml_data = self._get(access_token, saml_url)
            saml_count = len(saml_data.get("inboundSamlConfigs") or [])
        except ConnectorError:
            pass  # SAML not configured or permission denied
        try:
            oidc_url = (
                f"https://identitytoolkit.googleapis.com/admin/v2/projects/{project_id}/oauthIdpConfigs"
            )
            oidc_data = self._get(access_token, oidc_url)
            oidc_count = len(oidc_data.get("oauthIdpConfigs") or [])
        except ConnectorError:
            pass  # OIDC not configured or permission denied

        auth_record: dict = {
            "record_type":              FIREBASE_AUTH_CONFIG,
            "record_id":                f"{project_id}/auth_config",
            "name":                     f"{project_id}/auth_config",
            "project_id":               project_id,
            "sign_in_email_enabled":    bool(email_cfg.get("enabled", False)),
            "sign_in_phone_enabled":    bool(phone_cfg.get("enabled", False)),
            "anonymous_enabled":        bool(anon_cfg.get("enabled", False)),
            "mfa_enabled":              mfa_cfg.get("state") == "ENABLED",
            "mfa_state":                mfa_cfg.get("state"),
            "authorized_domain_count":  len(authorized_domains),
            "saml_provider_count":      saml_count,
            "oidc_provider_count":      oidc_count,
            "config_fetch_warnings":    [],
        }
        records: list[dict] = [auth_record]

        # Emit one record per authorized domain.
        for domain in authorized_domains:
            domain_lower = domain.lower()
            is_default = any(
                domain_lower.endswith(d) for d in _FIREBASE_DEFAULT_DOMAINS
            )
            is_localhost = domain_lower in ("localhost", "127.0.0.1", "::1")
            records.append({
                "record_type":               FIREBASE_AUTHORIZED_DOMAIN,
                "record_id":                 f"{project_id}/{domain}",
                "name":                      domain,
                "project_id":                project_id,
                "domain":                    domain,
                "is_localhost":              is_localhost,
                "is_default_firebase_domain": is_default,
                "config_fetch_warnings":     [],
            })

        return records

    def _fetch_firebase_rules(
        self,
        access_token: str,
        project_id: str,
        warnings: list[str],
    ) -> list[dict]:
        """Fetch active Firestore and Storage Security Rules deployments.

        Uses the Firebase Rules API to find active releases and their ruleset
        content.  The raw rules source is NEVER stored — only SHA-256[:16] hash
        and conservative public-access analysis results are kept.

        Returns a list of firebase_firestore_ruleset and firebase_storage_ruleset
        records.
        """
        releases_url = (
            f"https://firebaserules.googleapis.com/v1/projects/{project_id}/releases"
        )
        try:
            releases = self._get_paginated(
                access_token, releases_url, "releases"
            )
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append(
                    "firebase_rules: permission denied — "
                    "grant roles/firebaserules.viewer to the service account."
                )
                logger.info("firebase: rules skipped (403)")
                return []
            raise

        records: list[dict] = []
        seen_rulesets: dict[str, dict] = {}  # rulesetName → analyzed result

        for release in releases:
            # release["name"] is like "projects/{pid}/releases/cloud.firestore"
            # release["rulesetName"] is like "projects/{pid}/rulesets/{uuid}"
            release_full = release.get("name", "")
            ruleset_full = release.get("rulesetName", "")

            # Extract release short name (e.g. "cloud.firestore" or "firebase.storage")
            release_short = release_full.split("/releases/", 1)[-1] if "/releases/" in release_full else release_full

            is_firestore = "cloud.firestore" in release_short.lower() or "firestore" in release_short.lower()
            is_storage   = "firebase.storage" in release_short.lower() or "storage" in release_short.lower()

            if not (is_firestore or is_storage):
                continue  # skip unrecognised releases

            # Fetch and analyse ruleset source (only if not already fetched)
            analysis: dict = {
                "rules_hash": None,
                "public_read_detected": False,
                "public_write_detected": False,
                "authenticated_only_detected": False,
                "rule_summary": "Rules unavailable.",
                "parser_confidence": "low",
            }
            if ruleset_full:
                if ruleset_full in seen_rulesets:
                    analysis = seen_rulesets[ruleset_full]
                else:
                    try:
                        ruleset_url = f"https://firebaserules.googleapis.com/v1/{ruleset_full}"
                        ruleset_data = self._get(access_token, ruleset_url)
                        # Collect all source file contents, then discard immediately
                        source_files = (ruleset_data.get("source") or {}).get("files") or []
                        combined_source = "\n".join(
                            f.get("content", "") for f in source_files
                        )
                        analysis = _analyze_rules(combined_source)
                        # source is never stored in analysis dict
                    except ConnectorError as exc:
                        analysis["rule_summary"] = (
                            f"Rules source unavailable (HTTP {exc.status_code})."
                        )
                    seen_rulesets[ruleset_full] = analysis

            ruleset_name_hash = _sha256_prefix(ruleset_full) if ruleset_full else ""

            if is_firestore:
                records.append({
                    "record_type":              FIREBASE_FIRESTORE_RULESET,
                    "record_id":                f"{project_id}/firestore/{release_short}",
                    "name":                     release_short,
                    "project_id":               project_id,
                    "release_name":             release_short,
                    "ruleset_name_hash":        ruleset_name_hash,
                    "config_fetch_warnings":    [],
                    **analysis,
                })
            elif is_storage:
                # Derive bucket name from release name if possible
                # Storage releases can be "firebase.storage/{bucket}" or just "firebase.storage"
                bucket_part = release_short.split("/", 1)[-1] if "/" in release_short else ""
                bucket_name_hash = _sha256_prefix(bucket_part) if bucket_part else None

                records.append({
                    "record_type":              FIREBASE_STORAGE_RULESET,
                    "record_id":                f"{project_id}/storage/{release_short}",
                    "name":                     release_short,
                    "project_id":               project_id,
                    "release_name":             release_short,
                    "bucket_name_hash":         bucket_name_hash,
                    "ruleset_name_hash":        ruleset_name_hash,
                    "config_fetch_warnings":    [],
                    **analysis,
                })

        logger.info(
            "firebase: rules fetched total_releases=%d rules_records=%d",
            len(releases),
            len(records),
        )
        return records

    def _fetch_storage_buckets(
        self,
        access_token: str,
        project_id: str,
        warnings: list[str],
    ) -> list[dict]:
        """Fetch GCS bucket metadata for the project.

        GET https://storage.googleapis.com/storage/v1/b?project={project_id}

        Storage objects are NEVER listed, read, or downloaded.
        """
        url = "https://storage.googleapis.com/storage/v1/b"
        try:
            buckets = self._get_paginated(
                access_token,
                url,
                "items",
                params={"project": project_id, "projection": "full"},
                page_token_param="pageToken",
                page_token_field="nextPageToken",
            )
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append(
                    "firebase_storage_buckets: permission denied — "
                    "grant roles/storage.legacyBucketReader to the service account "
                    "for bucket-metadata-only access (no object reads)."
                )
                logger.info("firebase: storage_buckets skipped (403)")
                return []
            raise

        records: list[dict] = []
        for bucket in buckets:
            bucket_name = bucket.get("name", "")
            if not bucket_name:
                continue

            iam_config = bucket.get("iamConfiguration") or {}
            uniform = iam_config.get("uniformBucketLevelAccess") or {}

            # Public access prevention (GCS feature)
            pub_access = iam_config.get("publicAccessPrevention")

            versioning = bucket.get("versioning") or {}

            records.append({
                "record_type":                  FIREBASE_STORAGE_BUCKET,
                "record_id":                    f"{project_id}/{bucket_name}",
                "name":                         bucket_name,
                "project_id":                   project_id,
                "bucket_name":                  bucket_name,
                "bucket_name_hash":             _sha256_prefix(bucket_name),
                "location":                     bucket.get("location"),
                "storage_class":                bucket.get("storageClass"),
                "uniform_bucket_level_access":  uniform.get("enabled"),
                "public_access_prevention":     pub_access,
                "versioning_enabled":           versioning.get("enabled"),
                "config_fetch_warnings":        [],
            })

        logger.info("firebase: storage_buckets fetched count=%d", len(records))
        return records

    def _fetch_hosting(
        self,
        access_token: str,
        project_id: str,
        warnings: list[str],
    ) -> list[dict]:
        """Fetch Firebase Hosting site and domain metadata.

        GET https://firebasehosting.googleapis.com/v1beta1/projects/{project_id}/sites
        """
        sites_url = (
            f"https://firebasehosting.googleapis.com/v1beta1/projects/{project_id}/sites"
        )
        try:
            sites = self._get_paginated(access_token, sites_url, "sites")
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append(
                    "firebase_hosting: permission denied — "
                    "grant roles/firebasehosting.viewer to the service account."
                )
                logger.info("firebase: hosting skipped (403)")
                return []
            raise

        records: list[dict] = []
        for site in sites:
            # site["name"] = "projects/{pid}/sites/{siteId}"
            site_name = site.get("name", "")
            site_id = site_name.split("/sites/", 1)[-1] if "/sites/" in site_name else site_name
            if not site_id:
                continue

            default_url = site.get("defaultUrl")
            app_id = site.get("appId")

            # Fetch domains for this site
            domains: list[dict] = []
            try:
                domains_url = (
                    f"https://firebasehosting.googleapis.com/v1beta1/{site_name}/domains"
                )
                domains = self._get_paginated(access_token, domains_url, "domains")
            except ConnectorError:
                pass  # Non-fatal: domains unavailable

            custom_domain_count = sum(
                1 for d in domains
                if d.get("domainType") == "CUSTOM"
            )

            records.append({
                "record_type":          FIREBASE_HOSTING_SITE,
                "record_id":            f"{project_id}/{site_id}",
                "name":                 site_id,
                "project_id":           project_id,
                "site_id":              site_id,
                "default_url":          default_url,
                "app_id":               app_id,
                "custom_domain_count":  custom_domain_count,
                "config_fetch_warnings": [],
            })

            for domain in domains:
                domain_name = domain.get("domainName", "")
                if not domain_name:
                    continue
                records.append({
                    "record_type":           FIREBASE_HOSTING_DOMAIN,
                    "record_id":             f"{project_id}/{site_id}/{domain_name}",
                    "name":                  domain_name,
                    "project_id":            project_id,
                    "site_id":               site_id,
                    "domain":                domain_name,
                    "domain_type":           domain.get("domainType", ""),
                    "status":                domain.get("domainStatus"),
                    "config_fetch_warnings": [],
                })

        logger.info("firebase: hosting fetched site_count=%d", sum(1 for r in records if r["record_type"] == FIREBASE_HOSTING_SITE))
        return records

    def _fetch_cloud_functions(
        self,
        access_token: str,
        project_id: str,
        warnings: list[str],
    ) -> list[dict]:
        """Fetch Cloud Functions metadata.

        GET https://cloudfunctions.googleapis.com/v1/projects/{project_id}/locations/-/functions

        SECURITY: Environment variable VALUES are NEVER stored.  Only the count
        of environment variable KEYS is recorded.  Labels and resource metadata
        are included; secret values are NEVER accessed.
        """
        url = (
            f"https://cloudfunctions.googleapis.com/v1/projects/{project_id}"
            f"/locations/-/functions"
        )
        try:
            functions = self._get_paginated(access_token, url, "functions")
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append(
                    "firebase_functions: permission denied — "
                    "grant roles/cloudfunctions.viewer to the service account."
                )
                logger.info("firebase: cloud_functions skipped (403)")
                return []
            raise

        records: list[dict] = []
        for fn in functions:
            # fn["name"] = "projects/{pid}/locations/{region}/functions/{name}"
            fn_name_full = fn.get("name", "")
            parts = fn_name_full.split("/")
            fn_name = parts[-1] if parts else fn_name_full
            region  = parts[-3] if len(parts) >= 3 else ""

            runtime = fn.get("runtime")
            status  = fn.get("status")

            # Trigger type — inferred from which trigger key is present
            trigger_type = _classify_trigger(fn)

            # SECURITY: env var VALUES are never stored.  Only count the KEYS.
            env_vars = fn.get("environmentVariables") or {}
            env_var_key_count = len(env_vars)

            records.append({
                "record_type":          FIREBASE_FUNCTION_METADATA,
                "record_id":            f"{project_id}/{region}/{fn_name}",
                "name":                 fn_name,
                "project_id":           project_id,
                "function_name":        fn_name,
                "region":               region,
                "runtime":              runtime,
                "trigger_type":         trigger_type,
                "status":               status,
                "env_var_key_count":    env_var_key_count,
                "config_fetch_warnings": [],
            })

        logger.info("firebase: cloud_functions fetched count=%d", len(records))
        return records

    # ── Credential validation ─────────────────────────────────────────────────

    def _parse_credentials(self, credentials: dict) -> dict:
        """Parse and return service account credentials.

        If credentials["service_account_json"] is present, parse it as JSON.
        Otherwise expect the fields directly in credentials.
        """
        if "service_account_json" in credentials:
            raw = credentials["service_account_json"]
            if isinstance(raw, str):
                try:
                    return json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        "service_account_json is not valid JSON. "
                        "Paste the complete service account JSON file."
                    ) from exc
            elif isinstance(raw, dict):
                return raw
        return credentials

    # ── M57.8: Remote Config + App Check ─────────────────────────────────────

    def _fetch_remote_config(
        self,
        access_token: str,
        project_id: str,
        warnings: list[str],
    ) -> list[dict]:
        """Fetch Firebase Remote Config template structural metadata.

        API: GET firebaseremoteconfig.googleapis.com/v1/projects/{project_id}/remoteConfig

        Returns a single ``firebase_remote_config_template`` record, or an
        empty list if the API is unavailable or permission is denied.

        SECURITY / DATA MINIMISATION:
        - Parameter VALUES (default or conditional) are NEVER stored.
        - Condition expressions are NEVER stored.
        - ``updateUser`` email/display name is NEVER stored.
        - Only counts, hashes of key/name lists, and version metadata are kept.
        - ``parameterKeys_hash`` is SHA-256[:16] of sorted parameter key names.
        - ``conditionNames_hash`` is SHA-256[:16] of sorted condition names.
        """
        url = (
            f"https://firebaseremoteconfig.googleapis.com/v1"
            f"/projects/{project_id}/remoteConfig"
        )
        try:
            data = self._get(access_token, url)
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append(
                    "Remote Config API returned 403 — the service account may lack "
                    "roles/firebaseremoteconfig.viewer or equivalent read permission."
                )
                logger.warning(
                    "firebase: Remote Config 403 for project=%s — skipping",
                    project_id,
                )
                return []
            if exc.status_code == 404:
                # Remote Config not enabled for this project
                logger.debug(
                    "firebase: Remote Config 404 for project=%s — not enabled",
                    project_id,
                )
                return []
            warnings.append(
                f"Remote Config fetch error (HTTP {exc.status_code}): "
                f"{str(exc)[:120]}"
            )
            logger.warning(
                "firebase: Remote Config fetch failed project=%s code=%s",
                project_id, exc.status_code,
            )
            return []
        except Exception as exc:
            warnings.append(f"Remote Config fetch failed unexpectedly: {type(exc).__name__}")
            logger.warning(
                "firebase: Remote Config unexpected error project=%s %s",
                project_id, type(exc).__name__,
            )
            return []

        if not isinstance(data, dict):
            return []

        # ── Extract counts — parameter/condition/group dicts; no values stored ──
        parameters = data.get("parameters") or {}
        conditions = data.get("conditions") or []
        parameter_groups = data.get("parameterGroups") or {}

        parameter_count = len(parameters) if isinstance(parameters, dict) else 0
        condition_count = len(conditions) if isinstance(conditions, list) else 0
        parameter_group_count = (
            len(parameter_groups) if isinstance(parameter_groups, dict) else 0
        )

        # Hash parameter key names (sorted, deterministic) — values NOT included.
        param_keys_sorted = sorted(parameters.keys()) if isinstance(parameters, dict) else []
        parameter_keys_hash: Optional[str] = (
            _sha256_prefix(",".join(param_keys_sorted)) if param_keys_sorted else None
        )

        # Hash condition names (sorted) — expressions NOT included.
        cond_names_sorted = sorted(
            c.get("name") or "" for c in conditions if isinstance(c, dict)
        )
        condition_names_hash: Optional[str] = (
            _sha256_prefix(",".join(cond_names_sorted)) if cond_names_sorted else None
        )

        # ── Version metadata — no updateUser info stored ──────────────────────
        version = data.get("version") or {}
        version_number = str(version.get("versionNumber") or "") or None
        update_origin = str(version.get("updateOrigin") or "") or None
        update_type = str(version.get("updateType") or "") or None
        # updateUser, description are explicitly NOT extracted.

        record: dict = {
            "record_type":           FIREBASE_REMOTE_CONFIG_TEMPLATE,
            "record_id":             f"{project_id}/remote_config",
            "name":                  f"{project_id}/remote_config",
            "project_id":            project_id,
            "version_number":        version_number,
            "update_origin":         update_origin,
            "update_type":           update_type,
            "parameter_count":       parameter_count,
            "condition_count":       condition_count,
            "parameter_group_count": parameter_group_count,
            "parameter_keys_hash":   parameter_keys_hash,
            "condition_names_hash":  condition_names_hash,
            "config_fetch_warnings": [],
        }
        return [record]

    def _fetch_app_check(
        self,
        access_token: str,
        project_id: str,
        warnings: list[str],
    ) -> list[dict]:
        """Fetch Firebase App Check service enforcement metadata.

        API: GET firebaseappcheck.googleapis.com/v1beta/projects/{project_id}/services

        Returns a single ``firebase_app_check_config`` aggregate record, or an
        empty list if the API is unavailable or permission is denied.

        SECURITY / DATA MINIMISATION:
        - Debug tokens are NEVER read or stored.
        - App attestation data and device/user data are NEVER accessed.
        - Raw app IDs are NOT stored.
        - ``enforced_service_names`` holds Google API endpoint strings (e.g.
          "storage.googleapis.com") — infrastructure identifiers, not secrets.
        """
        url = (
            f"https://firebaseappcheck.googleapis.com/v1beta"
            f"/projects/{project_id}/services"
        )
        try:
            data = self._get(access_token, url)
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append(
                    "App Check API returned 403 — the service account may lack "
                    "roles/firebaseappcheck.viewer or equivalent read permission."
                )
                logger.warning(
                    "firebase: App Check 403 for project=%s — skipping",
                    project_id,
                )
                return []
            if exc.status_code == 404:
                logger.debug(
                    "firebase: App Check 404 for project=%s — not enabled",
                    project_id,
                )
                return []
            warnings.append(
                f"App Check fetch error (HTTP {exc.status_code}): {str(exc)[:120]}"
            )
            logger.warning(
                "firebase: App Check fetch failed project=%s code=%s",
                project_id, exc.status_code,
            )
            return []
        except Exception as exc:
            warnings.append(f"App Check fetch failed unexpectedly: {type(exc).__name__}")
            logger.warning(
                "firebase: App Check unexpected error project=%s %s",
                project_id, type(exc).__name__,
            )
            return []

        if not isinstance(data, dict):
            return []

        # ``services`` is the list of App Check–monitored services.
        services: list[dict] = data.get("services") or []
        if not isinstance(services, list):
            services = []

        # Extract short service name from the full resource name
        # e.g. "projects/123/services/storage.googleapis.com" → "storage.googleapis.com"
        def _service_short_name(svc: dict) -> str:
            full_name = str(svc.get("name") or "")
            return full_name.split("/services/", 1)[-1] if "/services/" in full_name else full_name

        enforced: list[str] = []
        unenforced: list[str] = []
        for svc in services:
            if not isinstance(svc, dict):
                continue
            mode = (svc.get("enforcementMode") or "").upper()
            short_name = _service_short_name(svc)
            if mode == "ENFORCED":
                enforced.append(short_name)
            else:
                unenforced.append(short_name)

        record: dict = {
            "record_type":              FIREBASE_APP_CHECK_CONFIG,
            "record_id":                f"{project_id}/app_check",
            "name":                     f"{project_id}/app_check",
            "project_id":               project_id,
            "service_count":            len(services),
            "enforced_service_count":   len(enforced),
            "unenforced_service_count": len(unenforced),
            "enforced_service_names":   sorted(enforced) or None,
            "config_fetch_warnings":    [],
        }
        return [record]

    # ── Public interface ───────────────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate service account credentials with a minimal API probe.

        Parses and validates the service account JSON fields, mints an OAuth2
        token, and makes a single probe request to confirm project access.

        Raises
        ------
        ValueError           — service account JSON is malformed or missing fields.
        AuthenticationError  — token exchange failed or API returned 401.
        ConnectorError       — project not found (404) or permission denied (403).
        NetworkError         — transport failure.
        """
        creds = self._parse_credentials(credentials)
        self._validate_sa_fields(creds)
        # SECURITY: creds["private_key"] is never logged.
        logger.info(
            "FirebaseConnector.validate_credentials: probing project=%s",
            creds.get("project_id"),
        )
        access_token = self._get_access_token(creds)
        # Probe: get project metadata (smallest reliable read for this SA)
        self._fetch_project_metadata(access_token, creds["project_id"])
        logger.info(
            "FirebaseConnector.validate_credentials: success project=%s",
            creds.get("project_id"),
        )
        return True

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all accessible Firebase configuration records.

        All surfaces are attempted.  Permission errors (HTTP 403) on optional
        surfaces are recorded as warnings and the fetch continues.

        Returns
        -------
        Flat list of normalised records.

        Raises
        ------
        AuthenticationError  — service account credentials are invalid/revoked.
        ConnectorError       — unexpected non-permission API error.
        RateLimitError       — API rate limit exceeded.
        NetworkError         — transport failure.

        SECURITY: credentials["private_key"] is NEVER logged anywhere in this
        method or its callees.
        """
        creds = self._parse_credentials(credentials)
        self._validate_sa_fields(creds)
        project_id = creds["project_id"]
        logger.info("FirebaseConnector.fetch: starting project=%s", project_id)

        # Mint a single access token for the entire fetch call.
        # SECURITY: access_token is never logged.
        access_token = self._get_access_token(creds)

        warnings: list[str] = []
        records: list[dict] = []

        # 1. Project metadata (required — failures are fatal)
        project_record = self._fetch_project_metadata(access_token, project_id)
        records.append(project_record)
        logger.info("FirebaseConnector.fetch: project_metadata ok")

        # 2. Firebase Auth config + authorized domains (optional — 403 → warning)
        try:
            auth_records = self._fetch_auth_config(access_token, project_id, warnings)
            records.extend(auth_records)
            logger.info(
                "FirebaseConnector.fetch: auth_records count=%d", len(auth_records)
            )
        except Exception as exc:
            logger.warning("firebase: auth_config fetch error %s", type(exc).__name__)
            warnings.append(f"auth_config fetch error: {type(exc).__name__}")

        # 3. Firebase Security Rules (Firestore + Storage) (optional)
        try:
            rules_records = self._fetch_firebase_rules(access_token, project_id, warnings)
            records.extend(rules_records)
            logger.info(
                "FirebaseConnector.fetch: rules_records count=%d", len(rules_records)
            )
        except Exception as exc:
            logger.warning("firebase: rules fetch error %s", type(exc).__name__)
            warnings.append(f"rules fetch error: {type(exc).__name__}")

        # 4. Storage buckets (optional)
        try:
            storage_records = self._fetch_storage_buckets(access_token, project_id, warnings)
            records.extend(storage_records)
            logger.info(
                "FirebaseConnector.fetch: storage_bucket_records count=%d",
                len(storage_records),
            )
        except Exception as exc:
            logger.warning("firebase: storage_buckets fetch error %s", type(exc).__name__)
            warnings.append(f"storage_buckets fetch error: {type(exc).__name__}")

        # 5. Firebase Hosting sites + domains (optional)
        try:
            hosting_records = self._fetch_hosting(access_token, project_id, warnings)
            records.extend(hosting_records)
            logger.info(
                "FirebaseConnector.fetch: hosting_records count=%d",
                len(hosting_records),
            )
        except Exception as exc:
            logger.warning("firebase: hosting fetch error %s", type(exc).__name__)
            warnings.append(f"hosting fetch error: {type(exc).__name__}")

        # 6. Cloud Functions metadata (optional)
        try:
            fn_records = self._fetch_cloud_functions(access_token, project_id, warnings)
            records.extend(fn_records)
            logger.info(
                "FirebaseConnector.fetch: function_records count=%d", len(fn_records)
            )
        except Exception as exc:
            logger.warning("firebase: cloud_functions fetch error %s", type(exc).__name__)
            warnings.append(f"cloud_functions fetch error: {type(exc).__name__}")

        # 7. Remote Config template metadata (optional — M57.8)
        rc_records = self._fetch_remote_config(access_token, project_id, warnings)
        records.extend(rc_records)
        logger.info(
            "FirebaseConnector.fetch: remote_config_records count=%d", len(rc_records)
        )

        # 8. App Check service enforcement metadata (optional — M57.8)
        ac_records = self._fetch_app_check(access_token, project_id, warnings)
        records.extend(ac_records)
        logger.info(
            "FirebaseConnector.fetch: app_check_records count=%d", len(ac_records)
        )

        # Attach accumulated warnings to the project record.
        if warnings:
            project_record["config_fetch_warnings"] = warnings

        logger.info(
            "FirebaseConnector.fetch: complete project=%s total_records=%d warnings=%d",
            project_id,
            len(records),
            len(warnings),
        )
        return records
