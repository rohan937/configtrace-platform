"""AWS connector — M36: Foundation + Account Inventory; M37: S3 Exposure.

Fetches safe account/inventory metadata from AWS using read-only IAM credentials.

Resources fetched in M36
-----------------------
aws_account_identity
    STS GetCallerIdentity — stable account ID, principal type, partition.
    Always fetched first; also used for duplicate-account detection.

aws_region
    EC2 DescribeRegions — one record per selected region.
    OPTIONAL: if ec2:DescribeRegions is not permitted (403/AccessDenied),
    falls back to the user-configured selected_regions list silently.

aws_service_inventory
    Lists which surfaces are actively monitored and which are planned.

Resources fetched in M37
-----------------------
aws_s3_bucket
    One record per S3 bucket visible to the credentials.
    Includes Block Public Access, policy public status, ACL public grants,
    encryption, versioning, logging, lifecycle rule count, and tag keys.
    Per-field optional failures are recorded as config_fetch_warnings rather
    than failing the entire sync (fail-soft design).

    SECURITY: object names/contents are NEVER fetched. Raw bucket policies are
    NEVER stored — only a short SHA-256 prefix (policy_hash) and parsed summary
    fields (public_principals_detected, policy_status_is_public) are kept.

Auth / credentials
------------------
Credentials dict:
    aws_access_key_id      : str          — IAM access key ID (AKIA...)
    aws_secret_access_key  : str          — IAM secret access key
    aws_default_region     : str          — primary region (default: us-east-1)
    aws_selected_regions   : list[str]    — regions to monitor

SECURITY
--------
- aws_access_key_id is NEVER logged in full. Only _safe_key_id() output is logged.
- aws_secret_access_key is NEVER logged under any circumstances.
- All API calls are read-only. No write operations are ever performed.
- Temporary session tokens are not stored or returned.
- S3 object contents and object keys are NEVER fetched or stored.
- Raw bucket policy text is NEVER stored; only policy_hash + parsed fields.

Future extension
----------------
Add new methods to AWSConnector for each new AWS milestone.
The _make_client() and _call_aws() helpers provide consistent error handling.
"""

from __future__ import annotations

import logging
from typing import Any

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.aws_schema import (
    AWS_ACCOUNT_IDENTITY,
    AWS_REGION,
    AWS_SERVICE_INVENTORY,
    AWS_S3_BUCKET,
)

logger = logging.getLogger(__name__)

# AWS error codes that indicate invalid/revoked credentials (401 equivalent)
_AUTH_ERROR_CODES = frozenset({
    "InvalidClientTokenId",
    "AuthFailure",
    "SignatureDoesNotMatch",
    "InvalidSignatureException",
    "TokenRefreshRequired",
    "ExpiredTokenException",
    "InvalidAccessKeyId",
    "MissingAuthenticationToken",
})

# AWS error codes that indicate permissions missing but creds valid (403 equivalent)
_ACCESS_DENIED_CODES = frozenset({
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
})

# AWS error codes for throttling/rate limiting
_THROTTLE_CODES = frozenset({
    "Throttling",
    "ThrottlingException",
    "RequestThrottled",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "ProvisionedThroughputExceededException",
    "TransactionInProgressException",
    "SlowDown",
})


# ── S3-specific "not found" error codes ──────────────────────────────────────
# These codes indicate a configuration is absent (safe state), not an error.
# Used by _fetch_bucket_* helpers to distinguish "not configured" from failures.
_S3_NOT_CONFIGURED_CODES: frozenset[str] = frozenset({
    "NoSuchPublicAccessBlockConfiguration",
    "NoSuchBucketPolicy",
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchLifecycleConfiguration",
    "NoSuchTagSet",
})

# ACL group URIs for public access detection
_ACL_ALL_USERS_URI         = "http://acs.amazonaws.com/groups/global/AllUsers"
_ACL_AUTH_USERS_URI        = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
_ACL_READ_PERMISSIONS      = frozenset({"READ", "FULL_CONTROL"})
_ACL_WRITE_PERMISSIONS     = frozenset({"WRITE", "FULL_CONTROL"})


def _parse_bucket_policy_public(policy_json: str) -> bool:
    """Return True if the bucket policy contains a public principal.

    A public principal is defined as:
    - Principal: "*"
    - Principal: {"AWS": "*"}  or  {"AWS": ["*", ...]}

    Only Allow statements are checked. Deny overrides are not evaluated here
    because the authoritative public-exposure signal is policy_status_is_public
    from GetBucketPolicyStatus. This function provides a secondary conservative
    indicator when GetBucketPolicyStatus is unavailable.

    SECURITY: policy_json is parsed in memory only; it is never stored.
    """
    import json
    try:
        policy = json.loads(policy_json)
    except (json.JSONDecodeError, ValueError):
        return False

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect", "").upper() != "ALLOW":
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_p = principal.get("AWS", [])
            if isinstance(aws_p, str):
                aws_p = [aws_p]
            if isinstance(aws_p, list) and "*" in aws_p:
                return True
    return False


def _parse_principal_type(arn: str) -> str:
    """Extract principal type from an IAM ARN.

    Examples:
        arn:aws:iam::123456789012:user/alice          → "user"
        arn:aws:iam::123456789012:role/MyRole         → "role"
        arn:aws:sts::123456789012:assumed-role/R/sess → "assumed-role"
        arn:aws:iam::123456789012:root                → "root"
    """
    if not arn:
        return "unknown"
    parts = arn.split(":")
    if len(parts) < 6:
        return "unknown"
    resource = parts[5]  # e.g. "user/alice", "role/MyRole", "assumed-role/R/sess"
    resource_type = resource.split("/")[0].lower()
    return resource_type if resource_type else "unknown"


def _parse_partition(arn: str) -> str:
    """Extract partition from an IAM ARN (aws, aws-cn, aws-us-gov)."""
    if not arn:
        return "aws"
    parts = arn.split(":")
    return parts[1] if len(parts) >= 2 else "aws"


class AWSConnector(BaseConnector):
    """Read-only AWS connector for account/inventory metadata — M36.

    Supports AWS access key ID + secret access key authentication.
    Designed to be extended in future milestones (S3, Security Groups, IAM, etc.)
    by adding new methods that reuse _make_client() and _call_aws().
    """

    def _safe_key_id(self, credentials: dict) -> str:
        """Return a safe partial key ID for logging. NEVER logs the full key."""
        key_id = credentials.get("aws_access_key_id", "")
        if len(key_id) >= 4:
            return key_id[:4] + "***"
        return "***"

    def _default_region(self, credentials: dict) -> str:
        """Return the configured default region or us-east-1."""
        return credentials.get("aws_default_region") or "us-east-1"

    def _selected_regions(self, credentials: dict) -> list[str]:
        """Return the list of regions to monitor. Falls back to [default_region]."""
        regions = credentials.get("aws_selected_regions")
        if regions and isinstance(regions, list) and len(regions) > 0:
            return regions
        return [self._default_region(credentials)]

    def _make_client(self, service: str, credentials: dict, region: str | None = None) -> Any:
        """Create a boto3 client with explicit credentials.

        Extracted into its own method so tests can patch it cleanly without
        patching the entire boto3 module.

        SECURITY: aws_secret_access_key is never logged — it is passed directly
        to boto3 and is not stored anywhere in this class.
        """
        import boto3  # Local import so module is importable without boto3 installed
        region = region or self._default_region(credentials)
        # SECURITY: do not log credentials
        logger.debug(
            "aws._make_client  service=%s  region=%s  key_id=%s",
            service,
            region,
            self._safe_key_id(credentials),
        )
        return boto3.client(
            service,
            aws_access_key_id=credentials["aws_access_key_id"],
            aws_secret_access_key=credentials["aws_secret_access_key"],
            region_name=region,
        )

    def _call_aws(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Call an AWS API function and translate exceptions to connector errors.

        This is the single translation point for all AWS API calls. Any new
        method added in future milestones should wrap its boto3 calls here.

        Raises:
            AuthenticationError: Invalid or revoked credentials (AWS 401 equivalent).
            ConnectorError(status_code=403): Valid credentials but no permission.
            RateLimitError: AWS throttling / request limit exceeded.
            ConnectorError: Other AWS API errors (5xx, unexpected codes).
            NetworkError: Transport-level failure (no HTTP response received).
        """
        try:
            import botocore.exceptions  # noqa: F401 — ensure importable before calling fn
            return fn(*args, **kwargs)
        except Exception as exc:
            # Import botocore locally to avoid module-level dependency
            try:
                import botocore.exceptions as _bce
            except ImportError:
                raise ConnectorError(f"boto3/botocore not installed: {exc}") from exc

            if isinstance(exc, _bce.ClientError):
                error_code = exc.response["Error"]["Code"]
                error_message = exc.response["Error"]["Message"]

                if error_code in _AUTH_ERROR_CODES:
                    raise AuthenticationError(
                        f"AWS credentials are invalid or expired ({error_code}). "
                        "Verify the access key ID and secret access key are correct "
                        "and the IAM user has not been disabled or deleted.",
                        status_code=401,
                    ) from exc

                if error_code in _ACCESS_DENIED_CODES:
                    raise ConnectorError(
                        f"AWS access denied ({error_code}): {error_message}. "
                        "The IAM user or role lacks permission for this operation.",
                        status_code=403,
                    ) from exc

                if error_code in _THROTTLE_CODES:
                    raise RateLimitError(
                        f"AWS request throttled ({error_code}). "
                        "ConfigTrace will retry on the next scheduled sync."
                    ) from exc

                if error_code in {"ServiceUnavailable", "InternalError",
                                  "InternalErrorException", "ServiceUnavailableException"}:
                    raise ConnectorError(
                        f"AWS service temporarily unavailable ({error_code}).",
                        status_code=503,
                    ) from exc

                # Catch-all for other ClientErrors
                raise ConnectorError(
                    f"AWS API error ({error_code}): {error_message}",
                    status_code=None,
                ) from exc

            if isinstance(exc, _bce.NoCredentialsError):
                raise AuthenticationError(
                    "AWS credentials are missing or could not be loaded.",
                    status_code=401,
                ) from exc

            if isinstance(exc, _bce.PartialCredentialsError):
                raise AuthenticationError(
                    "AWS credentials are incomplete (missing access key ID or secret).",
                    status_code=401,
                ) from exc

            if isinstance(exc, (
                _bce.EndpointConnectionError,
                _bce.ConnectTimeoutError,
                _bce.ReadTimeoutError,
                _bce.ConnectionError,
            )):
                raise NetworkError(
                    f"Network error reaching AWS: {exc}"
                ) from exc

            # Unknown exception type — re-raise as-is
            raise

    # ── Public interface ───────────────────────────────────────────────────────

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate using STS GetCallerIdentity.

        STS GetCallerIdentity is the safest AWS validation call — it requires
        no IAM permissions beyond valid credentials and works for any principal
        type (IAM user, role, assumed role).

        Returns True on success. Raises AuthenticationError on invalid creds,
        ConnectorError on other API errors, NetworkError on transport failures.

        SECURITY: aws_secret_access_key is NEVER logged.
        """
        logger.info(
            "AWSConnector.validate_credentials  key_id=%s",
            self._safe_key_id(credentials),
        )
        client = self._make_client("sts", credentials)
        self._call_aws(client.get_caller_identity)
        logger.info(
            "AWSConnector.validate_credentials: success  key_id=%s",
            self._safe_key_id(credentials),
        )
        return True

    def fetch(self, credentials: dict) -> list[dict]:
        """Fetch all AWS account/inventory and S3 records.

        Returns a flat list of normalized records:
        - 1 × aws_account_identity  (M36)
        - N × aws_region            (M36, one per selected region)
        - 1 × aws_service_inventory (M36/M37)
        - M × aws_s3_bucket         (M37, one per visible S3 bucket)

        All resources use fail-soft behavior for optional endpoints.
        The account identity is the only required call — a 403 on account
        identity propagates as AuthenticationError.

        S3 listing is fail-soft: if s3:ListAllMyBuckets is denied, S3 records
        are omitted and the sync still succeeds. Per-bucket optional fields
        that require additional permissions also fail soft (config_fetch_warnings).

        SECURITY: Credentials are never included in returned records.
                  S3 object contents and keys are never fetched.
        """
        logger.info(
            "AWSConnector.fetch: starting  key_id=%s",
            self._safe_key_id(credentials),
        )

        records: list[dict] = []

        # 1. Account identity (required — also confirms credentials are valid)
        account_record = self._fetch_account_identity(credentials)
        records.append(account_record)
        logger.info(
            "AWSConnector.fetch: account_identity fetched  account_id=%s",
            account_record.get("account_id", ""),
        )

        # 2. Regions (optional — fails soft on 403)
        region_records = self._fetch_regions(credentials)
        records.extend(region_records)
        logger.info(
            "AWSConnector.fetch: regions fetched  count=%d",
            len(region_records),
        )

        # 3. S3 buckets (optional — fails soft on 403)
        # SECURITY: credentials are passed to _make_client only; never stored
        # in records. Object contents and keys are never fetched.
        s3_records = self._fetch_s3_buckets(credentials)
        records.extend(s3_records)
        logger.info(
            "AWSConnector.fetch: s3_buckets fetched  count=%d",
            len(s3_records),
        )

        # 4. Service inventory (reflects active surfaces)
        inventory_record = self._fetch_service_inventory(credentials, s3_count=len(s3_records))
        records.append(inventory_record)

        logger.info(
            "AWSConnector.fetch: complete  total_records=%d",
            len(records),
        )
        return records

    # ── Fetch helpers ──────────────────────────────────────────────────────────

    def _fetch_account_identity(self, credentials: dict) -> dict:
        """Fetch account identity via STS GetCallerIdentity and normalize.

        SECURITY: Does not log ARN or account ID in full in any sensitive context.
        The account ID is used as the resource identifier and stored in metadata.
        """
        client = self._make_client("sts", credentials)
        response = self._call_aws(client.get_caller_identity)

        account_id: str = response.get("Account", "")
        arn: str = response.get("Arn", "")

        principal_type = _parse_principal_type(arn)
        partition = _parse_partition(arn)
        selected = self._selected_regions(credentials)
        default_region = self._default_region(credentials)

        return {
            "record_type":      AWS_ACCOUNT_IDENTITY,
            "record_id":        account_id,
            "name":             f"AWS Account {account_id}",
            # Account identity
            "account_id":       account_id,
            "principal_arn":    arn,          # full ARN — safe (not a secret)
            "principal_type":   principal_type,
            "partition":        partition,
            # Region configuration
            "default_region":   default_region,
            "selected_regions": selected,
        }

    def _fetch_regions(self, credentials: dict) -> list[dict]:
        """Fetch enabled regions from EC2 DescribeRegions and normalize.

        Returns one record per selected region.

        Fail-soft: if ec2:DescribeRegions is not permitted (403 / AccessDenied),
        this method returns records for the user-configured selected_regions
        without opt_in_status from AWS (uses "unknown" as fallback).
        """
        selected = self._selected_regions(credentials)
        region = self._default_region(credentials)

        try:
            client = self._make_client("ec2", credentials, region=region)
            response = self._call_aws(
                client.describe_regions,
                AllRegions=False,
                Filters=[
                    {
                        "Name": "opt-in-status",
                        "Values": ["opt-in-not-required", "opted-in"],
                    }
                ],
            )
            discovered: dict[str, dict] = {
                r["RegionName"]: r for r in response.get("Regions", [])
            }
            source = "discovered"
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.info(
                    "aws: ec2:DescribeRegions not permitted — "
                    "using user-selected regions without opt-in metadata"
                )
                discovered = {}
                source = "selected"
            else:
                raise

        records = []
        for region_name in selected:
            raw = discovered.get(region_name, {})
            records.append({
                "record_type":   AWS_REGION,
                "record_id":     region_name,
                "name":          region_name,
                "region_name":   region_name,
                "opt_in_status": raw.get("OptInStatus", "unknown"),
                "enabled":       True,
                "source":        source,
            })
        return records

    def _fetch_service_inventory(self, credentials: dict, s3_count: int = 0) -> dict:
        """Return a service inventory record reflecting active monitored surfaces.

        Records which surfaces are actively monitored (M36: account_inventory;
        M37: + s3) and which are planned for future milestones.
        This record allows diff tracking to detect when the set of active
        surfaces or selected regions changes.

        Args:
            credentials: AWS credentials (used only for region extraction).
            s3_count:    Number of S3 bucket records fetched this sync.
                         Used to update s3_bucket_count for change detection.
        """
        selected = self._selected_regions(credentials)
        return {
            "record_type":      AWS_SERVICE_INVENTORY,
            "record_id":        "service_inventory",
            "name":             "AWS Service Inventory",
            "selected_regions": selected,
            "enabled_surfaces": ["account_inventory", "s3"],
            "s3_bucket_count":  s3_count,
            "future_surfaces": [
                "security_groups", "iam", "route53", "cloudfront",
                "secrets", "rds", "lambda", "api_gateway", "load_balancers",
                "waf", "cloudtrail", "guardduty", "security_hub",
                "ecs", "eks", "ecr", "eventbridge", "sqs", "sns",
                "kms", "backup", "organizations", "cloudwatch",
            ],
        }

    def get_account_id(self, credentials: dict) -> str:
        """Return the AWS account ID for the given credentials.

        Used by integration_service to get the stable identifier before creating
        the Resource row. Calls STS GetCallerIdentity.

        SECURITY: aws_secret_access_key is never logged.
        """
        client = self._make_client("sts", credentials)
        response = self._call_aws(client.get_caller_identity)
        return response.get("Account", "")

    # ── S3 fetch methods (M37) ─────────────────────────────────────────────────

    def _fetch_s3_buckets(self, credentials: dict) -> list[dict]:
        """List all S3 buckets and fetch configuration for each.

        Returns one aws_s3_bucket record per bucket. Fail-soft on 403:
        if s3:ListAllMyBuckets is denied, returns an empty list so the rest
        of the sync still succeeds.

        Per-bucket optional field failures (e.g. missing GetBucketPolicy
        permission) are recorded in config_fetch_warnings on the record,
        not propagated as integration-level failures.

        SECURITY:
        - Object contents and object keys are NEVER fetched.
        - Raw bucket policy text is NEVER stored; only policy_hash + parsed fields.
        - aws credentials are never placed in any returned record.
        """
        # Use us-east-1 as the signing region for the global S3 endpoint.
        # boto3 automatically handles routing to bucket-specific regions.
        client = self._make_client("s3", credentials, region="us-east-1")

        try:
            response = self._call_aws(client.list_buckets)
        except ConnectorError as exc:
            if exc.status_code == 403:
                logger.info(
                    "aws: s3:ListAllMyBuckets not permitted — "
                    "skipping S3 monitoring for this sync"
                )
                return []
            raise

        buckets = response.get("Buckets") or []
        records: list[dict] = []
        for bucket in buckets:
            bucket_name: str = bucket.get("Name") or ""
            if not bucket_name:
                continue
            creation_date = bucket.get("CreationDate")
            try:
                record = self._fetch_bucket_config(
                    client, bucket_name, creation_date, credentials
                )
                records.append(record)
            except Exception:
                # Belt-and-suspenders: a single bad bucket must never abort
                # the full sync. Log and continue.
                logger.warning(
                    "aws: failed to fetch config for bucket %r — skipping",
                    bucket_name,
                    exc_info=True,
                )

        logger.debug(
            "aws._fetch_s3_buckets: fetched %d bucket record(s)  key_id=%s",
            len(records),
            self._safe_key_id(credentials),
        )
        return records

    def _fetch_bucket_config(
        self,
        client: Any,
        bucket_name: str,
        creation_date: Any,
        credentials: dict,
    ) -> dict:
        """Assemble a complete aws_s3_bucket record for one bucket.

        Each optional sub-helper is wrapped with a fail-soft handler so that
        an unexpected exception (e.g. wrong boto3 method name, API shape change,
        network hiccup on a single field) adds a ``*_error`` entry to
        ``config_fetch_warnings`` and returns None-valued fallback fields
        instead of skipping the bucket entirely.

        Expected permission errors (403) and "not configured" states
        (NoSuch*) are handled inside each sub-helper before they reach here.

        SECURITY: credentials are only forwarded to _make_client for regional
        clients; they are never placed in the returned record.
        """
        warnings: list[str] = []

        # ── Bucket region ──────────────────────────────────────────────────────
        bucket_region = self._fetch_bucket_region(client, bucket_name)

        # ── Creation date (immutable, stored for context only) ─────────────────
        creation_date_str: str | None = None
        if creation_date is not None:
            try:
                creation_date_str = creation_date.isoformat()
            except AttributeError:
                creation_date_str = str(creation_date)

        # ── Fail-soft wrapper ──────────────────────────────────────────────────
        # Calls fn(); on any unexpected exception logs a warning, appends
        # ``warning_key + "_error"`` to the shared warnings list, and returns
        # fallback so the caller always gets a usable dict.
        def _safe(fn: Any, fallback: dict, warning_key: str) -> dict:
            try:
                return fn()
            except Exception:
                logger.warning(
                    "aws._fetch_bucket_config: unexpected error fetching %s "
                    "for bucket %r — using safe fallback",
                    warning_key, bucket_name, exc_info=True,
                )
                warnings.append(warning_key + "_error")
                return fallback

        # ── Per-field config (all optional / fail-soft) ────────────────────────
        bpa = _safe(
            lambda: self._fetch_bucket_public_access_block(client, bucket_name, warnings),
            {
                "block_public_acls":              None,
                "ignore_public_acls":             None,
                "block_public_policy":            None,
                "restrict_public_buckets":        None,
                "public_access_block_configured": None,
            },
            "s3_public_access_block",
        )
        policy_info = _safe(
            lambda: self._fetch_bucket_policy_info(client, bucket_name, warnings),
            {"policy_present": None, "policy_hash": None, "public_principals_detected": None},
            "s3_policy",
        )
        policy_stat = _safe(
            lambda: self._fetch_bucket_policy_status(client, bucket_name, warnings),
            {"policy_status_is_public": None},
            "s3_policy_status",
        )
        acl_info = _safe(
            lambda: self._fetch_bucket_acl(client, bucket_name, warnings),
            {
                "acl_all_users_read":             None,
                "acl_all_users_write":            None,
                "acl_authenticated_users_read":   None,
                "acl_authenticated_users_write":  None,
            },
            "s3_acl",
        )
        enc_info = _safe(
            lambda: self._fetch_bucket_encryption(client, bucket_name, warnings),
            {"encryption_enabled": None, "encryption_algorithm": None, "bucket_key_enabled": None},
            "s3_encryption",
        )
        ver_info = _safe(
            lambda: self._fetch_bucket_versioning(client, bucket_name, warnings),
            {"versioning_status": None, "mfa_delete_status": None},
            "s3_versioning",
        )
        log_info = _safe(
            lambda: self._fetch_bucket_logging(client, bucket_name, warnings),
            {"logging_enabled": None, "logging_target_bucket": None},
            "s3_logging",
        )
        lifecycle = _safe(
            lambda: self._fetch_bucket_lifecycle(client, bucket_name, warnings),
            {"lifecycle_rule_count": None},
            "s3_lifecycle",
        )
        tag_info = _safe(
            lambda: self._fetch_bucket_tags(client, bucket_name, warnings),
            {"tag_keys": None},
            "s3_tagging",
        )

        record: dict[str, Any] = {
            "record_type":   AWS_S3_BUCKET,
            "record_id":     bucket_name,    # stable key used by diff_service
            "name":          bucket_name,
            "bucket_name":   bucket_name,
            "bucket_region": bucket_region,
            "creation_date": creation_date_str,
        }
        record.update(bpa)
        record.update(policy_info)
        record.update(policy_stat)
        record.update(acl_info)
        record.update(enc_info)
        record.update(ver_info)
        record.update(log_info)
        record.update(lifecycle)
        record.update(tag_info)
        record["config_fetch_warnings"] = sorted(warnings)

        return record

    def _fetch_bucket_region(self, client: Any, bucket_name: str) -> str:
        """Return the bucket's AWS region.

        GetBucketLocation returns None (or "") for us-east-1 buckets.
        All other regions are returned as-is.
        """
        try:
            response = self._call_aws(
                client.get_bucket_location, Bucket=bucket_name
            )
            location = response.get("LocationConstraint")
            return location if location else "us-east-1"
        except ConnectorError:
            logger.debug(
                "aws: could not determine region for bucket %r", bucket_name
            )
            return "unknown"

    def _fetch_bucket_public_access_block(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch Block Public Access (BPA) configuration.

        Returns a dict with block_public_acls, ignore_public_acls,
        block_public_policy, restrict_public_buckets, and the boolean
        public_access_block_configured (False when BPA is not set at all).

        NoSuchPublicAccessBlockConfiguration → all fields False, configured=False.
        403 → all fields None (unavailable), warning added.
        """
        try:
            response = self._call_aws(
                client.get_public_access_block, Bucket=bucket_name
            )
            cfg = response.get("PublicAccessBlockConfiguration") or {}
            return {
                "block_public_acls":         cfg.get("BlockPublicAcls",         False),
                "ignore_public_acls":        cfg.get("IgnorePublicAcls",        False),
                "block_public_policy":       cfg.get("BlockPublicPolicy",       False),
                "restrict_public_buckets":   cfg.get("RestrictPublicBuckets",   False),
                "public_access_block_configured": True,
            }
        except ConnectorError as exc:
            msg = str(exc)
            if "NoSuchPublicAccessBlockConfiguration" in msg:
                # BPA not set — this is a legitimate "not configured" state
                return {
                    "block_public_acls":         False,
                    "ignore_public_acls":        False,
                    "block_public_policy":       False,
                    "restrict_public_buckets":   False,
                    "public_access_block_configured": False,
                }
            if exc.status_code == 403:
                warnings.append("s3_public_access_block_unavailable")
                return {
                    "block_public_acls":         None,
                    "ignore_public_acls":        None,
                    "block_public_policy":       None,
                    "restrict_public_buckets":   None,
                    "public_access_block_configured": None,
                }
            raise

    def _fetch_bucket_policy_info(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch bucket policy and derive public-principal presence.

        SECURITY: Raw policy text is NEVER stored. Only a short SHA-256
        prefix (policy_hash) and the boolean public_principals_detected are
        recorded.

        NoSuchBucketPolicy → policy_present=False, hash/public detection omitted.
        403 → policy_present=None (unavailable), warning added.
        """
        import hashlib
        try:
            response = self._call_aws(
                client.get_bucket_policy, Bucket=bucket_name
            )
            policy_json: str = response.get("Policy") or ""
            policy_hash = hashlib.sha256(policy_json.encode()).hexdigest()[:16]
            public_principals = _parse_bucket_policy_public(policy_json)
            return {
                "policy_present":            True,
                "policy_hash":               policy_hash,
                "public_principals_detected": public_principals,
            }
        except ConnectorError as exc:
            msg = str(exc)
            if "NoSuchBucketPolicy" in msg:
                return {
                    "policy_present":            False,
                    "policy_hash":               None,
                    "public_principals_detected": False,
                }
            if exc.status_code == 403:
                warnings.append("s3_policy_unavailable")
                return {
                    "policy_present":            None,
                    "policy_hash":               None,
                    "public_principals_detected": None,
                }
            raise

    def _fetch_bucket_policy_status(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch AWS's computed public-policy status for the bucket.

        GetBucketPolicyStatus asks AWS whether the bucket policy makes the
        bucket public. This is the authoritative signal for public-policy
        exposure (more reliable than our own policy parsing).

        403 or no policy → policy_status_is_public=None (unavailable).
        """
        try:
            response = self._call_aws(
                client.get_bucket_policy_status, Bucket=bucket_name
            )
            status = response.get("PolicyStatus") or {}
            return {
                "policy_status_is_public": status.get("IsPublic"),
            }
        except ConnectorError as exc:
            msg = str(exc)
            # "NoSuchBucketPolicy" or "NoSuchPublicAccessBlockConfiguration"
            # can also appear here for buckets without policies
            if exc.status_code == 403 or "NoSuchBucketPolicy" in msg:
                if exc.status_code == 403:
                    warnings.append("s3_policy_status_unavailable")
                return {"policy_status_is_public": None}
            raise

    def _fetch_bucket_acl(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch ACL and detect public grants for AllUsers and AuthenticatedUsers.

        Returns boolean fields for read/write access to each public group.
        403 → all fields None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_acl, Bucket=bucket_name
            )
            grants = response.get("Grants") or []
            au_read = au_write = False
            auu_read = auu_write = False
            for grant in grants:
                grantee = grant.get("Grantee") or {}
                uri = grantee.get("URI") or ""
                perm = grant.get("Permission") or ""
                if uri == _ACL_ALL_USERS_URI:
                    if perm in _ACL_READ_PERMISSIONS:
                        au_read = True
                    if perm in _ACL_WRITE_PERMISSIONS:
                        au_write = True
                elif uri == _ACL_AUTH_USERS_URI:
                    if perm in _ACL_READ_PERMISSIONS:
                        auu_read = True
                    if perm in _ACL_WRITE_PERMISSIONS:
                        auu_write = True
            return {
                "acl_all_users_read":             au_read,
                "acl_all_users_write":            au_write,
                "acl_authenticated_users_read":   auu_read,
                "acl_authenticated_users_write":  auu_write,
            }
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append("s3_acl_unavailable")
                return {
                    "acl_all_users_read":             None,
                    "acl_all_users_write":            None,
                    "acl_authenticated_users_read":   None,
                    "acl_authenticated_users_write":  None,
                }
            raise

    def _fetch_bucket_encryption(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch server-side encryption configuration.

        Returns encryption_enabled=True with algorithm/bucket_key details,
        or encryption_enabled=False if not configured.
        403 → encryption_enabled=None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_encryption, Bucket=bucket_name
            )
            sse_cfg = response.get("ServerSideEncryptionConfiguration") or {}
            rules = sse_cfg.get("Rules") or []
            if rules:
                rule = rules[0]
                default = rule.get("ApplyServerSideEncryptionByDefault") or {}
                return {
                    "encryption_enabled":    True,
                    "encryption_algorithm":  default.get("SSEAlgorithm"),
                    "bucket_key_enabled":    rule.get("BucketKeyEnabled"),
                }
            return {
                "encryption_enabled":    True,
                "encryption_algorithm":  None,
                "bucket_key_enabled":    None,
            }
        except ConnectorError as exc:
            msg = str(exc)
            if "ServerSideEncryptionConfigurationNotFoundError" in msg:
                return {
                    "encryption_enabled":    False,
                    "encryption_algorithm":  None,
                    "bucket_key_enabled":    None,
                }
            if exc.status_code == 403:
                warnings.append("s3_encryption_unavailable")
                return {
                    "encryption_enabled":    None,
                    "encryption_algorithm":  None,
                    "bucket_key_enabled":    None,
                }
            raise

    def _fetch_bucket_versioning(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch versioning and MFA-delete status.

        Versioning status:
            "Enabled"   → versioning_status = "enabled"
            "Suspended"  → versioning_status = "suspended"
            "" / absent  → versioning_status = "disabled"

        MFA delete:
            "Enabled"   → mfa_delete_status = "enabled"
            "Disabled"  → mfa_delete_status = "disabled"
            absent      → mfa_delete_status = None

        403 → both fields None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_versioning, Bucket=bucket_name
            )
            raw_status = response.get("Status") or ""
            raw_mfa = response.get("MFADelete") or ""
            versioning_status = (
                "enabled"   if raw_status == "Enabled"
                else "suspended" if raw_status == "Suspended"
                else "disabled"
            )
            mfa_delete_status = (
                raw_mfa.lower()
                if raw_mfa.lower() in ("enabled", "disabled")
                else None
            )
            return {
                "versioning_status":   versioning_status,
                "mfa_delete_status":   mfa_delete_status,
            }
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append("s3_versioning_unavailable")
                return {
                    "versioning_status":   None,
                    "mfa_delete_status":   None,
                }
            raise

    def _fetch_bucket_logging(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch server access logging configuration.

        Returns logging_enabled=True with target bucket if enabled,
        or logging_enabled=False if not configured (empty response).
        403 → logging_enabled=None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_logging, Bucket=bucket_name
            )
            logging_cfg = response.get("LoggingEnabled")
            if logging_cfg:
                return {
                    "logging_enabled":        True,
                    "logging_target_bucket":  logging_cfg.get("TargetBucket"),
                }
            return {
                "logging_enabled":        False,
                "logging_target_bucket":  None,
            }
        except ConnectorError as exc:
            if exc.status_code == 403:
                warnings.append("s3_logging_unavailable")
                return {
                    "logging_enabled":        None,
                    "logging_target_bucket":  None,
                }
            raise

    def _fetch_bucket_lifecycle(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch lifecycle rule count.

        Returns lifecycle_rule_count=N, or 0 if no rules configured.
        403 → lifecycle_rule_count=None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_lifecycle_configuration, Bucket=bucket_name
            )
            rules = response.get("Rules") or []
            return {"lifecycle_rule_count": len(rules)}
        except ConnectorError as exc:
            msg = str(exc)
            if "NoSuchLifecycleConfiguration" in msg:
                return {"lifecycle_rule_count": 0}
            if exc.status_code == 403:
                warnings.append("s3_lifecycle_unavailable")
                return {"lifecycle_rule_count": None}
            raise

    def _fetch_bucket_tags(
        self, client: Any, bucket_name: str, warnings: list[str]
    ) -> dict:
        """Fetch bucket tag keys (not values — values may be sensitive).

        Returns tag_keys as a sorted list of key strings, or None if no tags.
        403 → tag_keys=None, warning added.
        """
        try:
            response = self._call_aws(
                client.get_bucket_tagging, Bucket=bucket_name
            )
            tag_set = response.get("TagSet") or []
            keys = sorted(tag["Key"] for tag in tag_set if "Key" in tag)
            return {"tag_keys": keys if keys else None}
        except ConnectorError as exc:
            msg = str(exc)
            if "NoSuchTagSet" in msg:
                return {"tag_keys": None}
            if exc.status_code == 403:
                warnings.append("s3_tagging_unavailable")
                return {"tag_keys": None}
            raise
