"""AWS connector — M36: Foundation + Account Inventory.

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
    Lightweight placeholder — lists which surfaces are actively monitored
    (M36: account_inventory only) and which are planned for future milestones.

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

Future extension
----------------
Add new methods to AWSConnector (list_s3_buckets, etc.) for each new
AWS milestone. The _make_client() and _call_aws() helpers provide
consistent error handling for all methods.
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
        """Fetch all M36 AWS account/inventory records.

        Returns a flat list of normalized records:
        - 1 × aws_account_identity
        - N × aws_region (one per selected region)
        - 1 × aws_service_inventory (placeholder)

        All resources use fail-soft behavior for optional endpoints.
        The account identity is the only required call; a 403 on account
        identity propagates as AuthenticationError because it means the
        credentials cannot even identify the account.

        SECURITY: Credentials are never included in returned records.
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

        # 3. Service inventory placeholder
        inventory_record = self._fetch_service_inventory(credentials)
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

    def _fetch_service_inventory(self, credentials: dict) -> dict:
        """Return a lightweight service inventory placeholder record.

        Records which surfaces are actively monitored in M36 and which are
        planned for future milestones. This record allows diff tracking to
        detect when the set of selected regions changes.
        """
        selected = self._selected_regions(credentials)
        return {
            "record_type":      AWS_SERVICE_INVENTORY,
            "record_id":        "service_inventory",
            "name":             "AWS Service Inventory",
            "selected_regions": selected,
            "enabled_surfaces": ["account_inventory"],
            "future_surfaces": [
                "s3", "security_groups", "iam", "route53", "cloudfront",
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
