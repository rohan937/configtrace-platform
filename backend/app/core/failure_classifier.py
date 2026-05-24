"""Sync failure classification — M32.

Maps Python exceptions raised during a sync to structured, machine-readable
failure categories, provider-specific error codes, and user-facing remediation
hints.

Design goals
------------
* Machine-readable: ``failure_category`` and ``error_code`` are stable
  identifiers that the frontend can use to render tailored error UIs.
* User-friendly: ``recommended_action`` is plain English shown directly in the
  UI so the user knows what to do.
* Provider-aware: the same exception type (e.g. ``AuthenticationError``) maps
  to a different error code depending on whether the integration uses a GitHub
  PAT, a GitHub App, or a Cloudflare token.
* Safe: exception messages are NOT included in returned strings — the caller
  passes the raw ``error_message`` separately so we never risk leaking a token
  or private key via the classification fields.

Failure categories (stable, machine-readable)
---------------------------------------------
  authentication        — credentials rejected (401/403)
  resource_missing      — target resource deleted/moved (404)
  provider_unavailable  — provider returned 5xx
  rate_limited          — provider enforced rate limiting (429)
  network               — transport-level failure (no HTTP response received)
  config_error          — server misconfiguration (bad private key, missing env)
  internal_error        — unexpected Python error
  unknown               — unclassified

Error codes (provider-specific, stable)
----------------------------------------
GitHub (PAT):
  github_token_revoked, github_repo_not_found, github_api_unavailable
GitHub App:
  github_app_uninstalled, github_repo_not_found, github_api_unavailable
Cloudflare:
  cloudflare_token_revoked, cloudflare_zone_not_found, cloudflare_api_unavailable
Vercel:
  vercel_token_revoked, vercel_project_not_found, vercel_api_unavailable
Stripe:
  stripe_key_revoked, stripe_permissions_insufficient, stripe_account_not_found, stripe_api_unavailable
AWS (whole-integration failures, via classify_failure):
  aws_credentials_invalid, aws_access_denied, aws_resource_not_found, aws_api_unavailable
AWS EC2/VPC (partial/per-API failures, via classify_aws_ec2_failure):
  aws_ec2_access_denied, aws_ec2_region_disabled, aws_ec2_rate_limited, aws_ec2_api_unavailable
  aws_security_groups_unavailable, aws_security_group_rules_unavailable
  aws_vpc_unavailable, aws_subnets_unavailable, aws_route_tables_unavailable
  aws_internet_gateways_unavailable, aws_network_acls_unavailable
AWS IAM (partial/per-API failures, via classify_aws_iam_failure):
  aws_iam_access_denied, aws_iam_rate_limited, aws_iam_api_unavailable
  aws_iam_users_unavailable, aws_iam_roles_unavailable, aws_iam_groups_unavailable
  aws_iam_policies_unavailable, aws_iam_policy_versions_unavailable
  aws_iam_inline_policies_unavailable, aws_iam_access_keys_unavailable
  aws_iam_mfa_unavailable
AWS Route53 (partial/per-API failures, via classify_aws_route53_failure):
  aws_route53_access_denied, aws_route53_rate_limited, aws_route53_api_unavailable
  aws_route53_hosted_zones_unavailable, aws_route53_records_unavailable
AWS CloudFront (partial/per-API failures, via classify_aws_cloudfront_failure):
  aws_cloudfront_access_denied, aws_cloudfront_rate_limited, aws_cloudfront_api_unavailable
  aws_cloudfront_distributions_unavailable, aws_cloudfront_distribution_config_unavailable
AWS Secrets Manager (partial/per-API failures, via classify_aws_secretsmanager_failure):
  aws_secretsmanager_access_denied, aws_secretsmanager_rate_limited, aws_secretsmanager_api_unavailable
  aws_secretsmanager_list_unavailable, aws_secretsmanager_describe_unavailable
  aws_secretsmanager_versions_unavailable, aws_secretsmanager_policy_unavailable
AWS SSM (partial/per-API failures, via classify_aws_ssm_failure):
  aws_ssm_access_denied, aws_ssm_rate_limited, aws_ssm_api_unavailable
  aws_ssm_describe_parameters_unavailable, aws_ssm_tags_unavailable
Generic:
  rate_limit_exceeded, network_error, config_error, internal_error, unknown
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class FailureClassification:
    """Structured description of a sync failure.

    Attributes:
        category:           Broad, stable category string.
        error_code:         Provider-specific, stable code string.
        recommended_action: Plain-English remediation hint for the user.
    """

    category: str
    error_code: str
    recommended_action: str


# Threshold above which an integration is considered to "need attention".
# Exposed here so tests and the router helper share the same constant.
NEEDS_ATTENTION_THRESHOLD = 3

# How many seconds constitute the failure-alert cooldown period (24 hours).
FAILURE_ALERT_COOLDOWN_SECONDS = 86_400


def classify_failure(
    exc: Exception,
    provider: str,
    credential_type: Optional[str] = None,
) -> FailureClassification:
    """Return a :class:`FailureClassification` for *exc*.

    Args:
        exc:             The exception that caused the sync to fail.
        provider:        ``"cloudflare"`` or ``"github"`` — used to select
                         provider-specific error codes.
        credential_type: ``"github_app"`` or ``"pat"`` (GitHub only) — used
                         to distinguish App-uninstall from token-revoke.
                         Pass ``None`` when not applicable or unknown.

    Returns:
        A :class:`FailureClassification` with stable ``category``,
        ``error_code``, and ``recommended_action`` strings.
    """
    # Import inside function to keep the module importable without the full
    # connector stack (e.g. during unit tests that mock connectors).
    from app.connectors.exceptions import (
        AuthenticationError,
        ConnectorError,
        NetworkError,
        RateLimitError,
    )

    # ── Authentication failures ───────────────────────────────────────────────
    if isinstance(exc, AuthenticationError):
        return _classify_auth(provider, credential_type)

    # ── Rate limiting ─────────────────────────────────────────────────────────
    if isinstance(exc, RateLimitError):
        return FailureClassification(
            category="rate_limited",
            error_code="rate_limit_exceeded",
            recommended_action=(
                "The provider's rate limit was reached. "
                "The next scheduled sync will retry automatically."
            ),
        )

    # ── Network errors (checked BEFORE generic ConnectorError because
    #    NetworkError is a subclass of ConnectorError) ─────────────────────────
    if isinstance(exc, NetworkError):
        return FailureClassification(
            category="network",
            error_code="network_error",
            recommended_action=(
                "A network error prevented the sync from completing. "
                "The next scheduled sync will retry automatically."
            ),
        )

    # ── Generic ConnectorError: inspect status_code ───────────────────────────
    if isinstance(exc, ConnectorError):
        return _classify_connector(exc, provider)

    # ── ValueError: typically a configuration / decoding problem ─────────────
    # Examples: decode_private_key raised ValueError, missing integration row.
    if isinstance(exc, (ValueError, KeyError)):
        return FailureClassification(
            category="config_error",
            error_code="config_error",
            recommended_action=(
                "A server configuration error occurred. "
                "Contact support if the problem persists."
            ),
        )

    # ── RuntimeError: GitHub App JWT or installation token minting ───────────
    if isinstance(exc, RuntimeError):
        # RuntimeError from mint_app_jwt / mint_installation_token
        msg = str(exc).lower()
        if "authentication failed" in msg or "401" in msg or "403" in msg:
            return _classify_auth(provider, credential_type)
        if "installation" in msg and ("not found" in msg or "404" in msg):
            return FailureClassification(
                category="authentication",
                error_code="github_app_uninstalled",
                recommended_action=(
                    "The GitHub App installation was not found. "
                    "Re-install the GitHub App from your integrations page."
                ),
            )
        # Treat remaining RuntimeErrors as provider unavailable
        return FailureClassification(
            category="provider_unavailable",
            error_code=(
                "github_api_unavailable"
                if provider == "github"
                else f"{provider}_api_unavailable"
                if provider
                else "provider_unavailable"
            ),
            recommended_action=(
                "The provider API returned an unexpected error. "
                "The next scheduled sync will retry automatically."
            ),
        )

    # ── Catch-all ─────────────────────────────────────────────────────────────
    return FailureClassification(
        category="unknown",
        error_code="unknown",
        recommended_action=(
            "An unexpected error occurred. "
            "Check the server logs or contact support."
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _classify_auth(
    provider: str, credential_type: Optional[str]
) -> FailureClassification:
    """Return an authentication FailureClassification for the given provider."""
    if provider == "github":
        if credential_type == "github_app":
            return FailureClassification(
                category="authentication",
                error_code="github_app_uninstalled",
                recommended_action=(
                    "The GitHub App installation was revoked or uninstalled. "
                    "Re-install the GitHub App from your integrations page."
                ),
            )
        # PAT path (credential_type == "pat" or None)
        return FailureClassification(
            category="authentication",
            error_code="github_token_revoked",
            recommended_action=(
                "Your GitHub Personal Access Token was revoked or expired. "
                "Reconnect this integration with a new token."
            ),
        )
    if provider == "cloudflare":
        return FailureClassification(
            category="authentication",
            error_code="cloudflare_token_revoked",
            recommended_action=(
                "Your Cloudflare API token was revoked or expired. "
                "Reconnect this integration with a new token."
            ),
        )
    if provider == "vercel":
        return FailureClassification(
            category="authentication",
            error_code="vercel_token_revoked",
            recommended_action=(
                "Your Vercel API token was revoked or expired. "
                "Reconnect this integration with a new token."
            ),
        )
    if provider == "stripe":
        return FailureClassification(
            category="authentication",
            error_code="stripe_key_revoked",
            recommended_action=(
                "Your Stripe API key was revoked or expired. "
                "Reconnect this integration with a new restricted API key."
            ),
        )
    if provider == "aws":
        return FailureClassification(
            category="authentication",
            error_code="aws_credentials_invalid",
            recommended_action=(
                "The AWS access key ID or secret access key is invalid or has been revoked. "
                "Verify the credentials in the AWS IAM console and reconnect this integration "
                "with a valid read-only key."
            ),
        )
    # Unknown provider
    return FailureClassification(
        category="authentication",
        error_code="credentials_rejected",
        recommended_action=(
            "The provider rejected the stored credentials. "
            "Reconnect this integration with fresh credentials."
        ),
    )


def _classify_connector(exc: "ConnectorError", provider: str) -> FailureClassification:
    """Classify a generic ConnectorError by its HTTP status_code."""
    status = exc.status_code

    # ── 403: permissions error ────────────────────────────────────────────────
    # For Stripe, 403 means the restricted key no longer has read access to any
    # monitored resource.  This is treated as an authentication/permission issue
    # rather than a transient error, so the user must take action.
    if status == 403:
        if provider == "aws":
            return FailureClassification(
                category="authentication",
                error_code="aws_access_denied",
                recommended_action=(
                    "The AWS IAM credentials do not have permission to call required "
                    "read-only APIs. Ensure the IAM user has at minimum: "
                    "sts:GetCallerIdentity (required). "
                    "For EC2/VPC network monitoring (all optional): "
                    "ec2:DescribeRegions, ec2:DescribeSecurityGroups, ec2:DescribeVpcs, "
                    "ec2:DescribeSubnets, ec2:DescribeRouteTables, "
                    "ec2:DescribeInternetGateways, ec2:DescribeNetworkAcls. "
                    "For S3 monitoring (all optional): s3:ListAllMyBuckets, "
                    "s3:GetBucketLocation, s3:GetPublicAccessBlock, "
                    "s3:GetBucketPolicy, s3:GetBucketPolicyStatus, s3:GetBucketAcl, "
                    "s3:GetEncryptionConfiguration, s3:GetBucketVersioning, "
                    "s3:GetBucketLogging, s3:GetLifecycleConfiguration, "
                    "s3:GetBucketTagging. "
                    "Missing optional permissions are recorded as warnings rather "
                    "than failures. "
                    "Reconnect after updating the IAM policy."
                ),
            )
        if provider == "stripe":
            return FailureClassification(
                category="authentication",
                error_code="stripe_permissions_insufficient",
                recommended_action=(
                    "The Stripe API key no longer has read access to any monitored resource. "
                    "Update the restricted key permissions (grant read access to at least one "
                    "of: Webhook Endpoints, Payment Method Configurations, or Events), "
                    "or reconnect with a valid key."
                ),
            )
        # Other providers: treat as auth failure.
        return _classify_auth(provider, None)

    if status == 404:
        if provider == "github":
            return FailureClassification(
                category="resource_missing",
                error_code="github_repo_not_found",
                recommended_action=(
                    "The GitHub repository was not found. "
                    "Verify it still exists and the integration has access."
                ),
            )
        if provider == "cloudflare":
            return FailureClassification(
                category="resource_missing",
                error_code="cloudflare_zone_not_found",
                recommended_action=(
                    "The Cloudflare zone was not found. "
                    "Verify the Zone ID is correct."
                ),
            )
        if provider == "vercel":
            return FailureClassification(
                category="resource_missing",
                error_code="vercel_project_not_found",
                recommended_action=(
                    "The Vercel project was not found. "
                    "Verify the Project ID is correct."
                ),
            )
        if provider == "stripe":
            return FailureClassification(
                category="resource_missing",
                error_code="stripe_account_not_found",
                recommended_action=(
                    "The Stripe account resource was not found. "
                    "Verify the API key has access to this account."
                ),
            )
        if provider == "aws":
            return FailureClassification(
                category="resource_missing",
                error_code="aws_resource_not_found",
                recommended_action=(
                    "The AWS resource was not found. "
                    "Verify the AWS account and region configuration."
                ),
            )
        return FailureClassification(
            category="resource_missing",
            error_code="resource_not_found",
            recommended_action=(
                "The monitored resource was not found. "
                "Verify it still exists and the integration has access."
            ),
        )

    if status is not None and status >= 500:
        if provider == "github":
            code = "github_api_unavailable"
        elif provider == "cloudflare":
            code = "cloudflare_api_unavailable"
        elif provider == "vercel":
            code = "vercel_api_unavailable"
        elif provider == "stripe":
            code = "stripe_api_unavailable"
        elif provider == "aws":
            code = "aws_api_unavailable"
        else:
            code = "provider_unavailable"
        return FailureClassification(
            category="provider_unavailable",
            error_code=code,
            recommended_action=(
                "The provider API is temporarily unavailable. "
                "The next scheduled sync will retry automatically."
            ),
        )

    # Other ConnectorErrors (unexpected status codes, parse errors, etc.)
    return FailureClassification(
        category="internal_error",
        error_code="internal_error",
        recommended_action=(
            "An unexpected error occurred while communicating with the provider. "
            "Check the server logs for details."
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# AWS EC2/VPC partial-failure classification — M38
# ─────────────────────────────────────────────────────────────────────────────

# Maps EC2 API name to the stable error_code produced when that API fails for
# a reason other than auth, rate-limiting, or a transient 5xx.
_AWS_EC2_API_CODE: dict[str, str] = {
    "DescribeSecurityGroups":     "aws_security_groups_unavailable",
    "DescribeSecurityGroupRules": "aws_security_group_rules_unavailable",
    "DescribeVpcs":               "aws_vpc_unavailable",
    "DescribeSubnets":            "aws_subnets_unavailable",
    "DescribeRouteTables":        "aws_route_tables_unavailable",
    "DescribeInternetGateways":   "aws_internet_gateways_unavailable",
    "DescribeNetworkAcls":        "aws_network_acls_unavailable",
}

# Recommended action returned for all per-API unavailability codes.
_EC2_PARTIAL_ACTION = (
    "ConfigTrace could not read optional EC2/VPC network metadata; "
    "other AWS checks may still work."
)

# Recommended action returned for EC2 access-denied errors.
_EC2_ACCESS_DENIED_ACTION = (
    "Grant ConfigTrace read-only EC2/VPC describe permissions. "
    "Required for network monitoring: ec2:DescribeSecurityGroups, ec2:DescribeVpcs, "
    "ec2:DescribeSubnets, ec2:DescribeRouteTables, ec2:DescribeInternetGateways, "
    "ec2:DescribeNetworkAcls. "
    "Missing permissions are skipped; other AWS checks may still work."
)


def classify_aws_ec2_failure(
    api_name: str,
    exc: Exception,
) -> FailureClassification:
    """Classify a partial EC2/VPC sync failure (per-API, per-region).

    Unlike :func:`classify_failure` (which classifies whole-integration
    failures), this function is used when an individual EC2 describe call
    fails inside ``_fetch_network_resources``.  The overall sync continues;
    the result is logged as a structured warning.

    Args:
        api_name: The EC2 API name that failed (e.g. ``"DescribeSecurityGroups"``).
        exc:      The exception raised by the failed call.

    Returns:
        A :class:`FailureClassification` with a stable ``error_code`` and a
        human-readable ``recommended_action``.  Credentials are never included
        in the returned strings.
    """
    from app.connectors.exceptions import (
        AuthenticationError,
        ConnectorError,
        NetworkError,
        RateLimitError,
    )

    # ── 403 / credentials rejected — check before api_name specificity ────────
    if isinstance(exc, AuthenticationError) or (
        isinstance(exc, ConnectorError) and exc.status_code == 403
    ):
        return FailureClassification(
            category="authentication",
            error_code="aws_ec2_access_denied",
            recommended_action=_EC2_ACCESS_DENIED_ACTION,
        )

    # ── Rate limiting ─────────────────────────────────────────────────────────
    if isinstance(exc, RateLimitError):
        return FailureClassification(
            category="rate_limited",
            error_code="aws_ec2_rate_limited",
            recommended_action=(
                "AWS throttled EC2/VPC describe calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    # ── Network error ─────────────────────────────────────────────────────────
    if isinstance(exc, NetworkError):
        return FailureClassification(
            category="network",
            error_code="network_error",
            recommended_action=(
                "A network error prevented EC2/VPC describe calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    # ── 5xx: EC2 API temporarily unavailable ──────────────────────────────────
    if isinstance(exc, ConnectorError) and exc.status_code is not None and exc.status_code >= 500:
        return FailureClassification(
            category="provider_unavailable",
            error_code="aws_ec2_api_unavailable",
            recommended_action=(
                "The EC2/VPC API returned a server error. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    # ── Region disabled or other ConnectorError ───────────────────────────────
    # If this is called for a region-client creation failure (no api_name
    # known), or for a region-opt-in error, classify as region-disabled.
    if isinstance(exc, ConnectorError) and not api_name:
        return FailureClassification(
            category="provider_unavailable",
            error_code="aws_ec2_region_disabled",
            recommended_action="Verify the selected AWS region is enabled in the AWS console.",
        )

    # ── Per-API codes for unexpected/generic failures ─────────────────────────
    error_code = _AWS_EC2_API_CODE.get(api_name, "aws_ec2_api_unavailable")
    return FailureClassification(
        category="provider_unavailable",
        error_code=error_code,
        recommended_action=_EC2_PARTIAL_ACTION,
    )


# ─────────────────────────────────────────────────────────────────────────────
# AWS IAM partial-failure classification — M39
# ─────────────────────────────────────────────────────────────────────────────

# Maps IAM API name to the stable error_code produced when that API fails for
# a reason other than auth, rate-limiting, or a transient 5xx.
_AWS_IAM_API_CODE: dict[str, str] = {
    "ListUsers":                "aws_iam_users_unavailable",
    "GetUser":                  "aws_iam_users_unavailable",
    "ListRoles":                "aws_iam_roles_unavailable",
    "GetRole":                  "aws_iam_roles_unavailable",
    "ListGroups":               "aws_iam_groups_unavailable",
    "GetGroup":                 "aws_iam_groups_unavailable",
    "ListPolicies":             "aws_iam_policies_unavailable",
    "GetPolicy":                "aws_iam_policies_unavailable",
    "GetPolicyVersion":         "aws_iam_policy_versions_unavailable",
    "ListPolicyVersions":       "aws_iam_policy_versions_unavailable",
    "GetRolePolicy":            "aws_iam_inline_policies_unavailable",
    "GetUserPolicy":            "aws_iam_inline_policies_unavailable",
    "GetGroupPolicy":           "aws_iam_inline_policies_unavailable",
    "ListRolePolicies":         "aws_iam_inline_policies_unavailable",
    "ListUserPolicies":         "aws_iam_inline_policies_unavailable",
    "ListGroupPolicies":        "aws_iam_inline_policies_unavailable",
    "ListAccessKeys":           "aws_iam_access_keys_unavailable",
    "GetAccessKeyLastUsed":     "aws_iam_access_keys_unavailable",
    "ListMFADevices":           "aws_iam_mfa_unavailable",
    "GetAccountSummary":        "aws_iam_api_unavailable",
    "GetAccountPasswordPolicy": "aws_iam_api_unavailable",
    "ListAttachedUserPolicies": "aws_iam_users_unavailable",
    "ListAttachedRolePolicies": "aws_iam_roles_unavailable",
    "ListAttachedGroupPolicies": "aws_iam_groups_unavailable",
    "ListOpenIDConnectProviders": "aws_iam_api_unavailable",
    "GetOpenIDConnectProvider": "aws_iam_api_unavailable",
    "ListSAMLProviders":        "aws_iam_api_unavailable",
    "GetSAMLProvider":          "aws_iam_api_unavailable",
}

# Recommended action returned for all per-API IAM unavailability codes.
_IAM_PARTIAL_ACTION = (
    "ConfigTrace could not read optional IAM metadata; "
    "other AWS checks may still work."
)

# Recommended action returned for IAM access-denied errors.
_IAM_ACCESS_DENIED_ACTION = (
    "Grant ConfigTrace read-only IAM permissions. "
    "Required for IAM monitoring: iam:ListUsers, iam:ListRoles, iam:ListGroups, "
    "iam:ListPolicies, iam:GetAccountSummary, iam:GetAccountPasswordPolicy. "
    "Missing permissions are skipped; other AWS checks may still work."
)


def classify_aws_iam_failure(
    api_name: str,
    exc: Exception,
) -> FailureClassification:
    """Classify a partial IAM sync failure (per-API).

    Unlike :func:`classify_failure` (which classifies whole-integration
    failures), this function is used when an individual IAM API call
    fails inside ``_fetch_iam_resources``.  The overall sync continues;
    the result is logged as a structured warning.

    Args:
        api_name: The IAM API name that failed (e.g. ``"ListUsers"``).
        exc:      The exception raised by the failed call.

    Returns:
        A :class:`FailureClassification` with a stable ``error_code`` and a
        human-readable ``recommended_action``.  Credentials are never included
        in the returned strings.
    """
    from app.connectors.exceptions import (
        AuthenticationError,
        ConnectorError,
        NetworkError,
        RateLimitError,
    )

    # ── 403 / credentials rejected ────────────────────────────────────────────
    if isinstance(exc, AuthenticationError) or (
        isinstance(exc, ConnectorError) and exc.status_code == 403
    ):
        return FailureClassification(
            category="authentication",
            error_code="aws_iam_access_denied",
            recommended_action=_IAM_ACCESS_DENIED_ACTION,
        )

    # ── Rate limiting ─────────────────────────────────────────────────────────
    if isinstance(exc, RateLimitError):
        return FailureClassification(
            category="rate_limited",
            error_code="aws_iam_rate_limited",
            recommended_action=(
                "AWS throttled IAM API calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    # ── Network error ─────────────────────────────────────────────────────────
    if isinstance(exc, NetworkError):
        return FailureClassification(
            category="network",
            error_code="network_error",
            recommended_action=(
                "A network error prevented IAM API calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    # ── 5xx: IAM API temporarily unavailable ──────────────────────────────────
    if isinstance(exc, ConnectorError) and exc.status_code is not None and exc.status_code >= 500:
        return FailureClassification(
            category="provider_unavailable",
            error_code="aws_iam_api_unavailable",
            recommended_action=(
                "The IAM API returned a server error. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    # ── Per-API codes for unexpected/generic failures ─────────────────────────
    error_code = _AWS_IAM_API_CODE.get(api_name, "aws_iam_api_unavailable")
    return FailureClassification(
        category="provider_unavailable",
        error_code=error_code,
        recommended_action=_IAM_PARTIAL_ACTION,
    )


# ── M40: Route53 per-API failure classification ───────────────────────────────

_AWS_ROUTE53_API_CODE: dict[str, str] = {
    "ListHostedZones":          "aws_route53_hosted_zones_unavailable",
    "GetHostedZone":            "aws_route53_hosted_zones_unavailable",
    "ListResourceRecordSets":   "aws_route53_records_unavailable",
    "ListTagsForResource":      "aws_route53_api_unavailable",
    "ListQueryLoggingConfigs":  "aws_route53_api_unavailable",
}

_ROUTE53_PARTIAL_ACTION = (
    "ConfigTrace could not read optional Route53 metadata; "
    "other AWS checks may still work."
)

_ROUTE53_ACCESS_DENIED_ACTION = (
    "Grant ConfigTrace read-only Route53 permissions. "
    "Required: route53:ListHostedZones, route53:GetHostedZone, "
    "route53:ListResourceRecordSets. "
    "Missing permissions are skipped; other AWS checks may still work."
)


def classify_aws_route53_failure(
    api_name: str,
    exc: Exception,
) -> "FailureClassification":
    """Classify a partial Route53 sync failure (per-API).

    Used when an individual Route53 API call fails inside
    ``_fetch_route53_resources``.  The overall sync continues; the result
    is logged as a structured warning.

    Args:
        api_name: The Route53 API name that failed (e.g. ``"ListHostedZones"``).
        exc:      The exception raised by the failed call.

    Returns:
        A :class:`FailureClassification` with a stable ``error_code``.
        Credentials are never included in returned strings.
    """
    from app.connectors.exceptions import (
        AuthenticationError,
        ConnectorError,
        NetworkError,
        RateLimitError,
    )

    if isinstance(exc, AuthenticationError) or (
        isinstance(exc, ConnectorError) and exc.status_code == 403
    ):
        return FailureClassification(
            category="authentication",
            error_code="aws_route53_access_denied",
            recommended_action=_ROUTE53_ACCESS_DENIED_ACTION,
        )

    if isinstance(exc, RateLimitError):
        return FailureClassification(
            category="rate_limited",
            error_code="aws_route53_rate_limited",
            recommended_action=(
                "AWS throttled Route53 API calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    if isinstance(exc, NetworkError):
        return FailureClassification(
            category="network",
            error_code="network_error",
            recommended_action=(
                "A network error prevented Route53 API calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    if isinstance(exc, ConnectorError) and exc.status_code is not None and exc.status_code >= 500:
        return FailureClassification(
            category="provider_unavailable",
            error_code="aws_route53_api_unavailable",
            recommended_action=(
                "The Route53 API returned a server error. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    error_code = _AWS_ROUTE53_API_CODE.get(api_name, "aws_route53_api_unavailable")
    return FailureClassification(
        category="provider_unavailable",
        error_code=error_code,
        recommended_action=_ROUTE53_PARTIAL_ACTION,
    )


# ── M40: CloudFront per-API failure classification ────────────────────────────

_AWS_CLOUDFRONT_API_CODE: dict[str, str] = {
    "ListDistributions":        "aws_cloudfront_distributions_unavailable",
    "GetDistribution":          "aws_cloudfront_distributions_unavailable",
    "GetDistributionConfig":    "aws_cloudfront_distribution_config_unavailable",
    "ListTagsForResource":      "aws_cloudfront_api_unavailable",
}

_CLOUDFRONT_PARTIAL_ACTION = (
    "ConfigTrace could not read optional CloudFront metadata; "
    "other AWS checks may still work."
)

_CLOUDFRONT_ACCESS_DENIED_ACTION = (
    "Grant ConfigTrace read-only CloudFront permissions. "
    "Required: cloudfront:ListDistributions, cloudfront:GetDistributionConfig. "
    "Missing permissions are skipped; other AWS checks may still work."
)


def classify_aws_cloudfront_failure(
    api_name: str,
    exc: Exception,
) -> "FailureClassification":
    """Classify a partial CloudFront sync failure (per-API).

    Used when an individual CloudFront API call fails inside
    ``_fetch_cloudfront_resources``.  The overall sync continues.

    Args:
        api_name: The CloudFront API name that failed.
        exc:      The exception raised by the failed call.

    Returns:
        A :class:`FailureClassification` with a stable ``error_code``.
    """
    from app.connectors.exceptions import (
        AuthenticationError,
        ConnectorError,
        NetworkError,
        RateLimitError,
    )

    if isinstance(exc, AuthenticationError) or (
        isinstance(exc, ConnectorError) and exc.status_code == 403
    ):
        return FailureClassification(
            category="authentication",
            error_code="aws_cloudfront_access_denied",
            recommended_action=_CLOUDFRONT_ACCESS_DENIED_ACTION,
        )

    if isinstance(exc, RateLimitError):
        return FailureClassification(
            category="rate_limited",
            error_code="aws_cloudfront_rate_limited",
            recommended_action=(
                "AWS throttled CloudFront API calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    if isinstance(exc, NetworkError):
        return FailureClassification(
            category="network",
            error_code="network_error",
            recommended_action=(
                "A network error prevented CloudFront API calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    if isinstance(exc, ConnectorError) and exc.status_code is not None and exc.status_code >= 500:
        return FailureClassification(
            category="provider_unavailable",
            error_code="aws_cloudfront_api_unavailable",
            recommended_action=(
                "The CloudFront API returned a server error. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    error_code = _AWS_CLOUDFRONT_API_CODE.get(api_name, "aws_cloudfront_api_unavailable")
    return FailureClassification(
        category="provider_unavailable",
        error_code=error_code,
        recommended_action=_CLOUDFRONT_PARTIAL_ACTION,
    )


# ── M41: Secrets Manager per-API failure classification ──────────────────────

_AWS_SECRETSMANAGER_API_CODE: dict[str, str] = {
    "ListSecrets":              "aws_secretsmanager_list_unavailable",
    "DescribeSecret":           "aws_secretsmanager_describe_unavailable",
    "ListSecretVersionIds":     "aws_secretsmanager_versions_unavailable",
    "GetResourcePolicy":        "aws_secretsmanager_policy_unavailable",
}

_SECRETSMANAGER_PARTIAL_ACTION = (
    "ConfigTrace could not read optional Secrets Manager metadata; "
    "other AWS checks may still work."
)

_SECRETSMANAGER_ACCESS_DENIED_ACTION = (
    "Grant ConfigTrace read-only Secrets Manager permissions. "
    "Required: secretsmanager:ListSecrets, secretsmanager:DescribeSecret, "
    "secretsmanager:ListSecretVersionIds, secretsmanager:GetResourcePolicy. "
    "ConfigTrace never calls GetSecretValue. "
    "Missing permissions are skipped; other AWS checks may still work."
)


def classify_aws_secretsmanager_failure(
    api_name: str,
    exc: Exception,
) -> "FailureClassification":
    """Classify a partial Secrets Manager sync failure (per-API).

    Used when an individual Secrets Manager API call fails inside
    ``_fetch_secrets_in_region``.  The overall sync continues; the result
    is logged as a structured warning.

    Args:
        api_name: The Secrets Manager API name (e.g. ``"ListSecrets"``).
        exc:      The exception raised by the failed call.

    Returns:
        A :class:`FailureClassification` with a stable ``error_code``.
        Credentials and secret values are never included in returned strings.
    """
    from app.connectors.exceptions import (
        AuthenticationError,
        ConnectorError,
        NetworkError,
        RateLimitError,
    )

    if isinstance(exc, AuthenticationError) or (
        isinstance(exc, ConnectorError) and exc.status_code == 403
    ):
        return FailureClassification(
            category="authentication",
            error_code="aws_secretsmanager_access_denied",
            recommended_action=_SECRETSMANAGER_ACCESS_DENIED_ACTION,
        )

    if isinstance(exc, RateLimitError):
        return FailureClassification(
            category="rate_limited",
            error_code="aws_secretsmanager_rate_limited",
            recommended_action=(
                "AWS throttled Secrets Manager API calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    if isinstance(exc, NetworkError):
        return FailureClassification(
            category="network",
            error_code="network_error",
            recommended_action=(
                "A network error prevented Secrets Manager API calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    if isinstance(exc, ConnectorError) and exc.status_code is not None and exc.status_code >= 500:
        return FailureClassification(
            category="provider_unavailable",
            error_code="aws_secretsmanager_api_unavailable",
            recommended_action=(
                "The Secrets Manager API returned a server error. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    error_code = _AWS_SECRETSMANAGER_API_CODE.get(api_name, "aws_secretsmanager_api_unavailable")
    return FailureClassification(
        category="provider_unavailable",
        error_code=error_code,
        recommended_action=_SECRETSMANAGER_PARTIAL_ACTION,
    )


# ── M41: SSM Parameter Store per-API failure classification ──────────────────

_AWS_SSM_API_CODE: dict[str, str] = {
    "DescribeParameters":       "aws_ssm_describe_parameters_unavailable",
    "ListTagsForResource":      "aws_ssm_tags_unavailable",
}

_SSM_PARTIAL_ACTION = (
    "ConfigTrace could not read optional SSM Parameter metadata; "
    "other AWS checks may still work."
)

_SSM_ACCESS_DENIED_ACTION = (
    "Grant ConfigTrace read-only SSM permissions. "
    "Required: ssm:DescribeParameters. "
    "ConfigTrace never calls GetParameter, GetParameters, or GetParameterHistory. "
    "Missing permissions are skipped; other AWS checks may still work."
)


def classify_aws_ssm_failure(
    api_name: str,
    exc: Exception,
) -> "FailureClassification":
    """Classify a partial SSM Parameter Store sync failure (per-API).

    Used when an individual SSM API call fails inside
    ``_fetch_ssm_in_region``.  The overall sync continues; the result
    is logged as a structured warning.

    Args:
        api_name: The SSM API name (e.g. ``"DescribeParameters"``).
        exc:      The exception raised by the failed call.

    Returns:
        A :class:`FailureClassification` with a stable ``error_code``.
        Parameter values are never included in returned strings.
    """
    from app.connectors.exceptions import (
        AuthenticationError,
        ConnectorError,
        NetworkError,
        RateLimitError,
    )

    if isinstance(exc, AuthenticationError) or (
        isinstance(exc, ConnectorError) and exc.status_code == 403
    ):
        return FailureClassification(
            category="authentication",
            error_code="aws_ssm_access_denied",
            recommended_action=_SSM_ACCESS_DENIED_ACTION,
        )

    if isinstance(exc, RateLimitError):
        return FailureClassification(
            category="rate_limited",
            error_code="aws_ssm_rate_limited",
            recommended_action=(
                "AWS throttled SSM API calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    if isinstance(exc, NetworkError):
        return FailureClassification(
            category="network",
            error_code="network_error",
            recommended_action=(
                "A network error prevented SSM API calls. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    if isinstance(exc, ConnectorError) and exc.status_code is not None and exc.status_code >= 500:
        return FailureClassification(
            category="provider_unavailable",
            error_code="aws_ssm_api_unavailable",
            recommended_action=(
                "The SSM API returned a server error. "
                "ConfigTrace will retry on the next sync."
            ),
        )

    error_code = _AWS_SSM_API_CODE.get(api_name, "aws_ssm_api_unavailable")
    return FailureClassification(
        category="provider_unavailable",
        error_code=error_code,
        recommended_action=_SSM_PARTIAL_ACTION,
    )
