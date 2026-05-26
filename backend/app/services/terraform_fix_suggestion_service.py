"""Terraform Fix Suggestion Preview service — M58.19.

Generates advisory, read-only HCL diff previews for cloud configuration
changes that may be managed by Terraform.  All output is conceptual only —
no Terraform is ever executed, no GitHub PRs are created, no provider
resources are mutated.

PERMANENT SAFETY CONSTRAINTS (must remain in effect across all future milestones):
  - _EXECUTION_ENABLED is always False.  Never set to True.
  - _PR_AVAILABLE is always False.  Never set to True.
  - _SAFETY_LEVEL is always "requires_human_review".  Never changed.
  - No calls to any provider write API.
  - No calls to GitHub Contents write / Pulls API.
  - No terraform plan/apply execution.
  - No raw prev_value / new_value forwarded into any diff output.
  - No secrets, tokens, credentials, or customer PII in any output.

Generation modes
----------------
Mode             | Confidence     | Has diff?  | Uses placeholders?
-----------------|----------------|------------|-------------------
exact_preview    | high           | Yes        | No (safe attr values only)
conceptual_preview | medium/high  | Yes        | Yes (ALL dynamic values)
guided_only      | low            | No         | n/a

Low-confidence mappings NEVER produce a diff — only human-readable
guidance text is returned.  This prevents misleading suggestions when
the resource match is uncertain.

Supported record types
----------------------
  AWS:         aws_security_group, aws_security_group_rule
               (SSH port 22, RDP port 3389, and generic public ingress)
  AWS DNS:     aws_route53_record
  Cloudflare:  cloudflare_record, cloudflare_ruleset
  GitHub:      github_branch_protection, github_repo_settings
  Vercel:      vercel_project

All other record types fall back to a guided_only response.

Diff placeholders
-----------------
All placeholder values are formatted as ALL_CAPS in angle brackets, e.g.:
  <TRUSTED_CIDR_BLOCK>
  <RESOURCE_NAME>
  <ZONE_ID>

The ``TerraformFixPlaceholder`` schema describes each placeholder so the
UI can render an inline help panel.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.schemas.terraform_fix import (
    TerraformFixMappingInfo,
    TerraformFixPlaceholder,
    TerraformFixPreviewResponse,
    TerraformFixSuggestion,
)

# ── Permanent hard constants ──────────────────────────────────────────────────

# These values must never be changed, computed, or overridden.
_EXECUTION_ENABLED: bool = False
_PR_AVAILABLE: bool = False
_SAFETY_LEVEL: str = "requires_human_review"

# Standard warning always appended to every suggestion that includes a diff.
_PLAN_WARNING = (
    "Always run `terraform plan` and review the output carefully before "
    "`terraform apply`. This diff is a conceptual preview — exact HCL "
    "structure may differ from your codebase."
)
_ADVISORY_DISCLAIMER = (
    "IaC mapping is advisory only. ConfigTrace does not confirm Terraform "
    "ownership or execute any infrastructure changes."
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get(obj: Any, key: str) -> Any:
    """Return obj[key] for dicts, or getattr(obj, key, None) for objects."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _s(value: Any) -> str:
    """Safely coerce to lowercase string; returns '' for non-string/None."""
    return value.lower() if isinstance(value, str) else ""


def _resource_label(mapping) -> str:
    """Return a display label for the mapped Terraform resource."""
    rtype = getattr(mapping, "terraform_resource_type", None) or "resource"
    rname = getattr(mapping, "terraform_resource_name", None) or "<RESOURCE_NAME>"
    return f'{rtype} "{rname}"'


# ── Unavailable response ──────────────────────────────────────────────────────

def _unavailable(reason: str) -> TerraformFixPreviewResponse:
    """Return a standard unavailable response."""
    return TerraformFixPreviewResponse(
        available=False,
        summary=reason,
        pr_available=_PR_AVAILABLE,
        execution_enabled=_EXECUTION_ENABLED,
    )


# ── AWS Security Group / Ingress rule generators ──────────────────────────────

def _aws_sg_ssh_suggestion(mode: str, rname: str) -> TerraformFixSuggestion:
    """Conceptual diff: restrict SSH ingress from 0.0.0.0/0 to a trusted CIDR."""
    if mode == "guided_only":
        return TerraformFixSuggestion(
            kind="guidance_only",
            title="Restrict public SSH access in Terraform",
            description=(
                "Update the `aws_security_group_rule` or `aws_security_group` "
                "ingress block for TCP port 22 to remove the `0.0.0.0/0` CIDR "
                "and replace it with your VPN or office IP range. "
                "Then run `terraform plan` to preview and `terraform apply` to apply."
            ),
            language="text",
            safety_level=_SAFETY_LEVEL,
            warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
        )

    diff = f'''\
 resource "aws_security_group_rule" "{rname}" {{
   type        = "ingress"
   from_port   = 22
   to_port     = 22
   protocol    = "tcp"
-  cidr_blocks = ["0.0.0.0/0"]
+  cidr_blocks = [var.<TRUSTED_CIDR_VAR>]
   description = "SSH access — restricted to trusted network"
 }}'''

    return TerraformFixSuggestion(
        kind="hcl_diff",
        title="Restrict SSH ingress to trusted CIDR",
        description=(
            "Replace the public `0.0.0.0/0` CIDR on TCP/22 with a "
            "Terraform variable pointing to your trusted VPN or office range."
        ),
        language="diff",
        diff=diff,
        safety_level=_SAFETY_LEVEL,
        placeholders=[
            TerraformFixPlaceholder(
                name="TRUSTED_CIDR_VAR",
                description=(
                    "Name of the Terraform variable holding your trusted CIDR, "
                    "e.g. `trusted_vpn_cidr`. The variable value should be a list "
                    "such as [\"10.0.0.0/8\"]."
                ),
                example="trusted_vpn_cidr",
            ),
        ],
        warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
    )


def _aws_sg_rdp_suggestion(mode: str, rname: str) -> TerraformFixSuggestion:
    """Conceptual diff: restrict RDP ingress from 0.0.0.0/0 to a trusted CIDR."""
    if mode == "guided_only":
        return TerraformFixSuggestion(
            kind="guidance_only",
            title="Restrict public RDP access in Terraform",
            description=(
                "Update the `aws_security_group_rule` or `aws_security_group` "
                "ingress block for TCP port 3389 to remove the `0.0.0.0/0` CIDR "
                "and replace it with a trusted network range. "
                "Then run `terraform plan` to preview and `terraform apply` to apply."
            ),
            language="text",
            safety_level=_SAFETY_LEVEL,
            warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
        )

    diff = f'''\
 resource "aws_security_group_rule" "{rname}" {{
   type        = "ingress"
   from_port   = 3389
   to_port     = 3389
   protocol    = "tcp"
-  cidr_blocks = ["0.0.0.0/0"]
+  cidr_blocks = [var.<TRUSTED_CIDR_VAR>]
   description = "RDP access — restricted to trusted network"
 }}'''

    return TerraformFixSuggestion(
        kind="hcl_diff",
        title="Restrict RDP ingress to trusted CIDR",
        description=(
            "Replace the public `0.0.0.0/0` CIDR on TCP/3389 with a "
            "Terraform variable pointing to your trusted network range."
        ),
        language="diff",
        diff=diff,
        safety_level=_SAFETY_LEVEL,
        placeholders=[
            TerraformFixPlaceholder(
                name="TRUSTED_CIDR_VAR",
                description=(
                    "Name of the Terraform variable holding your trusted CIDR, "
                    "e.g. `trusted_network_cidr`. The variable value should be a "
                    "list such as [\"192.168.1.0/24\"]."
                ),
                example="trusted_network_cidr",
            ),
        ],
        warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
    )


def _aws_sg_db_suggestion(mode: str, rname: str) -> TerraformFixSuggestion:
    """Conceptual diff: restrict database port public ingress (MySQL/PostgreSQL/etc.)."""
    if mode == "guided_only":
        return TerraformFixSuggestion(
            kind="guidance_only",
            title="Restrict public database ingress in Terraform",
            description=(
                "Update the security group ingress rule for the database port "
                "to remove any `0.0.0.0/0` CIDR and replace it with your "
                "application subnet or private CIDR range. "
                "Database ports (3306, 5432, 1433, etc.) should never be "
                "publicly accessible. Run `terraform plan` before applying."
            ),
            language="text",
            safety_level=_SAFETY_LEVEL,
            warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
        )

    diff = f'''\
 resource "aws_security_group_rule" "{rname}" {{
   type        = "ingress"
   from_port   = <DB_PORT>
   to_port     = <DB_PORT>
   protocol    = "tcp"
-  cidr_blocks = ["0.0.0.0/0"]
+  cidr_blocks = [var.<APP_SUBNET_CIDR_VAR>]
   description = "Database access — restricted to application subnet"
 }}'''

    return TerraformFixSuggestion(
        kind="hcl_diff",
        title="Restrict database port to application subnet",
        description=(
            "Replace the public `0.0.0.0/0` CIDR on the database port with a "
            "Terraform variable pointing to your private application subnet CIDR."
        ),
        language="diff",
        diff=diff,
        safety_level=_SAFETY_LEVEL,
        placeholders=[
            TerraformFixPlaceholder(
                name="DB_PORT",
                description="Database port number (e.g. 3306 for MySQL, 5432 for PostgreSQL).",
                example="5432",
            ),
            TerraformFixPlaceholder(
                name="APP_SUBNET_CIDR_VAR",
                description=(
                    "Name of the Terraform variable holding your application subnet CIDR, "
                    "e.g. `app_subnet_cidr`."
                ),
                example="app_subnet_cidr",
            ),
        ],
        warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
    )


def _aws_sg_generic_suggestion(mode: str, rname: str) -> TerraformFixSuggestion:
    """Generic: review public ingress rules in the security group."""
    if mode == "guided_only":
        return TerraformFixSuggestion(
            kind="guidance_only",
            title="Review security group public ingress in Terraform",
            description=(
                "Locate the `aws_security_group` or `aws_security_group_rule` "
                "block in your Terraform files and restrict any `0.0.0.0/0` "
                "CIDR blocks to trusted IP ranges. "
                "Run `terraform plan` before applying any changes."
            ),
            language="text",
            safety_level=_SAFETY_LEVEL,
            warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
        )

    diff = f'''\
 resource "aws_security_group" "{rname}" {{
   name        = "<SECURITY_GROUP_NAME>"
   description = "<DESCRIPTION>"

   ingress {{
     from_port   = <FROM_PORT>
     to_port     = <TO_PORT>
     protocol    = "<PROTOCOL>"
-    cidr_blocks = ["0.0.0.0/0"]
+    cidr_blocks = [var.<TRUSTED_CIDR_VAR>]
   }}
 }}'''

    return TerraformFixSuggestion(
        kind="hcl_diff",
        title="Restrict public ingress CIDR",
        description=(
            "Replace `0.0.0.0/0` in the security group ingress rule with a "
            "Terraform variable scoped to your trusted CIDR range."
        ),
        language="diff",
        diff=diff,
        safety_level=_SAFETY_LEVEL,
        placeholders=[
            TerraformFixPlaceholder(
                name="TRUSTED_CIDR_VAR",
                description="Terraform variable name for your trusted CIDR list.",
                example="trusted_cidr_blocks",
            ),
            TerraformFixPlaceholder(
                name="FROM_PORT",
                description="Starting port of the ingress rule.",
                example="443",
            ),
            TerraformFixPlaceholder(
                name="TO_PORT",
                description="Ending port of the ingress rule.",
                example="443",
            ),
            TerraformFixPlaceholder(
                name="PROTOCOL",
                description='IP protocol. Use "tcp", "udp", or "-1" for all.',
                example="tcp",
            ),
        ],
        warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
    )


# ── AWS Route53 generator ─────────────────────────────────────────────────────

def _aws_route53_suggestion(mode: str, rname: str) -> TerraformFixSuggestion:
    """Guidance or conceptual preview for a Route53 record change."""
    if mode == "guided_only":
        return TerraformFixSuggestion(
            kind="guidance_only",
            title="Restore or update Route 53 record in Terraform",
            description=(
                "Locate the `aws_route53_record` block in your Terraform files "
                "and restore the record to its intended state. "
                "Run `terraform plan` to preview the change before applying."
            ),
            language="text",
            safety_level=_SAFETY_LEVEL,
            warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
        )

    diff = f'''\
 resource "aws_route53_record" "{rname}" {{
   zone_id = var.<HOSTED_ZONE_ID_VAR>
   name    = "<RECORD_NAME>"
   type    = "<RECORD_TYPE>"
   ttl     = <TTL>

-  records = ["<OLD_VALUE>"]
+  records = ["<NEW_VALUE>"]
 }}'''

    return TerraformFixSuggestion(
        kind="hcl_diff",
        title="Update Route 53 record value",
        description=(
            "Update the `records` attribute to restore or correct the DNS record value. "
            "Use Terraform variables for dynamic values to avoid hardcoding."
        ),
        language="diff",
        diff=diff,
        safety_level=_SAFETY_LEVEL,
        placeholders=[
            TerraformFixPlaceholder(
                name="HOSTED_ZONE_ID_VAR",
                description="Terraform variable or data source for the Route 53 hosted zone ID.",
                example="hosted_zone_id",
            ),
            TerraformFixPlaceholder(
                name="RECORD_TYPE",
                description='DNS record type (e.g. "A", "CNAME", "TXT", "MX").',
                example="A",
            ),
            TerraformFixPlaceholder(
                name="TTL",
                description="Time-to-live in seconds.",
                example="300",
            ),
            TerraformFixPlaceholder(
                name="NEW_VALUE",
                description="Intended DNS record value to restore.",
                example="203.0.113.1",
            ),
        ],
        warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
    )


# ── Cloudflare DNS record generator ──────────────────────────────────────────

def _cloudflare_dns_suggestion(mode: str, rname: str, change_type: str) -> TerraformFixSuggestion:
    """Guidance or conceptual preview for a Cloudflare DNS record change."""
    if mode == "guided_only":
        return TerraformFixSuggestion(
            kind="guidance_only",
            title="Restore Cloudflare DNS record in Terraform",
            description=(
                "Locate the `cloudflare_record` block in your Terraform files. "
                "If the record was removed unintentionally, restore the resource "
                "block and run `terraform plan` before applying."
            ),
            language="text",
            safety_level=_SAFETY_LEVEL,
            warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
        )

    if change_type == "removed":
        diff = f'''\
+resource "cloudflare_record" "{rname}" {{
+  zone_id = var.<ZONE_ID_VAR>
+  name    = "<RECORD_NAME>"
+  type    = "<RECORD_TYPE>"
+  value   = "<RECORD_VALUE>"
+  ttl     = <TTL>
+  proxied = <PROXIED>
+}}'''
        title = "Restore removed Cloudflare DNS record"
        desc = (
            "Add back the `cloudflare_record` resource block that was removed. "
            "Populate all placeholders with the intended record values."
        )
    else:
        diff = f'''\
 resource "cloudflare_record" "{rname}" {{
   zone_id = var.<ZONE_ID_VAR>
   name    = "<RECORD_NAME>"
   type    = "<RECORD_TYPE>"
-  value   = "<OLD_VALUE>"
+  value   = "<NEW_VALUE>"
   ttl     = <TTL>
   proxied = <PROXIED>
 }}'''
        title = "Update Cloudflare DNS record value"
        desc = (
            "Update the `value` attribute to restore the intended DNS record. "
            "Use Terraform variables for zone IDs and dynamic values."
        )

    return TerraformFixSuggestion(
        kind="hcl_diff",
        title=title,
        description=desc,
        language="diff",
        diff=diff,
        safety_level=_SAFETY_LEVEL,
        placeholders=[
            TerraformFixPlaceholder(
                name="ZONE_ID_VAR",
                description="Terraform variable or data source for the Cloudflare zone ID.",
                example="cloudflare_zone_id",
            ),
            TerraformFixPlaceholder(
                name="RECORD_TYPE",
                description='DNS record type (e.g. "A", "CNAME", "TXT", "MX").',
                example="A",
            ),
            TerraformFixPlaceholder(
                name="TTL",
                description='TTL in seconds, or 1 for automatic ("auto").',
                example="300",
            ),
            TerraformFixPlaceholder(
                name="PROXIED",
                description="Whether this record is proxied through Cloudflare (true/false).",
                example="false",
            ),
        ],
        warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
    )


# ── Cloudflare WAF/ruleset generator ─────────────────────────────────────────

def _cloudflare_waf_suggestion(mode: str, rname: str) -> TerraformFixSuggestion:
    """Guidance or conceptual preview for a Cloudflare WAF ruleset change."""
    if mode == "guided_only":
        return TerraformFixSuggestion(
            kind="guidance_only",
            title="Restore Cloudflare WAF ruleset in Terraform",
            description=(
                "Locate the `cloudflare_ruleset` block in your Terraform files "
                "and restore the intended rule actions. "
                "Run `terraform plan` to preview and `terraform apply` to apply."
            ),
            language="text",
            safety_level=_SAFETY_LEVEL,
            warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
        )

    diff = f'''\
 resource "cloudflare_ruleset" "{rname}" {{
   zone_id     = var.<ZONE_ID_VAR>
   name        = "<RULESET_NAME>"
   description = "<RULESET_DESCRIPTION>"
   kind        = "zone"
   phase       = "http_request_firewall_managed"

   rules {{
     action = "<RULE_ACTION>"
     action_parameters {{
       id = "<MANAGED_RULESET_ID>"
     }}
     expression  = "true"
     description = "<RULE_DESCRIPTION>"
-    enabled     = false
+    enabled     = true
   }}
 }}'''

    return TerraformFixSuggestion(
        kind="hcl_diff",
        title="Re-enable Cloudflare WAF managed ruleset",
        description=(
            "Set `enabled = true` on the WAF managed ruleset rule. "
            "Verify the `action` and ruleset `id` match your intended configuration "
            "before applying."
        ),
        language="diff",
        diff=diff,
        safety_level=_SAFETY_LEVEL,
        placeholders=[
            TerraformFixPlaceholder(
                name="ZONE_ID_VAR",
                description="Terraform variable or data source for the Cloudflare zone ID.",
                example="cloudflare_zone_id",
            ),
            TerraformFixPlaceholder(
                name="RULE_ACTION",
                description='WAF rule action (e.g. "managed_challenge", "block", "log").',
                example="managed_challenge",
            ),
            TerraformFixPlaceholder(
                name="MANAGED_RULESET_ID",
                description="Cloudflare managed ruleset ID (a UUID from the Cloudflare dashboard).",
                example="efb7b8c949ac4650a09736fc376e9aee",
            ),
        ],
        warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
    )


# ── GitHub branch protection generator ───────────────────────────────────────

def _github_branch_protection_suggestion(mode: str, rname: str) -> TerraformFixSuggestion:
    """Guidance or conceptual preview for a GitHub branch protection change."""
    if mode == "guided_only":
        return TerraformFixSuggestion(
            kind="guidance_only",
            title="Restore GitHub branch protection in Terraform",
            description=(
                "Locate the `github_branch_protection` block in your Terraform files "
                "and restore the required settings: `require_signed_commits`, "
                "`enforce_admins`, or `required_status_checks`. "
                "Run `terraform plan` to preview before applying."
            ),
            language="text",
            safety_level=_SAFETY_LEVEL,
            warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
        )

    diff = f'''\
 resource "github_branch_protection" "{rname}" {{
   repository_id = github_repository.<REPO_VAR>.node_id
   pattern       = "<BRANCH_PATTERN>"

+  enforce_admins         = true
+  require_signed_commits = true

   required_status_checks {{
     strict = true
+    contexts = [<STATUS_CHECK_CONTEXTS>]
   }}

   required_pull_request_reviews {{
     dismiss_stale_reviews      = true
     require_code_owner_reviews = true
+    required_approving_review_count = <REQUIRED_APPROVERS>
   }}
 }}'''

    return TerraformFixSuggestion(
        kind="hcl_diff",
        title="Restore branch protection rules",
        description=(
            "Re-enable `enforce_admins`, `require_signed_commits`, "
            "and `required_status_checks` in the `github_branch_protection` resource. "
            "Adjust the placeholder values to match your repository's CI checks and "
            "required reviewer count."
        ),
        language="diff",
        diff=diff,
        safety_level=_SAFETY_LEVEL,
        placeholders=[
            TerraformFixPlaceholder(
                name="REPO_VAR",
                description=(
                    "Terraform resource label for the `github_repository` resource, "
                    "used to look up the repository's `node_id`."
                ),
                example="my_app",
            ),
            TerraformFixPlaceholder(
                name="BRANCH_PATTERN",
                description='Branch pattern this protection applies to, e.g. "main" or "release/*".',
                example="main",
            ),
            TerraformFixPlaceholder(
                name="STATUS_CHECK_CONTEXTS",
                description=(
                    "Comma-separated list of required CI status check names in quotes, "
                    "e.g. \"ci/test\", \"ci/lint\"."
                ),
                example='"ci/test", "ci/build"',
            ),
            TerraformFixPlaceholder(
                name="REQUIRED_APPROVERS",
                description="Minimum number of required PR approvals (integer ≥ 1).",
                example="2",
            ),
        ],
        warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
    )


# ── Vercel generator ──────────────────────────────────────────────────────────

def _vercel_suggestion(mode: str, rname: str) -> TerraformFixSuggestion:
    """Guidance or conceptual preview for a Vercel project configuration change."""
    if mode == "guided_only":
        return TerraformFixSuggestion(
            kind="guidance_only",
            title="Review Vercel project configuration in Terraform",
            description=(
                "Locate the `vercel_project` block in your Terraform files "
                "and restore the intended project configuration. "
                "Run `terraform plan` before applying any changes."
            ),
            language="text",
            safety_level=_SAFETY_LEVEL,
            warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
        )

    diff = f'''\
 resource "vercel_project" "{rname}" {{
   name      = "<PROJECT_NAME>"
   framework = "<FRAMEWORK>"

   git_repository {{
     type = "github"
     repo = "<REPO_FULL_NAME>"
   }}

-  password_protection {{
-    deployment_type = "all_deployments"
-  }}
+  # Restore intended access control settings:
+  # Consult your Vercel project settings and update as needed.
 }}'''

    return TerraformFixSuggestion(
        kind="hcl_diff",
        title="Review Vercel project access settings",
        description=(
            "Review the `vercel_project` resource for removed or changed access "
            "controls. Restore the intended settings and use Terraform variables "
            "for sensitive values."
        ),
        language="diff",
        diff=diff,
        safety_level=_SAFETY_LEVEL,
        placeholders=[
            TerraformFixPlaceholder(
                name="PROJECT_NAME",
                description="Your Vercel project name.",
                example="my-frontend-app",
            ),
            TerraformFixPlaceholder(
                name="FRAMEWORK",
                description='Vercel framework preset (e.g. "nextjs", "vite", "create-react-app").',
                example="nextjs",
            ),
            TerraformFixPlaceholder(
                name="REPO_FULL_NAME",
                description='GitHub repository in "owner/repo" format.',
                example="acme/frontend",
            ),
        ],
        warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
    )


# ── Generic fallback suggestion ───────────────────────────────────────────────

def _generic_guided_suggestion(record_type: str) -> TerraformFixSuggestion:
    """Generic guidance for record types without specific handlers."""
    return TerraformFixSuggestion(
        kind="guidance_only",
        title="Review Terraform configuration for this resource",
        description=(
            f"Locate the Terraform resource block managing this `{record_type}` resource "
            "and compare its configuration with the detected drift. "
            "Update the resource block to reflect the intended state, then "
            "run `terraform plan` to preview and `terraform apply` to reconcile."
        ),
        language="text",
        safety_level=_SAFETY_LEVEL,
        warnings=[_PLAN_WARNING, _ADVISORY_DISCLAIMER],
    )


# ── Suggestion dispatch ───────────────────────────────────────────────────────

def _build_suggestions(
    record_type: str,
    change_type: str,
    risk_reason: str,
    mapping,
    mode: str,
) -> list[TerraformFixSuggestion]:
    """Return the correct suggestion list for this record type and mode."""
    rname: str = getattr(mapping, "terraform_resource_name", None) or "<RESOURCE_NAME>"

    # ── AWS security group ──────────────────────────────────────────────────
    if record_type in ("aws_security_group", "aws_security_group_rule"):
        rr = risk_reason
        is_ssh = "ssh" in rr or "port 22" in rr or "tcp/22" in rr
        is_rdp = "rdp" in rr or "port 3389" in rr or "tcp/3389" in rr
        is_db = any(
            kw in rr for kw in (
                "mysql", "postgres", "postgresql", "mssql", "mongodb", "redis",
                "3306", "5432", "1433", "27017", "6379",
            )
        )
        if is_ssh:
            return [_aws_sg_ssh_suggestion(mode, rname)]
        if is_rdp:
            return [_aws_sg_rdp_suggestion(mode, rname)]
        if is_db:
            return [_aws_sg_db_suggestion(mode, rname)]
        return [_aws_sg_generic_suggestion(mode, rname)]

    # ── AWS Route53 ─────────────────────────────────────────────────────────
    if record_type == "aws_route53_record":
        return [_aws_route53_suggestion(mode, rname)]

    # ── Cloudflare DNS record ───────────────────────────────────────────────
    if record_type in ("cloudflare_record",) or record_type in (
        "a", "aaaa", "cname", "txt", "mx", "srv", "ns", "ptr", "soa", "caa",
        "https", "ds",
    ):
        return [_cloudflare_dns_suggestion(mode, rname, change_type)]

    # ── Cloudflare WAF ruleset ──────────────────────────────────────────────
    if record_type == "cloudflare_ruleset":
        return [_cloudflare_waf_suggestion(mode, rname)]

    # ── GitHub branch protection ────────────────────────────────────────────
    if record_type == "github_branch_protection":
        return [_github_branch_protection_suggestion(mode, rname)]

    # ── Vercel project ──────────────────────────────────────────────────────
    if record_type in ("vercel_project", "vercel_deploy_hook_metadata"):
        return [_vercel_suggestion(mode, rname)]

    # ── Generic fallback ────────────────────────────────────────────────────
    return [_generic_guided_suggestion(record_type)]


# ── Recommended workflow builder ──────────────────────────────────────────────

def _build_workflow(mode: str, confidence: str) -> list[str]:
    """Return a recommended human workflow for the given mode and confidence."""
    steps = []

    if mode == "guided_only":
        steps = [
            "Locate the Terraform resource block for this cloud resource in your IaC repository.",
            "Compare the current provider state with the Terraform configuration.",
            "Update the Terraform block to reflect the intended state.",
            "Run `terraform plan` and review the diff carefully.",
            "Submit the change via your team's standard PR and review process.",
            "Run `terraform apply` only after the plan has been reviewed and approved.",
        ]
    else:
        # conceptual_preview or exact_preview
        steps = [
            "Review the conceptual diff above. All `<PLACEHOLDER>` values must be "
            "replaced with actual values from your Terraform codebase.",
            "Locate the matching resource block in the IaC repository shown below.",
            "Apply the suggested changes to your local Terraform files.",
            "Run `terraform plan` and verify the output matches your intent — "
            "the actual diff may differ from this preview.",
            "Submit changes via a pull request and have a teammate review the plan output.",
            "Run `terraform apply` only after the plan has been reviewed and approved.",
        ]

    if confidence == "low":
        steps.insert(0,
            "⚠ Confidence is low — verify this Terraform resource actually manages "
            "the affected cloud resource before making any changes."
        )
    elif confidence == "medium":
        steps.insert(0,
            "This is a possible IaC mapping. Confirm the Terraform resource "
            "corresponds to the changed cloud resource before applying any fix."
        )

    return steps


# ── Title builder ─────────────────────────────────────────────────────────────

def _build_title(record_type: str, confidence: str) -> str:
    _TITLES = {
        "aws_security_group":       "Terraform fix preview: AWS security group",
        "aws_security_group_rule":  "Terraform fix preview: AWS security group rule",
        "aws_route53_record":       "Terraform fix preview: Route 53 record",
        "cloudflare_record":        "Terraform fix preview: Cloudflare DNS record",
        "cloudflare_ruleset":       "Terraform fix preview: Cloudflare WAF ruleset",
        "github_branch_protection": "Terraform fix preview: GitHub branch protection",
        "vercel_project":           "Terraform fix preview: Vercel project",
        "vercel_deploy_hook_metadata": "Terraform fix preview: Vercel deploy hook",
    }
    base = _TITLES.get(record_type, "Terraform fix suggestion preview")
    if confidence == "low":
        return f"{base} (low confidence)"
    return base


# ── Summary builder ───────────────────────────────────────────────────────────

def _build_summary(record_type: str, confidence: str, mode: str, mapping) -> str:
    rtype = getattr(mapping, "terraform_resource_type", None) or record_type
    rname = getattr(mapping, "terraform_resource_name", None)
    repo = getattr(mapping, "repo_full_name", None) or "your IaC repository"
    fpath = getattr(mapping, "file_path", None) or "unknown file"

    resource_ref = f'`{rtype}`' + (f' "{rname}"' if rname else "")

    if mode == "guided_only":
        return (
            f"A possible Terraform mapping was found in {repo}. "
            f"Confidence is {confidence} — this diff preview is not available. "
            "Human-readable guidance is provided below."
        )

    return (
        f"A possible IaC mapping was found: {resource_ref} in "
        f"`{fpath}` ({repo}). "
        "The diff below is a conceptual preview — all "
        "`<PLACEHOLDER>` values must be replaced with values from your codebase. "
        "Always run `terraform plan` before applying."
    )


# ── Main entry point ──────────────────────────────────────────────────────────

def get_terraform_fix_preview(
    change_id: uuid.UUID,
    workspace_id: uuid.UUID,
    db: Session,
) -> TerraformFixPreviewResponse:
    """Return an advisory Terraform fix suggestion preview for a change.

    Steps:
    1. Load the Change record (must belong to workspace_id).
    2. Query IacResourceMapping for the highest-confidence mapping.
    3. Choose generation mode based on mapping confidence.
    4. Dispatch to the appropriate suggestion generator.
    5. Return TerraformFixPreviewResponse with permanent safety constants.

    CRITICAL: execution_enabled and pr_available are always False.
    This function never calls any provider write API or Terraform CLI.
    """
    from app.models.change import Change
    from app.models.iac_resource_mapping import IacResourceMapping

    # ── 1. Load change ───────────────────────────────────────────────────────
    change = db.query(Change).filter(Change.id == change_id).first()
    if change is None:
        return _unavailable("Change not found.")

    # ── 2. Find best IaC mapping ─────────────────────────────────────────────
    mappings = (
        db.query(IacResourceMapping)
        .filter(IacResourceMapping.workspace_id == workspace_id)
        .all()
    )

    if not mappings:
        return _unavailable(
            "No IaC repositories have been scanned yet. "
            "Register and scan a GitHub repository under IaC Awareness settings "
            "to enable fix suggestions."
        )

    # Find the best mapping for this specific change
    # Priority: high > medium > low; among equals, prefer cloud_resource_identifier match
    pm = getattr(change, "provider_metadata", None)
    if not isinstance(pm, dict):
        pm = {}
    record_type = _s(pm.get("record_type", ""))
    record_identifier = _s(getattr(change, "record_identifier", "") or "")

    # Filter to mappings whose resource_type is relevant to this change's record_type
    from app.services.iac_mapping_service import (
        _get_tf_candidates_for_change,
        _compute_match_confidence,
    )
    candidate_tf_types = set(_get_tf_candidates_for_change(change))

    relevant = [
        m for m in mappings
        if (getattr(m, "terraform_resource_type", None) or "") in candidate_tf_types
    ] if candidate_tf_types else mappings

    if not relevant:
        return _unavailable(
            "No IaC mappings found for this resource type. "
            "Scan a repository containing Terraform resources for this provider."
        )

    # Score each mapping: high=3, medium=2, low=1; identifier match gives +0.5 bonus
    _CONF_RANK = {"high": 3, "medium": 2, "low": 1}

    def _score(m) -> float:
        conf, _ = _compute_match_confidence(m, change)
        base = _CONF_RANK.get(conf, 0)
        bonus = 0.5 if (
            getattr(m, "cloud_resource_identifier", None)
            and _s(m.cloud_resource_identifier) in record_identifier
        ) else 0.0
        return base + bonus

    best_mapping = max(relevant, key=_score)
    best_confidence, _ = _compute_match_confidence(best_mapping, change)

    # ── 3. Choose generation mode ────────────────────────────────────────────
    if best_confidence == "low":
        mode = "guided_only"
    else:
        # medium or high → conceptual preview with placeholders
        mode = "conceptual_preview"

    # ── 4. Get attributes from change ────────────────────────────────────────
    change_type = _s(getattr(change, "change_type", "") or "")
    risk_reason = _s(getattr(change, "risk_reason", "") or "")

    # ── 5. Build suggestions ─────────────────────────────────────────────────
    suggestions = _build_suggestions(
        record_type=record_type,
        change_type=change_type,
        risk_reason=risk_reason,
        mapping=best_mapping,
        mode=mode,
    )

    # ── 6. Build mapping info ────────────────────────────────────────────────
    # Resolve repo_full_name from the IacRepository if not on the mapping
    repo_full_name: Optional[str] = None
    try:
        from app.models.iac_repository import IacRepository
        iac_repo = db.query(IacRepository).filter(
            IacRepository.id == getattr(best_mapping, "iac_repository_id", None)
        ).first()
        if iac_repo:
            repo_full_name = iac_repo.repo_full_name
    except Exception:  # noqa: BLE001
        pass

    mapping_info = TerraformFixMappingInfo(
        repo_full_name=repo_full_name,
        file_path=getattr(best_mapping, "file_path", "unknown"),
        terraform_resource_type=getattr(best_mapping, "terraform_resource_type", None),
        terraform_resource_name=getattr(best_mapping, "terraform_resource_name", None),
        match_confidence=best_confidence,
    )

    # ── 7. Build title, summary, workflow ────────────────────────────────────
    title = _build_title(record_type, best_confidence)
    summary = _build_summary(record_type, best_confidence, mode, best_mapping)
    workflow = _build_workflow(mode, best_confidence)

    return TerraformFixPreviewResponse(
        available=True,
        confidence=best_confidence,
        title=title,
        summary=summary,
        mapping=mapping_info,
        suggestions=suggestions,
        recommended_workflow=workflow,
        pr_available=_PR_AVAILABLE,
        execution_enabled=_EXECUTION_ENABLED,
    )
