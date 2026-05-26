"""GitHub PR Draft service — M58.20.

Generates a safe, read-only GitHub PR draft proposal from a Terraform fix
suggestion.  No GitHub repository mutations occur in this service or milestone.

PERMANENT SAFETY CONSTRAINTS (must remain in effect permanently):
  - _CREATES_BRANCH     is always False.  Never set to True.
  - _COMMITS_CODE       is always False.  Never set to True.
  - _OPENS_PR           is always False.  Never set to True.
  - _EXECUTES_TERRAFORM is always False.  Never set to True.

No calls are made to:
  - GitHub Contents API write endpoints (create/update file)
  - GitHub Git refs API (create branch)
  - GitHub Commits API (create commit)
  - GitHub Pulls API (create pull request)
  - Any provider write API

All content is generated locally from:
  - The Terraform fix suggestion (M58.19)
  - The IaC resource mapping (M58.18)
  - The Change record (provider_metadata, record_identifier, risk_level)

Actual PR creation is deferred to M58.21 and requires:
  - GitHub App installation with repository contents write + pull_requests write
  - Explicit user opt-in per repository
  - Additional safety gates and audit trail

Data safety:
  - No raw prev_value / new_value forwarded into any PR body text.
  - No secrets, credentials, tokens, API keys, or webhook URLs in output.
  - No tfvars, tfstate, or .terraform/ content.
  - No customer PII (email addresses, order IDs, payment data).
  - Branch names are derived from record_type and a short sanitized resource label only.
  - Commit messages and PR titles use generic, non-sensational language.
  - PR body contains only advisory text and the conceptual diff from M58.19.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.schemas.github_pr_draft import (
    GitHubPrDraftObject,
    GitHubPrDraftRepo,
    GitHubPrDraftResponse,
    GitHubPrDraftSafetyFlags,
)
from app.schemas.terraform_fix import TerraformFixPreviewResponse

# ── Permanent hard constants ──────────────────────────────────────────────────

# These values must never be changed, computed, or overridden.
_CREATES_BRANCH: bool = False
_COMMITS_CODE: bool = False
_OPENS_PR: bool = False
_EXECUTES_TERRAFORM: bool = False

# Static safety flags instance — shared across all responses.
_SAFETY_FLAGS = GitHubPrDraftSafetyFlags(
    creates_branch=_CREATES_BRANCH,
    commits_code=_COMMITS_CODE,
    opens_pr=_OPENS_PR,
    executes_terraform=_EXECUTES_TERRAFORM,
    requires_human_review=True,
)

# Static labels — no GitHub label creation API is called.
_PR_LABELS = ["configtrace", "security", "terraform"]

# Future requirements notice added to every PR draft.
_FUTURE_REQUIREMENTS = [
    "GitHub App installation with 'repository contents: write' permission will be "
    "required in M58.21 to create actual branches and commits.",
    "GitHub App installation with 'pull requests: write' permission will be "
    "required in M58.21 to open actual pull requests.",
    "GitHub App 'metadata: read' permission is required for repository access.",
    "Actual PR creation requires explicit opt-in per repository in a future milestone.",
    "The Terraform fix preview (M58.19) must be available for this change.",
    "IaC mapping confidence should be medium or high for a full patch preview.",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get(obj: Any, key: str) -> Any:
    """Return obj[key] for dicts, or getattr(obj, key, None) for objects."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _s(value: Any) -> str:
    """Safely coerce to lowercase string; returns '' for non-string/None."""
    return value.lower() if isinstance(value, str) else ""


def _sanitize_segment(raw: str, max_len: int = 25) -> str:
    """Sanitize a string for use as a git branch name segment.

    - Lowercase
    - Replace non-alphanumeric with hyphens
    - Collapse consecutive hyphens
    - Strip leading/trailing hyphens
    - Truncate to max_len
    """
    name = raw.lower()
    name = re.sub(r"[^a-z0-9]", "-", name)
    name = re.sub(r"-{2,}", "-", name)
    name = name.strip("-")
    return name[:max_len]


def _build_branch_name(
    record_type: str,
    risk_reason: str,
    record_identifier: str,
) -> str:
    """Generate a safe git branch name from change metadata.

    Format: configtrace/<provider>-<action>-<resource>
    Maximum total length: 80 characters.

    Does NOT include any secret values, customer data, or sensitive metadata.
    """
    # ── Provider/action segment ─────────────────────────────────────────────
    rt = record_type.lower()

    if rt in ("aws_security_group", "aws_security_group_rule"):
        rr = risk_reason.lower()
        if "ssh" in rr or "port 22" in rr or "tcp/22" in rr:
            provider_action = "aws-restrict-public-ssh"
        elif "rdp" in rr or "port 3389" in rr or "tcp/3389" in rr:
            provider_action = "aws-restrict-public-rdp"
        elif any(kw in rr for kw in ("mysql", "postgres", "3306", "5432", "1433")):
            provider_action = "aws-restrict-db-ingress"
        else:
            provider_action = "aws-restrict-sg-ingress"
    elif rt == "aws_route53_record":
        provider_action = "aws-update-route53-record"
    elif rt in ("cloudflare_record",) or rt in (
        "a", "aaaa", "cname", "txt", "mx", "srv", "ns",
    ):
        provider_action = "cloudflare-restore-dns-record"
    elif rt == "cloudflare_ruleset":
        provider_action = "cloudflare-restore-waf-ruleset"
    elif rt == "github_branch_protection":
        provider_action = "github-restore-branch-protection"
    elif rt in ("github_repo_settings",):
        provider_action = "github-review-repo-settings"
    elif rt in ("vercel_project", "vercel_deploy_hook_metadata"):
        provider_action = "vercel-review-project-config"
    else:
        # Generic fallback — only safe metadata
        provider_clean = _sanitize_segment(rt.split("_")[0] if "_" in rt else rt, 15)
        provider_action = f"{provider_clean}-review-config"

    # ── Resource segment ─────────────────────────────────────────────────────
    # Extract a safe short identifier from record_identifier.
    # Use only the part after the last space/colon; truncate to 20 chars.
    # This avoids including account IDs, full ARNs, or customer-specific data.
    rid = _s(record_identifier)
    # Take the last token after common separators
    for sep in (":", "/", " "):
        if sep in rid:
            last_part = rid.rsplit(sep, 1)[-1].strip()
            if last_part and len(last_part) <= 30:
                rid = last_part
                break
    resource_segment = _sanitize_segment(rid, 20)

    if resource_segment:
        branch = f"configtrace/{provider_action}-{resource_segment}"
    else:
        branch = f"configtrace/{provider_action}"

    return branch[:80]


def _build_commit_message(record_type: str, risk_reason: str, record_identifier: str) -> str:
    """Build a safe, non-sensational commit message.

    Does NOT include: "breach", "hacked", "compromised", customer data, or secrets.
    """
    rt = record_type.lower()
    rr = risk_reason.lower()

    if rt in ("aws_security_group", "aws_security_group_rule"):
        if "ssh" in rr or "port 22" in rr:
            return "Restrict public SSH ingress detected by ConfigTrace"
        if "rdp" in rr or "port 3389" in rr:
            return "Restrict public RDP ingress detected by ConfigTrace"
        return "Restrict public security group ingress detected by ConfigTrace"
    if rt == "aws_route53_record":
        return "Update Route 53 record suggested by ConfigTrace"
    if rt in ("cloudflare_record",) or rt in ("a", "aaaa", "cname", "txt", "mx"):
        return "Restore Cloudflare DNS record suggested by ConfigTrace"
    if rt == "cloudflare_ruleset":
        return "Restore Cloudflare WAF ruleset suggested by ConfigTrace"
    if rt == "github_branch_protection":
        return "Restore branch protection rules detected by ConfigTrace"
    if rt == "github_repo_settings":
        return "Review GitHub repository configuration detected by ConfigTrace"
    if rt in ("vercel_project", "vercel_deploy_hook_metadata"):
        return "Review Vercel project configuration detected by ConfigTrace"
    return "Review Terraform configuration drift detected by ConfigTrace"


def _build_pr_title(record_type: str, risk_reason: str) -> str:
    """Build a safe PR title. Non-sensational, advisory language."""
    rt = record_type.lower()
    rr = risk_reason.lower()

    if rt in ("aws_security_group", "aws_security_group_rule"):
        if "ssh" in rr or "port 22" in rr:
            return "Restrict public SSH ingress detected by ConfigTrace"
        if "rdp" in rr or "port 3389" in rr:
            return "Restrict public RDP ingress detected by ConfigTrace"
        return "Restrict public security group inbound rule"
    if rt == "aws_route53_record":
        return "Restore Terraform-managed Route 53 DNS configuration"
    if rt in ("cloudflare_record",) or rt in ("a", "aaaa", "cname", "txt", "mx"):
        return "Restore Terraform-managed Cloudflare DNS record"
    if rt == "cloudflare_ruleset":
        return "Restore Cloudflare WAF ruleset configuration"
    if rt == "github_branch_protection":
        return "Restore branch protection configuration"
    if rt == "github_repo_settings":
        return "Review GitHub repository configuration drift"
    if rt in ("vercel_project", "vercel_deploy_hook_metadata"):
        return "Review Vercel project configuration drift"
    return "Review Terraform configuration drift detected by ConfigTrace"


def _build_pr_body(
    fix_preview: TerraformFixPreviewResponse,
    record_type: str,
    risk_level: str,
    record_identifier: str,
    change_id: uuid.UUID,
    is_outline_only: bool,
) -> str:
    """Build a full markdown PR body.

    Always includes:
    - Detection summary
    - IaC mapping details
    - Proposed change
    - Placeholder list (if any)
    - Validation checklist (includes terraform plan)
    - Safety disclaimer (ConfigTrace has not changed the repo)

    SAFETY: No raw prev_value/new_value, no secrets, no customer PII,
    no credentials, no tfvars/tfstate content.
    """
    mapping = fix_preview.mapping
    suggestion = fix_preview.suggestions[0] if fix_preview.suggestions else None

    # ── Header ────────────────────────────────────────────────────────────────
    lines = [
        "## ConfigTrace drift detection summary",
        "",
        (
            "ConfigTrace detected a configuration drift event that may correspond to "
            "a Terraform-managed resource. This PR draft is a **suggestion only** — "
            "ConfigTrace has not changed this repository, has not run Terraform, and "
            "has not created any branches, commits, or pull requests."
        ),
        "",
    ]

    # ── Detection details ─────────────────────────────────────────────────────
    lines += [
        "### Detection details",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Resource type | `{record_type}` |",
        f"| Risk level | {risk_level} |",
        f"| Change ID | `{change_id}` |",
        "",
    ]

    # ── IaC mapping ───────────────────────────────────────────────────────────
    if mapping:
        confidence_note = {
            "high": "High — exact resource identifier match",
            "medium": "Medium — name token match; verify before applying",
            "low": "Low — type-only match; manual verification required",
        }.get(mapping.match_confidence or "low", mapping.match_confidence or "low")

        rtype = mapping.terraform_resource_type or "unknown"
        rname = mapping.terraform_resource_name or ""
        resource_ref = f"`{rtype}`" + (f' `"{rname}"`' if rname else "")

        lines += [
            "### IaC mapping",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Repository | `{mapping.repo_full_name or 'unknown'}` |",
            f"| File | `{mapping.file_path}` |",
            f"| Resource | {resource_ref} |",
            f"| Confidence | {confidence_note} |",
            "",
        ]

    # ── Proposed change ───────────────────────────────────────────────────────
    if suggestion:
        lines += [
            "### Proposed change",
            "",
            f"**{suggestion.title}**",
            "",
            suggestion.description,
            "",
        ]

        if is_outline_only or suggestion.kind == "guidance_only":
            lines += [
                "> ⚠ **Patch not available.** The IaC mapping confidence is low or no "
                "HCL diff could be generated. Follow the guidance above to locate and "
                "update the resource block manually.",
                "",
            ]

    # ── Placeholders ─────────────────────────────────────────────────────────
    if suggestion and suggestion.placeholders:
        lines += [
            "### Placeholders to replace",
            "",
            "Before merging, replace all `<PLACEHOLDER>` values in the diff:",
            "",
        ]
        for ph in suggestion.placeholders:
            lines.append(f"- **`<{ph.name}>`** — {ph.description}  ")
            lines.append(f"  Example: `{ph.example}`")
        lines.append("")

    # ── Validation checklist ──────────────────────────────────────────────────
    lines += [
        "### Validation checklist",
        "",
        "Before merging this pull request:",
        "",
        "- [ ] Replace all `<PLACEHOLDER>` values with actual values from your environment",
        "- [ ] Run `terraform fmt` to ensure the file is correctly formatted",
        "- [ ] Run `terraform plan` and carefully review the output",
        "- [ ] Confirm the plan diff shows only the intended change",
        "- [ ] Have a teammate review both the code change and the `terraform plan` output",
        "- [ ] Merge only through your team's standard code-review and approval process",
        "- [ ] After `terraform apply`, trigger a ConfigTrace sync to confirm drift is resolved",
        "",
    ]

    # ── Safety disclaimer ─────────────────────────────────────────────────────
    lines += [
        "---",
        "",
        "### Safety disclaimer",
        "",
        "- **ConfigTrace has not changed this repository.**",
        "- **ConfigTrace has not run Terraform.**",
        "- **ConfigTrace has not created any branches, commits, or pull requests.**",
        "- This is a draft suggestion only. All changes require human review and approval.",
        "- The HCL diff above is a **conceptual preview** — "
        "verify against your actual Terraform codebase before applying.",
        "",
        "*Generated by ConfigTrace · Drift detection for infrastructure configuration*",
    ]

    return "\n".join(lines)


def _build_review_notes(
    fix_preview: TerraformFixPreviewResponse,
    is_outline_only: bool,
) -> list[str]:
    """Build the pre-merge review notes list."""
    notes = [
        "Replace all `<PLACEHOLDER>` values before merging.",
        "Run `terraform plan` in your environment and review the output.",
        "Confirm this resource is actually managed by Terraform before applying.",
        "Merge only through your team's standard code-review process.",
        "Trigger a ConfigTrace sync after `terraform apply` to confirm resolution.",
    ]
    if is_outline_only:
        notes.insert(
            0,
            "⚠ Patch preview is not available for this draft (low confidence mapping "
            "or guidance-only suggestion). Update the target file manually.",
        )
    if fix_preview.confidence == "medium":
        notes.insert(
            0,
            "⚠ Mapping confidence is medium — verify the Terraform resource "
            "corresponds to the changed cloud resource before applying.",
        )
    elif fix_preview.confidence == "low":
        notes.insert(
            0,
            "⚠ Mapping confidence is low — manual verification is required. "
            "Do not apply this change without confirming the IaC mapping.",
        )
    return notes


# ── Unavailable response ──────────────────────────────────────────────────────

def _unavailable(reason: str) -> GitHubPrDraftResponse:
    """Return a standard unavailable response with safety flags set."""
    return GitHubPrDraftResponse(
        available=False,
        safety=_SAFETY_FLAGS,
        reason=reason,
        requirements=_FUTURE_REQUIREMENTS,
    )


# ── Main entry point ──────────────────────────────────────────────────────────

def get_github_pr_draft(
    change_id: uuid.UUID,
    workspace_id: uuid.UUID,
    db: Session,
) -> GitHubPrDraftResponse:
    """Return a safe GitHub PR draft proposal for a change.

    Steps:
    1. Load the Change record.
    2. Fetch the Terraform fix preview (M58.19).
    3. If preview unavailable → return unavailable PR draft.
    4. Generate branch name, commit message, PR title, PR body, patch.
    5. Return GitHubPrDraftResponse with all safety constants enforced.

    CRITICAL: This function never calls any GitHub write API.
    creates_branch, commits_code, opens_pr, executes_terraform are always False.
    """
    from app.models.change import Change
    from app.services import terraform_fix_suggestion_service

    # ── 1. Load change ───────────────────────────────────────────────────────
    change = db.query(Change).filter(Change.id == change_id).first()
    if change is None:
        return _unavailable("Change not found.")

    # Extract safe change metadata
    pm = getattr(change, "provider_metadata", None)
    if not isinstance(pm, dict):
        pm = {}
    record_type = _s(pm.get("record_type", ""))
    risk_level = _s(getattr(change, "risk_level", "") or "")
    risk_reason = _s(getattr(change, "risk_reason", "") or "")
    record_identifier = str(getattr(change, "record_identifier", "") or "")

    # ── 2. Get Terraform fix preview ─────────────────────────────────────────
    fix_preview = terraform_fix_suggestion_service.get_terraform_fix_preview(
        change_id=change_id,
        workspace_id=workspace_id,
        db=db,
    )

    if not fix_preview.available:
        return _unavailable(
            fix_preview.summary
            or "No Terraform fix preview is available for this change."
        )

    # ── 3. Determine generation mode ─────────────────────────────────────────
    has_diff = any(
        s.kind == "hcl_diff" and s.diff
        for s in fix_preview.suggestions
    )
    is_low_confidence = fix_preview.confidence == "low"
    is_outline_only = is_low_confidence or not has_diff

    # Low confidence → outline-only draft (PR body with no patch).
    # We still generate the draft; the UI clearly labels it "outline only."

    # ── 4. Get IaC repository info ────────────────────────────────────────────
    repo_full_name = (
        fix_preview.mapping.repo_full_name
        if fix_preview.mapping else None
    )
    file_path = (
        fix_preview.mapping.file_path
        if fix_preview.mapping else "unknown"
    )
    default_branch = "main"  # Conservative default; M58.21 will read actual branch

    # Try to load the actual default_branch from IacRepository
    if fix_preview.mapping and fix_preview.mapping.repo_full_name:
        try:
            from app.models.iac_repository import IacRepository
            iac_repo = (
                db.query(IacRepository)
                .filter(
                    IacRepository.workspace_id == workspace_id,
                    IacRepository.repo_full_name == fix_preview.mapping.repo_full_name,
                )
                .first()
            )
            if iac_repo and iac_repo.default_branch:
                default_branch = iac_repo.default_branch
        except Exception:  # noqa: BLE001
            pass

    # ── 5. Build PR draft components ──────────────────────────────────────────
    branch_name = _build_branch_name(record_type, risk_reason, record_identifier)
    commit_message = _build_commit_message(record_type, risk_reason, record_identifier)
    pr_title = _build_pr_title(record_type, risk_reason)
    pr_body = _build_pr_body(
        fix_preview=fix_preview,
        record_type=record_type,
        risk_level=risk_level,
        record_identifier=record_identifier,
        change_id=change_id,
        is_outline_only=is_outline_only,
    )

    # Patch preview: reuse the first hcl_diff from M58.19 suggestions.
    # Do NOT generate a new aggressive patch — use exactly what M58.19 produced.
    patch_preview: Optional[str] = None
    if has_diff:
        for s in fix_preview.suggestions:
            if s.kind == "hcl_diff" and s.diff:
                patch_preview = s.diff
                break

    review_notes = _build_review_notes(fix_preview, is_outline_only)

    # ── 6. Build response ────────────────────────────────────────────────────
    draft_obj = GitHubPrDraftObject(
        branch_name=branch_name,
        commit_message=commit_message,
        pr_title=pr_title,
        pr_body=pr_body,
        target_file_path=file_path,
        patch_preview=patch_preview,
        labels=_PR_LABELS,
        review_notes=review_notes,
    )

    repo_info = GitHubPrDraftRepo(
        repo_full_name=repo_full_name or "unknown/repository",
        default_branch=default_branch,
        file_path=file_path,
    )

    mode_label = "outline_only" if is_outline_only else "draft_preview_only"

    return GitHubPrDraftResponse(
        available=True,
        mode=mode_label,
        title="GitHub PR draft suggestion",
        summary=(
            "ConfigTrace can prepare a PR proposal to apply the Terraform fix through "
            "your normal code-review workflow. Review the draft below — "
            "actual PR creation is disabled in this milestone."
        ),
        repo=repo_info,
        draft=draft_obj,
        safety=_SAFETY_FLAGS,
        requirements=_FUTURE_REQUIREMENTS,
        next_step=(
            "Review the PR title, body, and patch preview. "
            "Copy the content to open a real PR in GitHub. "
            "Actual automated PR creation will be available in a future milestone."
        ),
    )
