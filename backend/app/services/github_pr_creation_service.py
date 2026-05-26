"""GitHub PR creation service — M58.21.

Creates actual GitHub draft PRs via the GitHub App API.  This is the first
milestone that performs real GitHub repository mutations on behalf of a user.

PERMANENT SAFETY CONSTANTS (must remain in effect permanently):
  - _EXECUTES_TERRAFORM        is always False.  Never set True.
  - _MUTATES_PROVIDER_RESOURCE is always False.  Never set True.
  - _CONFIRMATION_PHRASE       is "CREATE DRAFT PR" — never weakened.

What this service DOES (only when all safety gates pass):
  1. Creates a new git branch off the target base branch.
  2. Creates a `.configtrace/fix-{short_id}.md` file on that branch.
  3. Opens a GitHub draft PR with the fix suggestion.
  4. Persists an audit record (GitHubPrSuggestion).

What this service NEVER does:
  - Never executes Terraform (plan, apply, or any subcommand).
  - Never modifies actual .tf files in the repository.
  - Never pushes directly to the default/protected branch.
  - Never auto-merges or auto-approves PRs.
  - Never modifies provider resources (AWS, Cloudflare, etc.).
  - Never creates PRs for low-confidence IaC mappings.
  - Never creates PRs without the explicit "CREATE DRAFT PR" confirmation.

Safety gates (enforced in order, all must pass):
  1. confirmation_phrase must be exactly "CREATE DRAFT PR"
  2. User must be workspace admin or owner
  3. Terraform fix preview must be available and not guided_only
  4. IaC mapping confidence must be "medium" or "high"
  5. acknowledge_placeholders must be True if fix has <PLACEHOLDER> values
  6. IacRepository must exist and belong to the workspace
  7. IacRepository.installation_id must be set (GitHub App installed)
  8. GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY must be configured
  9. target_base_branch must not be empty
  10. Target file_path must not be a .tfvars, .tfstate, or .terraform/ file

Data safety:
  - No raw prev_value / new_value is forwarded to GitHub.
  - No secrets, credentials, tokens, API keys, or webhook URLs in content.
  - No tfvars, tfstate, or .terraform/ file modification.
  - No customer PII (email addresses, order IDs, payment data).
  - Patch file content contains only advisory text and conceptual diff.
  - GitHub installation token is never logged, stored, or returned.
"""

from __future__ import annotations

import base64
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from app.schemas.github_pr_create import (
    GitHubPrCreateRequest,
    GitHubPrCreateResponse,
    GitHubPrCreateSafetyFlags,
)

logger = logging.getLogger(__name__)

_GITHUB_API_BASE = "https://api.github.com"
_REQUEST_TIMEOUT = 30.0

# ── Permanent hard constants ──────────────────────────────────────────────────

# These values MUST NEVER be changed, computed dynamically, or overridden.
_EXECUTES_TERRAFORM: bool = False
_MUTATES_PROVIDER_RESOURCE: bool = False

# Exact confirmation phrase — case-sensitive, no leading/trailing whitespace.
_CONFIRMATION_PHRASE: str = "CREATE DRAFT PR"

# File path patterns that are never safe to modify via automated PR.
_UNSAFE_PATH_PATTERNS: list[str] = [
    ".tfvars",
    ".tfstate",
    ".terraform/",
    ".terraform.lock.hcl",
]

# Safety flags instance — shared across all successful responses.
_SAFETY_FLAGS = GitHubPrCreateSafetyFlags(
    executes_terraform=_EXECUTES_TERRAFORM,
    mutates_provider_resource=_MUTATES_PROVIDER_RESOURCE,
    creates_draft_pr=True,
)


# ── Validation helpers ────────────────────────────────────────────────────────

def _validate_confirmation(confirmation_phrase: str) -> None:
    """Raise ValueError unless phrase matches exactly."""
    if confirmation_phrase != _CONFIRMATION_PHRASE:
        raise ValueError(
            f'Confirmation phrase does not match. '
            f'Type exactly: "{_CONFIRMATION_PHRASE}" (case-sensitive).'
        )


def _validate_base_branch(base_branch: str) -> None:
    """Raise ValueError if base branch is empty or whitespace."""
    if not base_branch or not base_branch.strip():
        raise ValueError("target_base_branch must not be empty.")


def _validate_file_path(file_path: str) -> None:
    """Raise ValueError if the file path contains unsafe patterns.

    ConfigTrace never modifies .tfvars, .tfstate, or .terraform/ files.
    """
    for pattern in _UNSAFE_PATH_PATTERNS:
        if pattern in file_path:
            raise ValueError(
                f"Target file path contains an unsafe pattern ({pattern!r}). "
                "ConfigTrace will not modify .tfvars, .tfstate, or .terraform/ files. "
                "Only .tf source files may be targeted."
            )


# ── Patch file content builder ────────────────────────────────────────────────

def _build_patch_file_content(
    change_id: uuid.UUID,
    record_type: str,
    risk_level: str,
    fix_description: str,
    fix_diff: Optional[str],
    fix_placeholders: list,
    short_id: str,
) -> str:
    """Build the markdown content for the .configtrace/fix-{short_id}.md file.

    SAFETY: No raw prev_value/new_value, no secrets, no customer PII,
    no credentials, no tfvars/tfstate content.
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        "# ConfigTrace fix suggestion",
        "",
        "> **ConfigTrace has not modified any Terraform files in this repository.**",
        "> This branch was created to support a team-reviewed fix.",
        "> All changes require human review and approval before merging.",
        "",
        "## Detection summary",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Resource type | `{record_type}` |",
        f"| Risk level | {risk_level} |",
        f"| Change ID | `{change_id}` |",
        f"| Detected on (UTC) | {now_utc} |",
        "",
        "## Suggested Terraform fix",
        "",
        fix_description,
        "",
    ]

    if fix_diff:
        lines += [
            "```diff",
            fix_diff,
            "```",
            "",
        ]
    else:
        lines += [
            "> ⚠ Patch diff not available. Follow the guidance above to locate and "
            "update the Terraform resource block manually.",
            "",
        ]

    if fix_placeholders:
        lines += [
            "### Placeholders to replace",
            "",
            "Replace all `<PLACEHOLDER>` values before merging:",
            "",
        ]
        for ph in fix_placeholders:
            name = getattr(ph, "name", str(ph))
            description = getattr(ph, "description", "")
            example = getattr(ph, "example", "")
            lines.append(f"- **`<{name}>`** — {description}")
            if example:
                lines.append(f"  Example: `{example}`")
        lines.append("")

    lines += [
        "## Pre-merge checklist",
        "",
        "- [ ] Replace all `<PLACEHOLDER>` values with actual values from your environment",
        "- [ ] Run `terraform fmt` to ensure the file is correctly formatted",
        "- [ ] Run `terraform plan` and carefully review the planned changes",
        "- [ ] Confirm the plan shows only the intended change",
        "- [ ] Have a teammate review both the code change and the `terraform plan` output",
        "- [ ] Merge only through your team's standard code-review and approval process",
        "- [ ] After `terraform apply`, trigger a ConfigTrace sync to confirm drift is resolved",
        "",
        "---",
        "",
        "*Generated by ConfigTrace · Drift detection for infrastructure configuration*",
        "*ConfigTrace has not run Terraform, executed remediation commands, "
        "or modified any cloud resources.*",
    ]

    return "\n".join(lines)


def _build_pr_body(
    change_id: uuid.UUID,
    record_type: str,
    risk_level: str,
    patch_file_path: str,
    short_id: str,
) -> str:
    """Build the GitHub PR body.

    Points reviewers to the patch file for full details.
    SAFETY: No raw change data, no secrets, no customer PII.
    """
    lines = [
        "## ConfigTrace drift detection",
        "",
        "ConfigTrace detected a configuration drift event and created this draft "
        "PR to facilitate team review.",
        "",
        f"See **`{patch_file_path}`** for the full fix suggestion, conceptual diff, "
        "and pre-merge checklist.",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Resource type | `{record_type}` |",
        f"| Risk level | {risk_level} |",
        f"| Change ID | `{change_id}` |",
        "",
        "### Quick pre-merge checklist",
        "",
        f"- [ ] Review `{patch_file_path}` for the full fix suggestion",
        "- [ ] Replace all `<PLACEHOLDER>` values with actual values",
        "- [ ] Run `terraform plan` and review the output",
        "- [ ] Get teammate approval before merging",
        "",
        "---",
        "",
        "**ConfigTrace has not modified any Terraform files, executed Terraform, "
        "or changed any cloud resources.**",
        "",
        "*Generated by ConfigTrace · Drift detection for infrastructure configuration*",
    ]
    return "\n".join(lines)


# ── GitHub API helpers ────────────────────────────────────────────────────────

def _make_install_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _mint_token(installation_id: str) -> str:
    """Mint a short-lived GitHub App installation token.

    SECURITY: Never log or persist the returned token.
    """
    from app.config import settings
    from app.core.github_app import decode_private_key, mint_app_jwt, mint_installation_token

    app_id = settings.GITHUB_APP_ID
    raw_key = settings.GITHUB_APP_PRIVATE_KEY

    if not app_id or not raw_key:
        raise ValueError(
            "GitHub App is not configured. Set GITHUB_APP_ID and "
            "GITHUB_APP_PRIVATE_KEY environment variables to enable PR creation."
        )

    pem = decode_private_key(raw_key)
    app_jwt = mint_app_jwt(app_id, pem)
    return mint_installation_token(int(installation_id), app_jwt)


def _get_branch_sha(owner: str, repo: str, branch: str, headers: dict) -> str:
    """Return the tip commit SHA for a branch.

    Raises RuntimeError if the branch does not exist or the API call fails.
    """
    url = f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/git/ref/heads/{branch}"
    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            resp = client.get(url, headers=headers)
    except httpx.RequestError as exc:
        raise RuntimeError(f"Network error getting branch SHA: {exc}") from exc

    if resp.status_code == 404:
        raise RuntimeError(
            f"Branch '{branch}' not found in {owner}/{repo}. "
            "Verify target_base_branch is correct."
        )
    if not resp.is_success:
        from app.core.github_app import _safe_github_message
        gh_msg = _safe_github_message(resp)
        raise RuntimeError(
            f"GitHub API error getting branch SHA "
            f"(HTTP {resp.status_code}): {gh_msg}"
        )
    return resp.json()["object"]["sha"]


def _create_ref(
    owner: str,
    repo: str,
    ref: str,
    sha: str,
    headers: dict,
) -> None:
    """Create a new git ref (branch) from the given SHA.

    ref should be in the form "refs/heads/<branch-name>".
    Raises RuntimeError if the branch already exists or the API call fails.
    """
    url = f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/git/refs"
    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            resp = client.post(url, headers=headers, json={"ref": ref, "sha": sha})
    except httpx.RequestError as exc:
        raise RuntimeError(f"Network error creating branch: {exc}") from exc

    if resp.status_code == 422:
        from app.core.github_app import _safe_github_message
        gh_msg = _safe_github_message(resp)
        raise RuntimeError(
            f"Could not create branch (already exists or invalid ref): {gh_msg}"
        )
    if not resp.is_success:
        from app.core.github_app import _safe_github_message
        gh_msg = _safe_github_message(resp)
        raise RuntimeError(
            f"GitHub API error creating branch "
            f"(HTTP {resp.status_code}): {gh_msg}"
        )


def _create_file(
    owner: str,
    repo: str,
    path: str,
    message: str,
    content_b64: str,
    branch: str,
    headers: dict,
) -> str:
    """Create a new file in the repository on the given branch.

    Returns the commit SHA.
    Raises RuntimeError on API failure.
    """
    url = f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}"
    payload = {
        "message": message,
        "content": content_b64,
        "branch": branch,
    }
    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            resp = client.put(url, headers=headers, json=payload)
    except httpx.RequestError as exc:
        raise RuntimeError(f"Network error creating file: {exc}") from exc

    if not resp.is_success:
        from app.core.github_app import _safe_github_message
        gh_msg = _safe_github_message(resp)
        raise RuntimeError(
            f"GitHub API error creating file "
            f"(HTTP {resp.status_code}): {gh_msg}"
        )
    body = resp.json()
    return (body.get("commit") or {}).get("sha", "")


def _create_pull_request(
    owner: str,
    repo: str,
    title: str,
    body: str,
    head: str,
    base: str,
    headers: dict,
) -> tuple[int, str]:
    """Create a GitHub draft pull request.

    Returns (pr_number, pr_html_url).
    Raises RuntimeError on API failure.
    """
    url = f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/pulls"
    payload = {
        "title": title,
        "body": body,
        "head": head,
        "base": base,
        "draft": True,
    }
    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            resp = client.post(url, headers=headers, json=payload)
    except httpx.RequestError as exc:
        raise RuntimeError(f"Network error creating pull request: {exc}") from exc

    if not resp.is_success:
        from app.core.github_app import _safe_github_message
        gh_msg = _safe_github_message(resp)
        raise RuntimeError(
            f"GitHub API error creating pull request "
            f"(HTTP {resp.status_code}): {gh_msg}"
        )
    body_json = resp.json()
    pr_number = body_json.get("number", 0)
    pr_url = body_json.get("html_url", "")
    return int(pr_number), str(pr_url)


def _delete_ref(owner: str, repo: str, ref: str, headers: dict) -> None:
    """Best-effort delete a git ref (branch).  Never raises — cleanup only."""
    url = f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/git/refs/{ref}"
    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            client.delete(url, headers=headers)
    except Exception:  # noqa: BLE001
        pass


# ── Main entry point ──────────────────────────────────────────────────────────

def create_github_pr(
    change_id: uuid.UUID,
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    request: GitHubPrCreateRequest,
    db: Session,
) -> GitHubPrCreateResponse:
    """Create an actual GitHub draft PR for a ConfigTrace change.

    All ten safety gates are evaluated before any GitHub API call is made.
    On any gate failure a ValueError (or PermissionError for role failures)
    is raised and no mutation occurs.

    On GitHub API failure after branch creation, a best-effort branch delete
    is attempted before returning an error response.

    Returns GitHubPrCreateResponse.  GitHub API errors after all gates pass
    are returned as success=False with an error message rather than raising,
    so the frontend can display them inline.

    CRITICAL:
      _EXECUTES_TERRAFORM        is always False — never changed.
      _MUTATES_PROVIDER_RESOURCE is always False — never changed.
    """
    from app.models.change import Change
    from app.models.iac_repository import IacRepository
    from app.models.github_pr_suggestion import GitHubPrSuggestion
    from app.services import terraform_fix_suggestion_service
    from app.services.workspace_service import require_role

    # ── Gate 1: Confirmation phrase ──────────────────────────────────────────
    _validate_confirmation(request.confirmation_phrase)

    # ── Gate 2: Role check ───────────────────────────────────────────────────
    # require_role raises LookupError (not member) or PermissionError (low role).
    require_role(workspace_id, actor_user_id, "admin", db)

    # ── Load Change ──────────────────────────────────────────────────────────
    change = db.query(Change).filter(Change.id == change_id).first()
    if change is None:
        raise LookupError("Change not found.")

    pm = getattr(change, "provider_metadata", None)
    if not isinstance(pm, dict):
        pm = {}
    record_type: str = str(pm.get("record_type", "") or "")
    risk_level: str = str(getattr(change, "risk_level", "") or "")
    risk_reason: str = str(getattr(change, "risk_reason", "") or "")
    record_identifier: str = str(getattr(change, "record_identifier", "") or "")

    # ── Gate 3: Fix preview must be available ────────────────────────────────
    fix_preview = terraform_fix_suggestion_service.get_terraform_fix_preview(
        change_id=change_id,
        workspace_id=workspace_id,
        db=db,
    )
    if not fix_preview.available:
        raise ValueError(
            "Terraform fix preview is not available for this change. "
            "PR creation requires an available fix preview (M58.19)."
        )

    # ── Gate 4: Confidence must be medium or high ────────────────────────────
    confidence = str(fix_preview.confidence or "")
    if confidence not in ("medium", "high"):
        raise ValueError(
            f"IaC mapping confidence is '{confidence}'. "
            "PR creation requires medium or high confidence. "
            "Low-confidence mappings require manual verification."
        )

    # ── Gate 5: Fix must not be guided_only (must have a diff) ──────────────
    has_diff = any(
        s.kind == "hcl_diff" and s.diff
        for s in fix_preview.suggestions
    )
    if not has_diff:
        raise ValueError(
            "The Terraform fix suggestion is guidance-only (no HCL diff). "
            "PR creation requires a conceptual diff (medium or high confidence). "
            "Update the Terraform resource manually using the guidance provided."
        )

    # ── Gate 6: Placeholder acknowledgement ──────────────────────────────────
    suggestion = next(
        (s for s in fix_preview.suggestions if s.kind == "hcl_diff"), None
    )
    has_placeholders = bool(suggestion and suggestion.placeholders)
    if has_placeholders and not request.acknowledge_placeholders:
        raise ValueError(
            "The Terraform fix suggestion contains <PLACEHOLDER> values that must "
            "be replaced before merging. Set acknowledge_placeholders=true to confirm "
            "you understand that placeholder values must be replaced manually."
        )

    # ── Gate 7: IacRepository must exist and belong to workspace ─────────────
    iac_repo = (
        db.query(IacRepository)
        .filter(
            IacRepository.id == request.iac_repository_id,
            IacRepository.workspace_id == workspace_id,
        )
        .first()
    )
    if iac_repo is None:
        raise ValueError(
            f"IaC repository {request.iac_repository_id} not found "
            "in this workspace."
        )

    # ── Gate 8: installation_id must be set ──────────────────────────────────
    installation_id = getattr(iac_repo, "installation_id", None)
    if not installation_id or not str(installation_id).strip():
        raise ValueError(
            f"IaC repository '{iac_repo.repo_full_name}' does not have a GitHub App "
            "installation configured. Install the ConfigTrace GitHub App on this "
            "repository first, then retry."
        )

    # ── Gate 9: base branch must not be empty ────────────────────────────────
    _validate_base_branch(request.target_base_branch)
    base_branch = request.target_base_branch.strip()

    # ── Gate 10: target file path must be safe ───────────────────────────────
    mapping_file_path = (
        fix_preview.mapping.file_path
        if fix_preview.mapping
        else ""
    )
    if mapping_file_path:
        _validate_file_path(mapping_file_path)

    # ── All gates passed — proceed with GitHub API calls ─────────────────────

    # Derive owner / repo from "owner/repo" full name.
    if "/" not in iac_repo.repo_full_name:
        raise ValueError(
            f"Invalid repo_full_name: {iac_repo.repo_full_name!r}. "
            "Expected 'owner/repo' format."
        )
    owner, repo_name = iac_repo.repo_full_name.split("/", 1)

    # Build branch name (reuse M58.20 logic).
    from app.services.github_pr_draft_service import _build_branch_name, _build_pr_title, _build_commit_message
    branch_name = _build_branch_name(record_type, risk_reason, record_identifier)
    pr_title = _build_pr_title(record_type, risk_reason)
    commit_message = _build_commit_message(record_type, risk_reason, record_identifier)

    # Build patch file path and content.
    short_id = str(change_id).replace("-", "")[:12]
    patch_file_path = f".configtrace/fix-{short_id}.md"
    fix_diff = suggestion.diff if suggestion else None
    fix_description = suggestion.description if suggestion else ""
    fix_placeholders = suggestion.placeholders if suggestion else []

    patch_file_content = _build_patch_file_content(
        change_id=change_id,
        record_type=record_type,
        risk_level=risk_level,
        fix_description=fix_description,
        fix_diff=fix_diff,
        fix_placeholders=fix_placeholders,
        short_id=short_id,
    )
    content_b64 = base64.b64encode(
        patch_file_content.encode("utf-8")
    ).decode("utf-8")

    pr_body = _build_pr_body(
        change_id=change_id,
        record_type=record_type,
        risk_level=risk_level,
        patch_file_path=patch_file_path,
        short_id=short_id,
    )

    # Mint installation token — never log or persist.
    try:
        install_token = _mint_token(str(installation_id))
    except (ValueError, RuntimeError) as exc:
        return GitHubPrCreateResponse(
            success=False,
            safety=_SAFETY_FLAGS,
            error=str(exc),
        )

    headers = _make_install_headers(install_token)
    branch_created = False

    try:
        # Step 1: Get base branch SHA.
        base_sha = _get_branch_sha(owner, repo_name, base_branch, headers)

        # Step 2: Create new branch.
        _create_ref(
            owner, repo_name,
            f"refs/heads/{branch_name}",
            base_sha,
            headers,
        )
        branch_created = True

        # Step 3: Create patch file on new branch.
        commit_sha = _create_file(
            owner, repo_name,
            patch_file_path,
            commit_message,
            content_b64,
            branch_name,
            headers,
        )

        # Step 4: Create draft PR.
        pr_number, pr_url = _create_pull_request(
            owner, repo_name,
            pr_title,
            pr_body,
            branch_name,
            base_branch,
            headers,
        )

    except RuntimeError as exc:
        # Best-effort cleanup: delete the branch if it was created.
        if branch_created:
            _delete_ref(owner, repo_name, f"heads/{branch_name}", headers)
        logger.error(
            "github_pr_creation_service error  change_id=%s  error=%s",
            change_id,
            exc,
        )
        return GitHubPrCreateResponse(
            success=False,
            safety=_SAFETY_FLAGS,
            error=str(exc),
        )

    # ── Persist audit record ──────────────────────────────────────────────────
    suggestion_row = GitHubPrSuggestion(
        change_id=change_id,
        workspace_id=workspace_id,
        iac_repository_id=request.iac_repository_id,
        actor_user_id=str(actor_user_id),
        pr_url=pr_url,
        pr_number=pr_number,
        branch_name=branch_name,
        base_branch=base_branch,
        patch_file_path=patch_file_path,
        commit_sha=commit_sha or None,
        pr_state="open",
    )
    db.add(suggestion_row)
    db.commit()
    db.refresh(suggestion_row)

    logger.info(
        "github_pr_creation_service success  change_id=%s  pr_number=%d  pr_url=%s",
        change_id,
        pr_number,
        pr_url,
    )

    return GitHubPrCreateResponse(
        success=True,
        pr_url=pr_url,
        pr_number=pr_number,
        branch_name=branch_name,
        base_branch=base_branch,
        patch_file_path=patch_file_path,
        commit_sha=commit_sha or None,
        safety=_SAFETY_FLAGS,
        suggestion_id=str(suggestion_row.id),
    )
