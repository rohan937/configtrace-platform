"""IaC Awareness Service — Milestone M58.18.

Responsibilities
----------------
* Scan Terraform ``.tf`` files (text/regex, no external HCL parser) to detect
  resource blocks and store safe metadata as ``IacResourceMapping`` rows.
* Manage CRUD for ``IacRepository`` rows.
* Resolve which Terraform resources *may* correspond to a given cloud change
  for the ``/changes/{id}/iac-context`` endpoint.

Safety rules (enforced throughout — do NOT relax without security review)
-------------------------------------------------------------------------
1. Full file contents are NEVER stored — only extracted metadata fields.
2. tfvars / tfstate / .terraform directory files are NEVER read or scanned.
3. Values that look like secrets (tokens, keys, passwords, long hex/base64) are
   NEVER stored — they are detected by ``_is_sensitive_value`` and silently dropped.
4. Terraform is NEVER executed; provider APIs are NEVER called; no resources are
   mutated, created, or destroyed.
5. No GitHub PRs are opened, no code is pushed, no commits are made.
6. Language policy: use "may be managed by Terraform", "possible IaC mapping".
   Reserve confident language only where match_confidence == "high".
"""

from __future__ import annotations

import base64
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from app.models.change import Change
from app.models.iac_repository import IacRepository
from app.models.iac_resource_mapping import IacResourceMapping
from app.models.integration import Integration
from app.core.encryption import decrypt_credentials
from app.schemas.iac import (
    IacChangeMappingCandidate,
    IacContextResponse,
    IacMappingListResponse,
    IacRepositoryCreate,
    IacRepositoryListResponse,
    IacRepositoryResponse,
    IacResourceMappingItem,
    IacScanResult,
)

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_MAX_FILES = 100
_MAX_FILE_SIZE_BYTES = 262_144       # 256 KB per file
_MAX_TOTAL_BYTES = 5_242_880         # 5 MB across all files in one scan

# Terraform HCL resource block opener.
RESOURCE_BLOCK_RE = re.compile(
    r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
    re.MULTILINE,
)

# Only store these known-safe attribute keys from HCL blocks.
_SAFE_ATTR_KEYS: frozenset[str] = frozenset({
    "name",
    "description",
    "display_name",
    "domain",
    "zone_name",
    "record_name",
    "type",
    "zone_id",
    "group_id",
    "vpc_id",
    "repository",
    "project",
    "project_name",
    "branch",
    "distribution_id",
    "web_acl_id",
    "trail_name",
    "resource_name",
    "resource_id",
})

# key = "value" attribute pattern inside an HCL block body.
_ATTR_RE = re.compile(r'^\s*(\w+)\s*=\s*"([^"]*)"', re.MULTILINE)

# Patterns that strongly indicate a sensitive value.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),            # AWS access key IDs
    re.compile(r'\b(password|passwd|secret|private_key|api_key|api_token|'
               r'access_token|auth_token|bearer)\b', re.IGNORECASE),
    re.compile(r'[0-9a-fA-F]{33,}'),                # long hex strings (>32 chars)
    re.compile(r'[A-Za-z0-9+/]{41,}={0,2}'),        # long base64 strings (>40 chars)
]


# ── Terraform resource type ↔ ConfigTrace provider/record-type tables ─────────

# Terraform resource type → ConfigTrace provider string
_TF_TO_PROVIDER: dict[str, str] = {
    "aws_security_group": "aws",
    "aws_security_group_rule": "aws",
    "aws_vpc_security_group_ingress_rule": "aws",
    "aws_cloudfront_distribution": "aws",
    "aws_wafv2_web_acl": "aws",
    "aws_route53_record": "aws",
    "aws_cloudtrail": "aws",
    "cloudflare_record": "cloudflare",
    "cloudflare_ruleset": "cloudflare",
    "cloudflare_zone_settings_override": "cloudflare",
    "github_branch_protection": "github",
    "github_repository_environment": "github",
    "github_actions_secret": "github",
    "github_repository": "github",
    "vercel_project": "vercel",
    "vercel_project_environment_variable": "vercel",
    "vercel_deploy_hook": "vercel",
}

# ConfigTrace record_type → list of relevant Terraform resource types
_RECORD_TYPE_TO_TF: dict[str, list[str]] = {
    "aws_security_group": [
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
    ],
    "aws_security_group_rule": [
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
    ],
    "aws_cloudfront_distribution": ["aws_cloudfront_distribution"],
    "aws_wafv2_web_acl": ["aws_wafv2_web_acl"],
    "aws_route53_record": ["aws_route53_record"],
    "aws_cloudtrail": ["aws_cloudtrail"],
    "cloudflare_record": ["cloudflare_record"],
    "cloudflare_ruleset": ["cloudflare_ruleset"],
    "cloudflare_zone_settings_override": ["cloudflare_zone_settings_override"],
    "github_branch_protection": ["github_branch_protection", "github_repository"],
    "github_repo_settings": ["github_repository"],
    "github_actions_secret": ["github_actions_secret"],
    "github_environment_protection": ["github_repository_environment"],
    "vercel_project": ["vercel_project", "vercel_project_environment_variable"],
}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class TerraformBlock:
    """Safe, metadata-only representation of one Terraform resource block.

    Contains NO raw file content, NO secrets, and NO variable interpolation
    results.  Only attribute key/value pairs whose keys are in ``_SAFE_ATTR_KEYS``
    and whose values pass ``_is_sensitive_value`` are stored in ``safe_attrs``.
    """

    resource_type: str       # e.g. "aws_security_group_rule"
    resource_name: str       # e.g. "allow_ssh"
    file_path: str           # relative path within the repository
    line_start: int          # 1-indexed line number of the opening ``resource`` line
    line_end: int            # 1-indexed line number of the closing ``}``
    safe_attrs: dict[str, str] = field(default_factory=dict)


# ── Pure scanner helpers (no I/O, no DB) ──────────────────────────────────────

def _is_sensitive_value(value: str) -> bool:
    """Return True if *value* looks like a secret that must not be stored.

    Checks for:
    - AWS access key IDs (``AKIA…``)
    - Long hex strings (> 32 chars, likely a token or hash)
    - Long base64 strings (> 40 chars before padding, likely a token)
    - Values whose text contains secret-adjacent keywords (``password``,
      ``secret``, ``private_key``, ``token``, ``api_key``, etc.)

    This is conservative on purpose: false positives (dropping a harmless
    value) are preferable to false negatives (storing a credential).
    """
    if not value:
        return False
    for pattern in _SECRET_PATTERNS:
        if pattern.search(value):
            return True
    return False


def _is_safe_file(file_path: str) -> bool:
    """Return True if *file_path* is safe to scan for Terraform resources.

    Rejects:
    - Anything inside a ``.terraform/`` directory (provider caches, lock files)
    - ``*.tfstate`` and ``*.tfstate.backup`` (may contain secrets and full state)
    - ``*.tfvars`` and ``*.tfvars.json`` (user-supplied variable values, may hold secrets)
    - ``.terraform.lock.hcl`` (dependency lock file, not resource definitions)

    Accepts:
    - ``*.tf`` files
    - ``*.tf.json`` files (JSON-syntax Terraform)
    """
    # Normalise path separators for cross-platform safety
    normalised = file_path.replace("\\", "/")

    # Reject anything that lives inside a .terraform directory
    if "/.terraform/" in normalised or normalised.startswith(".terraform/"):
        return False

    # Reject state and variable files — these may contain secrets
    lower = normalised.lower()
    if lower.endswith(".tfstate") or lower.endswith(".tfstate.backup"):
        return False
    if lower.endswith(".tfvars") or lower.endswith(".tfvars.json"):
        return False
    if lower.endswith(".terraform.lock.hcl"):
        return False

    # Accept Terraform HCL and JSON-syntax files
    if lower.endswith(".tf") or lower.endswith(".tf.json"):
        return True

    return False


def scan_terraform_content(content: str, file_path: str) -> list[TerraformBlock]:
    """Parse Terraform HCL content and return detected resource blocks.

    Uses text/regex scanning — no external HCL parser dependency.  Detects
    ``resource "<type>" "<name>" { ... }`` blocks by tracking brace depth.

    Safety guarantees:
    - Files larger than 256 KB are skipped entirely (caller should also check,
      but this function enforces the limit as a defence-in-depth measure).
    - Attribute values longer than 100 characters are dropped unconditionally.
    - Attribute values that pass ``_is_sensitive_value`` are dropped.
    - Only keys present in ``_SAFE_ATTR_KEYS`` are stored.
    - Full file content is NEVER stored.

    Args:
        content:   Raw text content of the Terraform file.
        file_path: Repository-relative path, used only for metadata storage.

    Returns:
        List of ``TerraformBlock`` instances, one per detected resource block.
    """
    # Defence-in-depth size guard (callers should pre-filter, but we enforce here)
    if len(content.encode("utf-8")) > _MAX_FILE_SIZE_BYTES:
        logger.debug("scan_terraform_content: skipping oversized file %s", file_path)
        return []

    lines = content.splitlines()
    blocks: list[TerraformBlock] = []

    i = 0
    while i < len(lines):
        line = lines[i]
        m = RESOURCE_BLOCK_RE.search(line)
        if m:
            resource_type = m.group(1)
            resource_name = m.group(2)
            line_start = i + 1  # convert to 1-indexed

            # Track brace depth to find the closing } of this block.
            # Count all { and } on the opening line first.
            depth = line.count("{") - line.count("}")
            body_lines: list[str] = [line]
            j = i + 1

            while j < len(lines) and depth > 0:
                body_lines.append(lines[j])
                depth += lines[j].count("{") - lines[j].count("}")
                j += 1

            line_end = j  # 1-indexed end line (inclusive of closing brace)
            block_body = "\n".join(body_lines)

            # Extract only safe, non-sensitive attributes from the block body.
            safe_attrs: dict[str, str] = {}
            for attr_match in _ATTR_RE.finditer(block_body):
                key = attr_match.group(1)
                value = attr_match.group(2)
                if key not in _SAFE_ATTR_KEYS:
                    continue
                # Drop oversized values — they are unlikely to be human-readable names
                if len(value) > 100:
                    continue
                # Drop values that look like secrets
                if _is_sensitive_value(value):
                    continue
                safe_attrs[key] = value

            blocks.append(
                TerraformBlock(
                    resource_type=resource_type,
                    resource_name=resource_name,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    safe_attrs=safe_attrs,
                )
            )
            # Advance past this block to avoid re-processing nested/adjacent lines
            i = j
        else:
            i += 1

    return blocks


def scan_files(
    files: list[tuple[str, str]],
    max_files: int = _MAX_FILES,
    max_total_bytes: int = _MAX_TOTAL_BYTES,
) -> list[TerraformBlock]:
    """Scan multiple Terraform files, respecting size and count limits.

    Files are processed in the order given.  Unsafe files (determined by
    ``_is_safe_file``) are silently skipped.  Processing stops once the
    cumulative byte count exceeds *max_total_bytes* or the number of accepted
    files reaches *max_files*.

    Args:
        files:           List of ``(file_path, content)`` tuples.
        max_files:       Maximum number of files to scan (default 100).
        max_total_bytes: Maximum total bytes across all scanned files (default 5 MB).

    Returns:
        Flat list of ``TerraformBlock`` instances from all scanned files.
    """
    all_blocks: list[TerraformBlock] = []
    files_processed = 0
    total_bytes = 0

    for file_path, content in files:
        if not _is_safe_file(file_path):
            logger.debug("scan_files: skipping unsafe file path %s", file_path)
            continue

        content_bytes = len(content.encode("utf-8"))
        if content_bytes > _MAX_FILE_SIZE_BYTES:
            logger.debug(
                "scan_files: skipping oversized file %s (%d bytes)", file_path, content_bytes
            )
            continue

        if total_bytes + content_bytes > max_total_bytes:
            logger.info(
                "scan_files: total byte limit (%d) reached; stopping after %d files",
                max_total_bytes,
                files_processed,
            )
            break

        if files_processed >= max_files:
            logger.info(
                "scan_files: file count limit (%d) reached; stopping", max_files
            )
            break

        blocks = scan_terraform_content(content, file_path)
        all_blocks.extend(blocks)
        total_bytes += content_bytes
        files_processed += 1

    return all_blocks


# ── Matching helpers ──────────────────────────────────────────────────────────

def _get_tf_candidates_for_change(change: Change) -> list[str]:
    """Return Terraform resource types relevant to this change's ``record_type``.

    Performs an exact lookup in ``_RECORD_TYPE_TO_TF`` first.  If no exact
    match is found, falls back to a prefix-based search: any entry in the
    lookup table whose key starts with the provider prefix of the change's
    record_type is included.

    The ``record_type`` on a ``Change`` row corresponds to the resource's
    ``provider_resource_type`` (e.g. ``"aws_security_group_rule"``,
    ``"cloudflare_record"``).

    Returns an empty list if no candidates are found — callers must handle
    this gracefully (do not raise).
    """
    # The Change model stores record_type indirectly via the resource relationship.
    # We derive it from record_identifier prefix or from provider_metadata when set.
    # The canonical source is resource.provider_resource_type, but that requires a
    # join.  We use the provider_metadata field when available, otherwise attempt
    # to infer from the record_identifier.
    record_type: str | None = None

    if change.provider_metadata and isinstance(change.provider_metadata, dict):
        record_type = change.provider_metadata.get("record_type") or change.provider_metadata.get(
            "resource_type"
        )

    # Exact lookup
    if record_type and record_type in _RECORD_TYPE_TO_TF:
        return _RECORD_TYPE_TO_TF[record_type]

    # Prefix-based fallback: derive provider prefix from record_type or
    # from the change record_identifier
    if not record_type:
        # Attempt to infer a provider prefix from record_identifier
        # e.g. "aws_security_group: sg-abc123" → "aws"
        identifier = change.record_identifier or ""
        for prefix in ("aws_", "cloudflare_", "github_", "vercel_", "stripe_"):
            if identifier.lower().startswith(prefix):
                record_type = identifier.split(":")[0].strip().lower()
                break

    if record_type:
        # Prefix fallback: collect all TF types whose known provider matches
        provider = _TF_TO_PROVIDER.get(record_type)
        if not provider:
            # Infer provider from record_type prefix
            for prefix in ("aws_", "cloudflare_", "github_", "vercel_"):
                if record_type.startswith(prefix):
                    provider = prefix.rstrip("_")
                    break

        if provider:
            return [
                tf_type
                for tf_type, prov in _TF_TO_PROVIDER.items()
                if prov == provider
            ]

    return []


def _compute_match_confidence(
    mapping: IacResourceMapping,
    change: Change,
) -> tuple[str, str]:
    """Compute (confidence, reason) for a mapping/change pair.

    Confidence levels:
    - ``"high"``   — exact ``cloud_resource_identifier`` match with the change's
                     ``record_identifier`` (or a token within it).
    - ``"medium"`` — ``cloud_resource_name`` or a safe name token extracted from
                     ``record_identifier`` matches the mapping's ``terraform_resource_name``
                     or a safe attribute value.
    - ``"low"``    — resource type and provider match only; no name evidence.

    The language for the ``reason`` field follows the advisory policy:
    "may be managed by Terraform" / "possible IaC mapping".

    Args:
        mapping: An ``IacResourceMapping`` row.
        change:  The ``Change`` being resolved.

    Returns:
        ``(confidence, reason)`` tuple where confidence is one of
        ``"high"``, ``"medium"``, or ``"low"``.
    """
    record_identifier = (change.record_identifier or "").strip()
    cloud_id = (mapping.cloud_resource_identifier or "").strip()
    cloud_name = (mapping.cloud_resource_name or "").strip()
    tf_name = (mapping.terraform_resource_name or "").strip()

    # ── High confidence: exact identifier match ───────────────────────────────
    if cloud_id and record_identifier:
        if cloud_id == record_identifier:
            return (
                "high",
                f"cloud_resource_identifier '{cloud_id}' exactly matches the change "
                f"record_identifier. This resource is very likely managed by Terraform.",
            )
        # Partial token match: the cloud ID appears as a token inside record_identifier
        if cloud_id in record_identifier or record_identifier in cloud_id:
            return (
                "high",
                f"cloud_resource_identifier '{cloud_id}' matches a token in "
                f"record_identifier '{record_identifier}'. This resource may be "
                f"managed by Terraform.",
            )

    # ── Medium confidence: name-level match ───────────────────────────────────
    # Tokenise record_identifier by common delimiters for fuzzy name matching
    identifier_tokens = set(
        t.lower().strip()
        for t in re.split(r'[\s:/|,\-_]+', record_identifier)
        if len(t) >= 2
    )

    if cloud_name and cloud_name.lower() in identifier_tokens:
        return (
            "medium",
            f"cloud_resource_name '{cloud_name}' matches a token in record_identifier. "
            f"This is a possible IaC mapping — review IaC source before making manual "
            f"console changes.",
        )

    if tf_name and tf_name.lower() in identifier_tokens:
        return (
            "medium",
            f"Terraform resource name '{tf_name}' matches a token in record_identifier. "
            f"This is a possible IaC mapping — review IaC source before making manual "
            f"console changes.",
        )

    # Check safe_attrs values if the mapping carries them (stored in match_reason
    # as structured text when populated by the scanner).  We parse key=value pairs
    # from the match_reason field as a best-effort approach.
    if mapping.match_reason:
        for token in identifier_tokens:
            if token and token in mapping.match_reason.lower():
                return (
                    "medium",
                    f"A name token from record_identifier matches attributes in the "
                    f"Terraform resource definition. This is a possible IaC mapping — "
                    f"review IaC source before making manual console changes.",
                )

    # ── Low confidence: provider / type match only ────────────────────────────
    provider = _TF_TO_PROVIDER.get(mapping.terraform_resource_type, mapping.provider)
    return (
        "low",
        f"Terraform resource type '{mapping.terraform_resource_type}' (provider: "
        f"{provider}) matches the change's resource type. This resource may be managed "
        f"by Terraform, but no name-level evidence was found. Review IaC source before "
        f"making manual console changes.",
    )


# ── Repository CRUD ───────────────────────────────────────────────────────────

def list_repositories(
    workspace_id: uuid.UUID,
    db: Session,
) -> list[IacRepository]:
    """List all ``IacRepository`` rows for *workspace_id*.

    Args:
        workspace_id: UUID of the workspace to query.
        db:           Active SQLAlchemy session.

    Returns:
        All registered repositories for the workspace, ordered by creation time
        (oldest first).
    """
    return (
        db.query(IacRepository)
        .filter(IacRepository.workspace_id == workspace_id)
        .order_by(IacRepository.created_at.asc())
        .all()
    )


def register_repository(
    workspace_id: uuid.UUID,
    data: IacRepositoryCreate,
    db: Session,
) -> IacRepository:
    """Register a new IaC repository for *workspace_id*.

    Validates that *repo_full_name* is not already registered in this workspace
    before inserting, so that operators cannot accidentally create duplicate
    scan targets.

    Args:
        workspace_id: UUID of the workspace that owns this repository.
        data:         Validated ``IacRepositoryCreate`` payload.
        db:           Active SQLAlchemy session.

    Returns:
        The newly created ``IacRepository`` row (committed).

    Raises:
        ValueError: If ``repo_full_name`` is already registered in this workspace.
    """
    # Duplicate-check: same workspace + same repo_full_name
    existing = (
        db.query(IacRepository)
        .filter(
            IacRepository.workspace_id == workspace_id,
            IacRepository.repo_full_name == data.repo_full_name,
        )
        .first()
    )
    if existing:
        raise ValueError(
            f"Repository '{data.repo_full_name}' is already registered for this workspace."
        )

    repo = IacRepository(
        workspace_id=workspace_id,
        integration_id=data.integration_id,
        repo_full_name=data.repo_full_name,
        default_branch=data.default_branch or "main",
        scanning_enabled=data.scanning_enabled if data.scanning_enabled is not None else True,
        provider="github",
        last_scan_status="pending",
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)
    logger.info(
        "register_repository: registered repo=%s workspace=%s",
        repo.repo_full_name,
        workspace_id,
    )
    return repo


# ── Scan function ─────────────────────────────────────────────────────────────

def scan_repository(
    repo_id: uuid.UUID,
    workspace_id: uuid.UUID,
    db: Session,
) -> IacScanResult:
    """Scan a registered repository for Terraform resource blocks.

    Flow
    ----
    1. Load the ``IacRepository`` row (404 → returns ``status="not_found"``).
    2. If no ``integration_id``: returns ``status="no_integration"`` — scanning
       requires a GitHub integration to fetch file contents.
    3. Load the linked ``Integration`` and decrypt credentials to obtain the
       GitHub token.
    4. Call the GitHub REST API to list the repository tree recursively.
       - If HTTP 403: returns ``status="no_access"`` advising the operator to
         grant Contents read permission.
    5. Filter tree entries to ``*.tf`` files, excluding unsafe paths.
    6. Fetch each file up to the per-file and total size limits.
    7. Scan fetched content with ``scan_files`` and create ``IacResourceMapping``
       rows for discovered resource blocks.
    8. Update ``IacRepository.last_scan_status``, ``last_scan_at``, and
       ``last_error`` fields.

    Safety guarantees
    -----------------
    - .terraform/, *.tfstate, *.tfvars files are NEVER fetched or scanned.
    - File content is decoded then immediately discarded; only parsed metadata
      rows are written to the database.
    - Sensitive attribute values are filtered by ``_is_sensitive_value`` before
      any DB write.
    - No Terraform execution; no provider API calls; no resource mutations.

    Args:
        repo_id:      UUID of the ``IacRepository`` to scan.
        workspace_id: UUID of the workspace (used for scoping and DB writes).
        db:           Active SQLAlchemy session.

    Returns:
        ``IacScanResult`` describing the outcome.  Never raises for expected
        error conditions (missing integration, GitHub permission errors, etc.);
        unexpected exceptions are caught, logged, and surfaced as
        ``status="error"``.
    """
    now = datetime.now(timezone.utc)

    # ── 1. Load repository ────────────────────────────────────────────────────
    repo: IacRepository | None = (
        db.query(IacRepository)
        .filter(
            IacRepository.id == repo_id,
            IacRepository.workspace_id == workspace_id,
        )
        .first()
    )
    if repo is None:
        logger.warning("scan_repository: repo %s not found in workspace %s", repo_id, workspace_id)
        return IacScanResult(
            status="not_found",
            message="IaC repository not found.",
            resources_found=0,
            files_scanned=0,
        )

    # ── 2. Check integration ──────────────────────────────────────────────────
    if repo.integration_id is None:
        logger.info(
            "scan_repository: repo %s has no integration_id; skipping scan", repo_id
        )
        _update_repo_scan_status(repo, "no_integration", now, db, error=None)
        return IacScanResult(
            status="no_integration",
            message=(
                "No GitHub integration is linked to this repository. "
                "Connect a GitHub integration to enable IaC scanning."
            ),
            resources_found=0,
            files_scanned=0,
        )

    # ── 3. Load integration and decrypt credentials ───────────────────────────
    integration: Integration | None = (
        db.query(Integration)
        .filter(Integration.id == repo.integration_id)
        .first()
    )
    if integration is None:
        logger.error(
            "scan_repository: integration %s not found for repo %s",
            repo.integration_id,
            repo_id,
        )
        _update_repo_scan_status(repo, "error", now, db, error="Linked integration not found.")
        return IacScanResult(
            status="error",
            message="Linked GitHub integration could not be found.",
            resources_found=0,
            files_scanned=0,
        )

    try:
        credentials = decrypt_credentials(
            integration.encrypted_credentials,
            integration.credential_iv,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "scan_repository: credential decryption failed for integration %s: %s",
            integration.id,
            exc,
        )
        _update_repo_scan_status(repo, "error", now, db, error="Credential decryption failed.")
        return IacScanResult(
            status="error",
            message="Failed to decrypt integration credentials.",
            resources_found=0,
            files_scanned=0,
        )

    # GitHub token may live under several key names depending on the integration type
    token: str | None = (
        credentials.get("token")
        or credentials.get("access_token")
        or credentials.get("api_token")
        or credentials.get("github_token")
    )
    if not token:
        logger.error(
            "scan_repository: no GitHub token found in credentials for integration %s",
            integration.id,
        )
        _update_repo_scan_status(
            repo, "error", now, db, error="No GitHub token in integration credentials."
        )
        return IacScanResult(
            status="error",
            message="No GitHub token found in integration credentials.",
            resources_found=0,
            files_scanned=0,
        )

    # ── 4. Fetch repository tree from GitHub ──────────────────────────────────
    owner, repo_name = repo.repo_full_name.split("/", 1)
    branch = repo.default_branch or "main"
    auth_headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        tree_resp = httpx.get(
            f"https://api.github.com/repos/{owner}/{repo_name}/git/trees/{branch}?recursive=1",
            headers=auth_headers,
            timeout=30,
        )
    except httpx.RequestError as exc:
        logger.error("scan_repository: GitHub tree request failed: %s", exc)
        _update_repo_scan_status(repo, "error", now, db, error=f"GitHub API request failed: {exc}")
        return IacScanResult(
            status="error",
            message=f"GitHub API request failed: {exc}",
            resources_found=0,
            files_scanned=0,
        )

    if tree_resp.status_code == 403:
        logger.warning(
            "scan_repository: 403 from GitHub for repo %s — missing Contents permission",
            repo.repo_full_name,
        )
        _update_repo_scan_status(
            repo,
            "no_access",
            now,
            db,
            error="GitHub API returned 403: missing Contents read permission.",
        )
        return IacScanResult(
            status="no_access",
            message=(
                "IaC scanning requires the GitHub Contents read permission. "
                "Please update the GitHub App installation to grant read access to "
                f"repository contents for '{repo.repo_full_name}'."
            ),
            resources_found=0,
            files_scanned=0,
        )

    if tree_resp.status_code == 404:
        _update_repo_scan_status(
            repo, "error", now, db, error="Repository or branch not found on GitHub."
        )
        return IacScanResult(
            status="error",
            message=(
                f"Repository '{repo.repo_full_name}' or branch '{branch}' not found on GitHub."
            ),
            resources_found=0,
            files_scanned=0,
        )

    if not tree_resp.is_success:
        error_msg = f"GitHub API returned HTTP {tree_resp.status_code}."
        _update_repo_scan_status(repo, "error", now, db, error=error_msg)
        return IacScanResult(
            status="error",
            message=error_msg,
            resources_found=0,
            files_scanned=0,
        )

    tree_data = tree_resp.json()
    tree_items = tree_data.get("tree", [])

    # ── 5. Filter tree to safe .tf files ─────────────────────────────────────
    tf_items = [
        item
        for item in tree_items
        if item.get("type") == "blob"
        and item.get("path", "").endswith(".tf")
        and _is_safe_file(item["path"])
    ]

    # ── 6. Fetch file content and accumulate (file_path, content) pairs ───────
    fetched_files: list[tuple[str, str]] = []
    total_bytes_fetched = 0

    for item in tf_items:
        if len(fetched_files) >= _MAX_FILES:
            logger.info(
                "scan_repository: reached max_files=%d for repo %s; stopping fetch",
                _MAX_FILES,
                repo.repo_full_name,
            )
            break

        file_path = item["path"]
        file_size = item.get("size", 0)

        # Skip individual files that exceed the per-file size limit
        if file_size > _MAX_FILE_SIZE_BYTES:
            logger.debug(
                "scan_repository: skipping oversized file %s (%d bytes)", file_path, file_size
            )
            continue

        # Stop if adding this file would exceed the total byte budget
        if total_bytes_fetched + file_size > _MAX_TOTAL_BYTES:
            logger.info(
                "scan_repository: total byte limit reached at %d bytes for repo %s",
                total_bytes_fetched,
                repo.repo_full_name,
            )
            break

        try:
            content_resp = httpx.get(
                f"https://api.github.com/repos/{owner}/{repo_name}/contents/{file_path}?ref={branch}",
                headers=auth_headers,
                timeout=15,
            )
        except httpx.RequestError as exc:
            logger.warning(
                "scan_repository: failed to fetch %s from %s: %s",
                file_path,
                repo.repo_full_name,
                exc,
            )
            continue

        if not content_resp.is_success:
            logger.debug(
                "scan_repository: HTTP %d fetching %s", content_resp.status_code, file_path
            )
            continue

        content_data = content_resp.json()
        raw_content = content_data.get("content", "")
        if not raw_content:
            continue

        # GitHub returns base64-encoded content with embedded newlines
        try:
            decoded_bytes = base64.b64decode(raw_content.replace("\n", ""))
            file_content = decoded_bytes.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            logger.debug("scan_repository: failed to decode %s: %s", file_path, exc)
            continue

        fetched_files.append((file_path, file_content))
        total_bytes_fetched += len(decoded_bytes)

    # ── 7. Scan fetched content and persist mappings ──────────────────────────
    blocks = scan_files(fetched_files, max_files=_MAX_FILES, max_total_bytes=_MAX_TOTAL_BYTES)

    # Delete stale mappings for this repository before inserting fresh results
    db.query(IacResourceMapping).filter(
        IacResourceMapping.iac_repository_id == repo.id
    ).delete(synchronize_session=False)

    resources_written = 0
    for block in blocks:
        provider = _TF_TO_PROVIDER.get(block.resource_type, "unknown")

        # Derive a cloud_resource_name from safe_attrs if available
        cloud_name = (
            block.safe_attrs.get("name")
            or block.safe_attrs.get("display_name")
            or block.safe_attrs.get("repository")
            or block.safe_attrs.get("project")
            or None
        )

        # Build a human-readable match_reason from non-empty safe attrs
        attr_summary = "; ".join(
            f"{k}={v}" for k, v in sorted(block.safe_attrs.items()) if v
        )
        match_reason = (
            f"Discovered via HCL scan of {block.file_path}:{block.line_start}"
            + (f" — {attr_summary}" if attr_summary else "")
        )

        mapping = IacResourceMapping(
            workspace_id=workspace_id,
            iac_repository_id=repo.id,
            provider=provider,
            # resource_type uses the Terraform type as a proxy at scan time;
            # it may be enriched with the exact ConfigTrace record_type later.
            resource_type=block.resource_type,
            terraform_resource_type=block.resource_type,
            terraform_resource_name=block.resource_name,
            file_path=block.file_path,
            line_start=block.line_start,
            line_end=block.line_end,
            cloud_resource_name=cloud_name,
            # cloud_resource_identifier is not known at scan time without provider lookup;
            # it may be populated later via tag_match or arn_match enrichment.
            cloud_resource_identifier=None,
            match_confidence="low",
            match_reason=match_reason,
            mapping_source="terraform_hcl_scan",
        )
        db.add(mapping)
        resources_written += 1

    # ── 8. Update repository scan status ─────────────────────────────────────
    _update_repo_scan_status(repo, "success", now, db, error=None)
    db.commit()

    logger.info(
        "scan_repository: completed scan of %s — %d files, %d resources",
        repo.repo_full_name,
        len(fetched_files),
        resources_written,
    )

    return IacScanResult(
        status="success",
        message=(
            f"Scanned {len(fetched_files)} Terraform file(s) in '{repo.repo_full_name}'. "
            f"Found {resources_written} resource block(s)."
        ),
        resources_found=resources_written,
        files_scanned=len(fetched_files),
    )


def _update_repo_scan_status(
    repo: IacRepository,
    status: str,
    scanned_at: datetime,
    db: Session,
    *,
    error: str | None,
) -> None:
    """Update the scan status fields on *repo* and flush (do not commit).

    Args:
        repo:       The ``IacRepository`` ORM object to update.
        status:     New ``last_scan_status`` value.
        scanned_at: UTC timestamp to write to ``last_scan_at``.
        db:         Active SQLAlchemy session.
        error:      Error message to store in ``last_error``, or ``None`` on success.
    """
    repo.last_scan_status = status
    repo.last_scan_at = scanned_at
    repo.last_error = error
    db.flush()


# ── Mappings list ─────────────────────────────────────────────────────────────

def list_mappings(
    workspace_id: uuid.UUID,
    provider: Optional[str],
    cloud_resource_identifier: Optional[str],
    resource_type: Optional[str],
    db: Session,
) -> list[tuple[IacResourceMapping, str]]:
    """List ``IacResourceMapping`` rows with the owning repo's ``repo_full_name`` joined.

    All filters are optional and combined with AND.  Results are ordered by
    the mapping's creation time (most recent first).

    Args:
        workspace_id:              Scope all results to this workspace.
        provider:                  Filter by provider (e.g. ``"aws"``, ``"cloudflare"``).
        cloud_resource_identifier: Filter by exact ``cloud_resource_identifier`` value.
        resource_type:             Filter by ``terraform_resource_type``.
        db:                        Active SQLAlchemy session.

    Returns:
        List of ``(IacResourceMapping, repo_full_name)`` tuples.
    """
    query = (
        db.query(IacResourceMapping, IacRepository.repo_full_name)
        .join(IacRepository, IacResourceMapping.iac_repository_id == IacRepository.id)
        .filter(IacResourceMapping.workspace_id == workspace_id)
    )

    if provider is not None:
        query = query.filter(IacResourceMapping.provider == provider)

    if cloud_resource_identifier is not None:
        query = query.filter(
            IacResourceMapping.cloud_resource_identifier == cloud_resource_identifier
        )

    if resource_type is not None:
        query = query.filter(
            IacResourceMapping.terraform_resource_type == resource_type
        )

    return (
        query.order_by(IacResourceMapping.created_at.desc()).all()
    )


# ── IaC context for a change ──────────────────────────────────────────────────

def get_iac_context(
    change_id: uuid.UUID,
    workspace_id: uuid.UUID,
    db: Session,
) -> IacContextResponse:
    """Compute the IaC context for a given change.

    Returns advisory information about which Terraform resources may correspond
    to the cloud change, using language that reflects uncertainty:
    "may be managed by Terraform", "possible IaC mapping", etc.

    Algorithm
    ---------
    1. Load the ``Change`` row (returns ``available=False`` on miss).
    2. Determine candidate Terraform resource types for the change's record type.
    3. Query ``IacResourceMapping`` rows in the workspace matching those types.
    4. Compute ``(confidence, reason)`` for each candidate mapping.
    5. Sort candidates: high → medium → low confidence.
    6. Return ``IacContextResponse``.

    Edge cases
    ----------
    - No IaC repositories registered → ``available=False`` with registration prompt.
    - No ``*.tf`` files scanned yet → ``available=False`` with scan prompt.
    - No matching mappings → ``available=False`` with explanatory summary.
    - Matching mappings found → ``available=True`` with sorted ``mappings`` list.

    Advisory language policy (enforced here):
    - Use "may be managed by Terraform" / "possible IaC mapping".
    - Use "review IaC source before making manual console changes".
    - Only use highly confident language when ``confidence == "high"``.
    - ``future_fix_note`` always states "Terraform patch suggestions are coming in M58.19."

    Args:
        change_id:    UUID of the ``Change`` to contextualise.
        workspace_id: UUID of the workspace (for scoping).
        db:           Active SQLAlchemy session.

    Returns:
        An ``IacContextResponse`` instance.  Never raises for normal conditions.
    """
    future_note = "Terraform patch suggestions are coming in M58.19."

    # ── 1. Load the change ────────────────────────────────────────────────────
    change: Change | None = (
        db.query(Change)
        .filter(Change.id == change_id)
        .first()
    )
    if change is None:
        return IacContextResponse(
            available=False,
            summary="Change not found.",
            mappings=[],
            recommended_workflow=None,
            future_fix_available=False,
            future_fix_note=future_note,
        )

    # ── Check whether any IaC repositories exist in this workspace ───────────
    repo_count: int = (
        db.query(IacRepository)
        .filter(IacRepository.workspace_id == workspace_id)
        .count()
    )
    if repo_count == 0:
        return IacContextResponse(
            available=False,
            summary=(
                "No IaC repositories are registered for this workspace. "
                "Register a GitHub repository to enable IaC mapping."
            ),
            mappings=[],
            recommended_workflow=None,
            future_fix_available=False,
            future_fix_note=future_note,
        )

    # ── Check whether any mappings exist in this workspace at all ─────────────
    total_mappings: int = (
        db.query(IacResourceMapping)
        .filter(IacResourceMapping.workspace_id == workspace_id)
        .count()
    )
    if total_mappings == 0:
        return IacContextResponse(
            available=False,
            summary=(
                "IaC repositories are registered but no Terraform resources have been "
                "scanned yet. Trigger a scan on your registered repositories to populate "
                "IaC mapping data."
            ),
            mappings=[],
            recommended_workflow=None,
            future_fix_available=False,
            future_fix_note=future_note,
        )

    # ── 2. Determine candidate Terraform resource types ───────────────────────
    candidate_tf_types = _get_tf_candidates_for_change(change)

    if not candidate_tf_types:
        return IacContextResponse(
            available=False,
            summary=(
                f"No Terraform resource type mapping is defined for this change's "
                f"resource type. IaC context is not available."
            ),
            mappings=[],
            recommended_workflow=None,
            future_fix_available=False,
            future_fix_note=future_note,
        )

    # ── 3. Query matching IacResourceMapping rows ─────────────────────────────
    candidate_mappings: list[IacResourceMapping] = (
        db.query(IacResourceMapping)
        .filter(
            IacResourceMapping.workspace_id == workspace_id,
            IacResourceMapping.terraform_resource_type.in_(candidate_tf_types),
        )
        .all()
    )

    if not candidate_mappings:
        return IacContextResponse(
            available=False,
            summary=(
                f"No Terraform resources of a matching type were found in scanned IaC "
                f"repositories. Ensure your repositories have been scanned and contain "
                f"Terraform definitions for this resource type."
            ),
            mappings=[],
            recommended_workflow=None,
            future_fix_available=False,
            future_fix_note=future_note,
        )

    # ── 4. Compute confidence for each mapping ────────────────────────────────
    ranked: list[tuple[str, str, IacResourceMapping]] = []
    for mapping in candidate_mappings:
        confidence, reason = _compute_match_confidence(mapping, change)
        ranked.append((confidence, reason, mapping))

    # ── 5. Sort: high → medium → low ─────────────────────────────────────────
    _confidence_order = {"high": 0, "medium": 1, "low": 2}
    ranked.sort(key=lambda t: _confidence_order.get(t[0], 3))

    # ── Build IacChangeMappingCandidate items ─────────────────────────────────
    # Load repo names for display (one extra query, but bounded by candidate count)
    repo_ids = {m.iac_repository_id for _, _, m in ranked}
    repos_by_id: dict[uuid.UUID, IacRepository] = {
        r.id: r
        for r in db.query(IacRepository).filter(IacRepository.id.in_(repo_ids)).all()
    }

    result_mappings: list[IacChangeMappingCandidate] = []
    for confidence, reason, mapping in ranked:
        owning_repo = repos_by_id.get(mapping.iac_repository_id)
        result_mappings.append(
            IacChangeMappingCandidate(
                mapping_id=mapping.id,
                iac_repository_id=mapping.iac_repository_id,
                repo_full_name=owning_repo.repo_full_name if owning_repo else None,
                terraform_resource_type=mapping.terraform_resource_type,
                terraform_resource_name=mapping.terraform_resource_name,
                file_path=mapping.file_path,
                line_start=mapping.line_start,
                line_end=mapping.line_end,
                cloud_resource_identifier=mapping.cloud_resource_identifier,
                cloud_resource_name=mapping.cloud_resource_name,
                match_confidence=confidence,
                match_reason=reason,
                mapping_source=mapping.mapping_source,
            )
        )

    best_confidence = ranked[0][0] if ranked else "low"
    count = len(result_mappings)

    if best_confidence == "high":
        summary = (
            f"This change may be managed by Terraform. "
            f"{count} possible IaC mapping(s) found — the top match has high confidence. "
            f"Review IaC source before making manual console changes."
        )
    elif best_confidence == "medium":
        summary = (
            f"{count} possible IaC mapping(s) found for this change. "
            f"These are possible IaC mappings based on name matching — review IaC source "
            f"before making manual console changes."
        )
    else:
        summary = (
            f"{count} possible IaC mapping(s) found for this change based on resource "
            f"type. No name-level evidence was found. This resource may be managed by "
            f"Terraform — review IaC source before making manual console changes."
        )

    recommended_workflow = (
        "1. Review the IaC source files listed above before making any manual console changes. "
        "2. If a Terraform definition exists, apply changes through your IaC pipeline rather "
        "than directly in the provider console. "
        "3. If the console change was intentional, update the Terraform definition to match "
        "to prevent configuration drift."
    )

    return IacContextResponse(
        available=True,
        summary=summary,
        mappings=result_mappings,
        recommended_workflow=recommended_workflow,
        future_fix_available=False,
        future_fix_note=future_note,
    )
