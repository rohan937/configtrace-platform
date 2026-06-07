"""GitHub security exposure rules — M60.4 / expanded in M60.4.1.

Every rule fires only on explicit, reliable normalized fields produced by the
GitHub connector (app/connectors/github.py + github_schema.py). Evidence is
metadata-only: repo/branch names, URLs, booleans, counts, deploy-key titles/ids.
No secrets, tokens, key material, webhook secrets, or payloads are ever read.

Record types consumed
---------------------
- ``github_webhook``                → webhook delivered over plain HTTP
- ``github_branch_protection``      → default-branch protection posture
- ``github_deploy_key``             → write-capable deploy keys
- ``github_environment_protection`` → unguarded production environments

Important data-shape facts (verified against the connector)
-----------------------------------------------------------
* Branch protection is fetched ONLY for the repository's default branch, so
  there is exactly one ``github_branch_protection`` record per repo. The
  connector normalizes a GitHub 404 (no rule configured) to
  ``protection_enabled=False``. A 403/permission error aborts the whole fetch
  via ConnectorError BEFORE this point, so ``protection_enabled=False`` reliably
  means "no protection configured" rather than "couldn't read it".
* When ``protection_enabled`` is False, all sub-fields are False/None. We
  therefore emit a single "protection missing" finding and do NOT also emit the
  force-push / review / status-check sub-rules (which would be redundant noise).

Deferred GitHub rules (intentionally NOT implemented — see report)
------------------------------------------------------------------
* Repository visibility public: the snapshot has ``visibility`` but NO
  "expected private" signal, so we cannot tell intended-private from
  intentionally-public. Flagging every public repo would be wrong. Deferred
  until an expected-visibility setting exists.
* Broad Actions permissions (``allowed_actions == "all"``): reliably captured,
  but "all" is GitHub's common default and is not, on its own, a current
  danger. Too low-signal / high false-positive to surface as an exposure.
* ``github_ruleset``: overlaps with branch protection semantics and would
  double-count; deferred to avoid conflicting findings.
"""

from __future__ import annotations

from typing import Any

from app.connectors.github_schema import (
    GITHUB_BRANCH_PROTECTION,
    GITHUB_DEPLOY_KEY,
    GITHUB_ENVIRONMENT_PROTECTION,
    GITHUB_WEBHOOK,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule keys ────────────────────────────────────────────────────────────────
_RULE_WEBHOOK_HTTP = "github_webhook_http"
_RULE_BP_MISSING = "github_branch_protection_missing"
_RULE_BP_FORCE_PUSH = "github_force_pushes_allowed"
_RULE_BP_DELETION = "github_branch_deletion_allowed"
_RULE_BP_NO_REVIEW = "github_pr_review_not_required"
_RULE_BP_NO_CHECKS = "github_status_checks_not_required"
_RULE_DEPLOY_KEY_WRITE = "github_deploy_key_write_access"
_RULE_ENV_UNPROTECTED = "github_env_protection_missing"

# Environment names treated as production for the unguarded-environment rule.
_PRODUCTION_ENV_NAMES = {"production", "prod"}


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Dispatch a normalized GitHub record to the relevant rule(s)."""
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == GITHUB_WEBHOOK:
        return _eval_webhook(record)
    if rtype == GITHUB_BRANCH_PROTECTION:
        return _eval_branch_protection(record)
    if rtype == GITHUB_DEPLOY_KEY:
        return _eval_deploy_key(record)
    if rtype == GITHUB_ENVIRONMENT_PROTECTION:
        return _eval_environment(record)
    return []


# ── Webhook over plain HTTP (M60.4) ──────────────────────────────────────────


def _eval_webhook(record: dict[str, Any]) -> list[FindingCandidate]:
    url = get_str(record, "url").strip()
    if not bool(record.get("active", True)):
        return []
    if not url.lower().startswith("http://"):
        return []

    record_id = get_str(record, "record_id") or None
    return [
        FindingCandidate(
            provider="github",
            rule_key=_RULE_WEBHOOK_HTTP,
            finding_key=make_finding_key(_RULE_WEBHOOK_HTTP, record_id),
            severity="critical",
            title="GitHub webhook uses plain HTTP",
            description=(
                "A GitHub webhook delivers events over plain HTTP. Event "
                "payloads and signature headers may be transmitted in cleartext, "
                "allowing interception or tampering."
            ),
            evidence={"rule": _RULE_WEBHOOK_HTTP, "url": url},
            remediation={
                "summary": "Restore HTTPS on the webhook endpoint and verify ownership.",
                "steps": [
                    "Change the webhook delivery URL back to https://.",
                    "Verify the endpoint is owned by your team.",
                    "Rotate the webhook secret if exposure is suspected.",
                ],
            },
            record_id=record_id,
        )
    ]


# ── Default-branch protection posture (M60.4.1) ──────────────────────────────


def _eval_branch_protection(record: dict[str, Any]) -> list[FindingCandidate]:
    # Require the explicit posture flag; ignore malformed/partial records.
    if "protection_enabled" not in record:
        return []

    record_id = get_str(record, "record_id") or None
    branch = get_str(record, "branch") or "default branch"
    out: list[FindingCandidate] = []

    if record.get("protection_enabled") is not True:
        # No protection rule on the default branch. Emit ONE finding; the
        # sub-rules below are meaningless without a rule, so we stop here.
        out.append(
            FindingCandidate(
                provider="github",
                rule_key=_RULE_BP_MISSING,
                finding_key=make_finding_key(_RULE_BP_MISSING, record_id),
                # High (not critical): the connector normalizes 404→disabled, a
                # reliable-but-not-infallible signal; keep severity conservative.
                severity="high",
                title="GitHub default branch has no protection",
                description=(
                    f"The {branch} has no branch protection rule. Commits can be "
                    f"pushed directly without review, and history can be rewritten "
                    f"or the branch deleted."
                ),
                evidence={"rule": _RULE_BP_MISSING, "branch": branch},
                remediation={
                    "summary": "Enable branch protection on the default branch.",
                    "steps": [
                        "Require pull request reviews before merging.",
                        "Require status checks to pass before merging.",
                        "Block force pushes and branch deletion.",
                    ],
                },
                record_id=record_id,
            )
        )
        return out

    # Protection IS enabled — evaluate weakening sub-rules from explicit flags.
    if record.get("allow_force_pushes") is True:
        out.append(
            _bp_sub(
                record_id,
                branch,
                rule=_RULE_BP_FORCE_PUSH,
                severity="high",
                title="GitHub default branch allows force pushes",
                description=(
                    f"Force pushes are permitted on the protected {branch}. "
                    f"History can be rewritten, erasing the audit trail."
                ),
                steps=["Disable 'Allow force pushes' in branch protection."],
                extra={"force_pushes_allowed": True},
            )
        )
    if record.get("allow_deletions") is True:
        out.append(
            _bp_sub(
                record_id,
                branch,
                rule=_RULE_BP_DELETION,
                severity="high",
                title="GitHub default branch allows deletion",
                description=(
                    f"Branch deletion is permitted on the protected {branch}. "
                    f"The protected branch could be removed."
                ),
                steps=["Disable 'Allow deletions' in branch protection."],
                extra={"deletions_allowed": True},
            )
        )

    # PR reviews not required (either the requirement is off, or count is 0/None).
    reviews_enabled = record.get("required_pull_request_reviews_enabled") is True
    review_count = record.get("required_approving_review_count")
    if not reviews_enabled or not isinstance(review_count, int) or review_count < 1:
        out.append(
            _bp_sub(
                record_id,
                branch,
                rule=_RULE_BP_NO_REVIEW,
                severity="high",
                title="GitHub default branch does not require PR review",
                description=(
                    f"The protected {branch} does not require an approving pull "
                    f"request review before merge. Unreviewed code can reach "
                    f"production."
                ),
                steps=[
                    "Require at least one approving review before merging.",
                    "Enable 'Dismiss stale approvals' for added safety.",
                ],
                extra={
                    "required_reviews": review_count
                    if isinstance(review_count, int)
                    else 0,
                },
            )
        )

    if record.get("required_status_checks_enabled") is not True:
        out.append(
            _bp_sub(
                record_id,
                branch,
                rule=_RULE_BP_NO_CHECKS,
                # Medium: missing checks is weaker than missing review/force-push.
                severity="medium",
                title="GitHub default branch does not require status checks",
                description=(
                    f"The protected {branch} does not require status checks to "
                    f"pass before merging. Broken or failing code can be merged."
                ),
                steps=["Require status checks to pass before merging."],
                extra={"status_checks_required": False},
            )
        )

    return out


def _bp_sub(
    record_id: str | None,
    branch: str,
    *,
    rule: str,
    severity: str,
    title: str,
    description: str,
    steps: list[str],
    extra: dict[str, Any],
) -> FindingCandidate:
    return FindingCandidate(
        provider="github",
        rule_key=rule,
        finding_key=make_finding_key(rule, record_id),
        severity=severity,
        title=title,
        description=description,
        evidence={"rule": rule, "branch": branch, **extra},
        remediation={"summary": title + ".", "steps": steps},
        record_id=record_id,
    )


# ── Deploy key with write access (M60.4.1) ───────────────────────────────────


def _eval_deploy_key(record: dict[str, Any]) -> list[FindingCandidate]:
    # read_only must be explicitly present and False to flag (connector defaults
    # missing read_only to True, so a partial record is safe and ignored).
    if "read_only" not in record:
        return []
    if record.get("read_only") is not False:
        return []

    record_id = get_str(record, "record_id") or None
    title = get_str(record, "title") or get_str(record, "name") or "deploy key"
    key_id = record.get("key_id")
    verified = bool(record.get("verified", False))

    evidence: dict[str, Any] = {
        "rule": _RULE_DEPLOY_KEY_WRITE,
        "key_title": title,
        "verified": verified,
    }
    if isinstance(key_id, int):
        evidence["key_id"] = key_id

    return [
        FindingCandidate(
            provider="github",
            rule_key=_RULE_DEPLOY_KEY_WRITE,
            finding_key=make_finding_key(_RULE_DEPLOY_KEY_WRITE, record_id),
            severity="high",
            title="GitHub deploy key has write access",
            description=(
                f"The deploy key '{title}' has read-write access to the "
                f"repository. A leaked write-capable deploy key allows pushing "
                f"malicious code."
            ),
            evidence=evidence,
            remediation={
                "summary": "Restrict the deploy key to read-only or remove it.",
                "steps": [
                    "Confirm the key needs write access; most do not.",
                    "Recreate it as read-only if write is unnecessary.",
                    "Remove the key if it is unused.",
                ],
            },
            record_id=record_id,
        )
    ]


# ── Unguarded production environment (M60.4.1) ───────────────────────────────


def _eval_environment(record: dict[str, Any]) -> list[FindingCandidate]:
    # Narrow, conservative: only environments explicitly named production/prod.
    env_name = (get_str(record, "environment_name") or get_str(record, "name")).strip()
    if env_name.lower() not in _PRODUCTION_ENV_NAMES:
        return []

    reviewers = record.get("reviewers_count")
    wait_timer = record.get("wait_timer")
    # Require the explicit numeric fields; ignore malformed records.
    if not isinstance(reviewers, int) or not isinstance(wait_timer, int):
        return []

    protected_branches = record.get("protected_branches") is True
    custom_policies = record.get("custom_branch_policies") is True
    has_branch_policy = protected_branches or custom_policies

    # Unguarded = no required reviewers AND no wait timer AND no branch policy.
    if reviewers > 0 or wait_timer > 0 or has_branch_policy:
        return []

    record_id = get_str(record, "record_id") or None
    return [
        FindingCandidate(
            provider="github",
            rule_key=_RULE_ENV_UNPROTECTED,
            finding_key=make_finding_key(_RULE_ENV_UNPROTECTED, record_id),
            # Medium: lack of env guard rails is a real weakening but not an
            # immediate exposure of data.
            severity="medium",
            title="GitHub production environment has no protection rules",
            description=(
                f"The '{env_name}' environment has no required reviewers, wait "
                f"timer, or deployment branch policy. Anyone able to run a "
                f"workflow can deploy to production without approval."
            ),
            evidence={
                "rule": _RULE_ENV_UNPROTECTED,
                "environment": env_name,
                "required_reviewers": reviewers,
                "wait_timer_minutes": wait_timer,
                "has_branch_policy": has_branch_policy,
            },
            remediation={
                "summary": "Add deployment protection rules to the production environment.",
                "steps": [
                    "Require at least one reviewer before deployment.",
                    "Restrict deployments to protected branches.",
                    "Consider a wait timer for an abort window.",
                ],
            },
            record_id=record_id,
        )
    ]
