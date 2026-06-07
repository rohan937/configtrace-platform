"""Vercel security exposure rules — M60.4.5.

Every rule fires only on explicit, reliable normalized fields produced by the
Vercel connector (app/connectors/vercel.py + vercel_schema.py). Evidence is
metadata-only: project name + deployment-protection booleans. No tokens, env
var values, or trusted-IP lists are ever read (the connector stores only a hash
of the CIDR list, which we never surface).

Record types consumed
---------------------
- ``vercel_deployment_protection`` → preview deployments reachable without auth

Deferred Vercel rules (intentionally NOT implemented — see report)
-----------------------------------------------------------------
* Production domain HTTPS / cert issue: ``vercel_domain`` carries ``verified``,
  ``redirect``, ``git_branch`` — but NO HTTPS/cert-status field (Vercel
  auto-provisions TLS), so this cannot be evaluated.
* Production branch unprotected/changed: no normalized "production branch
  protection" signal exists; branch changes are drift, not a current exposure.
* Deploy hook exposed: ``vercel_deploy_hook_metadata`` stores only id/name/ref.
  Every deploy hook is by nature an unauthenticated trigger URL, so flagging
  their mere existence would be noise — there is no risky-state signal.
* ``protection_bypass_for_automation``: a deliberate automation feature with no
  reliable "is this currently risky" signal; deferred to avoid false positives.
* Env var removed/missing: drift, not a current exposure.
"""

from __future__ import annotations

from typing import Any

from app.connectors.vercel_schema import VERCEL_DEPLOYMENT_PROTECTION
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

_RULE_PREVIEW_UNPROTECTED = "vercel_preview_unprotected"


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    if record.get("record_type") != VERCEL_DEPLOYMENT_PROTECTION:
        return []
    return _eval_protection(record)


def _eval_protection(record: dict[str, Any]) -> list[FindingCandidate]:
    # Require the authoritative flag; ignore malformed/partial records.
    if "preview_deployments_protected" not in record:
        return []

    protected = record.get("preview_deployments_protected") is True
    sso = record.get("sso_enabled") is True
    password = record.get("password_enabled") is True
    # Any protection mechanism active → not an exposure.
    if protected or sso or password:
        return []

    record_id = get_str(record, "record_id") or None
    project = get_str(record, "name") or record_id or "the project"

    return [
        FindingCandidate(
            provider="vercel",
            rule_key=_RULE_PREVIEW_UNPROTECTED,
            finding_key=make_finding_key(_RULE_PREVIEW_UNPROTECTED, record_id),
            # Medium: preview deployments often contain unreleased features and
            # may be reachable without auth, but they are not production data.
            severity="medium",
            title="Vercel preview deployments are not protected",
            description=(
                f"Preview deployments for '{project}' have no Vercel "
                f"Authentication, password, or preview protection enabled. "
                f"Preview URLs may be publicly accessible and could expose "
                f"unreleased features or non-production data."
            ),
            evidence={
                "rule": _RULE_PREVIEW_UNPROTECTED,
                "project": project,
                "preview_deployments_protected": False,
                "sso_enabled": False,
                # NOTE: do not use a key containing "password" — the UI masks
                # secret-looking keys. Convey the (empty) protection set instead.
                "active_protections": [],
            },
            remediation={
                "summary": "Enable protection for preview deployments.",
                "steps": [
                    "Enable Vercel Authentication or password protection for previews.",
                    "Restrict preview access to your team if not needed publicly.",
                ],
            },
            record_id=record_id,
        )
    ]
