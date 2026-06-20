"""Vercel security exposure rules — M60.4.5 + M70A.

Every rule fires only on explicit, reliable normalized fields produced by the
Vercel connector (app/connectors/vercel.py + vercel_schema.py). Evidence is
metadata-only: project name, branch names, env var KEY names + target
environments, deploy hook names/refs, and deployment-protection booleans. The
connector never reads or stores env var VALUES, deploy hook URLs (auth tokens),
trusted-IP lists (only a hash), tokens, or authorization headers — so none of
those can reach a finding.

CLAIM DISCIPLINE: a finding is evidence for review of a configuration that may
increase production-change risk. It never asserts that a secret was exposed,
that anyone gained access, that access was unauthorized, or that a breach or
attack occurred.

Record types consumed
---------------------
- ``vercel_project``               → production-branch posture
- ``vercel_domain``                → unverified production domain
- ``vercel_env_var``               → broad env-var target / sensitive-key scope
- ``vercel_deploy_hook_metadata``  → deploy hook targeting the production branch
- ``vercel_deployment_protection`` → preview deployments reachable without auth

Deferred Vercel rules (intentionally NOT implemented — see report)
-----------------------------------------------------------------
* ``vercel_project_protection_missing`` (production/deployment protection
  disabled): the ``vercel_deployment_protection`` record already drives
  ``vercel_preview_unprotected``, which fires when every protection mechanism is
  off. A separate "protection missing" rule on the same record would double-flag
  the identical state, so it is deferred to avoid redundant noise.
* Production domain HTTPS / cert issue: ``vercel_domain`` carries no HTTPS/cert
  field (Vercel auto-provisions TLS), so this cannot be evaluated.
* Deploy hook *existence*: every deploy hook is by nature an unauthenticated
  trigger URL; flagging mere existence is noise. Only a hook targeting the
  PRODUCTION branch is treated as a reviewable risk (a narrower, data-backed
  subset — see ``vercel_deploy_hook_production_branch``).
* ``protection_bypass_for_automation``: a deliberate automation feature with no
  reliable "is this currently risky" signal; deferred to avoid false positives.
* Env var removed/missing: drift, not a current exposure.
"""

from __future__ import annotations

import re
from typing import Any

from app.connectors.vercel_schema import (
    VERCEL_DEPLOY_HOOK_METADATA,
    VERCEL_DEPLOYMENT_PROTECTION,
    VERCEL_DOMAIN,
    VERCEL_ENV_VAR,
    VERCEL_PROJECT,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

_RULE_PREVIEW_UNPROTECTED = "vercel_preview_unprotected"
_RULE_PRODUCTION_BRANCH_MISSING = "vercel_production_branch_missing"
_RULE_PRODUCTION_BRANCH_UNUSUAL = "vercel_production_branch_unusual"
_RULE_DOMAIN_UNVERIFIED = "vercel_domain_unverified"
_RULE_ENV_VAR_BROAD_TARGET = "vercel_env_var_broad_target"
_RULE_SENSITIVE_ENV_VAR_BROAD_SCOPE = "vercel_sensitive_env_var_broad_scope"
_RULE_DEPLOY_HOOK_PRODUCTION_BRANCH = "vercel_deploy_hook_production_branch"

# Branch names that are conventionally the production branch — treated as normal.
_PRODUCTION_BRANCH_NAMES = frozenset({
    "main", "master", "prod", "production", "release", "trunk", "stable", "live",
})
# Branch names that are conventionally NOT production — flagged if set as the
# production branch.
_NON_PRODUCTION_BRANCH_NAMES = frozenset({
    "dev", "develop", "development", "test", "testing", "staging", "stage",
    "preview", "qa", "uat", "sandbox", "demo", "feature", "next", "canary",
})

# Non-production environment targets (env var scope).
_NON_PROD_TARGETS = frozenset({"preview", "development"})

# Substrings / whole tokens in an env var KEY name that suggest secret material.
# We never read the value — only the key name is inspected.
_SENSITIVE_SUBSTRINGS = (
    "secret", "token", "password", "passwd", "webhook", "signing", "credential",
    "private_key", "privatekey", "api_key", "apikey", "access_key", "accesskey",
    "database_url", "db_password", "db_url", "dsn", "auth_token",
)
_SENSITIVE_TOKENS = frozenset({
    "secret", "token", "password", "passwd", "pwd", "key", "keys", "webhook",
    "signing", "credential", "credentials", "private", "dsn", "auth", "cert",
})

# Public/benign key prefixes. Variables whose name starts with one of these is
# treated as public-by-convention and is NOT flagged as a high-severity secret —
# these prefixes are the framework-standard markers for values that are
# deliberately inlined into client bundles (so they cannot be secrets).
#
# DECISION: the prefix is authoritative. A name like ``NEXT_PUBLIC_SECRET_KEY``
# is NOT treated as sensitive — the framework would expose its value to the
# browser regardless of the substring, so flagging it as a broadly-scoped secret
# would be a false positive. We err toward NOT flagging only for these explicit
# public-by-convention prefixes; every other name keeps the conservative
# substring/token check.
_PUBLIC_KEY_PREFIXES = (
    "NEXT_PUBLIC_",
    "PUBLIC_",
    "VITE_",
    "REACT_APP_",
)

# Benign exact prefixes for clearly non-credential metadata (caching / redirect
# URLs). Kept narrow on purpose — see the carve-outs below.
_BENIGN_KEY_PREFIXES = (
    "AUTH_REDIRECT_",   # clearly a URL, not a credential
    "AUTH_CALLBACK_",   # clearly a URL, not a credential
)


def _is_public_or_benign_key(key: str) -> bool:
    """Return True when *key* is a public/benign name that must not be treated
    as a sensitive secret for the high-severity env-var finding."""
    ku = key.upper()
    if any(ku.startswith(p) for p in _PUBLIC_KEY_PREFIXES):
        return True
    if any(ku.startswith(p) for p in _BENIGN_KEY_PREFIXES):
        return True
    # CACHE_* is benign caching metadata, EXCEPT when it carries an explicit
    # credential token (e.g. CACHE_SECRET, CACHE_KEY used for auth).
    if ku.startswith("CACHE_"):
        rest = ku[len("CACHE_"):]
        if not any(t in rest for t in ("SECRET", "KEY", "TOKEN", "PASSWORD")):
            return True
    return False


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == VERCEL_DEPLOYMENT_PROTECTION:
        return _eval_protection(record)
    if rtype == VERCEL_PROJECT:
        return _eval_project(record)
    if rtype == VERCEL_DOMAIN:
        return _eval_domain(record)
    if rtype == VERCEL_ENV_VAR:
        return _eval_env_var(record)
    if rtype == VERCEL_DEPLOY_HOOK_METADATA:
        return _eval_deploy_hook(record)
    return []


# ── vercel_deployment_protection ─────────────────────────────────────────────


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


# ── vercel_project (production branch posture) ───────────────────────────────


def _eval_project(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or None
    project = get_str(record, "name") or record_id or "the project"
    git_repository = get_str(record, "git_repository")
    git_branch = get_str(record, "git_branch").strip()

    # Only meaningful for git-connected projects (production branch is a git
    # concept). Projects without a connected repository have no production
    # branch to evaluate.
    if not git_repository:
        return []

    # A. Production branch missing — git repo connected but no production branch.
    if not git_branch:
        return [
            FindingCandidate(
                provider="vercel",
                rule_key=_RULE_PRODUCTION_BRANCH_MISSING,
                finding_key=make_finding_key(_RULE_PRODUCTION_BRANCH_MISSING, record_id),
                severity="medium",
                title="Vercel project has no production branch configured",
                description=(
                    f"Project '{project}' is connected to a git repository but "
                    f"has no production branch set. Production deployments may "
                    f"track an unexpected branch. This is a configuration to "
                    f"review; it does not confirm unauthorized access or compromise."
                ),
                evidence={
                    "rule": _RULE_PRODUCTION_BRANCH_MISSING,
                    "project": project,
                    "git_repository_connected": True,
                    "production_branch_set": False,
                },
                remediation={
                    "summary": "Set an explicit production branch for the project.",
                    "steps": [
                        "Open the project's Git settings in Vercel.",
                        "Set the production branch to your intended release branch "
                        "(for example, main or master).",
                    ],
                },
                record_id=record_id,
            )
        ]

    # B. Production branch points to a conventionally non-production branch.
    if git_branch.lower() in _NON_PRODUCTION_BRANCH_NAMES:
        return [
            FindingCandidate(
                provider="vercel",
                rule_key=_RULE_PRODUCTION_BRANCH_UNUSUAL,
                finding_key=make_finding_key(_RULE_PRODUCTION_BRANCH_UNUSUAL, record_id),
                severity="medium",
                title="Vercel production branch looks non-production",
                description=(
                    f"Project '{project}' uses '{git_branch}' as its production "
                    f"branch, which matches a conventionally non-production name. "
                    f"Production deployments may track development or staging code. "
                    f"This is a setting to review; it does not confirm compromise."
                ),
                evidence={
                    "rule": _RULE_PRODUCTION_BRANCH_UNUSUAL,
                    "project": project,
                    "production_branch": git_branch,
                },
                remediation={
                    "summary": "Confirm the production branch is intentional.",
                    "steps": [
                        "Verify the production branch should be this branch.",
                        "If not, point the production branch at your release "
                        "branch (for example, main or master).",
                    ],
                },
                record_id=record_id,
            )
        ]

    return []


# ── vercel_domain ─────────────────────────────────────────────────────────────


def _eval_domain(record: dict[str, Any]) -> list[FindingCandidate]:
    # Only an explicit verified=False fires; verified or unknown is skipped.
    if record.get("verified") is not False:
        return []
    # Redirect-only domains are aliases, not a production-serving surface, so an
    # unverified redirect alias is not a reviewable exposure. Only skip on an
    # explicit redirect_only=True; a missing field falls through and fires
    # (conservative — err toward detection when redirect status is unknown).
    if record.get("redirect_only") is True:
        return []
    record_id = get_str(record, "record_id") or None
    domain = get_str(record, "name") or record_id or "a domain"

    return [
        FindingCandidate(
            provider="vercel",
            rule_key=_RULE_DOMAIN_UNVERIFIED,
            finding_key=make_finding_key(_RULE_DOMAIN_UNVERIFIED, record_id),
            severity="medium",
            title="Vercel domain is not verified",
            description=(
                f"Domain '{domain}' is attached to the project but is not "
                f"verified. Unverified domains may not serve traffic correctly "
                f"and can indicate an incomplete or stale domain configuration. "
                f"This is evidence for review and does not confirm compromise."
            ),
            evidence={
                "rule": _RULE_DOMAIN_UNVERIFIED,
                "domain": domain,
                "verified": False,
            },
            remediation={
                "summary": "Verify the domain or remove it if unused.",
                "steps": [
                    "Complete DNS verification for the domain in Vercel.",
                    "Remove the domain from the project if it is no longer used.",
                ],
            },
            record_id=record_id,
        )
    ]


# ── vercel_env_var ──────────────────────────────────────────────────────────


def _targets(record: dict[str, Any]) -> set[str]:
    raw = record.get("target")
    if isinstance(raw, str):
        return {raw.lower()}
    if isinstance(raw, (list, tuple)):
        return {str(t).lower() for t in raw if isinstance(t, str)}
    return set()


def _is_sensitive_key(key: str) -> bool:
    # Public/benign prefixes short-circuit the sensitivity check so names like
    # NEXT_PUBLIC_KEY / PUBLIC_SITE_URL / VITE_API_URL are not flagged.
    if _is_public_or_benign_key(key):
        return False
    kl = key.lower()
    if any(s in kl for s in _SENSITIVE_SUBSTRINGS):
        return True
    tokens = [t for t in re.split(r"[^a-z0-9]+", kl) if t]
    return any(t in _SENSITIVE_TOKENS for t in tokens)


def _eval_env_var(record: dict[str, Any]) -> list[FindingCandidate]:
    targets = _targets(record)
    if not targets:
        return []
    key = get_str(record, "key") or get_str(record, "name")
    record_id = get_str(record, "record_id") or None
    spans_non_prod = bool(targets & _NON_PROD_TARGETS)
    out: list[FindingCandidate] = []

    # E. Sensitive-looking key scoped beyond production (high). Checked first so
    #    its higher-severity signal is the primary one for secret-suggestive keys.
    if key and _is_sensitive_key(key) and spans_non_prod:
        out.append(
            FindingCandidate(
                provider="vercel",
                rule_key=_RULE_SENSITIVE_ENV_VAR_BROAD_SCOPE,
                finding_key=make_finding_key(_RULE_SENSITIVE_ENV_VAR_BROAD_SCOPE, record_id),
                severity="high",
                title="Sensitive-looking Vercel env var is broadly scoped",
                description=(
                    f"Environment variable '{key}' has a secret-suggestive name "
                    f"and is scoped to non-production environments "
                    f"({_fmt_targets(targets)}). Its metadata suggests broad "
                    f"scope. ConfigTrace never reads env var values; this is "
                    f"evidence for review and does not confirm that a secret was "
                    f"exposed or that any access was unauthorized."
                ),
                evidence={
                    "rule": _RULE_SENSITIVE_ENV_VAR_BROAD_SCOPE,
                    "env_var_name": key,
                    "target": sorted(targets),
                },
                remediation={
                    "summary": "Scope sensitive env vars to production only.",
                    "steps": [
                        "Review whether this variable needs to exist in preview "
                        "or development.",
                        "Use separate, non-production values for non-production "
                        "environments where possible.",
                    ],
                },
                record_id=record_id,
            )
        )

    # D. Broad target — spans production AND a non-production environment.
    if "production" in targets and spans_non_prod:
        out.append(
            FindingCandidate(
                provider="vercel",
                rule_key=_RULE_ENV_VAR_BROAD_TARGET,
                finding_key=make_finding_key(_RULE_ENV_VAR_BROAD_TARGET, record_id),
                severity="medium",
                title="Vercel env var spans production and non-production",
                description=(
                    f"Environment variable '{key or record_id}' is targeted at "
                    f"production and at least one non-production environment "
                    f"({_fmt_targets(targets)}). A single value shared across "
                    f"environments increases production-change risk. ConfigTrace "
                    f"never reads env var values; this is evidence for review."
                ),
                evidence={
                    "rule": _RULE_ENV_VAR_BROAD_TARGET,
                    "env_var_name": key,
                    "target": sorted(targets),
                },
                remediation={
                    "summary": "Use environment-specific values where possible.",
                    "steps": [
                        "Confirm this variable should share one value across "
                        "environments.",
                        "Define separate production and non-production values if "
                        "they should differ.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


def _fmt_targets(targets: set[str]) -> str:
    return ", ".join(sorted(targets))


# ── vercel_deploy_hook_metadata ──────────────────────────────────────────────


def _eval_deploy_hook(record: dict[str, Any]) -> list[FindingCandidate]:
    ref = get_str(record, "hook_ref").strip()
    if not ref or ref.lower() not in _PRODUCTION_BRANCH_NAMES:
        return []
    record_id = get_str(record, "record_id") or None
    hook_name = get_str(record, "hook_name") or get_str(record, "name") or "a deploy hook"

    return [
        FindingCandidate(
            provider="vercel",
            rule_key=_RULE_DEPLOY_HOOK_PRODUCTION_BRANCH,
            finding_key=make_finding_key(_RULE_DEPLOY_HOOK_PRODUCTION_BRANCH, record_id),
            severity="medium",
            title="Vercel deploy hook targets the production branch",
            description=(
                f"Deploy hook '{hook_name}' targets the production branch "
                f"'{ref}'. A deploy hook may allow a production deployment if its "
                f"URL is invoked. ConfigTrace never stores the hook URL; this is "
                f"evidence for review and does not confirm unauthorized access or "
                f"compromise."
            ),
            evidence={
                "rule": _RULE_DEPLOY_HOOK_PRODUCTION_BRANCH,
                "hook_name": hook_name,
                "hook_ref": ref,
            },
            remediation={
                "summary": "Confirm production deploy hooks are intended and limited.",
                "steps": [
                    "Verify this deploy hook should trigger production deployments.",
                    "Rotate or remove the hook if it is unused, and keep its URL "
                    "secret.",
                ],
            },
            record_id=record_id,
        )
    ]
