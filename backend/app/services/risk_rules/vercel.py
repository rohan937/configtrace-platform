"""Vercel risk classification rules — M33 (precision pass).

Classifies a Change (ORM object or plain dict) for a Vercel integration into
one of four risk levels.  Classification is driven by a structured risk matrix
that weighs:

  * record_type  — vercel_project / vercel_env_var / vercel_domain
  * field_path   — which field changed
  * change_type  — added / removed / modified
  * value direction — old → new (e.g. protection disabled, branch changed)
  * environment  — production vs. preview/development for env vars and domains
  * sensitivity  — whether the env var name looks like a secret/credential

Keywords are **one signal among several**, not the whole model.  An env var
named ``FEATURE_FLAG`` removed from production is still "high" even though the
name is not sensitive, because removing a production variable can break the app.

Risk levels
-----------
critical  — likely to break production immediately or expose the system
high      — production-affecting change; warrants immediate review
medium    — bounded impact; generally reversible; worth noting
low       — additive, hardening, or routine metadata; low urgency

Design decisions
----------------
* ``classify_vercel_change`` accepts both ORM ``Change`` objects and plain
  dicts — the ``_get`` helper provides unified attribute/key access so unit
  tests can pass simple dicts without DB fixtures.

* For env var changes the *current target* list is read from:
    - ``prev_value["target"]`` (for removed changes — that was the old state)
    - ``new_value["target"]``  (for added   changes — that is the new state)
    - ``prev_value`` / ``new_value`` directly when field_path == "target"
  This avoids relying on ``record_content`` which may not always be populated.

* Domain "production vs. preview" is determined by whether the domain record's
  ``git_branch`` field is set.  A domain without a branch is a global/production
  custom domain; one with a branch is a preview-branch domain.

Preview / non-production env var intentional design
----------------------------------------------------
Preview and development environment variable changes are deliberately classified
at a lower severity than production changes:

  * Preview env var **added**   → ``low``
    Adding a variable to a preview environment is routine during development.
    It does not affect production deployments.

  * Preview env var **removed** → ``medium``
    Removing a preview variable may break preview/staging deployments but
    cannot directly break production.  "medium" prompts investigation without
    triggering a high-priority alert.

These levels are *intentionally* not ``critical`` or ``high``.  Manual QA
confirmed: TEST_CONFIGTRACE_VAR add/remove in Preview → Medium is correct.
"""

from __future__ import annotations

from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Attribute-access helper (supports both ORM objects and plain dicts)
# ─────────────────────────────────────────────────────────────────────────────

def _get(obj: Any, key: str) -> Any:
    """Return *obj[key]* for dicts, or ``getattr(obj, key, None)`` for objects."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


# ─────────────────────────────────────────────────────────────────────────────
# Sensitive env var detection
# ─────────────────────────────────────────────────────────────────────────────

#: Substrings that indicate a sensitive or security-relevant environment
#: variable name.  Matched case-insensitively against the env var key.
#:
#: Keywords are intentionally broad (e.g. KEY, TOKEN) to catch variations
#: such as STRIPE_API_KEY, AUTH_TOKEN, NEXT_PUBLIC_CLERK_KEY.
#: False-positive rate is low in practice because production env var names
#: are almost always uppercase + underscore and semantically descriptive.
_SENSITIVE_PATTERNS: tuple[str, ...] = (
    # Environment markers
    "PRODUCTION", "PROD",
    # Data / storage
    "DATABASE", "DB", "URL", "HOST", "DOMAIN",
    # Auth / identity
    "AUTH", "SESSION", "JWT", "TOKEN", "SECRET", "PASSWORD", "PWD",
    # Cryptographic material
    "KEY", "API_KEY", "PRIVATE_KEY",
    # Third-party service credentials
    "STRIPE", "CLOUDFLARE", "AWS", "VERCEL",
    "SUPABASE", "FIREBASE", "OPENAI",
    "CLERK", "RESEND",
    # Webhooks and callbacks
    "WEBHOOK",
    # Next.js public env vars (client-side exposure of any value is sensitive)
    "NEXT_PUBLIC",
)


def _is_sensitive_env_var(key_name: str) -> bool:
    """Return True if *key_name* contains a known sensitive pattern."""
    upper = (key_name or "").upper()
    return any(pat in upper for pat in _SENSITIVE_PATTERNS)


def _targets_production(target: Any) -> bool:
    """Return True if *target* includes the string ``'production'``."""
    if isinstance(target, list):
        return "production" in target
    if isinstance(target, str):
        return target == "production"
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Per-record-type classifiers
# ─────────────────────────────────────────────────────────────────────────────

def _classify_env_var_change(
    change_type: str,
    field_path: str | None,
    prev_value: Any,
    new_value: Any,
    record_name: str,
) -> tuple[str, str]:
    """Classify a ``vercel_env_var`` change."""

    is_sensitive = _is_sensitive_env_var(record_name)
    name = record_name or "(unnamed)"

    # ── removed ──────────────────────────────────────────────────────────────
    if change_type == "removed":
        prev_rec = prev_value if isinstance(prev_value, dict) else {}
        target_list = prev_rec.get("target", [])
        in_prod = _targets_production(target_list)

        if in_prod and is_sensitive:
            return (
                "critical",
                f"Sensitive production environment variable '{name}' was removed. "
                "Runtime code that depends on this variable will likely fail or crash. "
                "Check for application errors and restore the variable if it was removed unintentionally.",
            )
        if in_prod:
            return (
                "high",
                f"Production environment variable '{name}' was removed. "
                "Any runtime code depending on this variable may fail. "
                "Verify the removal was intentional and that nothing in the deployment relies on it.",
            )
        return (
            "medium",
            f"Environment variable '{name}' was removed from a non-production environment. "
            "Confirm this is intentional and that no preview or development workflows depend on it.",
        )

    # ── added ─────────────────────────────────────────────────────────────────
    if change_type == "added":
        new_rec = new_value if isinstance(new_value, dict) else {}
        target_list = new_rec.get("target", [])
        in_prod = _targets_production(target_list)

        if in_prod and is_sensitive:
            return (
                "medium",
                f"Sensitive environment variable '{name}' was added to the production environment. "
                "Confirm this credential is expected, intentional, and scoped correctly. "
                "Review who has access to modify production environment variables.",
            )
        if in_prod:
            return (
                "medium",
                f"Environment variable '{name}' was added to the production environment. "
                "Verify this is an expected configuration change.",
            )
        return (
            "low",
            f"Environment variable '{name}' was added to a non-production environment.",
        )

    # ── modified ──────────────────────────────────────────────────────────────
    if change_type == "modified":
        # Target list changed — env var promoted or demoted between environments
        if field_path == "target":
            old_targets = prev_value if isinstance(prev_value, list) else []
            new_targets = new_value if isinstance(new_value, list) else []
            was_prod = "production" in (old_targets or [])
            now_prod = "production" in (new_targets or [])

            if now_prod and not was_prod:
                return (
                    "high",
                    f"Environment variable '{name}' was promoted to production "
                    f"(target changed from {old_targets} to {new_targets}). "
                    "Production code will now read this variable. "
                    "Verify the value is production-safe and expected.",
                )
            if was_prod and not now_prod:
                return (
                    "high",
                    f"Environment variable '{name}' was removed from production "
                    f"(target changed from {old_targets} to {new_targets}). "
                    "Production code that relied on this variable may fail. "
                    "Check for runtime errors after this change.",
                )
            return (
                "medium",
                f"Environment variable '{name}' target environments changed "
                f"from {old_targets} to {new_targets}.",
            )

        # updated_at changed — the value was rotated (we never see the new value)
        if field_path == "updated_at":
            if is_sensitive:
                return (
                    "high",
                    f"Sensitive environment variable '{name}' was updated. "
                    "The secret value may have been rotated. "
                    "Confirm all services consuming this credential have been updated "
                    "and that the rotation was authorized.",
                )
            return (
                "medium",
                f"Environment variable '{name}' was updated. "
                "The value may have changed. Verify dependent services are still functioning.",
            )

        # env_type changed (most notable: encrypted → plain is a security downgrade)
        if field_path == "env_type":
            if new_value == "plain" and prev_value in ("encrypted", "secret"):
                return (
                    "high",
                    f"Environment variable '{name}' type changed from '{prev_value}' to 'plain'. "
                    "A previously encrypted secret is now stored as plaintext — "
                    "this is a security downgrade. Review whether this variable contains "
                    "sensitive data and re-encrypt if necessary.",
                )
            if prev_value == "plain" and new_value in ("encrypted", "secret"):
                return (
                    "low",
                    f"Environment variable '{name}' type was upgraded from 'plain' to '{new_value}'. "
                    "The variable is now encrypted at rest.",
                )
            return (
                "medium",
                f"Environment variable '{name}' type changed from '{prev_value}' to '{new_value}'.",
            )

        # key renamed
        if field_path == "key":
            return (
                "medium",
                f"Environment variable was renamed from '{prev_value}' to '{new_value}'. "
                "Any code referencing the old variable name will break. "
                "Ensure all references have been updated.",
            )

        # git_branch scope changed (branch-specific env var)
        if field_path == "git_branch":
            return (
                "medium",
                f"Environment variable '{name}' is now scoped to a different branch "
                f"(changed from '{prev_value}' to '{new_value}'). "
                "Verify preview deployments still receive the correct configuration.",
            )

        # Catch-all for other env var fields
        return (
            "medium",
            f"Environment variable '{name}' configuration changed (field: {field_path}).",
        )

    # Unknown change_type
    return (
        "low",
        f"Environment variable '{name}' was {change_type}.",
    )


def _classify_project_change(
    change_type: str,
    field_path: str | None,
    prev_value: Any,
    new_value: Any,
    record_name: str,
) -> tuple[str, str]:
    """Classify a ``vercel_project`` change."""

    proj = record_name or "project"

    if change_type == "modified":
        # ── Build pipeline — supply-chain / deployment critical ────────────────
        if field_path == "build_command":
            prev_str = f"'{prev_value}'" if prev_value is not None else "the default"
            new_str  = f"'{new_value}'"  if new_value  is not None else "the default"
            return (
                "high",
                f"The build command changed from {prev_str} to {new_str}. "
                "Future deployments will execute a different build process. "
                "Verify this change is intentional and does not introduce unexpected steps.",
            )

        if field_path == "install_command":
            prev_str = f"'{prev_value}'" if prev_value is not None else "the default"
            new_str  = f"'{new_value}'"  if new_value  is not None else "the default"
            return (
                "high",
                f"The install command changed from {prev_str} to {new_str}. "
                "Future deployments will run a different installation step, "
                "which may fetch different package versions or fail entirely. "
                "Verify the new command is correct.",
            )

        if field_path == "root_directory":
            prev_str = f"'{prev_value}'" if prev_value else "the repository root"
            new_str  = f"'{new_value}'"  if new_value  else "the repository root"
            return (
                "high",
                f"The root directory changed from {prev_str} to {new_str}. "
                "Vercel will now look for source files in a different location. "
                "Monorepo builds may fail if the path is incorrect.",
            )

        if field_path == "output_directory":
            prev_str = f"'{prev_value}'" if prev_value else "the framework default"
            new_str  = f"'{new_value}'"  if new_value  else "the framework default"
            return (
                "medium",
                f"The output directory changed from {prev_str} to {new_str}. "
                "Verify the build still produces files in the expected location.",
            )

        # ── Framework and runtime ──────────────────────────────────────────────
        if field_path == "framework":
            prev_str = prev_value or "None (other)"
            new_str  = new_value  or "None (other)"
            return (
                "high",
                f"The framework preset changed from '{prev_str}' to '{new_str}'. "
                "This changes how Vercel builds and routes the project. "
                "Verify build configuration, routing rules, and output structure are still correct.",
            )

        if field_path == "node_version":
            return (
                "medium",
                f"The Node.js runtime version changed from '{prev_value}' to '{new_value}'. "
                "Check that all dependencies and build scripts are compatible with the new runtime.",
            )

        # ── Project identity ───────────────────────────────────────────────────
        if field_path == "name":
            return (
                "medium",
                f"The project name changed from '{prev_value}' to '{new_value}'. "
                "Vercel deployment URLs derived from the project name may change. "
                "Check any hardcoded references to the old project name.",
            )

        # ── Git connection ─────────────────────────────────────────────────────
        if field_path == "git_branch":
            return (
                "high",
                f"The production branch changed from '{prev_value}' to '{new_value}'. "
                "Future production deployments will be built from a different branch. "
                "Confirm this matches your intended release workflow.",
            )

        if field_path == "git_repository":
            return (
                "high",
                f"The connected Git repository changed from '{prev_value}' to '{new_value}'. "
                "Future deployments will source code from a different repository. "
                "Verify this was an intentional migration and not unauthorized.",
            )

        # ── Deployment protection ──────────────────────────────────────────────
        if field_path == "sso_protection":
            was_enabled = bool(prev_value)
            now_enabled = bool(new_value)
            if was_enabled and not now_enabled:
                return (
                    "critical",
                    f"Deployment SSO protection was disabled for project '{proj}'. "
                    "Production deployments may now be accessible without SSO authentication. "
                    "Verify this was intentional and that access control is still adequate.",
                )
            if not was_enabled and now_enabled:
                return (
                    "low",
                    f"Deployment SSO protection was enabled for project '{proj}' "
                    f"(type: '{new_value}'). "
                    "Access to deployments now requires SSO authentication.",
                )
            # Protection changed type (e.g. "preview" → "all")
            return (
                "medium",
                f"Deployment SSO protection scope changed from '{prev_value}' to '{new_value}'.",
            )

        if field_path == "password_protection":
            was_enabled = bool(prev_value)
            now_enabled = bool(new_value)
            if was_enabled and not now_enabled:
                return (
                    "high",
                    f"Password protection was disabled for project '{proj}'. "
                    "Deployments that were previously password-gated may now be publicly accessible. "
                    "Verify this was intentional.",
                )
            if not was_enabled and now_enabled:
                return (
                    "low",
                    f"Password protection was enabled for project '{proj}' "
                    f"(type: '{new_value}'). "
                    "Deployments now require a password to access.",
                )
            return (
                "medium",
                f"Password protection scope changed from '{prev_value}' to '{new_value}'.",
            )

        # Catch-all for other project fields
        return (
            "low",
            f"Project setting '{field_path}' was modified.",
        )

    # Project record added or removed (unusual — project records are stable)
    return (
        "low",
        f"Vercel project record was {change_type}.",
    )


def _classify_domain_change(
    change_type: str,
    field_path: str | None,
    prev_value: Any,
    new_value: Any,
    record_name: str,
    provider_metadata: dict,
) -> tuple[str, str]:
    """Classify a ``vercel_domain`` change."""

    domain = record_name or "(unknown domain)"

    if change_type == "removed":
        prev_rec = prev_value if isinstance(prev_value, dict) else {}
        is_preview = bool(prev_rec.get("git_branch"))
        if not is_preview:
            return (
                "critical",
                f"Production domain '{domain}' was removed from the project. "
                "Traffic to this domain will stop routing to the Vercel project. "
                "DNS will return NXDOMAIN or resolve to a different destination. "
                "Restore the domain immediately if this was unintentional.",
            )
        return (
            "medium",
            f"Preview branch domain '{domain}' was removed from the project. "
            "Traffic to this branch-specific domain will no longer route to Vercel.",
        )

    if change_type == "added":
        new_rec = new_value if isinstance(new_value, dict) else {}
        is_preview = bool(new_rec.get("git_branch"))
        if not is_preview:
            return (
                "medium",
                f"Domain '{domain}' was added to the project. "
                "Verify DNS is configured correctly and that SSL provisioning completes "
                "before routing production traffic through this domain.",
            )
        return (
            "low",
            f"Preview branch domain '{domain}' was added to the project.",
        )

    if change_type == "modified":
        # Determine if this is a production (custom) or preview (branch) domain
        record_content: dict = provider_metadata.get("record_content") or {}
        is_preview = bool(record_content.get("git_branch"))

        if field_path == "verified":
            if new_value is False:
                return (
                    "high",
                    f"Domain '{domain}' is no longer verified. "
                    "Vercel cannot serve traffic for unverified domains. "
                    "Check DNS configuration and re-verify ownership to restore service.",
                )
            # False → True (verified)
            return (
                "low",
                f"Domain '{domain}' was successfully verified. "
                "Vercel can now serve traffic for this domain.",
            )

        if field_path == "redirect":
            if not is_preview:
                # Production domain redirect changed — high impact
                if new_value is None:
                    return (
                        "medium",
                        f"Production domain '{domain}' no longer redirects to '{prev_value}'. "
                        "Direct traffic will now resolve to the Vercel project. "
                        "Verify this routing change is intentional.",
                    )
                prev_str = f"'{prev_value}'" if prev_value else "none"
                return (
                    "high",
                    f"The redirect target for production domain '{domain}' changed "
                    f"from {prev_str} to '{new_value}'. "
                    "All traffic to this domain will now be forwarded to a different destination. "
                    "Verify this routing change is correct.",
                )
            # Preview branch domain redirect changed — medium impact
            prev_str = f"'{prev_value}'" if prev_value else "none"
            new_str  = f"'{new_value}'"  if new_value  else "none"
            return (
                "medium",
                f"Preview domain '{domain}' redirect changed from {prev_str} to {new_str}.",
            )

        if field_path == "git_branch":
            return (
                "low",
                f"Domain '{domain}' is now associated with branch '{new_value}' "
                f"(previously: '{prev_value}'). "
                "Preview deployments for the new branch will serve this domain.",
            )

        # Catch-all for other domain fields
        return (
            "low",
            f"Domain '{domain}' configuration changed (field: {field_path}).",
        )

    return (
        "low",
        f"Domain '{domain}' was {change_type}.",
    )


def _classify_deploy_hook_metadata(
    change_type: str,
    field_path: str | None,
    prev_value: Any,
    new_value: Any,
    record_name: str,
) -> tuple[str, str]:
    """Rules for ``vercel_deploy_hook_metadata`` records — M57.9.

    Deploy hooks trigger deployments via a secret URL.  Changes to hooks
    may indicate unauthorised CI/CD pipeline additions or removal of
    deployment triggers.

    Priority chain (first match wins):
    1. removed → medium (existing trigger gone)
    2. added   → medium (new deployment trigger)
    3. hook_ref changed → low (branch/ref target changed)
    4. hook_name changed → low (cosmetic rename)
    """
    hook_label = f"Deploy hook '{record_name}'" if record_name else "A deploy hook"

    if change_type == "removed":
        return (
            "medium",
            f"{hook_label} was removed. Any CI/CD pipeline using this hook "
            "will no longer be able to trigger deployments.",
        )

    if change_type == "added":
        return (
            "medium",
            f"{hook_label} was added. A new trigger may now initiate Vercel "
            "deployments. Verify it was added intentionally.",
        )

    if field_path == "hook_ref":
        # Changing a deploy hook's target ref redirects what gets deployed
        # whenever any external CI/CD system calls the hook URL. If the new
        # ref points at an unintended branch, the next hook invocation can
        # ship the wrong code to production → high.
        return (
            "high",
            f"{hook_label} target branch changed from '{prev_value}' to "
            f"'{new_value}'. External CI/CD systems calling this hook will "
            "now trigger deploys from the new branch — verify the change "
            "was intentional and that the new branch holds the code you "
            "want to ship.",
        )

    return (
        "low",
        f"{hook_label} configuration changed (field: {field_path}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main classifier
# ─────────────────────────────────────────────────────────────────────────────

def classify_vercel_change(change: Any) -> tuple[str, str]:
    """Classify a Vercel change and return ``(risk_level, risk_reason)``.

    Accepts either a SQLAlchemy ``Change`` ORM object or a plain ``dict``.

    Args:
        change: A ``Change`` instance or dict with fields
                ``change_type``, ``field_path``, ``prev_value``,
                ``new_value``, ``provider_metadata``.

    Returns:
        ``(risk_level, risk_reason)`` where *risk_level* is one of
        ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
    """
    change_type:       str  = (_get(change, "change_type") or "").lower()
    field_path:        Any  = _get(change, "field_path")
    prev_value:        Any  = _get(change, "prev_value")
    new_value:         Any  = _get(change, "new_value")
    # Defence in depth: tolerate provider_metadata that is missing, None,
    # or a non-dict value (str / int / list / etc. from a malformed payload).
    # `or {}` alone only handles falsy values; non-dict truthy inputs would
    # otherwise crash on .get(...). Never raise out of risk classification —
    # the caller treats an uncategorised change as low-risk by default.
    raw_pm = _get(change, "provider_metadata")
    provider_metadata: dict = raw_pm if isinstance(raw_pm, dict) else {}

    record_type: str = provider_metadata.get("record_type", "")
    record_name: str = provider_metadata.get("record_name") or ""

    if record_type == "vercel_env_var":
        return _classify_env_var_change(
            change_type, field_path, prev_value, new_value, record_name
        )

    if record_type == "vercel_project":
        return _classify_project_change(
            change_type, field_path, prev_value, new_value, record_name
        )

    if record_type == "vercel_domain":
        return _classify_domain_change(
            change_type, field_path, prev_value, new_value, record_name, provider_metadata
        )

    if record_type == "vercel_deploy_hook_metadata":
        return _classify_deploy_hook_metadata(
            change_type, field_path, prev_value, new_value, record_name
        )

    # ── M59.12 expansion ────────────────────────────────────────────────────
    if record_type == "vercel_deployment":
        return _classify_deployment_change(
            change_type, field_path, prev_value, new_value, provider_metadata
        )
    if record_type == "vercel_team_member":
        return _classify_team_member_change(
            change_type, field_path, prev_value, new_value, provider_metadata
        )
    if record_type == "vercel_edge_config_item":
        return _classify_edge_config_item_change(
            change_type, field_path, prev_value, new_value, provider_metadata
        )
    if record_type == "vercel_cron_job":
        return _classify_cron_job_change(
            change_type, field_path, prev_value, new_value, provider_metadata
        )
    if record_type == "vercel_deployment_protection":
        return _classify_deployment_protection_change(
            change_type, field_path, prev_value, new_value, provider_metadata
        )
    if record_type == "vercel_integration_installation":
        return _classify_integration_installation_change(
            change_type, field_path, prev_value, new_value, provider_metadata
        )
    if record_type == "vercel_function_runtime":
        return _classify_function_runtime_change(
            change_type, field_path, prev_value, new_value, provider_metadata
        )
    if record_type == "vercel_firewall_rule":
        return _classify_firewall_rule_change(
            change_type, field_path, prev_value, new_value, provider_metadata
        )

    # Unknown Vercel record type — return low with a generic message
    return (
        "low",
        "No specific Vercel risk pattern matched. "
        "This change may be routine configuration maintenance.",
    )


# ═════════════════════════════════════════════════════════════════════════════
# M59.12 — Vercel expansion classifiers
# ═════════════════════════════════════════════════════════════════════════════
#
# Wording policy (shared)
# -----------------------
# Hedged: "may disrupt", "could affect", "may expose", "verify".  Never
# "definitely down", "compromised", or "hacked".  We classify configuration
# deltas, not runtime outcomes.


import re as _re_vercel_m5912


# Git branch / Vercel-username allow-list regex.  Reasons that interpolate
# operator-supplied strings (branch names, usernames) MUST pass them through
# this gate so a misconfigured value carrying a credential shape cannot leak.
# Real git branch names are rarely longer than 80 chars.  Real Vercel
# usernames are ≤ 39 chars.  Both regexes cap length and require a
# conservative character set.
_VERCEL_BRANCH_LIKE_RE = _re_vercel_m5912.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,79}$"
)
_VERCEL_USERNAME_LIKE_RE = _re_vercel_m5912.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,38}$"
)

# Defence-in-depth blocklist: even if a value passes the shape check, reject
# anything that begins with a known credential prefix.  These prefixes are
# never plausible branch / username choices in practice.
_VERCEL_CREDENTIAL_PREFIX_BLOCKLIST: tuple[str, ...] = (
    "sk_live_", "sk_test_", "rk_live_", "rk_test_",
    "whsec_", "ghp_", "gho_", "github_pat_",
    "AKIA", "ASIA",
    "vercel_token", "vercel_pat",
    "Bearer ", "Authorization:",
    "-----BEGIN ",
)


def _has_credential_prefix(s: str) -> bool:
    return any(s.startswith(p) for p in _VERCEL_CREDENTIAL_PREFIX_BLOCKLIST)


def _safe_branch_label(value: object) -> str:
    s = str(value or "")
    if not s or len(s) > 80:
        return "the configured branch"
    if _has_credential_prefix(s):
        return "the configured branch"
    return s if _VERCEL_BRANCH_LIKE_RE.match(s) else "the configured branch"


def _safe_username_label(value: object) -> str:
    s = str(value or "")
    if not s or len(s) > 39:
        return "the configured user"
    if _has_credential_prefix(s):
        return "the configured user"
    return s if _VERCEL_USERNAME_LIKE_RE.match(s) else "the configured user"


# ── Sensitive Edge-Config / feature-flag key patterns ───────────────────────
_EDGE_CONFIG_SENSITIVE_KEY_PATTERNS: tuple[str, ...] = (
    "AUTH", "API", "BACKEND", "PAYMENT", "STRIPE", "PROD", "PRODUCTION",
    "DB", "DATABASE", "SECRET", "PRIVATE_KEY", "TOKEN", "WEBHOOK",
)


def _vercel_edge_key_is_sensitive(key: str) -> bool:
    u = (key or "").upper()
    return any(p in u for p in _EDGE_CONFIG_SENSITIVE_KEY_PATTERNS)


# ── Production-cron name patterns ───────────────────────────────────────────
_VERCEL_PROD_CRON_PATTERNS: tuple[str, ...] = (
    "billing", "billing-", "invoice", "payment", "payout",
    "sync", "cleanup", "purge", "rotate", "rotation",
    "backup", "snapshot",
)


def _vercel_cron_is_production_critical(pm: dict) -> bool:
    """Heuristic: cron jobs whose name/path hint at billing/sync/cleanup
    operations are production-critical."""
    name = str(pm.get("name") or pm.get("record_id") or "").lower()
    path = str(pm.get("path") or "").lower()
    haystack = f"{name} {path}"
    target_env = str(pm.get("target_env") or "").lower()
    if target_env == "production":
        return True
    return any(p in haystack for p in _VERCEL_PROD_CRON_PATTERNS)


# ─────────────────────────────────────────────────────────────────────────────
# A. vercel_deployment
# ─────────────────────────────────────────────────────────────────────────────


def _classify_deployment_change(
    change_type: str, field_path: Any, prev_value: Any, new_value: Any,
    pm: dict,
) -> tuple[str, str]:
    dep_id = str(pm.get("record_id") or "unknown")
    target = str(pm.get("target") or "").lower()
    is_production = (target == "production"
                     or bool(pm.get("is_current_production_alias", False)))

    if change_type == "removed":
        sev = "high" if is_production else "medium"
        return (
            sev,
            f"Vercel deployment {dep_id} was removed.  Production routing "
            "may be affected if this was the active deployment.",
        )

    if change_type == "added":
        # New production deployments are routine; preview is also routine.
        return (
            "low",
            f"A new Vercel deployment {dep_id} was created.",
        )

    # ── Production alias / promotion signals ────────────────────────────────
    if field_path == "is_current_production_alias":
        if prev_value is False and new_value is True:
            # A preview/staging deployment was promoted to production.
            return (
                "high",
                f"Vercel deployment {dep_id} was promoted to the production "
                "alias.  Verify the promotion was intentional and that the "
                "deployment was built from the expected source.",
            )
        if prev_value is True and new_value is False:
            # The deployment lost the production alias — typically because
            # another deployment took over.  This often indicates a rollback.
            return (
                "high",
                f"Vercel deployment {dep_id} is no longer the production "
                "alias — another deployment may have taken over or a "
                "rollback occurred.  Verify the active deployment matches "
                "the intended source.",
            )

    if field_path == "target":
        prev_s = str(prev_value or "").lower()
        new_s = str(new_value or "").lower()
        if prev_s != "production" and new_s == "production":
            return (
                "critical",
                f"Vercel deployment {dep_id} target was changed to 'production'. "
                "A non-production deployment is now serving production traffic — "
                "verify the change is intentional.",
            )
        if prev_s == "production" and new_s != "production":
            return (
                "high",
                f"Vercel deployment {dep_id} target was changed away from "
                "'production'.  Verify the change is intentional.",
            )

    if field_path == "source_branch":
        prev_label = _safe_branch_label(prev_value)
        new_label = _safe_branch_label(new_value)
        if is_production:
            return (
                "high",
                f"Vercel production deployment {dep_id} source branch "
                f"changed from '{prev_label}' to '{new_label}'.  Verify "
                "the new branch is the intended release source.",
            )
        return (
            "medium",
            f"Vercel deployment {dep_id} source branch changed.",
        )

    if field_path == "deployment_url":
        return (
            "medium",
            f"Vercel deployment {dep_id} URL changed.  Verify any external "
            "references still point at the intended deployment.",
        )

    if field_path == "state":
        new_s = str(new_value or "").lower()
        if new_s == "error":
            sev = "high" if is_production else "medium"
            return (
                sev,
                f"Vercel deployment {dep_id} entered 'ERROR' state.  "
                "Investigate build/runtime failures.",
            )
        if new_s == "canceled":
            return (
                "medium",
                f"Vercel deployment {dep_id} was canceled.",
            )
        if new_s == "ready":
            return (
                "low",
                f"Vercel deployment {dep_id} is now READY.",
            )

    if field_path == "creator_username":
        prev_label = _safe_username_label(prev_value)
        new_label = _safe_username_label(new_value)
        return (
            "medium",
            f"Vercel deployment {dep_id} creator changed from '{prev_label}' "
            f"to '{new_label}'.  Verify the new creator is authorised.",
        )

    return (
        "low",
        f"Vercel deployment {dep_id} configuration changed "
        f"({field_path or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# B. vercel_team_member
# ─────────────────────────────────────────────────────────────────────────────

_VERCEL_ROLE_RANK: dict[str, int] = {
    "viewer": 1, "member": 2, "developer": 3, "admin": 4, "owner": 5,
}


def _classify_team_member_change(
    change_type: str, field_path: Any, prev_value: Any, new_value: Any,
    pm: dict,
) -> tuple[str, str]:
    name = str(pm.get("name") or pm.get("record_id") or "unknown")
    outside = bool(pm.get("is_outside_collaborator", False))

    if change_type == "added":
        role = str(pm.get("role") or new_value or "").lower()
        if outside and role in ("admin", "owner"):
            return (
                "critical",
                f"Outside collaborator {name} was added with '{role}' role. "
                "External-account access at admin/owner level grants broad "
                "control — verify the grant was approved.",
            )
        if role in ("admin", "owner"):
            return (
                "high",
                f"Vercel member {name} was added with '{role}' role.  "
                "Verify the grant was approved.",
            )
        if role in ("developer",):
            sev = "high" if outside else "medium"
            return (
                sev,
                f"Vercel {'outside collaborator' if outside else 'member'} "
                f"{name} was added with '{role}' role.",
            )
        return (
            "low",
            f"Vercel member {name} was added with '{role or 'unknown'}' role.",
        )

    if change_type == "removed":
        return (
            "medium",
            f"Vercel member {name} was removed.  Verify the change was "
            "intentional — losing a team member may affect availability of "
            "review and on-call coverage.",
        )

    if field_path == "role":
        prev_s = str(prev_value or "").lower()
        new_s = str(new_value or "").lower()
        prev_r = _VERCEL_ROLE_RANK.get(prev_s, 0)
        new_r = _VERCEL_ROLE_RANK.get(new_s, 0)
        if new_r > prev_r and new_s in ("admin", "owner"):
            sev = "critical" if outside else "high"
            return (
                sev,
                f"Vercel member {name} role was raised from '{prev_s}' to "
                f"'{new_s}'.  This grants broad project control — verify "
                "the grant was approved.",
            )
        if new_r > prev_r:
            sev = "high" if outside else "medium"
            return (
                sev,
                f"Vercel member {name} role was raised from '{prev_s}' to "
                f"'{new_s}'.",
            )
        if new_r < prev_r:
            return (
                "low",
                f"Vercel member {name} role was lowered from '{prev_s}' to "
                f"'{new_s}'.",
            )

    if field_path == "is_outside_collaborator":
        if prev_value is False and new_value is True:
            return (
                "high",
                f"Vercel member {name} was reclassified as an outside "
                "collaborator.  Review whether their current role is still "
                "appropriate.",
            )

    if field_path == "project_scope":
        return (
            "medium",
            f"Vercel member {name} project scope changed.  Verify the new "
            "scope is intentional.",
        )

    return (
        "low",
        f"Vercel member {name} metadata changed "
        f"({field_path or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# C. vercel_edge_config_item
# ─────────────────────────────────────────────────────────────────────────────


def _classify_edge_config_item_change(
    change_type: str, field_path: Any, prev_value: Any, new_value: Any,
    pm: dict,
) -> tuple[str, str]:
    key = str(pm.get("key") or pm.get("name") or pm.get("record_id") or "unknown")
    target = str(pm.get("target") or "").lower()
    is_production = target in ("production", "all")
    is_sensitive_key = _vercel_edge_key_is_sensitive(key)

    if change_type == "removed":
        sev = ("high" if (is_sensitive_key and is_production)
               else "medium")
        return (
            sev,
            f"Vercel Edge Config item '{key}' was removed (target={target or 'unknown'}). "
            "Code that reads this flag may now fall back to defaults — "
            "verify the runtime behaviour is intentional.",
        )

    if change_type == "added":
        sev = ("medium" if (is_sensitive_key and is_production) else "low")
        return (
            sev,
            f"A new Vercel Edge Config item '{key}' was created "
            f"(target={target or 'unknown'}).",
        )

    if field_path == "value_hash":
        if is_sensitive_key and is_production:
            return (
                "high",
                f"Vercel Edge Config item '{key}' value changed in "
                "production.  This key looks security-sensitive "
                "(auth/api/payment/backend-style label) — verify the new "
                "value is intentional.",
            )
        if is_production:
            return (
                "medium",
                f"Vercel Edge Config item '{key}' value changed in "
                "production.  Verify the new behaviour matches expectations.",
            )
        return (
            "low",
            f"Vercel Edge Config item '{key}' value changed in "
            f"{target or 'non-prod'}.",
        )

    if field_path == "value_type":
        return (
            "medium",
            f"Vercel Edge Config item '{key}' value type changed from "
            f"{prev_value!r} to {new_value!r}.  Verify consumer code can "
            "handle the new type.",
        )

    if field_path == "target":
        if target == "production":
            return (
                "high",
                f"Vercel Edge Config item '{key}' was promoted to "
                "production.  Verify the value is the intended one for the "
                "production environment.",
            )

    return (
        "low",
        f"Vercel Edge Config item '{key}' metadata changed "
        f"({field_path or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# D. vercel_cron_job
# ─────────────────────────────────────────────────────────────────────────────


def _classify_cron_job_change(
    change_type: str, field_path: Any, prev_value: Any, new_value: Any,
    pm: dict,
) -> tuple[str, str]:
    cid = str(pm.get("record_id") or pm.get("name") or "unknown")
    is_critical = _vercel_cron_is_production_critical(pm)

    if change_type == "removed":
        sev = "high" if is_critical else "medium"
        return (
            sev,
            f"Vercel cron job {cid} was removed.  Scheduled execution at the "
            "previous cadence no longer runs — verify the change is "
            "intentional.",
        )

    if change_type == "added":
        return (
            "low",
            f"A new Vercel cron job {cid} was created.",
        )

    if field_path == "enabled":
        if prev_value is True and new_value is False:
            sev = "high" if is_critical else "medium"
            return (
                sev,
                f"Vercel cron job {cid} was disabled.  Scheduled execution "
                "no longer runs — verify the change is intentional.",
            )
        if new_value is True:
            return (
                "low",
                f"Vercel cron job {cid} was re-enabled.",
            )

    if field_path == "schedule":
        return (
            "medium",
            f"Vercel cron job {cid} schedule changed from {prev_value!r} to "
            f"{new_value!r}.  Verify the new cron expression matches the "
            "intended cadence.",
        )

    if field_path == "path":
        sev = "high" if is_critical else "medium"
        return (
            sev,
            f"Vercel cron job {cid} target path changed from {prev_value!r} "
            f"to {new_value!r}.  Verify the new endpoint is the intended one.",
        )

    if field_path == "region":
        return (
            "low",
            f"Vercel cron job {cid} region changed from {prev_value!r} to "
            f"{new_value!r}.",
        )

    if field_path == "target_env":
        if str(new_value or "").lower() == "production":
            return (
                "medium",
                f"Vercel cron job {cid} was scoped to production.  Verify "
                "the change is intentional.",
            )

    return (
        "low",
        f"Vercel cron job {cid} metadata changed "
        f"({field_path or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# E. vercel_deployment_protection
# ─────────────────────────────────────────────────────────────────────────────


def _classify_deployment_protection_change(
    change_type: str, field_path: Any, prev_value: Any, new_value: Any,
    pm: dict,
) -> tuple[str, str]:
    pid = str(pm.get("name") or pm.get("record_id") or "unknown")

    if field_path == "sso_enabled":
        if prev_value is True and new_value is False:
            return (
                "high",
                f"Vercel Authentication (SSO) was disabled on project {pid}. "
                "Preview/protected deployments may now be reachable without "
                "team-member sign-in — verify the change is intentional.",
            )
        return (
            "low",
            f"Vercel Authentication (SSO) was enabled on project {pid}.",
        )

    if field_path == "password_enabled":
        if prev_value is True and new_value is False:
            return (
                "high",
                f"Vercel password protection was disabled on project {pid}. "
                "Preview/protected deployments may now be reachable without "
                "a password.",
            )
        return (
            "low",
            f"Vercel password protection was enabled on project {pid}.",
        )

    if field_path == "protection_bypass_for_automation":
        if prev_value is False and new_value is True:
            return (
                "high",
                f"Vercel deployment-protection bypass for automation was "
                f"enabled on project {pid}.  Automation tokens can now skip "
                "the protection barrier — verify the change is intentional.",
            )
        return (
            "low",
            f"Vercel deployment-protection bypass was removed on project "
            f"{pid}.",
        )

    if field_path == "trusted_ips_count":
        try:
            prev_n = int(prev_value or 0)
            new_n = int(new_value or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        if new_n > prev_n:
            return (
                "high",
                f"Vercel trusted-IP allowlist was broadened on project {pid} "
                f"(from {prev_n} to {new_n}).  More IPs can now bypass "
                "deployment protection.",
            )
        return (
            "low",
            f"Vercel trusted-IP allowlist was narrowed on project {pid} "
            f"(from {prev_n} to {new_n}).",
        )

    if field_path == "trusted_ips_cidr_hash":
        return (
            "medium",
            f"Vercel trusted-IP allowlist on project {pid} was modified "
            "(content hash changed).  Verify the new allowlist is "
            "intentional.",
        )

    if field_path == "preview_comments_public":
        if prev_value is False and new_value is True:
            return (
                "medium",
                f"Vercel preview comments were made public on project {pid}. "
                "Comments are visible to anyone with the preview URL.",
            )

    if field_path == "preview_deployments_protected":
        if prev_value is True and new_value is False:
            return (
                "high",
                f"Vercel preview-deployment protection was disabled on "
                f"project {pid}.  Preview URLs may now be reachable without "
                "authentication.",
            )

    return (
        "low",
        f"Vercel deployment-protection setting on project {pid} changed "
        f"({field_path or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# F. vercel_integration_installation
# ─────────────────────────────────────────────────────────────────────────────


def _classify_integration_installation_change(
    change_type: str, field_path: Any, prev_value: Any, new_value: Any,
    pm: dict,
) -> tuple[str, str]:
    name = str(pm.get("name") or pm.get("record_id") or "unknown")

    if change_type == "added":
        if bool(pm.get("has_admin_access")):
            return (
                "critical",
                f"Vercel integration '{name}' was installed with admin "
                "access.  The integration can change project settings, env "
                "vars, and domains.  Verify the integration is trusted.",
            )
        if (bool(pm.get("has_env_access"))
                or bool(pm.get("has_deployment_access"))
                or bool(pm.get("has_domain_access"))):
            return (
                "high",
                f"Vercel integration '{name}' was installed with elevated "
                "permissions (env, deployment, or domain).  Verify the "
                "integration is trusted.",
            )
        return (
            "medium",
            f"Vercel integration '{name}' was installed.  Review its "
            "permissions and project scope.",
        )

    if change_type == "removed":
        return (
            "medium",
            f"Vercel integration '{name}' was removed.  Any automation it "
            "provided no longer runs — verify the change is intentional.",
        )

    for cap_field in (
        "has_admin_access", "has_env_access",
        "has_deployment_access", "has_domain_access",
    ):
        if field_path == cap_field and prev_value is False and new_value is True:
            sev = "critical" if cap_field == "has_admin_access" else "high"
            return (
                sev,
                f"Vercel integration '{name}' gained {cap_field} permission. "
                "Verify the grant was approved and reduce permissions if "
                "unnecessary.",
            )

    if field_path == "project_count":
        try:
            prev_n = int(prev_value or 0)
            new_n = int(new_value or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        if new_n > prev_n:
            sev = "high"
            return (
                sev,
                f"Vercel integration '{name}' project scope broadened from "
                f"{prev_n} to {new_n} projects.  Verify the additional "
                "projects were intentionally connected.",
            )
        return (
            "low",
            f"Vercel integration '{name}' project scope narrowed from "
            f"{prev_n} to {new_n} projects.",
        )

    return (
        "low",
        f"Vercel integration '{name}' metadata changed "
        f"({field_path or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# G. vercel_function_runtime
# ─────────────────────────────────────────────────────────────────────────────


# Runtimes considered EOL or substantially behind current LTS — we don't
# hardcode an authoritative list; the heuristic is "downgrades to an older
# Node major or non-current runtime should surface a Medium reason".
def _vercel_runtime_is_older(prev_s: str, new_s: str) -> bool:
    """Heuristic comparison for Node runtimes.  Returns True if *new_s*
    looks like an older Node major than *prev_s*."""
    m_prev = _re_vercel_m5912.match(r"nodejs(\d+)", prev_s or "")
    m_new = _re_vercel_m5912.match(r"nodejs(\d+)", new_s or "")
    if m_prev and m_new:
        return int(m_new.group(1)) < int(m_prev.group(1))
    return False


def _classify_function_runtime_change(
    change_type: str, field_path: Any, prev_value: Any, new_value: Any,
    pm: dict,
) -> tuple[str, str]:
    pid = str(pm.get("name") or pm.get("record_id") or "unknown")

    if field_path == "default_runtime":
        prev_s = str(prev_value or "").lower()
        new_s = str(new_value or "").lower()
        if _vercel_runtime_is_older(prev_s, new_s):
            return (
                "high",
                f"Vercel project {pid} default runtime was downgraded from "
                f"{prev_s!r} to {new_s!r}.  Verify the downgrade is "
                "intentional — older runtimes may receive less security "
                "patching.",
            )
        return (
            "medium",
            f"Vercel project {pid} default runtime changed from {prev_s!r} "
            f"to {new_s!r}.  Verify the new runtime is intentional.",
        )

    if field_path == "default_region":
        return (
            "medium",
            f"Vercel project {pid} default region changed from {prev_value!r} "
            f"to {new_value!r}.  Latency for end users may shift.",
        )

    if field_path == "default_max_duration_seconds":
        try:
            prev_n = int(prev_value or 0)
            new_n = int(new_value or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        if new_n > prev_n:
            return (
                "medium",
                f"Vercel project {pid} default function max_duration was "
                f"raised from {prev_n}s to {new_n}s.  Verify the new limit "
                "is intentional (may increase cost).",
            )
        return (
            "low",
            f"Vercel project {pid} default function max_duration was lowered "
            f"from {prev_n}s to {new_n}s.",
        )

    if field_path == "default_memory_mb":
        return (
            "medium",
            f"Vercel project {pid} default function memory changed from "
            f"{prev_value!r}MB to {new_value!r}MB.",
        )

    if field_path == "public_function_route_count":
        try:
            prev_n = int(prev_value or 0)
            new_n = int(new_value or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        if new_n > prev_n:
            return (
                "high",
                f"Vercel project {pid} public function route count "
                f"increased from {prev_n} to {new_n}.  More routes are now "
                "publicly reachable — verify each new route applies the "
                "intended auth/rate-limiting.",
            )
        return (
            "low",
            f"Vercel project {pid} public function route count decreased "
            f"from {prev_n} to {new_n}.",
        )

    if field_path in ("edge_function_count", "serverless_function_count"):
        try:
            prev_n = int(prev_value or 0)
            new_n = int(new_value or 0)
        except (TypeError, ValueError):
            prev_n = new_n = 0
        direction = "increased" if new_n > prev_n else "decreased"
        return (
            "low",
            f"Vercel project {pid} {field_path} {direction} from {prev_n} "
            f"to {new_n}.",
        )

    return (
        "low",
        f"Vercel project {pid} function/runtime setting changed "
        f"({field_path or 'unknown field'}).",
    )


# ─────────────────────────────────────────────────────────────────────────────
# H. vercel_firewall_rule
# ─────────────────────────────────────────────────────────────────────────────

_VERCEL_FW_PROTECTIVE_ACTIONS: frozenset[str] = frozenset(
    {"block", "challenge", "log"}
)
_VERCEL_FW_PERMISSIVE_ACTIONS: frozenset[str] = frozenset(
    {"allow", "bypass"}
)


def _classify_firewall_rule_change(
    change_type: str, field_path: Any, prev_value: Any, new_value: Any,
    pm: dict,
) -> tuple[str, str]:
    description = str(pm.get("description") or pm.get("name")
                      or pm.get("record_id") or "unknown")
    targets_prod = bool(pm.get("targets_production", True))

    if change_type == "removed":
        prev_action = str(pm.get("action") or "").lower()
        sev = ("high" if (targets_prod and prev_action in _VERCEL_FW_PROTECTIVE_ACTIONS)
               else "medium")
        return (
            sev,
            f"Vercel firewall rule '{description}' was removed.  Whatever "
            "attack pattern or path it covered is no longer filtered at the "
            "edge.",
        )

    if change_type == "added":
        return (
            "medium",
            f"A new Vercel firewall rule '{description}' was added.  Review "
            "the rule to ensure it matches the intended traffic.",
        )

    if field_path == "action":
        prev_s = str(prev_value or "").lower()
        new_s = str(new_value or "").lower()
        if prev_s == "block" and new_s in _VERCEL_FW_PERMISSIVE_ACTIONS:
            sev = "critical" if targets_prod else "high"
            return (
                sev,
                f"Vercel firewall rule '{description}' action was lowered "
                f"from 'block' to '{new_s}'.  Traffic that was previously "
                "blocked is now permitted — this may weaken edge filtering.",
            )
        if (prev_s in _VERCEL_FW_PROTECTIVE_ACTIONS
                and new_s in _VERCEL_FW_PERMISSIVE_ACTIONS):
            sev = "high" if targets_prod else "medium"
            return (
                sev,
                f"Vercel firewall rule '{description}' action was lowered "
                f"from '{prev_s}' to '{new_s}'.  Verify the change is "
                "intentional.",
            )
        if (prev_s in _VERCEL_FW_PERMISSIVE_ACTIONS
                and new_s in _VERCEL_FW_PROTECTIVE_ACTIONS):
            return (
                "low",
                f"Vercel firewall rule '{description}' action was "
                f"strengthened from '{prev_s}' to '{new_s}'.",
            )
        return (
            "medium",
            f"Vercel firewall rule '{description}' action changed from "
            f"'{prev_s}' to '{new_s}'.",
        )

    if field_path == "enabled":
        if prev_value is True and new_value is False:
            sev = "high" if targets_prod else "medium"
            return (
                sev,
                f"Vercel firewall rule '{description}' was disabled.  The "
                "attack pattern it covered is no longer filtered at the edge.",
            )
        if new_value is True:
            return (
                "low",
                f"Vercel firewall rule '{description}' was re-enabled.",
            )

    if field_path == "expression_hash":
        # Hash change means the matching logic was changed; we never see the
        # expression text.
        return (
            "medium",
            f"Vercel firewall rule '{description}' matching expression was "
            "modified.  Verify the new pattern matches the intended traffic.",
        )

    return (
        "low",
        f"Vercel firewall rule '{description}' metadata changed "
        f"({field_path or 'unknown field'}).",
    )
