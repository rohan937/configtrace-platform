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
    provider_metadata: dict = _get(change, "provider_metadata") or {}

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

    # Unknown Vercel record type — return low with a generic message
    return (
        "low",
        "No specific Vercel risk pattern matched. "
        "This change may be routine configuration maintenance.",
    )
