"""Firebase risk classification rules — M53.

Entry point: ``classify_firebase_change(change)``

Risk levels
-----------
critical  — Firestore/Storage rules changed to public write.
            Auth security restriction removed on sensitive change.

high      — Firestore/Storage public read exposed.
            Anonymous auth enabled.
            Suspicious authorized domain added (non-firebase, non-localhost).
            OAuth/SAML/OIDC provider config changed.
            Ruleset hash changed to public read/write.
            Storage uniform_bucket_level_access disabled.
            Hosting production domain removed.

medium    — Auth provider enabled/disabled.
            Authorized domain removed.
            Ruleset changed but no obvious public access detected.
            Storage bucket config changed (class, location, versioning).
            Hosting domain/site changed.
            Cloud Function runtime/trigger/status changed.
            Auth domain count changed.
            MFA state changed.

low       — Project display name / metadata changed.
            Provider metadata changed non-significantly.
            Expected Firebase domain added.
            Routine config drift.
            Security strengthened (e.g. uniform_bucket_level_access enabled).

Language policy
---------------
All risk_reason strings use may/could language:
  "Firestore rules may allow public writes."
  "Storage rules could expose files publicly."
  "Anonymous Auth was enabled; verify this is intentional."

NEVER assert data was leaked, breached, or compromised.

Directionality
--------------
Security-weakening changes (public access newly enabled, domains removed,
auth providers added without review) are classified higher.
Security-strengthening changes (bucket access locked, auth hardened) are
classified low or medium.
"""

from __future__ import annotations

from typing import Any


def _get(obj: object, field: str) -> Any:
    """Safely retrieve a field from a Change object or plain dict."""
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


# ── firebase_project ──────────────────────────────────────────────────────────

def _classify_project_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("low", "A new Firebase project was added to ConfigTrace monitoring.")
    if ct == "removed":
        return ("high", "The Firebase project record was removed — unexpected; verify the project still exists.")

    if fp == "lifecycle_state":
        if str(new_v).upper() in ("DELETED", "DELETE_REQUESTED"):
            return (
                "critical",
                "The Firebase project lifecycle state changed to DELETED or DELETE_REQUESTED. "
                "This may indicate the project is being deleted. "
                "Verify this is intentional.",
            )
        return ("medium", "The Firebase project lifecycle state changed.")
    if fp == "display_name":
        return ("low", "The Firebase project display name changed.")
    if fp in ("has_realtime_db", "has_storage", "hosting_site"):
        return ("medium", "A Firebase project resource configuration changed.")

    return ("low", "A Firebase project metadata field changed.")


# ── firebase_auth_config ──────────────────────────────────────────────────────

def _classify_auth_config_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("low", "Firebase Authentication configuration baseline captured.")
    if ct == "removed":
        return ("high", "Firebase Authentication configuration record removed — unexpected.")

    if fp == "anonymous_enabled":
        if new_v is True or new_v == "true":
            return (
                "high",
                "Anonymous Authentication was enabled on this Firebase project. "
                "Anonymous users can sign in without credentials; verify this is intentional "
                "and that security rules restrict their data access appropriately.",
            )
        # Disabled — security strengthened
        return (
            "low",
            "Anonymous Authentication was disabled. "
            "Users can no longer sign in anonymously.",
        )

    if fp == "mfa_enabled" or fp == "mfa_state":
        if new_v in (False, "false", "DISABLED"):
            return (
                "high",
                "Multi-factor authentication was disabled on this Firebase project. "
                "Verify this is intentional and that alternative security controls are in place.",
            )
        # MFA enabled — security strengthened
        return (
            "low",
            "Multi-factor authentication was enabled. "
            "This strengthens the security posture of the Firebase project.",
        )

    if fp == "authorized_domain_count":
        return (
            "medium",
            "The count of Firebase Authentication authorized domains changed. "
            "Review the authorized domain list to confirm all domains are expected.",
        )

    if fp in ("saml_provider_count", "oidc_provider_count"):
        provider_type = "SAML" if "saml" in fp else "OIDC"
        return (
            "medium",
            f"The number of {provider_type} identity providers changed. "
            "Verify the provider configuration is correct and expected.",
        )

    if fp == "sign_in_email_enabled":
        if new_v is False or new_v == "false":
            return ("medium", "Email/password sign-in was disabled in Firebase Authentication.")
        return ("low", "Email/password sign-in was enabled in Firebase Authentication.")

    if fp == "sign_in_phone_enabled":
        if new_v is False or new_v == "false":
            return ("medium", "Phone number sign-in was disabled in Firebase Authentication.")
        return ("medium", "Phone number sign-in was enabled in Firebase Authentication.")

    return ("medium", "A Firebase Authentication configuration setting changed.")


# ── firebase_auth_provider ────────────────────────────────────────────────────

def _classify_auth_provider_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")
    pm    = (_get(change, "provider_metadata") or {}) if isinstance(_get(change, "provider_metadata"), dict) else {}
    provider_id = pm.get("provider_id", "")

    if ct == "added":
        return (
            "medium",
            f"A Firebase Authentication provider was added ({provider_id}). "
            "Verify the provider configuration is correct.",
        )
    if ct == "removed":
        return (
            "high",
            f"A Firebase Authentication provider was removed ({provider_id}). "
            "Users who signed in through this provider may lose access.",
        )

    if fp == "enabled":
        if new_v is True or new_v == "true":
            return (
                "medium",
                f"Firebase Authentication provider {provider_id!r} was enabled. "
                "Users can now sign in using this provider.",
            )
        return (
            "medium",
            f"Firebase Authentication provider {provider_id!r} was disabled. "
            "Users signed in through this provider may be affected.",
        )

    return ("medium", f"A Firebase Authentication provider setting changed ({provider_id}).")


# ── firebase_authorized_domain ────────────────────────────────────────────────

def _classify_authorized_domain_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    pm = (_get(change, "provider_metadata") or {}) if isinstance(_get(change, "provider_metadata"), dict) else {}
    domain = pm.get("domain", "")
    is_default = pm.get("is_default_firebase_domain", False)
    is_localhost = pm.get("is_localhost", False)

    if ct == "added":
        if is_localhost:
            return (
                "low",
                f"A localhost domain was added to Firebase authorized domains ({domain}). "
                "This is typically used for local development only.",
            )
        if is_default:
            return (
                "low",
                f"A default Firebase domain was added to authorized domains ({domain}).",
            )
        # Custom or unknown domain added
        return (
            "high",
            f"A custom domain was added to Firebase Authentication authorized domains ({domain}). "
            "Verify this domain belongs to your application. "
            "Unauthorized domains could be used for OAuth redirect attacks.",
        )

    if ct == "removed":
        if is_localhost or is_default:
            return ("low", f"A Firebase default/localhost domain was removed ({domain}).")
        return (
            "medium",
            f"A custom domain was removed from Firebase Authentication authorized domains ({domain}). "
            "Users on this domain may no longer be able to sign in.",
        )

    return ("low", f"A Firebase authorized domain record changed ({domain}).")


# ── firebase_firestore_ruleset ────────────────────────────────────────────────

def _classify_firestore_ruleset_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("low", "Firestore Security Rules baseline captured.")
    if ct == "removed":
        return ("medium", "Firestore Security Rules record removed — unexpected.")

    # Highest-signal fields: public access detection
    if fp == "public_write_detected":
        if new_v is True or new_v == "true":
            return (
                "critical",
                "Firestore Security Rules may now allow public write access without authentication. "
                "Verify the rules are correct and that writes require authentication where expected.",
            )
        # Changed from public to non-public — security improvement
        return (
            "low",
            "Firestore Security Rules no longer appear to allow public write access. "
            "This is a security improvement; verify the rules are correct.",
        )

    if fp == "public_read_detected":
        if new_v is True or new_v == "true":
            return (
                "high",
                "Firestore Security Rules may now allow public read access without authentication. "
                "Verify that sensitive data is appropriately protected.",
            )
        return (
            "low",
            "Firestore Security Rules no longer appear to allow public read access. "
            "Security improved.",
        )

    if fp == "authenticated_only_detected":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "Firestore Security Rules may no longer require authentication for all access. "
                "Review the updated rules to ensure data is appropriately protected.",
            )
        return ("low", "Firestore Security Rules now appear to require authentication.")

    if fp == "rules_hash" or fp == "ruleset_name_hash":
        return (
            "medium",
            "The active Firestore Security Rules deployment changed. "
            "Review the updated rules to confirm the change is expected and access control is correct.",
        )

    if fp == "rule_summary":
        return ("medium", "Firestore Security Rules analysis result changed.")

    return ("medium", "A Firestore Security Rules configuration changed.")


# ── firebase_storage_bucket ───────────────────────────────────────────────────

def _classify_storage_bucket_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("low", "A new Firebase/Google Cloud Storage bucket was added.")
    if ct == "removed":
        return ("high", "A Firebase/Google Cloud Storage bucket was removed or is no longer accessible.")

    if fp == "uniform_bucket_level_access":
        if new_v is False or new_v == "false":
            return (
                "high",
                "Uniform bucket-level access was disabled on a Cloud Storage bucket. "
                "Object-level ACLs are now active and could allow unintended public access. "
                "Verify that bucket and object ACLs are correctly configured.",
            )
        # Enabled — security strengthened
        return (
            "low",
            "Uniform bucket-level access was enabled on a Cloud Storage bucket. "
            "This centralises access control and prevents object-level ACL bypasses.",
        )

    if fp == "public_access_prevention":
        if str(new_v).lower() in ("inherited", "unspecified", ""):
            return (
                "high",
                "Public access prevention on a Cloud Storage bucket was changed from 'enforced'. "
                "The bucket may now allow public objects based on IAM or ACLs. "
                "Verify this is intentional.",
            )
        if str(new_v).lower() == "enforced":
            return (
                "low",
                "Public access prevention was enforced on a Cloud Storage bucket. "
                "This prevents public access regardless of ACLs.",
            )
        return ("medium", "Cloud Storage bucket public access prevention setting changed.")

    if fp == "storage_class":
        return ("low", "The Cloud Storage bucket storage class changed.")
    if fp == "location":
        return (
            "medium",
            "The Cloud Storage bucket location changed. "
            "Verify data residency requirements are still met.",
        )
    if fp == "versioning_enabled":
        return ("low", "Cloud Storage bucket versioning setting changed.")

    return ("medium", "A Cloud Storage bucket configuration changed.")


# ── firebase_storage_ruleset ──────────────────────────────────────────────────

def _classify_storage_ruleset_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("low", "Firebase Storage Security Rules baseline captured.")
    if ct == "removed":
        return ("medium", "Firebase Storage Security Rules record removed — unexpected.")

    if fp == "public_write_detected":
        if new_v is True or new_v == "true":
            return (
                "critical",
                "Firebase Storage Security Rules may now allow public write access without authentication. "
                "This could allow anyone to upload files to your storage bucket. "
                "Verify the rules are correct immediately.",
            )
        return (
            "low",
            "Firebase Storage Security Rules no longer appear to allow public write access. "
            "Security improved.",
        )

    if fp == "public_read_detected":
        if new_v is True or new_v == "true":
            return (
                "high",
                "Firebase Storage Security Rules may now allow public read access without authentication. "
                "Verify that stored files are not sensitive.",
            )
        return ("low", "Firebase Storage Security Rules no longer appear to allow public read. Security improved.")

    if fp == "authenticated_only_detected":
        if new_v is False or new_v == "false":
            return (
                "medium",
                "Firebase Storage Security Rules may no longer require authentication. "
                "Review the updated rules.",
            )
        return ("low", "Firebase Storage Security Rules now appear to require authentication.")

    if fp in ("rules_hash", "ruleset_name_hash"):
        return (
            "medium",
            "The active Firebase Storage Security Rules deployment changed. "
            "Review the updated rules to confirm access control is correct.",
        )

    return ("medium", "A Firebase Storage Security Rules configuration changed.")


# ── firebase_hosting_site ─────────────────────────────────────────────────────

def _classify_hosting_site_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")

    if ct == "added":
        return ("low", "A new Firebase Hosting site was added.")
    if ct == "removed":
        return (
            "high",
            "A Firebase Hosting site was removed. "
            "Hosted content on this site may no longer be accessible.",
        )

    if fp == "custom_domain_count":
        old_v = _get(change, "prev_value")
        if old_v is not None and new_v is not None:
            try:
                if int(new_v) < int(old_v):
                    return (
                        "high",
                        "The number of custom domains on a Firebase Hosting site decreased. "
                        "A production domain may have been removed.",
                    )
            except (TypeError, ValueError):
                pass
        return ("medium", "The count of custom domains on a Firebase Hosting site changed.")

    if fp == "default_url":
        return (
            "medium",
            "The default URL for a Firebase Hosting site changed. "
            "Verify the hosting configuration is correct.",
        )

    return ("medium", "A Firebase Hosting site configuration changed.")


# ── firebase_hosting_domain ───────────────────────────────────────────────────

def _classify_hosting_domain_change(change: object) -> tuple[str, str]:
    ct = (_get(change, "change_type") or "").lower()
    fp = (_get(change, "field_path") or "").lower()
    pm = (_get(change, "provider_metadata") or {}) if isinstance(_get(change, "provider_metadata"), dict) else {}
    domain = pm.get("domain", "")
    domain_type = pm.get("domain_type", "")

    if ct == "added":
        if domain_type == "CUSTOM":
            return (
                "medium",
                f"A custom domain was added to Firebase Hosting ({domain}). "
                "Verify the domain is correctly configured and belongs to your application.",
            )
        return ("low", f"A Firebase Hosting domain was added ({domain}).")

    if ct == "removed":
        if domain_type == "CUSTOM":
            return (
                "high",
                f"A custom domain was removed from Firebase Hosting ({domain}). "
                "If this was a production domain, your application may be unavailable on it.",
            )
        return ("low", f"A Firebase Hosting domain was removed ({domain}).")

    if fp == "status":
        return ("medium", f"The status of a Firebase Hosting domain changed ({domain}).")

    return ("medium", f"A Firebase Hosting domain configuration changed ({domain}).")


# ── firebase_function_metadata ────────────────────────────────────────────────

def _classify_function_metadata_change(change: object) -> tuple[str, str]:
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    new_v = _get(change, "new_value")
    pm = (_get(change, "provider_metadata") or {}) if isinstance(_get(change, "provider_metadata"), dict) else {}
    fn_name = pm.get("function_name", "")

    if ct == "added":
        return ("low", f"A new Cloud Function was added ({fn_name}).")
    if ct == "removed":
        return ("medium", f"A Cloud Function was removed ({fn_name}).")

    if fp == "status":
        if str(new_v).upper() in ("FAILED", "CRASH_LOOP_BACK_OFF", "UNKNOWN"):
            return (
                "medium",
                f"Cloud Function {fn_name!r} status changed to {new_v!r}. "
                "Verify the function is healthy.",
            )
        return ("low", f"Cloud Function {fn_name!r} status changed to {new_v!r}.")

    if fp == "runtime":
        return (
            "medium",
            f"The runtime for Cloud Function {fn_name!r} changed to {new_v!r}. "
            "Verify this is an intentional upgrade or change.",
        )

    if fp == "trigger_type":
        return (
            "medium",
            f"The trigger type for Cloud Function {fn_name!r} changed to {new_v!r}. "
            "Verify the trigger configuration is correct.",
        )

    if fp == "env_var_key_count":
        return (
            "medium",
            f"The number of environment variable keys for Cloud Function {fn_name!r} changed. "
            "Verify the environment configuration is correct. "
            "(ConfigTrace does not store environment variable values.)",
        )

    return ("low", f"A Cloud Function metadata field changed ({fn_name}).")


# ── Main dispatcher ────────────────────────────────────────────────────────────

# ── M57.8: firebase_remote_config_template ────────────────────────────────────

def _classify_remote_config_change(change: object) -> tuple[str, str]:
    """Classify risk for ``firebase_remote_config_template`` changes (M57.8).

    Remote Config controls which feature flags, parameters, and conditions are
    served to clients.  Structural changes (parameter removals, condition drops)
    may unexpectedly affect app behaviour.

    Priority order:
    1. Removed template record → high (unexpected; RC may be misconfigured)
    2. Added template record → low (baseline captured)
    3. parameter_count drops → medium (parameters removed)
    4. condition_count drops → medium (conditions removed)
    5. parameter_keys_hash / condition_names_hash changed → medium (structural)
    6. update_type changed to FORCED_UPDATE / ROLLBACK → medium (operational)
    7. version_number / update_origin → low (routine increments)
    8. parameter_group_count changes → low
    """
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    old_v = _get(change, "old_value")
    new_v = _get(change, "new_value")

    if ct == "removed":
        return (
            "high",
            "The Firebase Remote Config template record was removed. "
            "This may indicate the template was deleted or the connector lost access. "
            "Verify the project's Remote Config is still active.",
        )
    if ct == "added":
        return (
            "low",
            "Firebase Remote Config template baseline captured. "
            "Future structural changes will generate change events.",
        )

    def _int(v: object) -> int:
        try:
            return int(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return 0

    if fp == "parameter_count":
        old_n, new_n = _int(old_v), _int(new_v)
        if new_n < old_n:
            return (
                "medium",
                f"Firebase Remote Config parameter count decreased from {old_n} to {new_n}. "
                "Parameters may have been removed — verify this is intentional and that "
                "client apps handle missing parameters gracefully.",
            )
        return (
            "low",
            f"Firebase Remote Config parameter count changed from {old_n} to {new_n}.",
        )

    if fp == "condition_count":
        old_n, new_n = _int(old_v), _int(new_v)
        if new_n < old_n:
            return (
                "medium",
                f"Firebase Remote Config condition count decreased from {old_n} to {new_n}. "
                "Conditions may have been removed; targeted parameter values may no longer apply.",
            )
        return (
            "low",
            f"Firebase Remote Config condition count changed from {old_n} to {new_n}.",
        )

    if fp == "parameter_keys_hash":
        return (
            "medium",
            "The set of Firebase Remote Config parameter keys may have changed. "
            "Review the template to confirm additions or removals are intentional.",
        )

    if fp == "condition_names_hash":
        return (
            "medium",
            "The set of Firebase Remote Config condition names may have changed. "
            "Review the template to confirm the targeting logic is correct.",
        )

    if fp == "update_type":
        update_type_str = str(new_v or "").upper()
        if update_type_str in ("FORCED_UPDATE", "ROLLBACK"):
            return (
                "medium",
                f"Firebase Remote Config was updated with type {update_type_str!r}. "
                "Forced updates and rollbacks may affect all clients immediately.",
            )
        return (
            "low",
            f"Firebase Remote Config update type changed to {new_v!r}.",
        )

    if fp == "version_number":
        return (
            "low",
            f"Firebase Remote Config version incremented to {new_v!r}. "
            "This is recorded on every template publish.",
        )

    if fp == "update_origin":
        return (
            "low",
            f"Firebase Remote Config was published from {new_v!r} (previously {old_v!r}).",
        )

    if fp == "parameter_group_count":
        return (
            "low",
            f"Firebase Remote Config parameter group count changed from {old_v} to {new_v}.",
        )

    return ("low", "A Firebase Remote Config template metadata field changed.")


# ── M57.8: firebase_app_check_config ─────────────────────────────────────────

def _classify_app_check_change(change: object) -> tuple[str, str]:
    """Classify risk for ``firebase_app_check_config`` changes (M57.8).

    Firebase App Check reduces unauthorized API access.  Removing enforcement
    from services could allow unattested clients to call Firebase APIs.

    Priority order:
    1. Removed record → high (App Check monitoring lost)
    2. Added record → low (baseline captured)
    3. enforced_service_count decreases → high (protection reduced)
    4. unenforced_service_count increases → high (more services unprotected)
    5. service_count changes → medium (services added/removed from monitoring)
    6. enforced_service_names changes → medium (which services are covered)
    """
    fp = (_get(change, "field_path") or "").lower()
    ct = (_get(change, "change_type") or "").lower()
    old_v = _get(change, "old_value")
    new_v = _get(change, "new_value")

    if ct == "removed":
        return (
            "high",
            "The Firebase App Check configuration record was removed. "
            "This may indicate App Check is no longer enabled or the connector "
            "lost access to the App Check API.",
        )
    if ct == "added":
        return (
            "low",
            "Firebase App Check configuration baseline captured. "
            "Future enforcement changes will generate change events.",
        )

    def _int(v: object) -> int:
        try:
            return int(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return 0

    if fp == "enforced_service_count":
        old_n, new_n = _int(old_v), _int(new_v)
        if new_n < old_n:
            return (
                "high",
                f"Firebase App Check enforcement was removed from {old_n - new_n} service(s) "
                f"(enforced: {old_n} → {new_n}). "
                "Unenforced services may accept requests from unattested clients.",
            )
        return (
            "low",
            f"Firebase App Check enforcement was added to {new_n - old_n} service(s) "
            f"(enforced: {old_n} → {new_n}). "
            "This may improve protection against unauthorized clients.",
        )

    if fp == "unenforced_service_count":
        old_n, new_n = _int(old_v), _int(new_v)
        if new_n > old_n:
            return (
                "high",
                f"The number of Firebase services without App Check enforcement "
                f"increased from {old_n} to {new_n}. "
                "Additional services may now accept requests from unattested clients.",
            )
        return (
            "low",
            f"The number of unenforced Firebase App Check services decreased "
            f"from {old_n} to {new_n}.",
        )

    if fp == "service_count":
        old_n, new_n = _int(old_v), _int(new_v)
        if new_n < old_n:
            return (
                "medium",
                f"The number of Firebase services monitored by App Check decreased "
                f"from {old_n} to {new_n}. Verify no service was removed unintentionally.",
            )
        return (
            "medium",
            f"The number of Firebase services monitored by App Check changed "
            f"from {old_n} to {new_n}.",
        )

    if fp == "enforced_service_names":
        return (
            "medium",
            "The set of Firebase App Check–enforced services changed. "
            "Review which services now have enforcement active.",
        )

    return ("low", "A Firebase App Check configuration field changed.")


def classify_firebase_change(change: object) -> tuple[str, str]:
    """Return (risk_level, risk_reason) for a Firebase change.

    Dispatches to a per-record-type classifier.  Returns
    ``("low", "…")`` as a safe fallback for unrecognised record types.
    """
    pm = _get(change, "provider_metadata") or {}
    record_type = (pm.get("record_type") or "").lower() if isinstance(pm, dict) else ""

    if record_type == "firebase_project":
        return _classify_project_change(change)
    if record_type == "firebase_auth_config":
        return _classify_auth_config_change(change)
    if record_type == "firebase_auth_provider":
        return _classify_auth_provider_change(change)
    if record_type == "firebase_authorized_domain":
        return _classify_authorized_domain_change(change)
    if record_type == "firebase_firestore_ruleset":
        return _classify_firestore_ruleset_change(change)
    if record_type == "firebase_storage_bucket":
        return _classify_storage_bucket_change(change)
    if record_type == "firebase_storage_ruleset":
        return _classify_storage_ruleset_change(change)
    if record_type == "firebase_hosting_site":
        return _classify_hosting_site_change(change)
    if record_type == "firebase_hosting_domain":
        return _classify_hosting_domain_change(change)
    if record_type == "firebase_function_metadata":
        return _classify_function_metadata_change(change)
    # M57.8
    if record_type == "firebase_remote_config_template":
        return _classify_remote_config_change(change)
    if record_type == "firebase_app_check_config":
        return _classify_app_check_change(change)

    return ("low", f"A Firebase configuration record changed ({record_type}).")
