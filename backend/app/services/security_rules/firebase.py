"""Firebase security exposure rules — M60.4 / fixed + expanded in M60.4.4.

Every rule fires only on explicit, reliable normalized fields produced by the
Firebase connector (app/connectors/firebase.py + firebase_schema.py). Evidence
is metadata-only: project id, release name, public read/write booleans, parser
confidence, auth setting booleans. Raw security-rule text is NEVER read — the
connector only stores hashes and detection booleans, and we never surface even
the rule summary.

M60.4.4 fix
-----------
The M60.4 rule checked ``record.get("is_public")`` — a field the connector does
NOT emit (the real fields are ``public_read_detected`` / ``public_write_detected``
+ ``parser_confidence``). That rule therefore never fired on real data. This
module corrects the logic to the real schema and adds Storage rules + auth.

Record types consumed
---------------------
- ``firebase_firestore_ruleset`` → Firestore rules allow public read/write
- ``firebase_storage_ruleset``   → Storage rules allow public read/write
- ``firebase_auth_config``       → anonymous sign-in enabled

Deferred Firebase rules (intentionally NOT implemented — see report)
-------------------------------------------------------------------
* "Unsafe auth provider": ``firebase_auth_provider`` only carries provider_type
  (saml/oidc) + enabled — none of which is inherently unsafe. The clear signal
  is ``anonymous_enabled`` (auth_config), which we DO use.
* Missing API-key restrictions: there is no ``firebase_api_key`` /
  web-app-config record type, so this cannot be evaluated. Deferred.
* Low-confidence rule detections: when ``parser_confidence == "low"`` we do NOT
  flag, to avoid false positives from ambiguous rule sources.
"""

from __future__ import annotations

from typing import Any

from app.connectors.firebase_schema import (
    FIREBASE_AUTH_CONFIG,
    FIREBASE_DATABASE_RULESET,
    FIREBASE_FIRESTORE_RULESET,
    FIREBASE_STORAGE_RULESET,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

_RULE_FIRESTORE_PUBLIC = "firebase_rules_public"  # kept key (Firestore)
_RULE_STORAGE_PUBLIC = "firebase_storage_rules_public"
_RULE_ANON_AUTH = "firebase_anonymous_auth_enabled"
# M72A
_RULE_DB_PUBLIC_READ = "firebase_database_public_read"
_RULE_DB_PUBLIC_WRITE = "firebase_database_public_write"
_RULE_AUTH_PROTECTION_MISSING = "firebase_auth_protection_missing"


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == FIREBASE_FIRESTORE_RULESET:
        return _eval_ruleset(record, "Firestore", _RULE_FIRESTORE_PUBLIC)
    if rtype == FIREBASE_STORAGE_RULESET:
        return _eval_ruleset(record, "Storage", _RULE_STORAGE_PUBLIC)
    if rtype == FIREBASE_DATABASE_RULESET:
        return _eval_database_ruleset(record)
    if rtype == FIREBASE_AUTH_CONFIG:
        return _eval_auth_config(record)
    return []


# ── Realtime Database public-rule detection (M72A) ───────────────────────────


def _eval_database_ruleset(record: dict[str, Any]) -> list[FindingCandidate]:
    """Realtime Database rules: separate public-read and public-write findings.

    Both rules are data-backed by the connector's metadata-only booleans
    (``public_read_detected`` / ``public_write_detected``). Low-confidence parses
    are skipped to avoid false positives. Raw rules JSON is never read here.
    """
    public_read = record.get("public_read_detected") is True
    public_write = record.get("public_write_detected") is True
    if not (public_read or public_write):
        return []

    confidence = get_str(record, "parser_confidence")
    if confidence == "low":
        return []

    record_id = get_str(record, "record_id") or None
    instance = get_str(record, "name") or record_id or "the database instance"
    out: list[FindingCandidate] = []

    if public_read:
        out.append(
            FindingCandidate(
                provider="firebase",
                rule_key=_RULE_DB_PUBLIC_READ,
                finding_key=make_finding_key(_RULE_DB_PUBLIC_READ, record_id),
                severity="high",
                title="Firebase Realtime Database rules allow public read",
                description=(
                    f"The Realtime Database rules for {instance} appear to allow "
                    f"public (unauthenticated) read access. This may expose data "
                    f"depending on rule evaluation and application access patterns. "
                    f"This is evidence for review and does not confirm data "
                    f"exposure, unauthorized access, or compromise."
                ),
                evidence={
                    "rule": _RULE_DB_PUBLIC_READ,
                    "service": get_str(record, "service") or "realtime_database",
                    "public_read_detected": True,
                    "parser_confidence": confidence or "unknown",
                },
                remediation={
                    "summary": "Require authentication in the Realtime Database rules.",
                    "steps": [
                        "Replace '.read': true with auth-scoped expressions (e.g. auth != null).",
                        "Scope reads to the data each user owns.",
                        "Test rules in the Firebase rules simulator before publishing.",
                    ],
                },
                record_id=record_id,
            )
        )

    if public_write:
        out.append(
            FindingCandidate(
                provider="firebase",
                rule_key=_RULE_DB_PUBLIC_WRITE,
                finding_key=make_finding_key(_RULE_DB_PUBLIC_WRITE, record_id),
                severity="critical",
                title="Firebase Realtime Database rules allow public write",
                description=(
                    f"The Realtime Database rules for {instance} appear to allow "
                    f"public (unauthenticated) write access. This may expose data "
                    f"depending on rule evaluation and application access patterns "
                    f"and may increase unauthorized-access risk. This is evidence "
                    f"for review and does not confirm data exposure, unauthorized "
                    f"access, or compromise."
                ),
                evidence={
                    "rule": _RULE_DB_PUBLIC_WRITE,
                    "service": get_str(record, "service") or "realtime_database",
                    "public_write_detected": True,
                    "parser_confidence": confidence or "unknown",
                },
                remediation={
                    "summary": "Require authentication in the Realtime Database rules.",
                    "steps": [
                        "Replace '.write': true with auth-scoped, ownership-checked expressions.",
                        "Never allow unauthenticated writes to shared paths.",
                        "Test rules in the Firebase rules simulator before publishing.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── Firestore / Storage public-rule detection ────────────────────────────────


def _eval_ruleset(
    record: dict[str, Any], label: str, rule_key: str
) -> list[FindingCandidate]:
    public_read = record.get("public_read_detected") is True
    public_write = record.get("public_write_detected") is True
    if not (public_read or public_write):
        return []

    # Conservative: skip low-confidence detections to avoid false positives.
    confidence = get_str(record, "parser_confidence")
    if confidence == "low":
        return []

    record_id = get_str(record, "record_id") or None
    release = get_str(record, "release_name") or record_id or "the active ruleset"

    # Public WRITE is worse than public READ.
    severity = "critical" if public_write else "high"
    access = "read and write" if public_write else "read"

    return [
        FindingCandidate(
            provider="firebase",
            rule_key=rule_key,
            finding_key=make_finding_key(rule_key, record_id),
            severity=severity,
            title=f"Firebase {label} rules allow public {access}",
            description=(
                f"The active {label} security ruleset appears to allow public "
                f"{access} access (an overly permissive 'allow' rule). This may "
                f"expose data to unauthenticated users."
            ),
            evidence={
                "rule": rule_key,
                "release": release,
                "public_read_detected": public_read,
                "public_write_detected": public_write,
                "parser_confidence": confidence or "unknown",
            },
            remediation={
                "summary": f"Tighten {label} security rules to require auth.",
                "steps": [
                    "Replace broad 'allow if true' rules with auth-scoped checks.",
                    "Restrict access to the documents/objects each user owns.",
                    "Test rules with the Firebase rules simulator before publishing.",
                ],
            },
            record_id=record_id,
        )
    ]


# ── Auth config (M60.4.4) ────────────────────────────────────────────────────


def _eval_auth_config(record: dict[str, Any]) -> list[FindingCandidate]:
    record_id = get_str(record, "record_id") or "auth_config"
    project = get_str(record, "project_id")
    out: list[FindingCandidate] = []

    if record.get("anonymous_enabled") is True:
        out.append(
            FindingCandidate(
                provider="firebase",
                rule_key=_RULE_ANON_AUTH,
                finding_key=make_finding_key(_RULE_ANON_AUTH, record_id),
                severity="medium",
                title="Firebase anonymous authentication is enabled",
                description=(
                    "Anonymous authentication is enabled. Combined with permissive "
                    "security rules, this may allow unauthenticated users to access "
                    "data. Ensure rules do not treat anonymous users as trusted."
                ),
                evidence={
                    "rule": _RULE_ANON_AUTH,
                    "project_id": project,
                    "anonymous_enabled": True,
                },
                remediation={
                    "summary": "Disable anonymous auth if not required.",
                    "steps": [
                        "Turn off the anonymous sign-in provider unless needed.",
                        "If kept, ensure security rules scope anonymous access tightly.",
                    ],
                },
                record_id=record_id,
            )
        )

    # ── M72A. Multi-factor authentication not enforced. ──────────────────────
    # Only an explicit mfa_enabled=False fires; missing/unknown is skipped.
    if record.get("mfa_enabled") is False:
        out.append(
            FindingCandidate(
                provider="firebase",
                rule_key=_RULE_AUTH_PROTECTION_MISSING,
                finding_key=make_finding_key(_RULE_AUTH_PROTECTION_MISSING, record_id),
                severity="medium",
                title="Firebase multi-factor authentication is not enabled",
                description=(
                    "Multi-factor authentication is not enabled for this Firebase "
                    "project's Authentication configuration. Without MFA, accounts "
                    "rely on a single factor, which may increase unauthorized-access "
                    "risk. This is evidence for review and does not confirm "
                    "unauthorized access or compromise."
                ),
                evidence={
                    "rule": _RULE_AUTH_PROTECTION_MISSING,
                    "project_id": project,
                    "mfa_enabled": False,
                },
                remediation={
                    "summary": "Enable multi-factor authentication for Firebase Auth.",
                    "steps": [
                        "Turn on MFA (TOTP/SMS) in the Firebase Authentication settings.",
                        "Encourage or require enrollment for privileged accounts.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out
