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


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == FIREBASE_FIRESTORE_RULESET:
        return _eval_ruleset(record, "Firestore", _RULE_FIRESTORE_PUBLIC)
    if rtype == FIREBASE_STORAGE_RULESET:
        return _eval_ruleset(record, "Storage", _RULE_STORAGE_PUBLIC)
    if rtype == FIREBASE_AUTH_CONFIG:
        return _eval_auth_config(record)
    return []


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
    if record.get("anonymous_enabled") is not True:
        return []

    record_id = get_str(record, "record_id") or "auth_config"
    project = get_str(record, "project_id")

    return [
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
    ]
