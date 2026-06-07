"""Firebase security exposure rules — M60.4.

Backed by the normalized ``firebase_firestore_ruleset`` record
(app/connectors/firebase_schema.py): ``is_public`` (bool, conservative
"allow if true"-style analysis), ``record_id``. Raw rule text is never stored
or inspected — only the boolean flag.
"""

from __future__ import annotations

from typing import Any

from app.connectors.firebase_schema import FIREBASE_FIRESTORE_RULESET
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

_RULE_RULES_PUBLIC = "firebase_rules_public"


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    if record.get("record_type") != FIREBASE_FIRESTORE_RULESET:
        return []

    if "is_public" not in record:
        return []
    if record.get("is_public") is not True:
        return []

    record_id = get_str(record, "record_id") or None
    name = get_str(record, "name") or record_id or "the active ruleset"

    return [
        FindingCandidate(
            provider="firebase",
            rule_key=_RULE_RULES_PUBLIC,
            finding_key=make_finding_key(_RULE_RULES_PUBLIC, record_id),
            severity="high",
            title="Firebase Firestore rules appear publicly permissive",
            description=(
                "The active Firestore security ruleset appears to allow public "
                "access (an overly permissive allow rule). This can expose "
                "documents to unauthenticated reads or writes."
            ),
            evidence={"rule": _RULE_RULES_PUBLIC, "ruleset": name},
            remediation={
                "summary": "Tighten Firestore security rules to require auth.",
                "steps": [
                    "Replace broad 'allow if true' rules with auth-scoped checks.",
                    "Restrict reads/writes to the documents each user owns.",
                    "Test rules with the Firebase rules simulator before publishing.",
                ],
            },
            record_id=record_id,
        )
    ]
