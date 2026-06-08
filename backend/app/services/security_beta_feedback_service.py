"""Qualitative beta feedback for Security Exposure reports (M63.6).

Stores an optional rating (+ short comment) after a report export. First-party
only; allowlisted + truncated context. Never stores report contents or any
sensitive payload.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.security_beta_feedback import SecurityBetaFeedback

ALLOWED_RATINGS: frozenset[str] = frozenset({"useful", "somewhat", "not_useful"})

# Only report-export feedback for now; extend deliberately.
ALLOWED_FEEDBACK_TYPES: frozenset[str] = frozenset({"report_export"})

# Small, non-sensitive context. Anything else is dropped. NEVER contains report
# markdown/JSON/CSV, evidence, remediation, notes, secrets, tokens, payloads,
# acceptance reasons, or rule JSON.
ALLOWED_CONTEXT_KEYS: frozenset[str] = frozenset(
    {
        "report_type",
        "export_format",
        "finding_count",
        "active_count",
        "critical_count",
        "high_count",
        "demo_loaded",
    }
)

MAX_COMMENT_LEN = 500
MAX_STR_LEN = 100
MAX_CONTEXT_KEYS = 12


def sanitize_context(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Allowlisted, scalar-only, truncated copy of the context object."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in ALLOWED_CONTEXT_KEYS:
            continue
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, (int, float)):
            out[key] = value
        elif isinstance(value, str):
            out[key] = value[:MAX_STR_LEN]
        else:
            continue  # drop None / dict / list / anything else
        if len(out) >= MAX_CONTEXT_KEYS:
            break
    return out


def record_feedback(
    *,
    workspace_id: uuid.UUID,
    user_id: Optional[uuid.UUID],
    feedback_type: str,
    rating: str,
    comment: Optional[str],
    context: Optional[dict[str, Any]],
    db: Session,
) -> SecurityBetaFeedback:
    """Validate + persist one feedback row. Raises ValueError on bad enums."""
    if feedback_type not in ALLOWED_FEEDBACK_TYPES:
        raise ValueError(f"Unknown feedback_type: {feedback_type!r}")
    if rating not in ALLOWED_RATINGS:
        raise ValueError(f"Invalid rating: {rating!r}")

    safe_comment: Optional[str] = None
    if isinstance(comment, str):
        trimmed = comment.strip()
        if trimmed:
            safe_comment = trimmed[:MAX_COMMENT_LEN]

    feedback = SecurityBetaFeedback(
        workspace_id=workspace_id,
        user_id=user_id,
        feedback_type=feedback_type,
        rating=rating,
        comment=safe_comment,
        context=sanitize_context(context),
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)
    return feedback
