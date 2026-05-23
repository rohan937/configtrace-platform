"""AWS connector record type constants — M36 / M37."""
from __future__ import annotations

# ── M36 record types ──────────────────────────────────────────────────────────
AWS_ACCOUNT_IDENTITY = "aws_account_identity"
AWS_REGION = "aws_region"
AWS_SERVICE_INVENTORY = "aws_service_inventory"

# ── M37 record types ──────────────────────────────────────────────────────────
AWS_S3_BUCKET = "aws_s3_bucket"

AWS_RECORD_TYPES: frozenset[str] = frozenset({
    AWS_ACCOUNT_IDENTITY,
    AWS_REGION,
    AWS_SERVICE_INVENTORY,
    # M37
    AWS_S3_BUCKET,
})
