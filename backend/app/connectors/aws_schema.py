"""AWS connector record type constants — M36."""
from __future__ import annotations

AWS_ACCOUNT_IDENTITY = "aws_account_identity"
AWS_REGION = "aws_region"
AWS_SERVICE_INVENTORY = "aws_service_inventory"

AWS_RECORD_TYPES: frozenset[str] = frozenset({
    AWS_ACCOUNT_IDENTITY,
    AWS_REGION,
    AWS_SERVICE_INVENTORY,
})
