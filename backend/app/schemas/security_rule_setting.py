"""Pydantic schemas for workspace security rule settings — M61.7."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import UUID4, BaseModel, ConfigDict


class SecurityRuleSettingItem(BaseModel):
    """Effective enable/disable state for one rule in the current workspace."""

    rule_key: str
    enabled: bool
    # True when an explicit override row exists (vs the implicit default).
    explicit_setting: bool
    updated_at: Optional[datetime] = None
    updated_by_user_id: Optional[UUID4] = None

    model_config = ConfigDict(from_attributes=True)


class SecurityRuleSettingsListResponse(BaseModel):
    """All known rules with their effective state for the workspace."""

    items: List[SecurityRuleSettingItem]
    total: int


class RuleSettingUpdateRequest(BaseModel):
    """Body for PATCH /security/rules/settings/{rule_key}."""

    enabled: bool
