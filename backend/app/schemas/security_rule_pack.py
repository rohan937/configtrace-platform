"""Pydantic schemas for the Security Exposure rule pack (M63.3)."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel


class SecurityRulePackRule(BaseModel):
    rule_key: str
    provider: str
    rule_version: str
    introduced_in: str
    status: str  # "active"
    confidence: str  # high | medium | low
    severity: str
    category: str


class SecurityRulePackResponse(BaseModel):
    name: str
    version: str
    released_at: Optional[str] = None
    description: str
    rule_count: int
    providers: List[str]
    rules: List[SecurityRulePackRule]
