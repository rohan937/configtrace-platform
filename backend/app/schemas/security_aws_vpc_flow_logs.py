"""Schemas for AWS VPC Flow Logs ingestion (M67.10)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AwsVpcFlowLogSyncRequest(BaseModel):
    """POST /security/aws-vpc-flow-logs/sync request body.

    ``flow_log_bucket`` is required: VPC Flow Logs are read from a configured
    flow-log delivery bucket in S3 (bounded).
    """

    flow_log_bucket: str = Field(min_length=1, max_length=255)
    integration_id: Optional[str] = None
    flow_log_prefix: Optional[str] = Field(default=None, max_length=512)
    max_files: Optional[int] = Field(default=None, ge=1, le=200)
    max_events: Optional[int] = Field(default=None, ge=1, le=50000)


class AwsVpcFlowLogSyncResponse(BaseModel):
    """VPC Flow Log ingestion summary."""

    attempted: bool
    succeeded: bool
    provider: str
    integration_id: Optional[str] = None
    source: str
    files_seen: int = 0
    files_read: int = 0
    flows_seen: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    permission_limited: bool = False
    error_message: Optional[str] = None


class AwsVpcFlowSignalGenerateRequest(BaseModel):
    """POST /security/aws-vpc-flow-logs/generate-signals request (optional)."""

    lookback_hours: Optional[int] = Field(default=None, ge=1, le=168)
    max_signals: Optional[int] = Field(default=None, ge=1, le=1000)
    rejected_threshold: Optional[int] = Field(default=None, ge=1, le=1_000_000)
    sensitive_port_threshold: Optional[int] = Field(default=None, ge=1, le=1_000_000)
    bytes_threshold: Optional[int] = Field(default=None, ge=1, le=1_000_000_000_000)


class AwsVpcFlowSignalGenerateResponse(BaseModel):
    """VPC Flow Log network-signal generation summary (M67.11)."""

    provider: str
    events_scanned: int = 0
    interfaces_scanned: int = 0
    signals_created: int = 0
    signals_skipped: int = 0
