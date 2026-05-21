// ── Shared ────────────────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

// ── DNS record (snapshot state element) ───────────────────────────────────────

export interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  value: string;
  [key: string]: unknown;
}

// ── Changes ───────────────────────────────────────────────────────────────────

export type ChangeType = "added" | "removed" | "modified";
export type RiskLevel = "critical" | "high" | "medium" | "low" | "unknown";

export interface ChangeListItem {
  id: string;
  integration_id: string;
  resource_id: string;
  change_type: ChangeType;
  record_identifier: string;
  field_path: string | null;
  prev_value: unknown;
  new_value: unknown;
  risk_level: RiskLevel;
  risk_reason: string | null;
  provider_metadata: Record<string, unknown> | null;
  created_at: string;
}

export interface ChangeDetail extends ChangeListItem {
  prev_snapshot_id: string | null;
  new_snapshot_id: string | null;
  prev_snapshot_state: DnsRecord[] | null;
  new_snapshot_state: DnsRecord[] | null;
  prev_snapshot_created_at: string | null;
  new_snapshot_created_at: string | null;
}

// ── Resources ─────────────────────────────────────────────────────────────────

export interface ResourceListItem {
  id: string;
  integration_id: string;
  provider_resource_type: string;
  provider_resource_id: string;
  display_name: string | null;
  metadata: Record<string, unknown> | null;
  last_snapshot_at: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface ResourceDetail extends ResourceListItem {
  snapshot_count: number;
  change_count: number;
}

// ── Snapshots ─────────────────────────────────────────────────────────────────

export interface SnapshotListItem {
  id: string;
  resource_id: string;
  integration_id: string;
  content_hash: string;
  triggered_by: string | null;
  sync_run_id: string | null;
  state: DnsRecord[];
  created_at: string;
}

// ── Integrations ──────────────────────────────────────────────────────────────

export type IntegrationStatus = "active" | "error" | "paused" | "unknown";

export interface Integration {
  id: string;
  user_id: string;
  provider: string;
  display_name: string;
  status: IntegrationStatus;
  last_synced_at: string | null;
  created_at: string;
  updated_at: string;
}

// ── Sync runs ─────────────────────────────────────────────────────────────────

export type SyncRunStatus = "pending" | "running" | "success" | "failed";

export interface SyncRun {
  id: string;
  integration_id: string;
  status: SyncRunStatus;
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
  created_at: string;
}
