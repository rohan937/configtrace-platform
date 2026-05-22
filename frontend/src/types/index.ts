// ── Shared ────────────────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

// ── DNS record (snapshot state element) ───────────────────────────────────────

/**
 * Shape of a DNS record as returned by the Cloudflare connector.
 * All named fields are optional because the exact set varies by record type;
 * the index signature allows arbitrary additional fields from the backend.
 */
export interface DnsRecord {
  /** DNS record type, e.g. "A", "CNAME", "MX". */
  record_type?: string;
  name?: string;
  /** Resolved content / value of the record. */
  content?: string;
  ttl?: number;
  proxied?: boolean | null;
  priority?: number | null;
  comment?: string | null;
  record_id?: string;
  modified_on?: string | null;
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
  triggered_by: string;
  sync_run_id: string | null;
  state: DnsRecord[];
  created_at: string;
}

// ── Integrations ──────────────────────────────────────────────────────────────

export type IntegrationStatus = "active" | "error" | "paused" | "unknown";

/** Request body for POST /integrations. */
export interface IntegrationCreateRequest {
  provider: "cloudflare";
  display_name: string;
  /** Sent to backend once; never stored in frontend state after submission. */
  api_token: string;
  zone_id: string;
}

/** Matches backend IntegrationResponse schema (no user_id, no updated_at). */
export interface Integration {
  id: string;
  provider: string;
  display_name: string;
  status: IntegrationStatus;
  last_synced_at: string | null;
  created_at: string;
}

/** Matches backend IntegrationListResponse (uses "integrations" key, not "items"). */
export interface IntegrationListResponse {
  integrations: Integration[];
  total: number;
}

// ── Sync runs ─────────────────────────────────────────────────────────────────

/** Matches backend SyncRunResponse schema. */
export type SyncRunStatus = "pending" | "running" | "completed" | "failed";

export interface SyncRun {
  id: string;
  integration_id: string;
  user_id: string;
  status: SyncRunStatus;
  triggered_by: string;
  started_at: string | null;
  completed_at: string | null;
  change_count: number | null;
  snapshot_count: number | null;
  error_message: string | null;
  created_at: string;
}
