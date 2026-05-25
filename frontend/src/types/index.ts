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

/** Request body for POST /integrations.
 *
 * Provider-specific fields are optional at the type level; the caller must
 * provide the correct subset for the chosen provider.
 *
 * Cloudflare: api_token + zone_id (required)
 * GitHub:     github_token + repo_owner + repo_name (required)
 * Vercel:     vercel_token + vercel_project_id (required)
 * Stripe:     stripe_api_key (required)
 * AWS:        aws_access_key_id + aws_secret_access_key + aws_default_region (required)
 *             aws_selected_regions (optional, defaults to [aws_default_region])
 */
export interface IntegrationCreateRequest {
  provider: "cloudflare" | "github" | "vercel" | "stripe" | "aws";
  display_name: string;
  // ── Cloudflare fields ──────────────────────────────────────────────────────
  /** Sent to backend once; never stored in frontend state after submission. */
  api_token?: string;
  zone_id?: string;
  // ── GitHub fields ──────────────────────────────────────────────────────────
  /** Fine-grained PAT; sent once; never stored after submission. */
  github_token?: string;
  repo_owner?: string;
  repo_name?: string;
  // ── Vercel fields ──────────────────────────────────────────────────────────
  /** Vercel personal access token; sent once; never stored after submission. */
  vercel_token?: string;
  /** Vercel project ID (prj_xxx) or slug; sent once. */
  vercel_project_id?: string;
  // ── Stripe fields ──────────────────────────────────────────────────────────
  /**
   * Stripe restricted API key (rk_live_... or rk_test_...).
   * Sent once; cleared from state immediately after submission.
   * SECURITY: never stored in localStorage/sessionStorage; never returned by backend.
   */
  stripe_api_key?: string;
  // ── AWS fields ─────────────────────────────────────────────────────────────
  /**
   * AWS IAM access key ID (AKIA...).
   * Sent once; cleared from state immediately after submission.
   * SECURITY: never stored in localStorage/sessionStorage; never returned by backend.
   * Partially redacted in logs (first 4 chars only).
   */
  aws_access_key_id?: string;
  /**
   * AWS IAM secret access key.
   * Sent once; cleared from state immediately after submission.
   * SECURITY: never logged or returned by backend under any circumstances.
   */
  aws_secret_access_key?: string;
  /** Primary region for STS and EC2 calls (e.g. "us-east-1"). */
  aws_default_region?: string;
  /** Regions to actively monitor. Defaults to [aws_default_region] if omitted. */
  aws_selected_regions?: string[];
}

/** Matches backend IntegrationResponse schema (no user_id, no updated_at). */
export interface Integration {
  id: string;
  provider: string;
  display_name: string;
  status: IntegrationStatus;
  last_synced_at: string | null;
  created_at: string;
  /** Number of Resource rows attached to this integration (always ≥ 1 after creation). */
  resource_count: number;
  // M29 additions
  /** Scheduled sync cadence in minutes. Null means default (60). */
  sync_interval_minutes: number | null;
  /** Status of the most recent SyncRun for this integration, or null if never synced. */
  last_sync_status: "pending" | "running" | "completed" | "failed" | null;
  /** Error message from the most recent failed SyncRun, or null. */
  last_sync_error: string | null;
  // M31 addition
  /**
   * How the integration authenticates to GitHub.
   * "github_app" — GitHub App installation token (recommended)
   * "pat"        — fine-grained Personal Access Token
   * null         — not a GitHub integration (e.g. Cloudflare)
   */
  connection_method: "github_app" | "pat" | null;
  // M32 additions
  /**
   * Number of consecutive *scheduled* sync failures since the last success.
   * Reset to 0 on any successful sync.  Manual failures are not counted.
   */
  consecutive_failure_count: number;
  /**
   * True when consecutive_failure_count >= 3.  The backend computes this so
   * the frontend doesn't need to know the threshold.
   */
  needs_attention: boolean;
}

// ── GitHub App install flow (M31) ─────────────────────────────────────────────

/** Response from GET /integrations/github/app/install-url */
export interface GitHubAppInstallUrlResponse {
  install_url: string;
  state: string;
}

/** A single repository returned by GET /integrations/github/app/installation-repos */
export interface GitHubInstallationRepo {
  full_name: string;
  owner: string;
  name: string;
  private: boolean;
  description: string | null;
}

/** Response from GET /integrations/github/app/installation-repos */
export interface GitHubInstallationReposResponse {
  repos: GitHubInstallationRepo[];
  installation_id: number;
}

/** Request body for POST /integrations/github/app/complete */
export interface GitHubAppCompleteRequest {
  installation_id: number;
  state: string;
  repo_owner: string;
  repo_name: string;
  display_name: string;
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
  // M32: structured failure classification (null for non-failed runs)
  failure_category: string | null;
  error_code: string | null;
  recommended_action: string | null;
}

/** Matches backend SyncRunListResponse — GET /integrations/{id}/sync-runs. */
export interface SyncRunListResponse {
  sync_runs: SyncRun[];
  /** Filtered count of SyncRuns (reflects any applied status/trigger filters). */
  total: number;
  /** Current page number (1-indexed). */
  page: number;
  /** Rows per page. */
  page_size: number;
  /** Total number of pages. */
  total_pages: number;
}

// ── Dashboard summary (M34) ───────────────────────────────────────────────────

export interface IntegrationHealthCounts {
  total: number;
  active: number;
  paused: number;
  needs_attention: number;
  failed_last_24h: number;
  with_consecutive_failures: number;
}

export interface ResourceCounts {
  total: number;
  active: number;
}

export interface ChangeActivityCounts {
  total: number;
  last_24h: number;
  last_7d: number;
  high_critical_last_7d: number;
  last_change_at: string | null;
}

export interface RiskDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ProviderStats {
  provider: string;
  integration_count: number;
  resource_count: number;
  change_count_7d: number;
}

export interface DashboardRecentChange {
  id: string;
  integration_id: string;
  resource_id: string;
  integration_name: string | null;
  provider: string | null;
  record_identifier: string;
  change_type: string;
  risk_level: string;
  field_path: string | null;
  created_at: string;
}

export interface DashboardRecentFailedSync {
  integration_id: string;
  integration_name: string;
  provider: string;
  last_sync_status: string | null;
  last_sync_error: string | null;
  failure_category: string | null;
  error_code: string | null;
  recommended_action: string | null;
  consecutive_failure_count: number;
  needs_attention: boolean;
  last_failure_at: string | null;
}

export interface DashboardSummary {
  integration_health: IntegrationHealthCounts;
  resource_counts: ResourceCounts;
  change_activity: ChangeActivityCounts;
  risk_distribution: RiskDistribution;
  provider_distribution: ProviderStats[];
  recent_high_critical_changes: DashboardRecentChange[];
  recent_failed_syncs: DashboardRecentFailedSync[];
  last_updated_at: string;
}

// ── User settings (M34) ───────────────────────────────────────────────────────

export type AlertRiskThreshold = "critical_only" | "high_and_critical" | "medium_and_above";
export type TimelineRange = "24h" | "7d" | "30d" | "all";
export type ProviderFilter = "all" | "cloudflare" | "github" | "vercel" | "stripe" | "aws";

export interface UserSettings {
  // Alert policy
  alert_risk_threshold: AlertRiskThreshold;
  sync_failure_alerts_enabled: boolean;
  sync_failure_threshold: 2 | 3 | 5;
  sync_failure_cooldown_hours: 6 | 12 | 24;
  // Sync defaults (new integrations only)
  default_sync_enabled: boolean;
  default_sync_interval_minutes: 5 | 10 | 15 | 30 | 60;
  default_change_alerts_enabled: boolean;
  // UI preferences
  default_timeline_range: TimelineRange;
  default_provider_filter: ProviderFilter;
}

export type UserSettingsUpdateRequest = Partial<UserSettings>;

// ── Workspaces (M50) ──────────────────────────────────────────────────────────

export type WorkspaceRole = "owner" | "admin" | "member";
export type InviteRole = "admin" | "member";

export interface Workspace {
  id: string;
  name: string;
  created_by_user_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface WorkspaceListResponse {
  workspaces: Workspace[];
  total: number;
}

export interface WorkspaceMember {
  id: string;
  workspace_id: string;
  user_id: string;
  role: WorkspaceRole;
  email: string | null;
  display_name: string | null;
  created_at: string;
  updated_at: string;
}

export interface MemberListResponse {
  members: WorkspaceMember[];
  total: number;
}

export interface WorkspaceInvite {
  id: string;
  workspace_id: string;
  email: string;
  role: InviteRole;
  invited_by_user_id: string | null;
  expires_at: string;
  accepted_at: string | null;
  revoked_at: string | null;
  created_at: string;
  is_active: boolean;
}

export interface InviteCreateResponse extends WorkspaceInvite {
  /** Raw token — returned once; display or copy immediately. */
  invite_token: string;
  invite_url: string;
  /**
   * True when the backend successfully sent an invite email via Resend.
   * False when email is unconfigured or Resend returned an error.
   * The copy-link fallback is shown regardless of this value.
   */
  email_sent: boolean;
}

export interface InviteListResponse {
  invites: WorkspaceInvite[];
  total: number;
}

/** Returned by GET /invites/{token} — no auth required. */
export interface InvitePreview {
  workspace_name: string;
  inviter_email: string | null;
  role: InviteRole;
  email: string;
  expires_at: string;
  is_active: boolean;
}

// ── Workspace Audit Log (M51) ─────────────────────────────────────────────────

export interface WorkspaceAuditLog {
  id: string;
  workspace_id: string;
  actor_user_id: string | null;
  event_type: string;
  target_type: string | null;
  target_id: string | null;
  target_display_name: string | null;
  metadata_json: Record<string, unknown> | null;
  created_at: string;
  /** Joined from User (populated by service layer). */
  actor_email: string | null;
  actor_display_name: string | null;
}

export interface AuditLogListResponse {
  logs: WorkspaceAuditLog[];
  total: number;
}

// ── Billing (M52) ─────────────────────────────────────────────────────────────

export type BillingPlan = "free" | "pro" | "team";
export type BillingStatus =
  | "active"
  | "trialing"
  | "past_due"
  | "canceled"
  | "unpaid";

export interface PlanLimits {
  max_integrations: number;
  max_members: number;
  min_sync_interval_minutes: number;
  history_retention_days: number;
}

export interface BillingUsage {
  integrations: number;
  members: number;
}

export interface WorkspaceBilling {
  workspace_id: string;
  plan: BillingPlan;
  status: BillingStatus;
  stripe_customer_id: string | null;
  stripe_subscription_id: string | null;
  current_period_start: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  trial_end: string | null;
  limits: PlanLimits;
  usage: BillingUsage;
}
