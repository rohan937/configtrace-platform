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

// ── M57.2: Review workflow ──────────────────────────────────────────────────

export type ReviewStatus = "needs_review" | "acknowledged" | "expected" | "snoozed";

/** Review state embedded in a Change response. null means no review row exists → treat as needs_review. */
export interface ChangeReviewInfo {
  review_status: ReviewStatus;
  reviewed_by_user_id: string | null;
  reviewed_at: string | null;
  review_note: string | null;
  snoozed_until: string | null;
  snooze_reason: string | null;
}

/** Returned from review action endpoints (POST /changes/{id}/acknowledge etc.) */
export interface ChangeReviewResponse {
  change_id: string;
  review_status: ReviewStatus;
  reviewed_by_user_id: string | null;
  reviewed_at: string | null;
  review_note: string | null;
  snoozed_until: string | null;
  snooze_reason: string | null;
}

export interface AcknowledgeRequest {
  note?: string;
}

export interface MarkExpectedRequest {
  note?: string;
}

export interface SnoozeRequest {
  until: string;  // ISO 8601 UTC datetime
  reason?: string;
}

export interface ReopenRequest {
  note?: string;
}

// ─────────────────────────────────────────────────────────────────────────────

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
  /** M57.2: review state. null = no review row (treat as needs_review). */
  review: ChangeReviewInfo | null;
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

// ``needs_reconnect`` (M59.14) — set automatically when the upstream provider
// credentials are revoked / installation uninstalled / token rotated.  UI shows
// a Reconnect affordance instead of Sync Now.
export type IntegrationStatus =
  | "active"
  | "error"
  | "paused"
  | "needs_reconnect"
  | "unknown";

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
  provider: "cloudflare" | "github" | "vercel" | "stripe" | "aws" | "firebase" | "supabase" | "shopify";
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
  // ── Firebase fields ────────────────────────────────────────────────────────
  /**
   * Full contents of the Firebase service account JSON key file.
   * Sent once; cleared from state immediately after submission.
   * SECURITY: contains a private_key — never stored in localStorage/sessionStorage;
   * never returned by backend; stored encrypted at rest.
   */
  firebase_service_account_json?: string;
  // ── Supabase fields ────────────────────────────────────────────────────────
  /**
   * Supabase Management API personal access token (sbp_...).
   * Sent once; cleared from state immediately after submission.
   * SECURITY: never stored in localStorage/sessionStorage; never returned by backend.
   */
  supabase_access_token?: string;
  /** Supabase project reference string (20-char alphanumeric). */
  supabase_project_ref?: string;
  // ── Shopify fields ─────────────────────────────────────────────────────────
  /**
   * Shopify store domain, e.g. "mystore.myshopify.com".
   * Do not include "https://".
   */
  shopify_shop_domain?: string;
  /**
   * Shopify Admin API access token (shpat_...).
   * Sent once; cleared from state immediately after submission.
   * SECURITY: never stored in localStorage/sessionStorage; never returned by backend.
   */
  shopify_access_token?: string;
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
  // M57.6 additions
  /**
   * Whether automated scheduled sync is enabled for this integration.
   * false → manual-only (user must trigger syncs explicitly).
   * Used to display honest cadence copy: "Manual sync only" vs. "Monitoring cadence: every N min".
   */
  scheduled_sync_enabled: boolean;
  /**
   * UTC ISO timestamp of the most recent sync failure of any type, or null.
   * Used for time-since-failure display and stale-sync warnings.
   */
  last_failure_at: string | null;
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

/** M57.3: Review queue counts embedded in the dashboard summary. */
export interface ReviewQueueCounts {
  /** Total changes needing review (no row, or status=needs_review, or expired snooze). */
  total: number;
  /** Critical-risk changes needing review. */
  critical: number;
  /** High-risk changes needing review. */
  high: number;
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
  /** M57.3: review queue counts. */
  review_queue: ReviewQueueCounts;
}

// ── M57.3: Snooze rules ───────────────────────────────────────────────────────

export interface ChangeSnoozeRule {
  id: string;
  workspace_id: string;
  integration_id: string;
  record_identifier_pattern: string | null;
  field_path: string | null;
  risk_level: string | null;
  snoozed_until: string;  // ISO 8601
  reason: string | null;
  created_by_user_id: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

// ── M58.10: Change Correlation / Risk Clusters ───────────────────────────────

/** A single related change shown inside a correlation cluster. */
export interface CorrelationChangeItem {
  id: string;
  provider: string;
  risk_level: string;
  record_type: string | null;
  title: string;
  detected_at: string;
  /** Relative URL: "/changes/{id}" */
  url: string;
}

/** The primary (highest-scoring) cluster for a change. */
export interface CorrelationCluster {
  cluster_id: string;
  title: string;
  summary: string;
  confidence: "high" | "medium" | "low";
  /** "deployment_routing" | "payments_commerce" | "edge_security" |
   *  "auth_access" | "data_protection" | "provider_local" | "unknown" */
  cluster_type: string;
  time_window_minutes: number;
  signals: string[];
  recommended_review: string[];
  related_changes: CorrelationChangeItem[];
}

/** Response from GET /changes/{id}/correlation */
export interface CorrelationResponse {
  available: boolean;
  primary_cluster: CorrelationCluster | null;
}

// ── M58.11: Blast Radius ──────────────────────────────────────────────────────

/** One potential impact area in a blast radius analysis. */
export interface BlastRadiusItem {
  label: string;
  description: string;
  severity: string;       // "critical" | "high" | "medium" | "low"
  confidence: string;     // "high" | "medium" | "low"
  evidence: string[];
  recommended_review: string[];
}

/** A surface (resource class, workflow, or infra) that may be affected. */
export interface AffectedSurface {
  type: string;           // "resource" | "integration" | "workflow" | "infra"
  provider: string;
  label: string;
  description: string;
  count: number | null;
  confidence: string;     // "high" | "medium" | "low"
  known: boolean;
}

/** Response from GET /changes/{id}/blast-radius */
export interface BlastRadiusResponse {
  available: boolean;
  confidence: string;
  title: string;
  summary: string;
  /** e.g. ["network_exposure", "admin_access", "data_access"] */
  impact_domains: string[];
  items: BlastRadiusItem[];
  affected_surfaces: AffectedSurface[];
  limitations: string[];
}

// ── User settings (M34) ───────────────────────────────────────────────────────

export type AlertRiskThreshold = "critical_only" | "high_and_critical" | "medium_and_above";
export type TimelineRange = "24h" | "7d" | "30d" | "all";
export type ProviderFilter = "all" | "cloudflare" | "github" | "vercel" | "stripe" | "aws" | "shopify";

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

// ── User profile (M59.13) ─────────────────────────────────────────────────────
// First/last name supplied by the user in Settings → Profile.  The
// ``computed_display_name`` is resolved on the server using the policy:
//   first/last → display_name (if not the "ConfigTrace User" placeholder) → email.

export interface ProfileResponse {
  id: string;
  email: string;
  first_name: string | null;
  last_name: string | null;
  display_name: string | null;
  computed_display_name: string;
}

export interface ProfileUpdateRequest {
  first_name?: string | null;
  last_name?: string | null;
}

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

// ── Notification Settings (M57.1) ─────────────────────────────────────────────

export type NotifyRiskLevel =
  | "critical_only"
  | "high_and_critical"
  | "medium_and_above";

export interface WorkspaceNotificationSettings {
  workspace_id: string;
  /** Slack incoming-webhook channel enabled (legacy fallback). */
  slack_enabled: boolean;
  /**
   * Masked Slack webhook URL — first 12 chars + "****".
   * Null when no URL is configured.
   * SECURITY: full URL is never returned by the API.
   */
  slack_webhook_url_masked: string | null;
  /** Generic HTTPS webhook channel enabled. */
  webhook_enabled: boolean;
  /**
   * Masked generic webhook URL.
   * Null when no URL is configured.
   */
  webhook_url_masked: string | null;
  notify_on_risk_level: NotifyRiskLevel;

  // ── Slack App (M58.5) ─────────────────────────────────────────────────────
  /** True when the Slack App is enabled for delivery. */
  slack_app_enabled: boolean;
  /** True when a bot token is stored (OAuth installation completed). */
  slack_app_installed: boolean;
  /** Slack workspace name — safe to display. */
  slack_team_name: string | null;
  slack_team_id: string | null;
  /** Selected delivery channel. */
  slack_channel_id: string | null;
  slack_channel_name: string | null;
  slack_installed_at: string | null;
  slack_app_last_test_at: string | null;
  /** Last delivery error message, or null when healthy. */
  slack_app_last_error: string | null;
  /** M58.7: VAPID public key for browser push (URL-safe base64). Null when not configured. */
  vapid_public_key: string | null;
}

/** A single Slack channel returned by the channels list API. */
export interface SlackChannel {
  id: string;
  name: string;
  is_private: boolean;
  is_member: boolean;
}

export interface SlackChannelsListResponse {
  channels: SlackChannel[];
}

export interface SlackInstallUrlResponse {
  install_url: string;
  state: string;
}

export interface NotificationSettingsUpdateRequest {
  slack_enabled?: boolean;
  /**
   * New Slack webhook URL.  Pass "" to clear.
   * Must start with https://hooks.slack.com/services/.
   */
  slack_webhook_url?: string;
  webhook_enabled?: boolean;
  /**
   * New generic webhook URL.  Pass "" to clear.
   * Must be https://.  Private IPs are rejected by the backend.
   */
  webhook_url?: string;
  notify_on_risk_level?: NotifyRiskLevel;
}

export interface TestNotificationResponse {
  slack_sent: boolean;
  webhook_sent: boolean;
  error: string | null;
}

// ── Push Notifications (M58.7) ────────────────────────────────────────────────

/** Per-device minimum risk level for push delivery. */
export type PushMinRiskLevel = "high" | "critical_only";

/** Keys extracted from a browser PushSubscription object. */
export interface PushSubscriptionKeys {
  /** Base64url-encoded P-256 DH public key. */
  p256dh: string;
  /** Base64url-encoded authentication secret. */
  auth: string;
}

/** Full PushSubscription data sent to the backend. */
export interface PushSubscriptionData {
  endpoint: string;
  keys: PushSubscriptionKeys;
}

/**
 * Request body for POST /notifications/push/subscriptions.
 * Matches the backend PushSubscribeRequest schema (nested subscription object).
 */
export interface PushSubscribeRequest {
  /** Nested subscription object — endpoint + keys from browser PushSubscription. */
  subscription: PushSubscriptionData;
  device_label?: string;
  /** Defaults to "high" on the backend (high + critical). */
  min_risk_level?: PushMinRiskLevel;
}

/**
 * One device subscription returned by the backend.
 * SECURITY: endpoint, p256dh, auth are NEVER included.
 */
export interface PushSubscriptionResponse {
  id: string;
  workspace_id: string;
  device_label: string | null;
  browser_name: string | null;
  user_agent: string | null;
  enabled: boolean;
  min_risk_level: PushMinRiskLevel;
  last_used_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

/** Response from GET /notifications/push/subscriptions. */
export interface PushSubscriptionListResponse {
  subscriptions: PushSubscriptionResponse[];
  total: number;
}

/** Response from GET /notifications/push/public-key. */
export interface PushPublicKeyResponse {
  /** VAPID public key (URL-safe base64). Null when VAPID is not configured. */
  vapid_public_key: string | null;
  /** True when the server has a valid VAPID key pair configured. */
  configured: boolean;
}

/** Response from POST /notifications/push/test. */
export interface PushTestResponse {
  /** Number of push messages successfully sent. */
  sent: number;
  /** Total enabled subscriptions attempted. */
  total_subscriptions: number;
  /** Non-null if VAPID is unconfigured or all sends failed. */
  error: string | null;
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

// ── M58.8: Change Notes ───────────────────────────────────────────────────────

/** A single collaborative investigation note attached to a Change. */
export interface ChangeNote {
  id: string;
  change_id: string;
  workspace_id: string | null;
  author_user_id: string | null;
  body: string;
  created_at: string;
  updated_at: string;
}

/** Request body for POST /changes/{id}/notes. */
export interface ChangeNoteCreate {
  body: string;
}

/** Response from GET /changes/{id}/notes. */
export interface ChangeNoteListResponse {
  items: ChangeNote[];
  total: number;
}

// ── M58.14: Policy Engine ─────────────────────────────────────────────────────

/** A single policy violation detected for a change. */
export interface PolicyViolation {
  policy_key: string;
  name: string;
  severity: "critical" | "high" | "medium";
  description: string;
  evidence: string[];
  recommended_action: string;
}

/** Response from GET /changes/{id}/policy-violations. */
export interface PolicyViolationsResponse {
  violations: PolicyViolation[];
}

/** A workspace policy entry from the catalog with its current enabled state. */
export interface WorkspacePolicy {
  policy_key: string;
  name: string;
  description: string;
  provider: string | null;
  severity: "critical" | "high" | "medium";
  category: string;
  enabled: boolean;
  built_in: boolean;
}

/** Response from GET /workspaces/{id}/policies. */
export interface PolicyListResponse {
  policies: WorkspacePolicy[];
  total: number;
}

// ── M58.15: Weekly Digest ─────────────────────────────────────────────────────

export interface WeeklyDigestRiskCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface WeeklyDigestReviewCounts {
  needs_review: number;
  acknowledged: number;
  expected: number;
  snoozed: number;
}

export interface WeeklyDigestPolicyViolationEntry {
  policy_key: string;
  name: string;
  count: number;
  severity: string;
}

export interface WeeklyDigestPolicyViolations {
  total: number;
  top_policies: WeeklyDigestPolicyViolationEntry[];
}

export interface WeeklyDigestProviderActivity {
  provider: string;
  change_count: number;
  high_or_critical_count: number;
}

export interface WeeklyDigestTopRisk {
  change_id: string;
  title: string;
  provider: string;
  risk_level: string;
  status: string;
  url: string;
}

export interface WeeklyDigestStaleIntegration {
  integration_id: string;
  provider: string;
  name: string;
  last_synced_at: string | null;
  consecutive_failure_count: number;
}

/** Full weekly digest object returned by GET /weekly-digest/preview. */
export interface WeeklyDigest {
  workspace_id: string;
  workspace_name: string;
  period_start: string;
  period_end: string;
  generated_at: string;
  total_changes: number;
  risk_counts: WeeklyDigestRiskCounts;
  review_counts: WeeklyDigestReviewCounts;
  review_completion_rate: number;
  policy_violations: WeeklyDigestPolicyViolations;
  provider_activity: WeeklyDigestProviderActivity[];
  top_risks: WeeklyDigestTopRisk[];
  stale_integrations: WeeklyDigestStaleIntegration[];
  recommended_actions: string[];
}

/** Digest schedule settings from GET/PUT /weekly-digest/settings. */
export interface WeeklyDigestSettings {
  workspace_id: string;
  weekly_digest_enabled: boolean;
  weekly_digest_day: number;   // 0=Monday … 6=Sunday
  weekly_digest_hour: number;  // 0–23 UTC
  weekly_digest_timezone: string | null;
  weekly_digest_last_sent_at: string | null;
}

export interface WeeklyDigestSettingsUpdateRequest {
  weekly_digest_enabled?: boolean;
  weekly_digest_day?: number;
  weekly_digest_hour?: number;
  weekly_digest_timezone?: string | null;
}

/** Response from POST /weekly-digest/test. */
export interface WeeklyDigestTestResponse {
  sent: boolean;
  recipient: string | null;
  email_configured: boolean;
  preview_body: string | null;
  error: string | null;
}

// ── M58.16: Expected Change Windows ──────────────────────────────────────────

export type ExpectedChangeWindowStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "cancelled";

export type ExpectedChangeAlertBehavior = "annotate_only" | "suppress";

/** A single expected change window returned by the API. */
export interface ExpectedChangeWindow {
  id: string;
  workspace_id: string;
  created_by_user_id: string | null;
  approved_by_user_id: string | null;
  title: string;
  description: string | null;
  start_time: string;      // ISO 8601 UTC
  end_time: string;        // ISO 8601 UTC
  status: ExpectedChangeWindowStatus;
  alert_behavior: ExpectedChangeAlertBehavior;
  /** Optional provider filter. null = matches all providers. */
  filter_provider: string | null;
  /** Optional integration UUID filter. null = matches all integrations. */
  filter_integration_id: string | null;
  /** Optional risk level filter. null = matches all risk levels. */
  filter_risk_level: string | null;
  rejection_reason: string | null;
  approved_at: string | null;
  created_at: string;
  updated_at: string;
}

/** Response from GET /workspaces/{id}/expected-changes. */
export interface ExpectedChangeWindowListResponse {
  windows: ExpectedChangeWindow[];
  total: number;
}

/** Request body for POST /workspaces/{id}/expected-changes. */
export interface ExpectedChangeWindowCreate {
  title: string;
  description?: string;
  start_time: string;      // ISO 8601 UTC
  end_time: string;        // ISO 8601 UTC
  alert_behavior?: ExpectedChangeAlertBehavior;
  filter_provider?: string | null;
  filter_integration_id?: string | null;
  filter_risk_level?: string | null;
}

/** Request body for POST .../reject. */
export interface RejectWindowRequest {
  reason?: string;
}

/** Response from GET /changes/{id}/expected-change-match. */
export interface ExpectedChangeMatchResponse {
  matched: boolean;
  window: ExpectedChangeWindow | null;
  annotation: string | null;
}

// ── M58.17: Drift Control Score ───────────────────────────────────────────────

/** One factor (penalty or note) contributing to the Drift Control Score. */
export interface DriftScoreFactor {
  /** Machine-readable factor identifier. */
  key: string;
  /** Human-readable short name shown in the UI. */
  label: string;
  /** Score impact; negative = penalty (e.g. -12). */
  impact: number;
  /** 'good' | 'needs_attention' | 'critical' */
  status: "good" | "needs_attention" | "critical";
  /** Plain-English explanation shown in the UI. */
  detail: string;
  /** Short label for the CTA button, if any. */
  action_label?: string | null;
  /** Relative URL for the CTA, if any. */
  action_href?: string | null;
}

/** Raw metrics used to compute the Drift Control Score. */
export interface DriftScoreMetrics {
  providers_connected: number;
  total_changes_7d: number;
  high_critical_changes_7d: number;
  unreviewed_high_critical: number;
  policy_violations_7d: number;
  stale_integrations: number;
  /** Fraction of high/critical changes reviewed (0.0–1.0). */
  review_completion_rate: number;
  alerts_configured: boolean;
}

/**
 * Response from GET /workspaces/{id}/drift-score (M58.17).
 *
 * The Drift Control Score is advisory only — it measures review and alert
 * hygiene for configuration drift.  It is NOT a compliance certification,
 * security rating, or breach risk score.
 */
export interface DriftScoreResponse {
  /** 0–100, higher is better. */
  score: number;
  /** 'strong' | 'good' | 'needs_attention' | 'weak' */
  grade: "strong" | "good" | "needs_attention" | "weak";
  /** 'up' | 'down' | 'flat' | 'unknown' */
  trend: "up" | "down" | "flat" | "unknown";
  /** One-sentence advisory summary. */
  summary: string;
  /** Number of days the score covers (7). */
  period_days: number;
  factors: DriftScoreFactor[];
  positive_signals: string[];
  recommended_actions: string[];
  metrics: DriftScoreMetrics;
}

// ── M58.18: IaC Awareness ─────────────────────────────────────────────────────

export interface IacRepository {
  id: string;
  workspace_id: string;
  integration_id: string | null;
  provider: string;
  repo_full_name: string;
  default_branch: string | null;
  scanning_enabled: boolean;
  /** "success" | "no_integration" | "no_access" | "no_tf_files" | "error" | null */
  last_scan_status: string | null;
  last_scan_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface IacRepositoryListResponse {
  repositories: IacRepository[];
  total: number;
}

export interface IacRepositoryCreate {
  repo_full_name: string;
  integration_id?: string | null;
  default_branch?: string;
  scanning_enabled?: boolean;
}

export interface IacScanResult {
  /** "success" | "no_integration" | "no_access" | "no_tf_files" | "not_found" | "error" */
  status: string;
  message: string;
  resources_found: number;
  files_scanned: number;
}

export interface IacResourceMappingItem {
  id: string;
  workspace_id: string;
  iac_repository_id: string;
  repo_full_name: string;
  provider: string;
  resource_type: string;
  terraform_resource_type: string | null;
  terraform_resource_name: string | null;
  file_path: string;
  line_start: number | null;
  line_end: number | null;
  cloud_resource_identifier: string | null;
  cloud_resource_name: string | null;
  /** "high" | "medium" | "low" */
  match_confidence: string;
  match_reason: string;
  mapping_source: string;
  created_at: string;
  updated_at: string;
}

export interface IacMappingListResponse {
  mappings: IacResourceMappingItem[];
  total: number;
}

/** One possible Terraform resource that may correspond to a changed cloud resource. */
export interface IacChangeMappingCandidate {
  mapping_id: string;
  iac_repository_id: string;
  repo_full_name: string | null;
  terraform_resource_type: string | null;
  terraform_resource_name: string | null;
  file_path: string;
  line_start: number | null;
  line_end: number | null;
  cloud_resource_identifier: string | null;
  cloud_resource_name: string | null;
  /** "high" | "medium" | "low" */
  match_confidence: string;
  match_reason: string;
  mapping_source: string;
}

/**
 * Advisory IaC context for a change — GET /changes/{id}/iac-context.
 * Does NOT confirm Terraform ownership. Advisory only.
 */
export interface IacContextResponse {
  available: boolean;
  summary: string;
  mappings: IacChangeMappingCandidate[];
  recommended_workflow: string | null;
  /** Always false in M58.18; Terraform patch suggestions come in M58.19. */
  future_fix_available: boolean;
  future_fix_note: string | null;
}

// ── M58.19: Terraform Fix Suggestion Preview ──────────────────────────────────

/** The IaC mapping that was used to derive a Terraform fix suggestion. */
export interface TerraformFixMappingInfo {
  repo_full_name: string | null;
  file_path: string;
  terraform_resource_type: string | null;
  terraform_resource_name: string | null;
  /** "high" | "medium" | "low" */
  match_confidence: string;
}

/** A named placeholder inside a conceptual HCL diff. */
export interface TerraformFixPlaceholder {
  name: string;
  description: string;
  example: string;
}

/**
 * A single fix suggestion — either an HCL diff (conceptual_preview) or
 * human-readable guidance (guided_only).
 *
 * safety_level is always "requires_human_review".
 */
export interface TerraformFixSuggestion {
  /** "hcl_diff" | "guidance_only" */
  kind: string;
  title: string;
  description: string;
  /** "diff" | "hcl" | "text" */
  language: string;
  /** null for guidance_only */
  diff: string | null;
  /** Always "requires_human_review" */
  safety_level: string;
  placeholders: TerraformFixPlaceholder[];
  warnings: string[];
}

/**
 * Full response for GET /changes/{id}/terraform-fix-preview.
 *
 * PERMANENT SAFETY CONSTANTS (enforced by backend schema validators):
 * - execution_enabled is ALWAYS false
 * - pr_available is ALWAYS false
 */
export interface TerraformFixPreviewResponse {
  available: boolean;
  /** "high" | "medium" | "low" | null when unavailable */
  confidence: string | null;
  title: string | null;
  summary: string | null;
  mapping: TerraformFixMappingInfo | null;
  suggestions: TerraformFixSuggestion[];
  recommended_workflow: string[];
  /** Always false — GitHub PR creation not available in M58.19. */
  pr_available: false;
  /** Always false — Terraform is never executed. */
  execution_enabled: false;
}

// ── M58.20: GitHub PR Draft Flow ──────────────────────────────────────────────

/**
 * Hard-wired safety flags for the GitHub PR draft.
 * All write-action flags are permanently false in M58.20.
 */
export interface GitHubPrDraftSafetyFlags {
  /** Always false — no git refs API calls. */
  creates_branch: false;
  /** Always false — no contents write API calls. */
  commits_code: false;
  /** Always false — no pulls API calls. */
  opens_pr: false;
  /** Always false — Terraform is never executed. */
  executes_terraform: false;
  /** Always true. */
  requires_human_review: true;
}

/** The GitHub repository and file targeted by the PR draft. */
export interface GitHubPrDraftRepo {
  repo_full_name: string;
  default_branch: string;
  file_path: string;
}

/**
 * The proposed GitHub PR — branch name, commit, title, body, and patch.
 * All content is read-only. No GitHub API calls are made in M58.20.
 */
export interface GitHubPrDraftObject {
  branch_name: string;
  commit_message: string;
  pr_title: string;
  pr_body: string;
  target_file_path: string;
  /** null when the Terraform fix is guidance-only (low confidence). */
  patch_preview: string | null;
  labels: string[];
  review_notes: string[];
}

/**
 * Full response for GET /changes/{id}/github-pr-draft.
 *
 * PERMANENT SAFETY CONSTANTS:
 * - safety.creates_branch is ALWAYS false
 * - safety.commits_code is ALWAYS false
 * - safety.opens_pr is ALWAYS false
 * - safety.executes_terraform is ALWAYS false
 *
 * Actual PR creation is deferred to M58.21.
 */
export interface GitHubPrDraftResponse {
  available: boolean;
  /** "draft_preview_only" | "outline_only" */
  mode: string;
  title: string | null;
  summary: string | null;
  repo: GitHubPrDraftRepo | null;
  draft: GitHubPrDraftObject | null;
  safety: GitHubPrDraftSafetyFlags;
  requirements: string[];
  next_step: string | null;
  /** Reason why the draft is unavailable (when available=false). */
  reason: string | null;
  /** UUID of the IacRepository — populated in M58.21 for PR creation. */
  iac_repository_id: string | null;
}

// ── M58.21: GitHub PR Creation ────────────────────────────────────────────────

/** Request body for POST /changes/{id}/github-pr. */
export interface GitHubPrCreateRequest {
  /** Must be exactly "CREATE DRAFT PR" (case-sensitive). */
  confirmation_phrase: string;
  /** UUID of the target IacRepository. */
  iac_repository_id: string;
  /** Branch to base the PR off (e.g. "main"). */
  target_base_branch: string;
  /** Must be true when the fix has <PLACEHOLDER> values. */
  acknowledge_placeholders: boolean;
}

/**
 * Safety flags for the GitHub PR creation response.
 * executes_terraform and mutates_provider_resource are permanently false.
 */
export interface GitHubPrCreateSafetyFlags {
  /** Always false — Terraform is never executed. */
  executes_terraform: false;
  /** Always false — no cloud provider resources are mutated. */
  mutates_provider_resource: false;
  /** True when a draft PR was actually created. */
  creates_draft_pr: boolean;
}

/** Full response for POST /changes/{id}/github-pr. */
export interface GitHubPrCreateResponse {
  success: boolean;
  pr_url: string | null;
  pr_number: number | null;
  branch_name: string | null;
  base_branch: string | null;
  patch_file_path: string | null;
  commit_sha: string | null;
  safety: GitHubPrCreateSafetyFlags;
  /** Human-readable error when success=false. */
  error: string | null;
  /** UUID of the audit record. */
  suggestion_id: string | null;
}
