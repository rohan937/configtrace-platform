/**
 * ConfigTrace API client.
 *
 * All functions read NEXT_PUBLIC_API_BASE_URL from the environment
 * (default: http://localhost:8000).  Errors from the server are surfaced
 * as thrown Error objects with the message set to the server's detail string.
 *
 * Authentication (Milestone 21)
 * -----------------------------
 * Every function accepts an optional `token` argument — the JWT obtained
 * from Clerk via `useAuth().getToken()`.  When present it is sent as
 * `Authorization: Bearer <token>`.  When absent the request goes out
 * without an Authorization header, which is what local development
 * (dev-mode auth) expects.
 *
 * Pages should fetch the token in a `useEffect`/`useCallback` boundary
 * once Clerk has loaded, then pass it into each call.  Never store the
 * token in component state for longer than a single request — Clerk
 * rotates short-lived JWTs every ~60s.
 */

import type {
  ChangeDetail,
  ChangeListItem,
  ChangeReviewResponse,
  DashboardSummary,
  GitHubAppCompleteRequest,
  GitHubAppInstallUrlResponse,
  GitHubInstallationReposResponse,
  Integration,
  IntegrationCreateRequest,
  IntegrationListResponse,
  InviteCreateResponse,
  InviteListResponse,
  InvitePreview,
  MemberListResponse,
  PaginatedResponse,
  ProfileResponse,
  ProfileUpdateRequest,
  ResourceDetail,
  ResourceListItem,
  SecurityActivityEvent,
  SecurityActivitySyncResponse,
  SecurityCase,
  SecurityCaseCreateRequest,
  SecurityCaseDetail,
  SecurityCaseLink,
  SecurityCaseLinkCreateRequest,
  SecurityCaseReport,
  SecurityCaseUpdateRequest,
  SecurityCorrelationGenerateRequest,
  SecurityCorrelationGenerateResponse,
  SecurityFinding,
  SecurityIncidentSignal,
  SecuritySignalCorrelation,
  SecuritySignalGenerateRequest,
  SecuritySignalGenerateResponse,
  SnapshotListItem,
  SyncRun,
  SyncRunListResponse,
  UserSettings,
  UserSettingsUpdateRequest,
  Workspace,
  WorkspaceAuditLog,
  AuditLogListResponse,
  WorkspaceInvite,
  WorkspaceListResponse,
  WorkspaceMember,
  WorkspaceRole,
  InviteRole,
} from "@/types";

const BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") ??
  "http://localhost:8000";

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Build the headers for an authenticated request. */
function buildHeaders(
  token: string | null | undefined,
  extra?: HeadersInit,
): HeadersInit {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(extra as Record<string, string> | undefined),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function apiFetch<T>(
  path: string,
  options?: RequestInit & { token?: string | null },
): Promise<T> {
  const { token, headers, ...rest } = options ?? {};
  const url = `${BASE_URL}${path}`;

  // Catch network-level failures (server unreachable, CORS, DNS, timeout).
  // Without this, the browser throws a raw TypeError("Failed to fetch") that
  // gives the caller no context about which request failed or why.
  let res: Response;
  try {
    res = await fetch(url, {
      ...rest,
      headers: buildHeaders(token, headers),
    });
  } catch (err) {
    const cause = err instanceof Error ? err.message : String(err);
    throw new Error(`Network error — could not reach the server. (${cause})`);
  }

  if (!res.ok) {
    // Always surface the HTTP status so callers can see whether the backend
    // rejected the request (4xx) or had an internal error (5xx).
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail !== undefined) {
        // FastAPI can return detail as a string *or* a structured object.
        // When it's an object (e.g. our 402 billing limit errors), prefer the
        // nested "message" field for a human-readable string; fall back to
        // JSON.stringify so callers at least see something useful.
        if (typeof body.detail === "string") {
          detail = `HTTP ${res.status}: ${body.detail}`;
        } else if (
          typeof body.detail === "object" &&
          typeof body.detail?.message === "string"
        ) {
          detail = `HTTP ${res.status}: ${body.detail.message}`;
        } else {
          detail = `HTTP ${res.status}: ${JSON.stringify(body.detail)}`;
        }
      }
    } catch {
      // ignore JSON parse errors — keep the "HTTP N" prefix
    }
    throw new Error(detail);
  }

  return res.json() as Promise<T>;
}

function buildQuery(params: object): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      q.set(key, String(value as string | number | boolean));
    }
  }
  const qs = q.toString();
  return qs ? `?${qs}` : "";
}

// ── Workspaces (M50) ──────────────────────────────────────────────────────────

export async function getWorkspaces(
  token?: string | null,
): Promise<WorkspaceListResponse> {
  return apiFetch("/workspaces", { token });
}

export async function createWorkspace(
  name: string,
  token?: string | null,
): Promise<Workspace> {
  return apiFetch("/workspaces", {
    method: "POST",
    body: JSON.stringify({ name }),
    token,
  });
}

export async function getWorkspace(
  workspaceId: string,
  token?: string | null,
): Promise<Workspace> {
  return apiFetch(`/workspaces/${workspaceId}`, { token });
}

export async function patchWorkspace(
  workspaceId: string,
  name: string,
  token?: string | null,
): Promise<Workspace> {
  return apiFetch(`/workspaces/${workspaceId}`, {
    method: "PATCH",
    body: JSON.stringify({ name }),
    token,
  });
}

// ── Workspace members ─────────────────────────────────────────────────────────

export async function getWorkspaceMembers(
  workspaceId: string,
  token?: string | null,
): Promise<MemberListResponse> {
  return apiFetch(`/workspaces/${workspaceId}/members`, { token });
}

/** Current user's role in a workspace (M63.5) — drives permission UI gating. */
export async function getMyWorkspaceMembership(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").WorkspaceMembershipMe> {
  return apiFetch(`/workspaces/${workspaceId}/membership/me`, { token });
}

export async function updateMemberRole(
  workspaceId: string,
  memberId: string,
  role: WorkspaceRole,
  token?: string | null,
): Promise<WorkspaceMember> {
  return apiFetch(`/workspaces/${workspaceId}/members/${memberId}`, {
    method: "PATCH",
    body: JSON.stringify({ role }),
    token,
  });
}

export async function removeMember(
  workspaceId: string,
  memberId: string,
  token?: string | null,
): Promise<void> {
  const url = `${BASE_URL}/workspaces/${workspaceId}/members/${memberId}`;
  const res = await fetch(url, {
    method: "DELETE",
    headers: buildHeaders(token),
  });
  if (!res.ok && res.status !== 204) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = String(body.detail);
    } catch { /* ignore */ }
    throw new Error(detail);
  }
}

// ── Workspace invites ─────────────────────────────────────────────────────────

export async function getWorkspaceInvites(
  workspaceId: string,
  activeOnly?: boolean,
  token?: string | null,
): Promise<InviteListResponse> {
  const qs = activeOnly ? "?active_only=true" : "";
  return apiFetch(`/workspaces/${workspaceId}/invites${qs}`, { token });
}

export async function createInvite(
  workspaceId: string,
  email: string,
  role: InviteRole,
  token?: string | null,
): Promise<InviteCreateResponse> {
  return apiFetch(`/workspaces/${workspaceId}/invites`, {
    method: "POST",
    body: JSON.stringify({ email, role }),
    token,
  });
}

export async function revokeInvite(
  workspaceId: string,
  inviteId: string,
  token?: string | null,
): Promise<void> {
  const url = `${BASE_URL}/workspaces/${workspaceId}/invites/${inviteId}`;
  const res = await fetch(url, {
    method: "DELETE",
    headers: buildHeaders(token),
  });
  if (!res.ok && res.status !== 204) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = String(body.detail);
    } catch { /* ignore */ }
    throw new Error(detail);
  }
}

// ── Workspace notification settings (M57.1) ───────────────────────────────────

export async function getNotificationSettings(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").WorkspaceNotificationSettings> {
  return apiFetch(`/workspaces/${workspaceId}/notification-settings`, { token });
}

export async function updateNotificationSettings(
  workspaceId: string,
  body: import("@/types").NotificationSettingsUpdateRequest,
  token?: string | null,
): Promise<import("@/types").WorkspaceNotificationSettings> {
  return apiFetch(`/workspaces/${workspaceId}/notification-settings`, {
    method: "PUT",
    body: JSON.stringify(body),
    token,
  });
}

export async function sendTestNotification(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").TestNotificationResponse> {
  return apiFetch(`/workspaces/${workspaceId}/notification-settings/test`, {
    method: "POST",
    token,
  });
}

// ── Slack App install flow (M58.5) ────────────────────────────────────────────

/**
 * Generate a Slack App OAuth install URL with an HMAC-signed state token.
 *
 * Returns HTTP 503 if the server is not configured with Slack App credentials.
 */
export async function getSlackInstallUrl(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").SlackInstallUrlResponse> {
  return apiFetch(
    `/workspaces/${workspaceId}/notifications/slack/install-url`,
    { token },
  );
}

/**
 * List Slack channels accessible to the installed bot.
 *
 * Returns HTTP 422 if no Slack App installation exists for this workspace.
 */
export async function listSlackChannels(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").SlackChannelsListResponse> {
  return apiFetch(
    `/workspaces/${workspaceId}/notifications/slack/channels`,
    { token },
  );
}

/**
 * Select a Slack channel for alert delivery.
 *
 * Returns the updated notification settings.
 */
export async function updateSlackChannel(
  workspaceId: string,
  channelId: string,
  channelName: string,
  token?: string | null,
): Promise<import("@/types").WorkspaceNotificationSettings> {
  return apiFetch(`/workspaces/${workspaceId}/notifications/slack/channel`, {
    method: "PUT",
    body: JSON.stringify({ channel_id: channelId, channel_name: channelName }),
    token,
  });
}

/**
 * Send a test message via the installed Slack App bot.
 */
export async function sendSlackAppTest(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").TestNotificationResponse> {
  return apiFetch(`/workspaces/${workspaceId}/notifications/slack/test`, {
    method: "POST",
    token,
  });
}

/**
 * Remove the Slack App installation from a workspace.
 *
 * Clears the bot token and all Slack App configuration.
 * The legacy incoming-webhook configuration is unaffected.
 */
export async function disconnectSlackApp(
  workspaceId: string,
  token?: string | null,
): Promise<void> {
  const url = `${BASE_URL}/workspaces/${workspaceId}/notifications/slack`;
  const res = await fetch(url, {
    method: "DELETE",
    headers: buildHeaders(token),
  });
  if (!res.ok && res.status !== 204) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = String(body.detail);
    } catch { /* ignore */ }
    throw new Error(detail);
  }
}

// ── Workspace audit log (M51) ─────────────────────────────────────────────────

export async function getWorkspaceAuditLogs(
  workspaceId: string,
  token?: string | null,
  params?: { limit?: number; offset?: number; event_type?: string },
): Promise<AuditLogListResponse> {
  const qs = new URLSearchParams();
  if (params?.limit != null) qs.set("limit", String(params.limit));
  if (params?.offset != null) qs.set("offset", String(params.offset));
  if (params?.event_type) qs.set("event_type", params.event_type);
  const query = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetch(`/workspaces/${workspaceId}/audit-logs${query}`, { token });
}

// ── Invite accept flow ────────────────────────────────────────────────────────

export async function getInvitePreview(token: string): Promise<InvitePreview> {
  return apiFetch(`/invites/${token}`);
}

export async function acceptInvite(
  token: string,
  authToken?: string | null,
): Promise<WorkspaceMember> {
  return apiFetch(`/invites/${token}/accept`, {
    method: "POST",
    token: authToken,
  });
}

// ── Changes ───────────────────────────────────────────────────────────────────

export interface GetChangesParams {
  integration_id?: string;
  resource_id?: string;
  risk_level?: string;
  change_type?: string;
  provider?: string;
  since?: string;
  until?: string;
  review_status?: string;  // M57.2: filter by review status
  page?: number;
  page_size?: number;
}

export async function getChanges(
  params: GetChangesParams = {},
  token?: string | null,
): Promise<PaginatedResponse<ChangeListItem>> {
  return apiFetch(`/changes${buildQuery(params)}`, { token });
}

export async function getChange(
  changeId: string,
  token?: string | null,
): Promise<ChangeDetail> {
  return apiFetch(`/changes/${changeId}`, { token });
}

// ── M60.3: Configuration Risk findings (read-only) ─────────────────────────────

export interface GetSecurityFindingsParams {
  status?: string;
  severity?: string;
  provider?: string;
  integration_id?: string;
  resource_id?: string;
  page?: number;
  page_size?: number;
}

/** List security exposure findings for the current user's workspaces. */
export async function getSecurityFindings(
  params: GetSecurityFindingsParams = {},
  token?: string | null,
): Promise<PaginatedResponse<SecurityFinding>> {
  return apiFetch(`/security/findings${buildQuery(params)}`, { token });
}

/** Fetch full detail for a single security exposure finding. */
export async function getSecurityFinding(
  findingId: string,
  token?: string | null,
): Promise<SecurityFinding> {
  return apiFetch(`/security/findings/${findingId}`, { token });
}

/* ──────────────────────────────────────────────────────────────────────────
   Activity Events (M66.2 backend / M66.5 UI)

   Normalized control-plane GitHub audit activity — evidence behind Incident
   Signals. Not breach/attacker/compromise claims.
   ────────────────────────────────────────────────────────────────────────── */

export interface GetSecurityActivityEventsParams {
  provider?: string;
  event_type?: string;
  page?: number;
  page_size?: number;
}

/** List normalized activity events for the current user's workspace (M66.2). */
export async function getSecurityActivityEvents(
  params: GetSecurityActivityEventsParams = {},
  token?: string | null,
): Promise<PaginatedResponse<SecurityActivityEvent>> {
  return apiFetch(`/security/activity/events${buildQuery(params)}`, { token });
}

/** Fetch a single workspace-scoped activity event (404 cross-workspace) (M66.5). */
export async function getSecurityActivityEvent(
  eventId: string,
  token?: string | null,
): Promise<SecurityActivityEvent> {
  return apiFetch(`/security/activity/events/${eventId}`, { token });
}

/**
 * Trigger GitHub audit-log activity ingestion (M66.2). Admin/owner only.
 * Non-fatal: permission/availability limits are reported in the summary.
 */
export async function syncSecurityActivity(
  token?: string | null,
): Promise<SecurityActivitySyncResponse> {
  return apiFetch(`/security/activity/sync`, {
    method: "POST",
    body: JSON.stringify({}),
    token,
  });
}

export async function syncGitHubSecretScanning(
  token?: string | null,
): Promise<import("@/types").GitHubSecretScanningSyncResponse> {
  return apiFetch(`/security/github-secret-scanning/sync`, {
    method: "POST",
    body: JSON.stringify({}),
    token,
  });
}

export async function syncGitHubCodeScanning(
  token?: string | null,
): Promise<import("@/types").GitHubCodeScanningSyncResponse> {
  return apiFetch(`/security/github-code-scanning/sync`, {
    method: "POST",
    body: JSON.stringify({}),
    token,
  });
}

/* ──────────────────────────────────────────────────────────────────────────
   Incident Signals (M66.3 backend / M66.4 UI)

   Control-plane review signals from normalized GitHub audit activity. These are
   NOT breach/attacker/compromise confirmations — they may require review.
   ────────────────────────────────────────────────────────────────────────── */

export interface GetSecurityIncidentSignalsParams {
  provider?: string;
  status?: string;
  severity?: string;
  signal_type?: string;
  page?: number;
  page_size?: number;
}

/** List incident signals for the current user's workspace (M66.3). */
export async function getSecurityIncidentSignals(
  params: GetSecurityIncidentSignalsParams = {},
  token?: string | null,
): Promise<PaginatedResponse<SecurityIncidentSignal>> {
  return apiFetch(`/security/signals${buildQuery(params)}`, { token });
}

/** Fetch a single workspace-scoped incident signal (404 cross-workspace). */
export async function getSecurityIncidentSignal(
  signalId: string,
  token?: string | null,
): Promise<SecurityIncidentSignal> {
  return apiFetch(`/security/signals/${signalId}`, { token });
}

/**
 * Generate incident signals from recent activity events (M66.3). Admin/owner
 * only; GitHub-only for now. Idempotent — re-running creates no duplicates.
 */
export async function generateSecurityIncidentSignals(
  body: SecuritySignalGenerateRequest = {},
  token?: string | null,
): Promise<SecuritySignalGenerateResponse> {
  return apiFetch(`/security/signals/generate`, {
    method: "POST",
    body: JSON.stringify(body),
    token,
  });
}

/* ──────────────────────────────────────────────────────────────────────────
   Cases / Investigations (M66.8)

   Human-managed investigation containers grouping incident evidence.
   ────────────────────────────────────────────────────────────────────────── */

export interface GetSecurityCasesParams {
  status?: string;
  provider?: string;
  severity?: string;
  page?: number;
  page_size?: number;
}

export async function getSecurityCases(
  params: GetSecurityCasesParams = {},
  token?: string | null,
): Promise<PaginatedResponse<SecurityCase>> {
  return apiFetch(`/security/cases${buildQuery(params)}`, { token });
}

export async function getSecurityCase(
  caseId: string,
  token?: string | null,
): Promise<SecurityCaseDetail> {
  return apiFetch(`/security/cases/${caseId}`, { token });
}

export async function createSecurityCase(
  body: SecurityCaseCreateRequest,
  token?: string | null,
): Promise<SecurityCase> {
  return apiFetch(`/security/cases`, { method: "POST", body: JSON.stringify(body), token });
}

export async function updateSecurityCase(
  caseId: string,
  body: SecurityCaseUpdateRequest,
  token?: string | null,
): Promise<SecurityCase> {
  return apiFetch(`/security/cases/${caseId}`, { method: "PATCH", body: JSON.stringify(body), token });
}

export async function addSecurityCaseLink(
  caseId: string,
  body: SecurityCaseLinkCreateRequest,
  token?: string | null,
): Promise<SecurityCaseLink> {
  return apiFetch(`/security/cases/${caseId}/links`, { method: "POST", body: JSON.stringify(body), token });
}

export async function deleteSecurityCaseLink(
  caseId: string,
  linkId: string,
  token?: string | null,
): Promise<{ ok: boolean }> {
  return apiFetch(`/security/cases/${caseId}/links/${linkId}`, { method: "DELETE", token });
}

/** Create a case from a signal, linking the signal + its evidence (M66.8). */
export async function createCaseFromSignal(
  signalId: string,
  token?: string | null,
): Promise<SecurityCase> {
  return apiFetch(`/security/signals/${signalId}/create-case`, { method: "POST", body: JSON.stringify({}), token });
}

/** Create a case from a correlation, linking risk/activity/signal (M66.8). */
export async function createCaseFromCorrelation(
  correlationId: string,
  token?: string | null,
): Promise<SecurityCase> {
  return apiFetch(`/security/correlations/${correlationId}/create-case`, { method: "POST", body: JSON.stringify({}), token });
}

/* ── AWS security alerts (M67.2) — admin-only sync + signal generation ─────── */

export async function syncAwsSecurityAlerts(
  token?: string | null,
): Promise<import("@/types").AwsAlertSyncResponse> {
  return apiFetch(`/security/aws-alerts/sync`, { method: "POST", body: JSON.stringify({}), token });
}

export async function syncAwsCloudTrail(
  token?: string | null,
): Promise<import("@/types").AwsCloudTrailSyncResponse> {
  return apiFetch(`/security/aws-cloudtrail/sync`, { method: "POST", body: JSON.stringify({}), token });
}

export async function syncAwsSecurityHub(
  token?: string | null,
): Promise<import("@/types").AwsSecurityHubSyncResponse> {
  return apiFetch(`/security/aws-security-hub/sync`, { method: "POST", body: JSON.stringify({}), token });
}

export async function syncCloudflareActivity(
  token?: string | null,
): Promise<import("@/types").CloudflareActivitySyncResponse> {
  return apiFetch(`/security/cloudflare-activity/sync`, { method: "POST", body: JSON.stringify({}), token });
}

export async function syncCloudflareWafEvents(
  token?: string | null,
): Promise<import("@/types").CloudflareActivitySyncResponse> {
  return apiFetch(`/security/cloudflare-waf-events/sync`, { method: "POST", body: JSON.stringify({}), token });
}

export async function generateCloudflareSignals(
  token?: string | null,
): Promise<import("@/types").AwsSignalGenerateResponse> {
  return apiFetch(`/security/cloudflare-activity/generate-signals`, { method: "POST", body: JSON.stringify({}), token });
}

export async function generateCloudflareWafSignals(
  token?: string | null,
): Promise<import("@/types").CloudflareWafSignalGenerateResponse> {
  return apiFetch(`/security/cloudflare-waf-events/generate-signals`, { method: "POST", body: JSON.stringify({}), token });
}

export async function generateGitHubSecretScanningSignals(
  token?: string | null,
): Promise<import("@/types").GitHubSecretScanningSignalGenerateResponse> {
  return apiFetch(`/security/github-secret-scanning/generate-signals`, { method: "POST", body: JSON.stringify({}), token });
}

export async function generateGitHubCodeScanningSignals(
  token?: string | null,
): Promise<import("@/types").GitHubCodeScanningSignalGenerateResponse> {
  return apiFetch(`/security/github-code-scanning/generate-signals`, { method: "POST", body: JSON.stringify({}), token });
}

export async function generateAwsIncidentSignals(
  token?: string | null,
): Promise<import("@/types").AwsSignalGenerateResponse> {
  return apiFetch(`/security/aws-alerts/generate-signals`, { method: "POST", body: JSON.stringify({}), token });
}

export async function generateAwsIamBehaviorSignals(
  token?: string | null,
): Promise<import("@/types").AwsBehaviorSignalGenerateResponse> {
  return apiFetch(`/security/aws-cloudtrail/generate-behavior-signals`, { method: "POST", body: JSON.stringify({}), token });
}

export async function generateAwsIamChainSignals(
  token?: string | null,
): Promise<import("@/types").AwsIamChainSignalGenerateResponse> {
  return apiFetch(`/security/aws-iam-chains/generate-signals`, { method: "POST", body: JSON.stringify({}), token });
}

export async function generateAwsSecurityHubSignals(
  token?: string | null,
): Promise<import("@/types").AwsSignalGenerateResponse> {
  return apiFetch(`/security/aws-security-hub/generate-signals`, { method: "POST", body: JSON.stringify({}), token });
}

export async function generateAwsS3AccessSignals(
  token?: string | null,
): Promise<import("@/types").AwsS3AccessSignalGenerateResponse> {
  return apiFetch(`/security/aws-s3-data-events/generate-signals`, { method: "POST", body: JSON.stringify({}), token });
}

export async function generateAwsVpcFlowSignals(
  token?: string | null,
): Promise<import("@/types").AwsVpcFlowSignalGenerateResponse> {
  return apiFetch(`/security/aws-vpc-flow-logs/generate-signals`, { method: "POST", body: JSON.stringify({}), token });
}

/** Fetch a metadata-only Case Evidence Report payload (M66.9). */
export async function getSecurityCaseReport(
  caseId: string,
  token?: string | null,
): Promise<SecurityCaseReport> {
  return apiFetch(`/security/cases/${caseId}/report`, { token });
}

/* ── Incident Workflow demo (M66.10 github / M67.4 aws) — admin-only seed/clear ─ */

export async function getIncidentDemoStatus(
  token?: string | null,
  provider: "github" | "aws" = "github",
): Promise<import("@/types").IncidentDemoStatus> {
  return apiFetch(`/security/incident-demo/status?provider=${provider}`, { token });
}

export async function seedIncidentDemo(
  token?: string | null,
  provider: "github" | "aws" | "cloudflare" = "github",
): Promise<import("@/types").IncidentDemoSeedResponse> {
  return apiFetch(`/security/incident-demo/seed?provider=${provider}`, { method: "POST", body: JSON.stringify({}), token });
}

export async function clearIncidentDemo(
  token?: string | null,
  provider: "github" | "aws" | "cloudflare" = "github",
): Promise<{ cleared: boolean }> {
  return apiFetch(`/security/incident-demo/clear?provider=${provider}`, { method: "POST", body: JSON.stringify({}), token });
}

/* ──────────────────────────────────────────────────────────────────────────
   Correlations (M66.6)

   Configuration Risk × GitHub audit activity. Evidence for review — not
   breach/attacker/compromise confirmations.
   ────────────────────────────────────────────────────────────────────────── */

export interface GetSecurityCorrelationsParams {
  provider?: string;
  status?: string;
  severity?: string;
  correlation_type?: string;
  /** Evidence backlinks (M66.7): correlations linked to a given object. */
  linked_signal_id?: string;
  linked_finding_id?: string;
  linked_activity_event_id?: string;
  page?: number;
  page_size?: number;
}

/** List risk×activity correlations for the current user's workspace (M66.6). */
export async function getSecurityCorrelations(
  params: GetSecurityCorrelationsParams = {},
  token?: string | null,
): Promise<PaginatedResponse<SecuritySignalCorrelation>> {
  return apiFetch(`/security/correlations${buildQuery(params)}`, { token });
}

/** Fetch a single workspace-scoped correlation (404 cross-workspace) (M66.6). */
export async function getSecurityCorrelation(
  correlationId: string,
  token?: string | null,
): Promise<SecuritySignalCorrelation> {
  return apiFetch(`/security/correlations/${correlationId}`, { token });
}

/**
 * Generate risk×activity correlations (M66.6). Admin/owner only; GitHub-only.
 * Idempotent — re-running creates no duplicates.
 */
export async function generateSecurityCorrelations(
  body: SecurityCorrelationGenerateRequest = {},
  token?: string | null,
): Promise<SecurityCorrelationGenerateResponse> {
  return apiFetch(`/security/correlations/generate`, {
    method: "POST",
    body: JSON.stringify(body),
    token,
  });
}

/**
 * Mark a security finding as accepted risk (M61.1).
 *
 * Records that the team is intentionally carrying a known exposure until
 * `accepted_until` for the stated reason. This does NOT mark the exposure
 * resolved or fixed. Returns the updated finding.
 */
export async function acceptSecurityFindingRisk(
  findingId: string,
  body: import("@/types").AcceptRiskRequest,
  token?: string | null,
): Promise<SecurityFinding> {
  return apiFetch(`/security/findings/${findingId}/accept-risk`, {
    method: "POST",
    body: JSON.stringify(body),
    token,
  });
}

/**
 * Acknowledge a security finding (M61.2).
 *
 * Records that the team has reviewed the exposure and is tracking it. The
 * finding stays active — this does NOT mark it fixed or resolved.
 */
export async function acknowledgeSecurityFinding(
  findingId: string,
  token?: string | null,
): Promise<SecurityFinding> {
  return apiFetch(`/security/findings/${findingId}/acknowledge`, {
    method: "POST",
    token,
  });
}

/**
 * Snooze a security finding until a future time (M61.2).
 *
 * Pauses active attention on the exposure temporarily. This does NOT accept the
 * risk and does NOT mark the exposure fixed or resolved.
 */
export async function snoozeSecurityFinding(
  findingId: string,
  body: import("@/types").SecuritySnoozeRequest,
  token?: string | null,
): Promise<SecurityFinding> {
  return apiFetch(`/security/findings/${findingId}/snooze`, {
    method: "POST",
    body: JSON.stringify(body),
    token,
  });
}

/** List review notes for a security finding, oldest first (M61.3). */
export async function getSecurityFindingNotes(
  findingId: string,
  token?: string | null,
): Promise<import("@/types").SecurityFindingNoteListResponse> {
  return apiFetch(`/security/findings/${findingId}/notes`, { token });
}

/**
 * Add a review note to a security finding (M61.3).
 * Plain text, 2–2000 chars. Does NOT change the finding status.
 */
export async function createSecurityFindingNote(
  findingId: string,
  body: string,
  token?: string | null,
): Promise<import("@/types").SecurityFindingNote> {
  return apiFetch(`/security/findings/${findingId}/notes`, {
    method: "POST",
    body: JSON.stringify({ body }),
    token,
  });
}

/** Fetch the combined activity/audit feed for a security finding (M61.3). */
export async function getSecurityFindingActivity(
  findingId: string,
  token?: string | null,
): Promise<import("@/types").SecurityFindingActivityResponse> {
  return apiFetch(`/security/findings/${findingId}/activity`, { token });
}

/** List all known security rules with their effective enabled state (M61.7). */
export async function getSecurityRuleSettings(
  token?: string | null,
): Promise<import("@/types").SecurityRuleSettingsListResponse> {
  return apiFetch(`/security/rules/settings`, { token });
}

/** Active Configuration Risk rule pack + per-rule version manifest (M63.3). */
export async function getSecurityRulePack(
  token?: string | null,
): Promise<import("@/types").SecurityRulePack> {
  return apiFetch(`/security/rules/pack`, { token });
}

/** Beta analytics summary over first-party usage events (M63.4, admin-only). */
export async function getSecurityBetaEventsSummary(
  params: { days?: number; event_name?: string; route_group?: string } = {},
  token?: string | null,
): Promise<import("@/types").SecurityBetaSummary> {
  return apiFetch(`/security/beta-events/summary${buildQuery(params)}`, { token });
}

/** Submit optional qualitative feedback after a report export (M63.6). */
export async function submitSecurityBetaFeedback(
  body: import("@/types").SecurityBetaFeedbackRequest,
  token?: string | null,
): Promise<import("@/types").SecurityBetaFeedbackResponse> {
  return apiFetch(`/security/beta-feedback`, {
    method: "POST",
    token,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/**
 * Enable or disable a security rule for the current workspace (M61.7).
 * Disabling stops future findings from that rule; it does not resolve existing
 * findings or send notifications.
 */
export async function updateSecurityRuleSetting(
  ruleKey: string,
  enabled: boolean,
  token?: string | null,
): Promise<import("@/types").SecurityRuleSetting> {
  return apiFetch(`/security/rules/settings/${ruleKey}`, {
    method: "PATCH",
    body: JSON.stringify({ enabled }),
    token,
  });
}

/** Whether Configuration Risk demo data exists in the workspace (M62.2). */
export async function getSecurityDemoDataStatus(
  token?: string | null,
): Promise<import("@/types").SecurityDemoDataStatus> {
  return apiFetch(`/security/demo-data/status`, { token });
}

/** Seed a safe Configuration Risk demo dataset (opt-in, idempotent). */
export async function seedSecurityDemoData(
  token?: string | null,
): Promise<import("@/types").SecurityDemoDataStatus> {
  return apiFetch(`/security/demo-data/seed`, { method: "POST", token });
}

/** Remove the demo-created Configuration Risk rows for the workspace. */
export async function clearSecurityDemoData(
  token?: string | null,
): Promise<import("@/types").SecurityDemoClearResponse> {
  return apiFetch(`/security/demo-data`, { method: "DELETE", token });
}

/** Record a lightweight Configuration Risk beta usage event (M63.1).
 *  Metadata is allowlisted + truncated server-side. */
export async function postSecurityBetaEvent(
  body: { event_name: string; page_path?: string | null; metadata?: Record<string, unknown> },
  token?: string | null,
): Promise<{ id: string; ok: boolean }> {
  return apiFetch(`/security/beta-events`, {
    method: "POST",
    token,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** Provider coverage-quality report for Configuration Risk (M62.3). */
export async function getSecurityCoverage(
  token?: string | null,
): Promise<import("@/types").SecurityCoverageResponse> {
  return apiFetch(`/security/coverage`, { token });
}

// ── M57.3: Needs Review queue ─────────────────────────────────────────────────

export interface GetNeedsReviewParams {
  page?: number;
  page_size?: number;
}

/**
 * Fetch the "Needs Review" queue — changes with no review row, status=needs_review,
 * or an expired snooze.  Uses pre-DB filtering so page counts are accurate.
 */
export async function getNeedsReviewChanges(
  params: GetNeedsReviewParams = {},
  token?: string | null,
): Promise<PaginatedResponse<ChangeListItem>> {
  return apiFetch(`/changes/needs-review${buildQuery(params)}`, { token });
}

// ── M57.2: Change review actions ──────────────────────────────────────────────

export async function acknowledgeChange(
  changeId: string,
  body: { note?: string },
  token?: string | null,
): Promise<ChangeReviewResponse> {
  return apiFetch(`/changes/${changeId}/acknowledge`, {
    method: "POST",
    body: JSON.stringify(body),
    token,
  });
}

export async function markChangeExpected(
  changeId: string,
  body: { note?: string },
  token?: string | null,
): Promise<ChangeReviewResponse> {
  return apiFetch(`/changes/${changeId}/mark-expected`, {
    method: "POST",
    body: JSON.stringify(body),
    token,
  });
}

export async function snoozeChange(
  changeId: string,
  body: { until: string; reason?: string },
  token?: string | null,
): Promise<ChangeReviewResponse> {
  return apiFetch(`/changes/${changeId}/snooze`, {
    method: "POST",
    body: JSON.stringify(body),
    token,
  });
}

export async function reopenChange(
  changeId: string,
  body: { note?: string },
  token?: string | null,
): Promise<ChangeReviewResponse> {
  return apiFetch(`/changes/${changeId}/reopen`, {
    method: "POST",
    body: JSON.stringify(body),
    token,
  });
}

// ── Resources ─────────────────────────────────────────────────────────────────

export interface GetResourcesParams {
  integration_id?: string;
  page?: number;
  page_size?: number;
}

export async function getResources(
  params: GetResourcesParams = {},
  token?: string | null,
): Promise<PaginatedResponse<ResourceListItem>> {
  return apiFetch(`/resources${buildQuery(params)}`, { token });
}

export async function getResource(
  resourceId: string,
  token?: string | null,
): Promise<ResourceDetail> {
  return apiFetch(`/resources/${resourceId}`, { token });
}

export async function getResourceSnapshots(
  resourceId: string,
  params: { page?: number; page_size?: number } = {},
  token?: string | null,
): Promise<PaginatedResponse<SnapshotListItem>> {
  return apiFetch(
    `/resources/${resourceId}/snapshots${buildQuery(params)}`,
    { token },
  );
}

export async function getResourceChanges(
  resourceId: string,
  params: GetChangesParams = {},
  token?: string | null,
): Promise<PaginatedResponse<ChangeListItem>> {
  return apiFetch(
    `/resources/${resourceId}/changes${buildQuery(params)}`,
    { token },
  );
}

// ── Integrations ──────────────────────────────────────────────────────────────

export async function getIntegrations(
  token?: string | null,
): Promise<IntegrationListResponse> {
  return apiFetch("/integrations", { token });
}

/**
 * Fetch a single integration's detail by ID.
 *
 * Returns HTTP 404 if the integration does not exist, is soft-deleted, or
 * belongs to a different user.  Credentials are never included in the response.
 */
export async function getIntegration(
  integrationId: string,
  token?: string | null,
): Promise<Integration> {
  return apiFetch(`/integrations/${integrationId}`, { token });
}

/**
 * Fetch paginated sync runs for an integration.
 *
 * Supports offset pagination (page/page_size) and optional filters.
 * The response includes total, page, page_size, and total_pages for
 * the frontend paginator.
 *
 * Pass page=1, page_size=N for the integration detail page preview.
 * Pass page=N with filters for the dedicated sync-runs history page.
 */
export async function getIntegrationSyncRuns(
  integrationId: string,
  params: {
    page?: number;
    page_size?: number;
    status?: string;
    trigger?: string;
  } = {},
  token?: string | null,
): Promise<SyncRunListResponse> {
  return apiFetch(
    `/integrations/${integrationId}/sync-runs${buildQuery(params)}`,
    { token },
  );
}

/**
 * Create a new integration.
 *
 * The payload includes a plaintext api_token that is sent to the backend
 * once and encrypted server-side before storage.  The token is never
 * returned in any response and must not be stored in frontend state after
 * this call returns.
 */
export async function createIntegration(
  payload: IntegrationCreateRequest,
  token?: string | null,
): Promise<Integration> {
  return apiFetch("/integrations", {
    method: "POST",
    body: JSON.stringify(payload),
    token,
  });
}

/**
 * Update an integration's display name, sync interval, or status.
 * All fields optional — only provided fields are written.
 */
export interface IntegrationUpdateRequest {
  display_name?: string;
  sync_interval_minutes?: number;
  status?: "active" | "paused";
}

export async function patchIntegration(
  integrationId: string,
  data: IntegrationUpdateRequest,
  token?: string | null,
): Promise<Integration> {
  return apiFetch(`/integrations/${integrationId}`, {
    method: "PATCH",
    body: JSON.stringify(data),
    token,
  });
}

/** Soft-delete an integration (sets status='deleted'). Returns nothing on 204. */
export async function deleteIntegration(
  integrationId: string,
  token?: string | null,
): Promise<void> {
  const url = `${BASE_URL}/integrations/${integrationId}`;
  const res = await fetch(url, {
    method: "DELETE",
    headers: buildHeaders(token),
  });
  if (!res.ok && res.status !== 204) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = String(body.detail);
    } catch {
      // ignore
    }
    throw new Error(detail);
  }
}

/**
 * Token-only reconnect — replaces the API token while keeping the existing
 * resource pinned.
 *
 * Provider field mapping:
 *   Cloudflare → api_token
 *   GitHub     → github_token
 *   Vercel     → vercel_token
 *   Stripe     → stripe_api_key
 *   Firebase   → firebase_service_account_json
 *   Supabase   → supabase_access_token
 *
 * Never store the token in frontend state after this call returns.
 */
export interface IntegrationReconnectRequest {
  /** Cloudflare API token. */
  api_token?: string;
  /** GitHub fine-grained PAT. */
  github_token?: string;
  /** Vercel personal access token. */
  vercel_token?: string;
  /** Stripe restricted API key. */
  stripe_api_key?: string;
  /**
   * Firebase service account JSON key file contents.
   * SECURITY: contains a private_key — cleared immediately after submission.
   */
  firebase_service_account_json?: string;
  /**
   * Supabase Management API personal access token (sbp_...).
   * SECURITY: cleared immediately after submission.
   */
  supabase_access_token?: string;
}

export async function reconnectIntegration(
  integrationId: string,
  data: IntegrationReconnectRequest,
  token?: string | null,
): Promise<Integration> {
  return apiFetch(`/integrations/${integrationId}/reconnect`, {
    method: "POST",
    body: JSON.stringify(data),
    token,
  });
}

// ── GitHub App install flow (M31) ─────────────────────────────────────────────

/**
 * Generate a GitHub App install URL with an HMAC-signed state token.
 *
 * The returned state must be stored (e.g. sessionStorage) and passed to
 * completeGitHubAppInstall() after the GitHub callback.  It expires in 10 min.
 *
 * Returns HTTP 503 if the server is not configured with GitHub App credentials.
 */
export async function getGitHubAppInstallUrl(
  token?: string | null,
): Promise<GitHubAppInstallUrlResponse> {
  return apiFetch("/integrations/github/app/install-url", { token });
}

/**
 * List repositories accessible to a GitHub App installation.
 *
 * Call this from the callback page after GitHub redirects back with
 * installation_id.  The state token validates CSRF.
 *
 * Returns HTTP 400 if the state token is invalid or expired.
 * Returns HTTP 502 if the GitHub API is unreachable.
 */
export async function getInstallationRepositories(
  installationId: number,
  state: string,
  token?: string | null,
): Promise<GitHubInstallationReposResponse> {
  return apiFetch(
    `/integrations/github/app/installation-repos${buildQuery({
      installation_id: installationId,
      state,
    })}`,
    { token },
  );
}

/**
 * Complete a GitHub App installation — create the integration.
 *
 * The installation token is minted server-side and never exposed to the
 * frontend.  The state token must match the one from getGitHubAppInstallUrl().
 *
 * Returns HTTP 400 on state validation failure, auth error, or duplicate repo.
 * Returns HTTP 502 if the GitHub API is unreachable during validation.
 */
export async function completeGitHubAppInstall(
  payload: GitHubAppCompleteRequest,
  token?: string | null,
): Promise<Integration> {
  return apiFetch("/integrations/github/app/complete", {
    method: "POST",
    body: JSON.stringify(payload),
    token,
  });
}

// ── Syncs ─────────────────────────────────────────────────────────────────────

export async function triggerSync(
  integrationId: string,
  token?: string | null,
): Promise<SyncRun> {
  return apiFetch(`/syncs`, {
    method: "POST",
    body: JSON.stringify({ integration_id: integrationId }),
    token,
  });
}

export async function getSyncStatus(
  syncRunId: string,
  token?: string | null,
): Promise<SyncRun> {
  return apiFetch(`/syncs/${syncRunId}`, { token });
}

// ── Dashboard (M34) ───────────────────────────────────────────────────────────

/**
 * Fetch the full dashboard summary for the authenticated user.
 *
 * Returns integration health, resource counts, change activity, risk
 * distribution, provider distribution, recent high/critical changes,
 * and recent failed syncs.
 */
export async function getDashboardSummary(
  token?: string | null,
): Promise<DashboardSummary> {
  return apiFetch("/dashboard/summary", { token });
}

// ── Settings (M34) ───────────────────────────────────────────────────────────

/**
 * Fetch the authenticated user's settings.
 *
 * Always returns HTTP 200 — defaults are created on first access.
 */
export async function getSettings(
  token?: string | null,
): Promise<UserSettings> {
  return apiFetch("/settings", { token });
}

/**
 * Update one or more settings fields.
 *
 * Only provided (non-undefined) fields are written.
 * Returns the updated settings.
 */
export async function patchSettings(
  data: UserSettingsUpdateRequest,
  token?: string | null,
): Promise<UserSettings> {
  return apiFetch("/settings", {
    method: "PATCH",
    body: JSON.stringify(data),
    token,
  });
}

// ── User profile (M59.13) ────────────────────────────────────────────────────

/**
 * Fetch the authenticated user's profile (first_name / last_name plus
 * server-computed ``computed_display_name``).
 */
export async function getMyProfile(
  token?: string | null,
): Promise<ProfileResponse> {
  return apiFetch("/me/profile", { token });
}

/**
 * Update the authenticated user's profile.
 *
 * Omitted fields are unchanged.  An explicit empty string clears the field.
 * Names are trimmed and capped at 100 characters by the server.
 */
export async function patchMyProfile(
  data: ProfileUpdateRequest,
  token?: string | null,
): Promise<ProfileResponse> {
  return apiFetch("/me/profile", {
    method: "PATCH",
    body: JSON.stringify(data),
    token,
  });
}

// ── Push notifications (M58.7) ────────────────────────────────────────────────

/**
 * Fetch the VAPID public key for browser push subscription.
 *
 * Returns `configured: false` when VAPID is not set up server-side.
 * Safe to call without admin role — any workspace member can read the public key.
 */
export async function getPushPublicKey(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").PushPublicKeyResponse> {
  return apiFetch(
    `/workspaces/${workspaceId}/notifications/push/public-key`,
    { token },
  );
}

/**
 * Register a browser PushSubscription with the backend.
 *
 * Call this after `pushManager.subscribe()` succeeds and the user has
 * granted notification permission.  The backend encrypts endpoint + keys
 * before storage — they are never returned in any API response.
 *
 * Returns the new subscription metadata (no secrets).
 */
export async function subscribePush(
  workspaceId: string,
  body: import("@/types").PushSubscribeRequest,
  token?: string | null,
): Promise<import("@/types").PushSubscriptionResponse> {
  return apiFetch(
    `/workspaces/${workspaceId}/notifications/push/subscriptions`,
    {
      method: "POST",
      body: JSON.stringify(body),
      token,
    },
  );
}

/**
 * Update per-device push preferences (M60.13) without re-subscribing.
 *
 * Lets a user toggle which alert categories (Drift critical, Security
 * exposure critical, resolved-exposure) can reach this browser. Only the
 * fields provided are changed. Returns the updated subscription metadata.
 */
export async function updatePushSubscription(
  workspaceId: string,
  subscriptionId: string,
  body: import("@/types").PushSubscriptionUpdateRequest,
  token?: string | null,
): Promise<import("@/types").PushSubscriptionResponse> {
  return apiFetch(
    `/workspaces/${workspaceId}/notifications/push/subscriptions/${subscriptionId}`,
    {
      method: "PATCH",
      body: JSON.stringify(body),
      token,
    },
  );
}

/**
 * List all push subscriptions for a workspace.
 *
 * Returned records do NOT include endpoint URL or encryption keys.
 */
export async function listPushSubscriptions(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").PushSubscriptionListResponse> {
  return apiFetch(
    `/workspaces/${workspaceId}/notifications/push/subscriptions`,
    { token },
  );
}

/**
 * Remove a push subscription from the backend.
 *
 * Should also be called with `pushManager.unsubscribe()` on the browser side.
 * Returns nothing on 204.
 */
export async function deletePushSubscription(
  workspaceId: string,
  subscriptionId: string,
  token?: string | null,
): Promise<void> {
  const url = `${BASE_URL}/workspaces/${workspaceId}/notifications/push/subscriptions/${subscriptionId}`;
  const res = await fetch(url, {
    method: "DELETE",
    headers: buildHeaders(token),
  });
  if (!res.ok && res.status !== 204) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = String(body.detail);
    } catch { /* ignore */ }
    throw new Error(detail);
  }
}

/**
 * Send a test push notification to all enabled subscriptions for a workspace.
 *
 * Requires admin role.  Returns the count sent and total subscriptions attempted.
 */
export async function testPushNotifications(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").PushTestResponse> {
  return apiFetch(
    `/workspaces/${workspaceId}/notifications/push/test`,
    {
      method: "POST",
      token,
    },
  );
}

// ── Billing (M52) ────────────────────────────────────────────────────────────

/**
 * Fetch billing info, plan limits, and current usage for a workspace.
 * Requires admin or owner role.
 */
export async function getWorkspaceBilling(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").WorkspaceBilling> {
  return apiFetch(`/workspaces/${workspaceId}/billing`, { token });
}

/**
 * Create a Stripe Checkout session to upgrade a workspace.
 * Returns the Stripe-hosted checkout URL.
 * The frontend redirects to this URL; no card details touch our servers.
 *
 * @param priceId - Stripe price ID (validated server-side against allowlist).
 */
export async function createCheckoutSession(
  workspaceId: string,
  priceId: string,
  token?: string | null,
): Promise<{ checkout_url: string }> {
  return apiFetch(`/workspaces/${workspaceId}/billing/checkout`, {
    method: "POST",
    body: JSON.stringify({ price_id: priceId }),
    token,
  });
}

/**
 * Create a Stripe Billing Portal session for managing an existing subscription.
 * Returns the Stripe-hosted portal URL.
 */
export async function createPortalSession(
  workspaceId: string,
  token?: string | null,
): Promise<{ portal_url: string }> {
  return apiFetch(`/workspaces/${workspaceId}/billing/portal`, {
    method: "POST",
    body: JSON.stringify({}),
    token,
  });
}

// ── M58.8: Change Notes ───────────────────────────────────────────────────────

/**
 * List all investigation notes for a change (oldest first).
 * Only workspace members may call this.
 */
export async function getChangeNotes(
  changeId: string,
  token?: string | null,
): Promise<import("@/types").ChangeNoteListResponse> {
  return apiFetch(`/changes/${changeId}/notes`, { token });
}

/**
 * Add a team investigation note to a change.
 * Body is plain text, max 2000 characters.
 */
export async function createChangeNote(
  changeId: string,
  body: string,
  token?: string | null,
): Promise<import("@/types").ChangeNote> {
  return apiFetch(`/changes/${changeId}/notes`, {
    method: "POST",
    body: JSON.stringify({ body }),
    token,
  });
}

// ── M58.11: Blast Radius ──────────────────────────────────────────────────────

/**
 * Fetch the deterministic blast radius / potential impact analysis for a change.
 *
 * Returns { available: false } when no meaningful blast radius model applies.
 * Always resolves (never rejects on 200 responses).
 */
export async function getChangeBlastRadius(
  changeId: string,
  token?: string | null,
): Promise<import("@/types").BlastRadiusResponse> {
  return apiFetch(`/changes/${changeId}/blast-radius`, { token });
}

// ── M58.10: Change Correlation / Risk Clusters ────────────────────────────────

/**
 * Fetch the correlation / risk-cluster analysis for a change.
 *
 * Returns { available: false } when no meaningful cluster is detected.
 * Always resolves (never rejects on 200 responses).
 */
export async function getChangeCorrelation(
  changeId: string,
  token?: string | null,
): Promise<import("@/types").CorrelationResponse> {
  return apiFetch(`/changes/${changeId}/correlation`, { token });
}

// ── M58.14: Policy Engine ─────────────────────────────────────────────────────

/**
 * Evaluate all enabled workspace policies against a change.
 *
 * Returns { violations: [] } when no policies fire for this change.
 * Always resolves (never rejects on 200 responses).
 */
export async function getChangePolicyViolations(
  changeId: string,
  token?: string | null,
): Promise<import("@/types").PolicyViolationsResponse> {
  return apiFetch(`/changes/${changeId}/policy-violations`, { token });
}

/**
 * Fetch the full built-in policy catalog with per-workspace enabled states.
 */
export async function getWorkspacePolicies(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").PolicyListResponse> {
  return apiFetch(`/workspaces/${workspaceId}/policies`, { token });
}

/**
 * Enable or disable a built-in policy for a workspace.
 * Only admins may call this.
 */
export async function updateWorkspacePolicy(
  workspaceId: string,
  policyKey: string,
  enabled: boolean,
  token?: string | null,
): Promise<import("@/types").WorkspacePolicy> {
  return apiFetch(`/workspaces/${workspaceId}/policies/${policyKey}`, {
    token,
    method: "PUT",
    body: JSON.stringify({ enabled }),
  });
}

// ── M58.15: Weekly Digest ─────────────────────────────────────────────────────

/**
 * Fetch a live digest preview for the last 7 days (any member).
 */
export async function getWeeklyDigestPreview(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").WeeklyDigest> {
  return apiFetch(`/workspaces/${workspaceId}/weekly-digest/preview`, { token });
}

/**
 * Fetch digest schedule settings for a workspace.
 */
export async function getWeeklyDigestSettings(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").WeeklyDigestSettings> {
  return apiFetch(`/workspaces/${workspaceId}/weekly-digest/settings`, { token });
}

/**
 * Update digest schedule settings (admin only).
 */
export async function updateWeeklyDigestSettings(
  workspaceId: string,
  body: import("@/types").WeeklyDigestSettingsUpdateRequest,
  token?: string | null,
): Promise<import("@/types").WeeklyDigestSettings> {
  return apiFetch(`/workspaces/${workspaceId}/weekly-digest/settings`, {
    token,
    method: "PUT",
    body: JSON.stringify(body),
  });
}

/**
 * Send a test digest to the requesting user's email (admin only).
 * Returns the rendered digest body even when email is not configured.
 */
export async function sendTestWeeklyDigest(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").WeeklyDigestTestResponse> {
  return apiFetch(`/workspaces/${workspaceId}/weekly-digest/test`, {
    token,
    method: "POST",
    body: JSON.stringify({}),
  });
}

// ── M58.16: Expected Change Windows ──────────────────────────────────────────

/**
 * List expected change windows for a workspace.
 * Any workspace member may call this.
 */
export async function listExpectedChangeWindows(
  workspaceId: string,
  params?: { status?: string; page?: number; page_size?: number },
  token?: string | null,
): Promise<import("@/types").ExpectedChangeWindowListResponse> {
  const qs = new URLSearchParams();
  if (params?.status) qs.set("status", params.status);
  if (params?.page) qs.set("page", String(params.page));
  if (params?.page_size) qs.set("page_size", String(params.page_size));
  const query = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetch(`/workspaces/${workspaceId}/expected-changes${query}`, { token });
}

/**
 * Create a new expected change window in 'pending' status (admin only).
 */
export async function createExpectedChangeWindow(
  workspaceId: string,
  body: import("@/types").ExpectedChangeWindowCreate,
  token?: string | null,
): Promise<import("@/types").ExpectedChangeWindow> {
  return apiFetch(`/workspaces/${workspaceId}/expected-changes`, {
    token,
    method: "POST",
    body: JSON.stringify(body),
  });
}

/**
 * Approve a pending expected change window (admin only).
 */
export async function approveExpectedChangeWindow(
  workspaceId: string,
  windowId: string,
  token?: string | null,
): Promise<import("@/types").ExpectedChangeWindow> {
  return apiFetch(
    `/workspaces/${workspaceId}/expected-changes/${windowId}/approve`,
    { token, method: "POST", body: JSON.stringify({}) },
  );
}

/**
 * Reject a pending expected change window (admin only).
 */
export async function rejectExpectedChangeWindow(
  workspaceId: string,
  windowId: string,
  reason?: string,
  token?: string | null,
): Promise<import("@/types").ExpectedChangeWindow> {
  return apiFetch(
    `/workspaces/${workspaceId}/expected-changes/${windowId}/reject`,
    { token, method: "POST", body: JSON.stringify({ reason }) },
  );
}

/**
 * Cancel a pending or approved expected change window (admin only).
 */
export async function cancelExpectedChangeWindow(
  workspaceId: string,
  windowId: string,
  token?: string | null,
): Promise<import("@/types").ExpectedChangeWindow> {
  return apiFetch(
    `/workspaces/${workspaceId}/expected-changes/${windowId}/cancel`,
    { token, method: "POST", body: JSON.stringify({}) },
  );
}

/**
 * Check whether a change falls within an approved expected change window.
 * Returns matched=false when no window covers this change.
 */
export async function getExpectedChangeMatch(
  changeId: string,
  token?: string | null,
): Promise<import("@/types").ExpectedChangeMatchResponse> {
  return apiFetch(`/changes/${changeId}/expected-change-match`, { token });
}

// ── M58.17: Drift Control Score ───────────────────────────────────────────────

/**
 * Fetch the Drift Control Score for a workspace.
 *
 * GET /workspaces/{workspaceId}/drift-score
 *
 * The score (0–100) is advisory only — it measures review and alert hygiene
 * for configuration drift.  It is NOT a compliance or security rating.
 */
export async function getWorkspaceDriftScore(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").DriftScoreResponse> {
  return apiFetch(`/workspaces/${workspaceId}/drift-score`, { token });
}

// ── M58.18: IaC Awareness ─────────────────────────────────────────────────────

/**
 * List IaC repositories registered for a workspace.
 * GET /workspaces/{workspaceId}/iac/repositories
 */
export async function listIacRepositories(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").IacRepositoryListResponse> {
  return apiFetch(`/workspaces/${workspaceId}/iac/repositories`, { token });
}

/**
 * Register a GitHub repository for IaC scanning.
 * POST /workspaces/{workspaceId}/iac/repositories
 */
export async function registerIacRepository(
  workspaceId: string,
  body: import("@/types").IacRepositoryCreate,
  token?: string | null,
): Promise<import("@/types").IacRepository> {
  return apiFetch(`/workspaces/${workspaceId}/iac/repositories`, {
    token,
    method: "POST",
    body: JSON.stringify(body),
  });
}

/**
 * Trigger a safe metadata scan of an IaC repository.
 * POST /workspaces/{workspaceId}/iac/repositories/{repoId}/scan
 *
 * Reads .tf file metadata via the linked GitHub integration.
 * Never reads tfstate/tfvars; never stores file content.
 */
export async function scanIacRepository(
  workspaceId: string,
  repoId: string,
  token?: string | null,
): Promise<import("@/types").IacScanResult> {
  return apiFetch(
    `/workspaces/${workspaceId}/iac/repositories/${repoId}/scan`,
    { token, method: "POST", body: JSON.stringify({}) },
  );
}

/**
 * List IaC resource mappings for a workspace.
 * GET /workspaces/{workspaceId}/iac/mappings
 */
export async function listIacMappings(
  workspaceId: string,
  token?: string | null,
): Promise<import("@/types").IacMappingListResponse> {
  return apiFetch(`/workspaces/${workspaceId}/iac/mappings`, { token });
}

/**
 * Fetch advisory IaC context for a change.
 * GET /changes/{changeId}/iac-context
 *
 * Returns possible Terraform resource mappings for the changed cloud resource.
 * Advisory only — does NOT confirm Terraform ownership.
 */
export async function getChangeIacContext(
  changeId: string,
  token?: string | null,
): Promise<import("@/types").IacContextResponse> {
  return apiFetch(`/changes/${changeId}/iac-context`, { token });
}

// ── M58.19: Terraform Fix Suggestion Preview ──────────────────────────────────

export async function getChangeTerraformFixPreview(
  changeId: string,
  token?: string | null,
): Promise<import("@/types").TerraformFixPreviewResponse> {
  return apiFetch(`/changes/${changeId}/terraform-fix-preview`, { token });
}

// ── M58.20: GitHub PR Draft Flow ──────────────────────────────────────────────

export async function getChangeGitHubPrDraft(
  changeId: string,
  token?: string | null,
): Promise<import("@/types").GitHubPrDraftResponse> {
  return apiFetch(`/changes/${changeId}/github-pr-draft`, { token });
}

// ── M58.21: GitHub PR Creation ────────────────────────────────────────────────

export async function createChangeGitHubPr(
  changeId: string,
  body: import("@/types").GitHubPrCreateRequest,
  token?: string | null,
): Promise<import("@/types").GitHubPrCreateResponse> {
  return apiFetch(`/changes/${changeId}/github-pr`, {
    method: "POST",
    body: JSON.stringify(body),
    token,
  });
}

