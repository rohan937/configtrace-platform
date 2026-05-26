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
  ResourceDetail,
  ResourceListItem,
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
