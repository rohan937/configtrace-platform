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
  GitHubAppCompleteRequest,
  GitHubAppInstallUrlResponse,
  GitHubInstallationReposResponse,
  Integration,
  IntegrationCreateRequest,
  IntegrationListResponse,
  PaginatedResponse,
  ResourceDetail,
  ResourceListItem,
  SnapshotListItem,
  SyncRun,
  SyncRunListResponse,
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
      if (body?.detail) detail = `HTTP ${res.status}: ${String(body.detail)}`;
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

// ── Changes ───────────────────────────────────────────────────────────────────

export interface GetChangesParams {
  integration_id?: string;
  resource_id?: string;
  risk_level?: string;
  change_type?: string;
  provider?: string;
  since?: string;
  until?: string;
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
 * Fetch the most recent sync runs for an integration.
 *
 * ``limit`` defaults to 10 and is clamped to 50 server-side.
 * The response includes a ``total`` field reflecting the all-time SyncRun
 * count so the UI can show "Last N of M total runs".
 */
export async function getIntegrationSyncRuns(
  integrationId: string,
  limit: number = 10,
  token?: string | null,
): Promise<SyncRunListResponse> {
  return apiFetch(
    `/integrations/${integrationId}/sync-runs${buildQuery({ limit })}`,
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
 * resource (zone_id / repo_owner+repo_name) pinned.
 *
 * Provide api_token for Cloudflare integrations.
 * Provide github_token for GitHub integrations.
 * Never store the token in frontend state after this call returns.
 */
export interface IntegrationReconnectRequest {
  api_token?: string;
  github_token?: string;
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
