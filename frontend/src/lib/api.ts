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
  Integration,
  IntegrationCreateRequest,
  IntegrationListResponse,
  PaginatedResponse,
  ResourceDetail,
  ResourceListItem,
  SnapshotListItem,
  SyncRun,
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
  const res = await fetch(url, {
    ...rest,
    headers: buildHeaders(token, headers),
  });

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = String(body.detail);
    } catch {
      // ignore parse errors
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
