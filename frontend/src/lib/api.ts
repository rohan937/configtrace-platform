/**
 * ConfigTrace API client.
 *
 * All functions read NEXT_PUBLIC_API_BASE_URL from the environment
 * (default: http://localhost:8000).  Errors from the server are surfaced
 * as thrown Error objects with the message set to the server's detail string.
 */

import type {
  ChangeDetail,
  ChangeListItem,
  Integration,
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

async function apiFetch<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers ?? {}),
    },
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
): Promise<PaginatedResponse<ChangeListItem>> {
  return apiFetch(`/changes${buildQuery(params)}`);
}

export async function getChange(changeId: string): Promise<ChangeDetail> {
  return apiFetch(`/changes/${changeId}`);
}

// ── Resources ─────────────────────────────────────────────────────────────────

export interface GetResourcesParams {
  integration_id?: string;
  page?: number;
  page_size?: number;
}

export async function getResources(
  params: GetResourcesParams = {},
): Promise<PaginatedResponse<ResourceListItem>> {
  return apiFetch(`/resources${buildQuery(params)}`);
}

export async function getResource(resourceId: string): Promise<ResourceDetail> {
  return apiFetch(`/resources/${resourceId}`);
}

export async function getResourceSnapshots(
  resourceId: string,
  params: { page?: number; page_size?: number } = {},
): Promise<PaginatedResponse<SnapshotListItem>> {
  return apiFetch(`/resources/${resourceId}/snapshots${buildQuery(params)}`);
}

export async function getResourceChanges(
  resourceId: string,
  params: GetChangesParams = {},
): Promise<PaginatedResponse<ChangeListItem>> {
  return apiFetch(`/resources/${resourceId}/changes${buildQuery(params)}`);
}

// ── Integrations ──────────────────────────────────────────────────────────────

export async function getIntegrations(): Promise<PaginatedResponse<Integration>> {
  return apiFetch("/integrations");
}

// ── Syncs ─────────────────────────────────────────────────────────────────────

export async function triggerSync(integrationId: string): Promise<SyncRun> {
  return apiFetch(`/syncs`, {
    method: "POST",
    body: JSON.stringify({ integration_id: integrationId }),
  });
}

export async function getSyncStatus(syncRunId: string): Promise<SyncRun> {
  return apiFetch(`/syncs/${syncRunId}`);
}
