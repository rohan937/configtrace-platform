"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import type {
  ChangeListItem,
  Integration,
  ResourceListItem,
  SyncRun,
} from "@/types";
import {
  getGitHubAppInstallUrl,
  getIntegration,
  getIntegrationSyncRuns,
  getChanges,
  getResources,
  getSyncStatus,
  triggerSync,
} from "@/lib/api";
import { usePollingRefresh } from "@/hooks/usePollingRefresh";
import PageHeader from "@/components/common/PageHeader";
import StatusBadge from "@/components/common/StatusBadge";
import RiskBadge from "@/components/common/RiskBadge";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import RenameIntegrationModal from "@/components/integrations/RenameIntegrationModal";
import DeleteIntegrationModal from "@/components/integrations/DeleteIntegrationModal";
import ReconnectIntegrationModal from "@/components/integrations/ReconnectIntegrationModal";
import { patchIntegration } from "@/lib/api";
import {
  formatRelativeTime,
  formatAbsoluteTime,
  formatResourceType,
} from "@/lib/utils";

// ── Constants ─────────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = 30_000;
const SYNC_POLL_INTERVAL_MS = 2_000;
const SYNC_POLL_MAX = 90;

// ── GitHub monitored categories (static — same for all GitHub integrations) ───

const GITHUB_MONITORED_CATEGORIES = [
  "Repository settings",
  "Branch protection rules",
  "Actions secrets (metadata only, not values)",
  "Actions variables",
  "Webhooks",
  "Deploy keys",
  "Actions permissions",
];

// ── Vercel monitored categories (static — same for all Vercel integrations) ──

const VERCEL_MONITORED_CATEGORIES = [
  "Project settings (framework, build config, Node.js version)",
  "Environment variable names and target environments (values never stored)",
  "Custom domains and verification status",
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatInterval(minutes: number | null): string {
  const m = minutes ?? 60;
  if (m < 60) return `every ${m} min`;
  return "every 1 hour";
}

function formatDuration(startedAt: string | null, completedAt: string | null): string | null {
  if (!startedAt || !completedAt) return null;
  const ms = new Date(completedAt).getTime() - new Date(startedAt).getTime();
  if (ms < 0) return null;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return rem > 0 ? `${m}m ${rem}s` : `${m}m`;
}

function formatElapsed(since: Date | null): string {
  if (!since) return "";
  const s = Math.round((Date.now() - since.getTime()) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  return `${m}m ago`;
}

// ── Shared panel wrapper ──────────────────────────────────────────────────────

function Panel({
  title,
  children,
  action,
}: {
  title?: string;
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div
      style={{
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        padding: "16px",
      }}
    >
      {(title || action) && (
        <div
          className="flex items-center justify-between"
          style={{ marginBottom: "12px" }}
        >
          {title && (
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                fontWeight: 500,
                margin: 0,
              }}
            >
              {title}
            </p>
          )}
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

function MetaRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3" style={{ marginBottom: "8px" }}>
      <span
        style={{
          fontSize: "12px",
          color: "#565b6e",
          width: "140px",
          flexShrink: 0,
          paddingTop: "1px",
        }}
      >
        {label}
      </span>
      <span style={{ fontSize: "12px", color: "#b0b5c4" }}>{value}</span>
    </div>
  );
}

// ── Sync run status pill ──────────────────────────────────────────────────────

function SyncStatusPill({ status }: { status: string }) {
  const colors: Record<string, { bg: string; text: string; border: string }> = {
    completed: { bg: "rgba(60,207,126,0.10)", text: "#3ccf7e", border: "rgba(60,207,126,0.25)" },
    failed:    { bg: "rgba(232,64,64,0.10)",  text: "#e84040", border: "rgba(232,64,64,0.25)" },
    running:   { bg: "rgba(245,166,35,0.10)", text: "#f5a623", border: "rgba(245,166,35,0.25)" },
    pending:   { bg: "rgba(86,91,110,0.10)",  text: "#8b90a0", border: "#2a2d38" },
  };
  const c = colors[status] ?? colors.pending;
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 7px",
        borderRadius: "4px",
        fontSize: "11px",
        textTransform: "capitalize",
        background: c.bg,
        color: c.text,
        border: `1px solid ${c.border}`,
      }}
    >
      {status}
    </span>
  );
}

// ── Sync history table ────────────────────────────────────────────────────────

function SyncHistoryTable({
  runs,
  total,
}: {
  runs: SyncRun[];
  total: number;
}) {
  if (runs.length === 0) {
    return (
      <p style={{ fontSize: "13px", color: "#565b6e", margin: 0 }}>
        No sync runs yet. Use <strong style={{ color: "#8b90a0" }}>Sync Now</strong> or wait for a scheduled sync.
      </p>
    );
  }

  return (
    <>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
          <thead>
            <tr
              style={{
                borderBottom: "1px solid #2a2d38",
                color: "#565b6e",
                textTransform: "uppercase",
                fontSize: "10px",
                letterSpacing: "0.05em",
              }}
            >
              <th style={{ textAlign: "left", padding: "4px 8px 8px 0", fontWeight: 500 }}>When</th>
              <th style={{ textAlign: "left", padding: "4px 8px 8px 0", fontWeight: 500 }}>Type</th>
              <th style={{ textAlign: "left", padding: "4px 8px 8px 0", fontWeight: 500 }}>Status</th>
              <th style={{ textAlign: "right", padding: "4px 8px 8px 0", fontWeight: 500 }}>Snapshots</th>
              <th style={{ textAlign: "right", padding: "4px 8px 8px 0", fontWeight: 500 }}>Changes</th>
              <th style={{ textAlign: "right", padding: "4px 0 8px 0", fontWeight: 500 }}>Duration</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <tr
                key={run.id}
                style={{
                  borderBottom: "1px solid #1e2030",
                  background: run.status === "failed" ? "rgba(232,64,64,0.03)" : "transparent",
                }}
              >
                <td
                  style={{ padding: "8px 8px 8px 0", color: "#8b90a0" }}
                  title={run.started_at ? formatAbsoluteTime(run.started_at) : ""}
                >
                  {run.started_at ? formatRelativeTime(run.started_at) : "—"}
                </td>
                <td style={{ padding: "8px 8px 8px 0", color: "#565b6e" }}>
                  {run.triggered_by === "scheduled" ? "scheduled" : "manual"}
                </td>
                <td style={{ padding: "8px 8px 8px 0" }}>
                  <SyncStatusPill status={run.status} />
                </td>
                <td style={{ padding: "8px 8px 8px 0", textAlign: "right", color: "#565b6e" }}>
                  {run.snapshot_count ?? "—"}
                </td>
                <td style={{ padding: "8px 8px 8px 0", textAlign: "right", color: "#565b6e" }}>
                  {run.change_count != null ? run.change_count : "—"}
                </td>
                <td style={{ padding: "8px 0", textAlign: "right", color: "#565b6e" }}>
                  {formatDuration(run.started_at, run.completed_at) ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Error messages for failed runs */}
      {runs.some((r) => r.status === "failed" && r.error_message) && (
        <div style={{ marginTop: "12px" }}>
          {runs
            .filter((r) => r.status === "failed" && r.error_message)
            .map((r) => (
              <div
                key={r.id}
                style={{
                  padding: "8px 10px",
                  marginBottom: "6px",
                  background: "rgba(232,64,64,0.06)",
                  border: "1px solid rgba(232,64,64,0.18)",
                  borderRadius: "4px",
                  fontSize: "11px",
                }}
              >
                <span style={{ color: "#8b90a0" }}>
                  {r.started_at ? formatRelativeTime(r.started_at) : "Unknown time"}
                  {" — "}
                </span>
                <span style={{ color: "#e84040" }}>{r.error_message}</span>
              </div>
            ))}
        </div>
      )}

      {total > runs.length && (
        <p style={{ fontSize: "11px", color: "#3a3d4a", margin: "10px 0 0", textAlign: "right" }}>
          Showing last {runs.length} of {total} total sync runs
        </p>
      )}
    </>
  );
}

// ── Recent changes table ──────────────────────────────────────────────────────

function RecentChangesTable({ changes }: { changes: ChangeListItem[] }) {
  if (changes.length === 0) {
    return (
      <p style={{ fontSize: "13px", color: "#565b6e", margin: 0 }}>
        No configuration changes detected yet. Changes appear from the second sync onwards.
      </p>
    );
  }

  const CHANGE_TYPE_COLORS: Record<string, string> = {
    added:    "#3ccf7e",
    removed:  "#e84040",
    modified: "#f5a623",
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
      {changes.map((c) => (
        <Link
          key={c.id}
          href={`/changes/${c.id}`}
          style={{ textDecoration: "none" }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              padding: "8px 10px",
              background: "#1a1d26",
              border: "1px solid #2a2d38",
              borderRadius: "4px",
              cursor: "pointer",
              transition: "border-color 0.1s",
            }}
            onMouseOver={(e) =>
              (e.currentTarget.style.borderColor = "#3a3d4a")
            }
            onMouseOut={(e) =>
              (e.currentTarget.style.borderColor = "#2a2d38")
            }
          >
            <RiskBadge level={c.risk_level} />

            <span
              style={{
                fontSize: "11px",
                color: CHANGE_TYPE_COLORS[c.change_type] ?? "#8b90a0",
                textTransform: "uppercase",
                letterSpacing: "0.04em",
                width: "56px",
                flexShrink: 0,
              }}
            >
              {c.change_type}
            </span>

            <span
              className="flex-1 truncate"
              style={{ fontSize: "12px", color: "#b0b5c4" }}
            >
              {c.record_identifier}
              {c.field_path && (
                <span style={{ color: "#565b6e" }}> · {c.field_path}</span>
              )}
            </span>

            <span
              style={{ fontSize: "11px", color: "#565b6e", flexShrink: 0 }}
              title={formatAbsoluteTime(c.created_at)}
            >
              {formatRelativeTime(c.created_at)}
            </span>

            <span style={{ fontSize: "11px", color: "#3a3d4a" }}>→</span>
          </div>
        </Link>
      ))}
    </div>
  );
}

// ── Health panel ──────────────────────────────────────────────────────────────

function HealthPanel({
  integration,
  runs,
}: {
  integration: Integration;
  runs: SyncRun[];
}) {
  const lastSuccess = runs.find((r) => r.status === "completed") ?? null;
  const lastFailure = runs.find((r) => r.status === "failed") ?? null;

  return (
    <Panel title="Health">
      <MetaRow
        label="Status"
        value={<StatusBadge status={integration.status} />}
      />
      <MetaRow
        label="Scheduled sync"
        value={
          integration.status === "paused" ? (
            <span style={{ color: "#f5a623" }}>Paused</span>
          ) : (
            <span style={{ color: "#3ccf7e" }}>
              {formatInterval(integration.sync_interval_minutes)}
            </span>
          )
        }
      />
      <MetaRow
        label="Last sync"
        value={
          integration.last_synced_at ? (
            <span title={formatAbsoluteTime(integration.last_synced_at)}>
              {formatRelativeTime(integration.last_synced_at)}
            </span>
          ) : (
            <span style={{ color: "#565b6e" }}>Never</span>
          )
        }
      />
      <MetaRow
        label="Last sync status"
        value={
          integration.last_sync_status ? (
            <SyncStatusPill status={integration.last_sync_status} />
          ) : (
            <span style={{ color: "#565b6e" }}>—</span>
          )
        }
      />
      {lastSuccess && (
        <MetaRow
          label="Last success"
          value={
            <span title={lastSuccess.started_at ? formatAbsoluteTime(lastSuccess.started_at) : ""}>
              {lastSuccess.started_at ? formatRelativeTime(lastSuccess.started_at) : "—"}
            </span>
          }
        />
      )}
      {lastFailure && (
        <>
          <MetaRow
            label="Last failure"
            value={
              <span
                style={{ color: "#e84040" }}
                title={lastFailure.started_at ? formatAbsoluteTime(lastFailure.started_at) : ""}
              >
                {lastFailure.started_at ? formatRelativeTime(lastFailure.started_at) : "—"}
              </span>
            }
          />
          {lastFailure.error_message && (
            <MetaRow
              label="Error"
              value={
                <span style={{ color: "#e84040", wordBreak: "break-word" }}>
                  {lastFailure.error_message}
                </span>
              }
            />
          )}
          {lastFailure.recommended_action && (
            <MetaRow
              label="Action"
              value={
                <span style={{ color: "#f5a623", wordBreak: "break-word" }}>
                  {lastFailure.recommended_action}
                </span>
              }
            />
          )}
        </>
      )}
      {/* M32: needs-attention warning when ≥ 3 consecutive scheduled failures */}
      {integration.needs_attention && (
        <div
          style={{
            marginTop: "10px",
            padding: "8px 12px",
            background: "rgba(245,166,35,0.08)",
            border: "1px solid rgba(245,166,35,0.3)",
            borderRadius: "5px",
            fontSize: "12px",
            color: "#f5a623",
          }}
        >
          ⚠ {integration.consecutive_failure_count} consecutive scheduled syncs have failed.{" "}
          {lastFailure?.recommended_action
            ? lastFailure.recommended_action
            : "Check the sync history for details."}
        </div>
      )}
    </Panel>
  );
}

// ── Provider overview ─────────────────────────────────────────────────────────

function ProviderOverview({
  integration,
  resources,
}: {
  integration: Integration;
  resources: ResourceListItem[];
}) {
  const resource = resources[0] ?? null;

  if (integration.provider === "cloudflare") {
    return (
      <Panel title="Cloudflare overview">
        <MetaRow
          label="Zone ID"
          value={
            <code style={{ fontSize: "11px", color: "#8b90a0", fontFamily: "monospace" }}>
              {resource?.provider_resource_id ?? "—"}
            </code>
          }
        />
        <MetaRow
          label="Resource type"
          value={
            <span style={{ color: "#8b90a0" }}>
              {formatResourceType(resource?.provider_resource_type ?? "cloudflare_dns_zone")}
            </span>
          }
        />
        <MetaRow
          label="Last snapshot"
          value={
            resource?.last_snapshot_at ? (
              <span title={formatAbsoluteTime(resource.last_snapshot_at)}>
                {formatRelativeTime(resource.last_snapshot_at)}
              </span>
            ) : (
              <span style={{ color: "#565b6e" }}>Never</span>
            )
          }
        />
        <MetaRow label="Monitoring" value={<span style={{ color: "#8b90a0" }}>All DNS record types (A, AAAA, CNAME, MX, TXT, …)</span>} />
      </Panel>
    );
  }

  if (integration.provider === "github") {
    const slug = resource?.provider_resource_id ?? "—";
    return (
      <Panel title="GitHub overview">
        <MetaRow
          label="Repository"
          value={
            <code style={{ fontSize: "11px", color: "#8b90a0", fontFamily: "monospace" }}>
              {slug}
            </code>
          }
        />
        {integration.connection_method && (
          <MetaRow
            label="Auth method"
            value={
              <span style={{ color: "#8b90a0" }}>
                {integration.connection_method === "github_app"
                  ? "GitHub App (recommended)"
                  : "Personal Access Token"}
              </span>
            }
          />
        )}
        <MetaRow
          label="Last snapshot"
          value={
            resource?.last_snapshot_at ? (
              <span title={formatAbsoluteTime(resource.last_snapshot_at)}>
                {formatRelativeTime(resource.last_snapshot_at)}
              </span>
            ) : (
              <span style={{ color: "#565b6e" }}>Never</span>
            )
          }
        />
        <div style={{ marginTop: "8px" }}>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              marginBottom: "6px",
            }}
          >
            Monitored categories
          </p>
          <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {GITHUB_MONITORED_CATEGORIES.map((cat) => (
              <li
                key={cat}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  padding: "2px 0",
                  paddingLeft: "12px",
                  position: "relative",
                }}
              >
                <span
                  style={{
                    position: "absolute",
                    left: 0,
                    color: "#3a3d4a",
                  }}
                >
                  ·
                </span>
                {cat}
              </li>
            ))}
          </ul>
        </div>
      </Panel>
    );
  }

  if (integration.provider === "vercel") {
    const projectId = resource?.provider_resource_id ?? "—";
    return (
      <Panel title="Vercel overview">
        <MetaRow
          label="Project ID"
          value={
            <code style={{ fontSize: "11px", color: "#8b90a0", fontFamily: "monospace" }}>
              {projectId}
            </code>
          }
        />
        <MetaRow
          label="Last snapshot"
          value={
            resource?.last_snapshot_at ? (
              <span title={formatAbsoluteTime(resource.last_snapshot_at)}>
                {formatRelativeTime(resource.last_snapshot_at)}
              </span>
            ) : (
              <span style={{ color: "#565b6e" }}>Never</span>
            )
          }
        />
        <div style={{ marginTop: "8px" }}>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              marginBottom: "6px",
            }}
          >
            Monitored categories
          </p>
          <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {VERCEL_MONITORED_CATEGORIES.map((cat) => (
              <li
                key={cat}
                style={{
                  fontSize: "12px",
                  color: "#8b90a0",
                  padding: "2px 0",
                  paddingLeft: "12px",
                  position: "relative",
                }}
              >
                <span style={{ position: "absolute", left: 0, color: "#3a3d4a" }}>·</span>
                {cat}
              </li>
            ))}
          </ul>
        </div>
      </Panel>
    );
  }

  return (
    <Panel title="Provider overview">
      <p style={{ fontSize: "12px", color: "#565b6e", margin: 0 }}>
        Provider: <strong style={{ color: "#8b90a0" }}>{integration.provider}</strong>
      </p>
    </Panel>
  );
}

// ── Main page content ─────────────────────────────────────────────────────────

type ModalType = "rename" | "delete" | "reconnect" | null;

export default function IntegrationDetailPage() {
  const params = useParams();
  const router = useRouter();
  const integrationId = params.id as string;

  const [integration, setIntegration] = useState<Integration | null>(null);
  const [syncRuns, setSyncRuns] = useState<SyncRun[]>([]);
  const [syncRunsTotal, setSyncRunsTotal] = useState(0);
  const [resources, setResources] = useState<ResourceListItem[]>([]);
  const [recentChanges, setRecentChanges] = useState<ChangeListItem[]>([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [activeModal, setActiveModal] = useState<ModalType>(null);
  const [pauseInProgress, setPauseInProgress] = useState(false);

  // Sync Now state
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<string | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);
  const mountedRef = useRef(true);

  const { getToken, isLoaded } = useAuth();

  // ── Data fetching ──────────────────────────────────────────────────────────

  // Fetch integration + sync-runs + recent changes (polled every 30s)
  const fetchDynamic = useCallback(async () => {
    try {
      const token = await getToken();
      const [integrationData, runsData, changesData] = await Promise.all([
        getIntegration(integrationId, token),
        getIntegrationSyncRuns(integrationId, { page: 1, page_size: 10 }, token),
        getChanges({ integration_id: integrationId, page_size: 10 }, token),
      ]);
      if (!mountedRef.current) return;
      setIntegration(integrationData);
      setSyncRuns(runsData.sync_runs);
      setSyncRunsTotal(runsData.total);
      setRecentChanges(changesData.items);
      setError(null);
    } catch (err) {
      if (!mountedRef.current) return;
      const msg = err instanceof Error ? err.message : "Failed to load integration.";
      // If 404, the integration was deleted — redirect to list.
      if (msg.includes("404") || msg === "HTTP 404") {
        router.replace("/integrations");
        return;
      }
      setError(msg);
    }
  }, [integrationId, getToken, router]);

  // Fetch resources (only on initial load + manual refresh)
  const fetchResources = useCallback(async () => {
    try {
      const token = await getToken();
      const data = await getResources({ integration_id: integrationId }, token);
      if (!mountedRef.current) return;
      setResources(data.items);
    } catch {
      // Non-fatal — page still works without resources
    }
  }, [integrationId, getToken]);

  const fetchAll = useCallback(async () => {
    await Promise.all([fetchDynamic(), fetchResources()]);
  }, [fetchDynamic, fetchResources]);

  // Initial load
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  useEffect(() => {
    if (!isLoaded) return;
    (async () => {
      setLoading(true);
      await fetchAll();
      setLoading(false);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoaded]);

  // Polling — only runs after initial load succeeds
  const { refresh, lastUpdatedAt } = usePollingRefresh({
    callback: fetchDynamic,
    intervalMs: POLL_INTERVAL_MS,
    enabled: !loading && error === null,
  });

  // ── Sync Now ───────────────────────────────────────────────────────────────

  async function handleSyncNow() {
    if (!integration || syncing) return;
    setSyncing(true);
    setSyncResult(null);
    setSyncError(null);

    let syncRunId: string;
    try {
      const token = await getToken();
      const run = await triggerSync(integrationId, token);
      syncRunId = run.id;
    } catch (err) {
      setSyncing(false);
      setSyncError(err instanceof Error ? err.message : "Failed to start sync.");
      return;
    }

    // Poll until done
    let polls = 0;
    function poll() {
      setTimeout(async () => {
        if (!mountedRef.current) return;
        polls++;
        try {
          const token = await getToken();
          const run = await getSyncStatus(syncRunId, token);
          if (run.status === "completed") {
            const changes = run.change_count ?? 0;
            const snaps = run.snapshot_count ?? 0;
            let msg: string;
            if (changes > 0) {
              msg = `Sync complete — ${changes} change${changes === 1 ? "" : "s"} detected.`;
            } else if (snaps > 0) {
              msg = "Baseline created. Changes appear from the second sync onwards.";
            } else {
              msg = "No changes since last sync — state is unchanged.";
            }
            if (mountedRef.current) {
              setSyncing(false);
              setSyncResult(msg);
              // Refresh data to pick up new sync run + updated status
              void fetchDynamic();
            }
            return;
          }
          if (run.status === "failed") {
            if (mountedRef.current) {
              setSyncing(false);
              setSyncError(
                run.error_message
                  ? `Sync failed: ${run.error_message}`
                  : "Sync failed. Check that the Celery worker is running."
              );
              void fetchDynamic();
            }
            return;
          }
          if (polls < SYNC_POLL_MAX && mountedRef.current) poll();
          else if (mountedRef.current) {
            setSyncing(false);
            setSyncError("Sync timed out.");
          }
        } catch (err) {
          if (mountedRef.current) {
            setSyncing(false);
            setSyncError(err instanceof Error ? err.message : "Lost connection.");
          }
        }
      }, SYNC_POLL_INTERVAL_MS);
    }
    poll();
  }

  // ── GitHub App re-install ──────────────────────────────────────────────────

  async function handleReinstallApp() {
    try {
      const token = await getToken();
      const { install_url, state } = await getGitHubAppInstallUrl(token);
      sessionStorage.setItem("github_app_oauth_state", state);
      window.location.href = install_url;
    } catch {
      // Non-fatal — stay on the page
    }
  }

  // ── Pause / resume ─────────────────────────────────────────────────────────

  async function handleTogglePause() {
    if (!integration) return;
    const newStatus = integration.status === "paused" ? "active" : "paused";
    setPauseInProgress(true);
    try {
      const token = await getToken();
      const updated = await patchIntegration(integration.id, { status: newStatus }, token);
      if (mountedRef.current) setIntegration(updated);
    } catch {
      // Non-fatal — leave UI unchanged
    } finally {
      setPauseInProgress(false);
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  if (loading) return <LoadingState />;
  if (error) {
    return (
      <div className="px-6 py-6">
        <ErrorState message={error} />
        <div className="flex justify-center mt-4">
          <button
            onClick={() => { setError(null); setLoading(true); void fetchAll().finally(() => setLoading(false)); }}
            style={{
              background: "transparent",
              border: "1px solid #4f80f7",
              color: "#4f80f7",
              borderRadius: "6px",
              padding: "6px 14px",
              fontSize: "13px",
              cursor: "pointer",
              fontFamily: "inherit",
            }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }
  if (!integration) return null;

  const isPaused = integration.status === "paused";
  const providerLabel =
    integration.provider === "cloudflare"
      ? "Cloudflare DNS"
      : integration.provider === "github"
      ? "GitHub repository"
      : integration.provider === "vercel"
      ? "Vercel project"
      : integration.provider;

  const failedRuns = syncRuns.filter((r) => r.status === "failed");

  return (
    <>
      {/* ── Modals ── */}
      {activeModal === "rename" && (
        <RenameIntegrationModal
          integration={integration}
          onClose={() => setActiveModal(null)}
          onSuccess={(updated) => {
            setIntegration(updated);
            setActiveModal(null);
          }}
        />
      )}
      {activeModal === "delete" && (
        <DeleteIntegrationModal
          integration={integration}
          onClose={() => setActiveModal(null)}
          onSuccess={() => {
            setActiveModal(null);
            router.replace("/integrations");
          }}
        />
      )}
      {activeModal === "reconnect" && (
        <ReconnectIntegrationModal
          integration={integration}
          onClose={() => setActiveModal(null)}
          onSuccess={(updated) => {
            setIntegration(updated);
            setActiveModal(null);
          }}
        />
      )}

      <PageHeader
        title={integration.display_name}
        description={`${providerLabel} · ${formatInterval(integration.sync_interval_minutes)} scheduled sync`}
      />

      <div className="px-6 pb-8">

        {/* ── Header bar: badges + actions ──────────────────────────────── */}
        <div
          className="flex flex-wrap items-center gap-3 mb-6 p-4"
          style={{ background: "#13151a", border: "1px solid #2a2d38", borderRadius: "6px" }}
        >
          {/* Provider + status */}
          <div className="flex items-center gap-2 flex-1">
            <span
              style={{
                fontSize: "11px",
                color: "#565b6e",
                background: "#1c1e26",
                border: "1px solid #2a2d38",
                borderRadius: "4px",
                padding: "2px 8px",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
              }}
            >
              {providerLabel}
            </span>
            <StatusBadge status={integration.status} />
            {integration.last_sync_status === "failed" && (
              <span
                title={integration.last_sync_error ?? "Last sync failed"}
                style={{ color: "#e84040", fontSize: "11px" }}
              >
                ● Sync error
              </span>
            )}
            {(integration.last_sync_status === "running" ||
              integration.last_sync_status === "pending") && (
              <span style={{ color: "#f5a623", fontSize: "11px" }}>● Syncing…</span>
            )}
          </div>

          {/* Last updated indicator */}
          {lastUpdatedAt && (
            <span
              style={{ fontSize: "11px", color: "#3a3d4a" }}
              title="Data is refreshed automatically every 30s"
            >
              Updated {formatElapsed(lastUpdatedAt)}
            </span>
          )}

          {/* Action buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => { void handleSyncNow(); }}
              disabled={syncing || isPaused || pauseInProgress}
              style={{
                padding: "6px 12px",
                borderRadius: "6px",
                border: "1px solid #3a3d4a",
                background: syncing ? "#1c1e26" : "#1e2030",
                color: syncing || isPaused ? "#565b6e" : "#b0b5c4",
                fontSize: "12px",
                cursor: syncing || isPaused || pauseInProgress ? "not-allowed" : "pointer",
                fontFamily: "inherit",
              }}
              title={isPaused ? "Resume the integration to sync" : undefined}
            >
              {syncing ? "Syncing…" : isPaused ? "Sync paused" : "Sync Now"}
            </button>

            <button
              onClick={() => setActiveModal("rename")}
              style={{ padding: "6px 10px", borderRadius: "6px", border: "1px solid #2a2d38", background: "transparent", color: "#8b90a0", fontSize: "12px", cursor: "pointer", fontFamily: "inherit" }}
            >
              Rename
            </button>

            <button
              onClick={() => { void handleTogglePause(); }}
              disabled={pauseInProgress}
              style={{ padding: "6px 10px", borderRadius: "6px", border: "1px solid #2a2d38", background: "transparent", color: "#8b90a0", fontSize: "12px", cursor: "pointer", fontFamily: "inherit" }}
            >
              {isPaused ? "Resume" : "Pause"}
            </button>

            {/* Credential update — "Re-install App" for GitHub App, "Update token" otherwise */}
            {integration.connection_method === "github_app" ? (
              <button
                onClick={() => { void handleReinstallApp(); }}
                style={{ padding: "6px 10px", borderRadius: "6px", border: "1px solid #2a2d38", background: "transparent", color: "#8b90a0", fontSize: "12px", cursor: "pointer", fontFamily: "inherit" }}
              >
                Re-install GitHub App
              </button>
            ) : (
              <button
                onClick={() => setActiveModal("reconnect")}
                style={{ padding: "6px 10px", borderRadius: "6px", border: "1px solid #2a2d38", background: "transparent", color: "#8b90a0", fontSize: "12px", cursor: "pointer", fontFamily: "inherit" }}
              >
                Update token
              </button>
            )}

            <button
              onClick={() => setActiveModal("delete")}
              style={{ padding: "6px 10px", borderRadius: "6px", border: "1px solid rgba(232,64,64,0.3)", background: "transparent", color: "#e84040", fontSize: "12px", cursor: "pointer", fontFamily: "inherit" }}
            >
              Delete
            </button>

            <button
              onClick={refresh}
              title="Refresh data now"
              style={{ padding: "6px 10px", borderRadius: "6px", border: "1px solid #2a2d38", background: "transparent", color: "#565b6e", fontSize: "12px", cursor: "pointer", fontFamily: "inherit" }}
            >
              ↻ Refresh
            </button>
          </div>
        </div>

        {/* Sync Now feedback */}
        {(syncResult || syncError) && (
          <div
            className="mb-4 px-4 py-2"
            style={{
              background: syncError ? "rgba(232,64,64,0.06)" : "rgba(60,207,126,0.06)",
              border: `1px solid ${syncError ? "rgba(232,64,64,0.2)" : "rgba(60,207,126,0.2)"}`,
              borderRadius: "6px",
              fontSize: "13px",
              color: syncError ? "#e84040" : "#3ccf7e",
            }}
          >
            {syncError ?? syncResult}
          </div>
        )}

        {/* ── Two-column layout (left: health + overview, right: history) ── */}
        <div
          className="gap-5"
          style={{
            display: "grid",
            gridTemplateColumns: "minmax(240px, 320px) 1fr",
            alignItems: "start",
          }}
        >
          {/* Left column */}
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <HealthPanel integration={integration} runs={syncRuns} />
            <ProviderOverview integration={integration} resources={resources} />
          </div>

          {/* Right column */}
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

            {/* Sync history */}
            <Panel
              title={`Sync history${syncRunsTotal > 0 ? ` · ${syncRunsTotal} total` : ""}`}
            >
              <SyncHistoryTable runs={syncRuns} total={syncRunsTotal} />
              {syncRunsTotal > 0 && (
                <div style={{ marginTop: "10px", textAlign: "right" }}>
                  <Link
                    href={`/integrations/${integrationId}/sync-runs`}
                    style={{ fontSize: "12px", color: "#4f80f7", textDecoration: "none" }}
                  >
                    View all sync runs →
                  </Link>
                </div>
              )}
            </Panel>

            {/* Recent changes */}
            <Panel title="Recent changes">
              {recentChanges.length > 0 && (
                <div style={{ marginBottom: "10px" }}>
                  <RecentChangesTable changes={recentChanges} />
                </div>
              )}
              {recentChanges.length === 0 && (
                <RecentChangesTable changes={[]} />
              )}
              {recentChanges.length >= 10 && (
                <div style={{ marginTop: "8px", textAlign: "right" }}>
                  <Link
                    href={`/timeline?integration_id=${integration.id}`}
                    style={{ fontSize: "11px", color: "#4f80f7", textDecoration: "none" }}
                  >
                    View all in timeline →
                  </Link>
                </div>
              )}
            </Panel>

            {/* Error history */}
            {failedRuns.length > 0 && (
              <Panel title="Recent sync errors">
                {failedRuns.map((r) => (
                  <div
                    key={r.id}
                    style={{
                      padding: "10px",
                      marginBottom: "6px",
                      background: "rgba(232,64,64,0.05)",
                      border: "1px solid rgba(232,64,64,0.15)",
                      borderRadius: "4px",
                    }}
                  >
                    <div className="flex items-center justify-between" style={{ marginBottom: "4px" }}>
                      <span style={{ fontSize: "12px", color: "#e84040" }}>Sync failed</span>
                      <span
                        style={{ fontSize: "11px", color: "#565b6e" }}
                        title={r.started_at ? formatAbsoluteTime(r.started_at) : ""}
                      >
                        {r.started_at ? formatRelativeTime(r.started_at) : "—"}
                      </span>
                    </div>
                    {r.error_message && (
                      <p style={{ fontSize: "12px", color: "#8b90a0", margin: 0, wordBreak: "break-word" }}>
                        {r.error_message}
                      </p>
                    )}
                  </div>
                ))}
              </Panel>
            )}

          </div>
        </div>

        {/* ── Back link ── */}
        <div style={{ marginTop: "24px" }}>
          <Link
            href="/integrations"
            style={{ fontSize: "12px", color: "#565b6e", textDecoration: "none" }}
          >
            ← Back to integrations
          </Link>
        </div>
      </div>
    </>
  );
}
