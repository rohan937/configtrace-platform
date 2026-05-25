"use client";

import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { getWorkspaceAuditLogs } from "@/lib/api";
import type { WorkspaceAuditLog } from "@/types";
import PageHeader from "@/components/common/PageHeader";

const PAGE_SIZE = 50;

// ── Event label map ───────────────────────────────────────────────────────────

const EVENT_LABELS: Record<string, string> = {
  workspace_created:             "Workspace created",
  workspace_renamed:             "Workspace renamed",
  member_invited:                "Member invited",
  invite_revoked:                "Invite revoked",
  invite_accepted:               "Invite accepted",
  member_removed:                "Member removed",
  member_role_changed:           "Member role changed",
  integration_created:           "Integration connected",
  integration_deleted:           "Integration removed",
  integration_updated:           "Integration updated",
  manual_sync_triggered:         "Sync triggered",
  billing_checkout_started:      "Billing checkout started",
  billing_portal_opened:         "Billing portal opened",
  plan_changed:                  "Plan changed",
  subscription_status_changed:   "Subscription status changed",
  trial_started:                 "Trial started",
  trial_ended:                   "Trial ended",
};

function eventLabel(eventType: string): string {
  return EVENT_LABELS[eventType] ?? eventType.replace(/_/g, " ");
}

// ── Event category ────────────────────────────────────────────────────────────

type EventCategory = "all" | "members" | "billing" | "integrations" | "workspace";

const CATEGORY_PREFIXES: Record<EventCategory, (e: string) => boolean> = {
  all: () => true,
  members:      (e) => ["member_invited","invite_revoked","invite_accepted","member_removed","member_role_changed"].includes(e),
  billing:      (e) => e.includes("billing") || e.includes("plan") || e.includes("subscription") || e.includes("trial"),
  integrations: (e) => e.includes("integration") || e === "manual_sync_triggered",
  workspace:    (e) => e.includes("workspace"),
};

function getEventCategory(eventType: string): EventCategory {
  if (CATEGORY_PREFIXES.members(eventType))      return "members";
  if (CATEGORY_PREFIXES.billing(eventType))      return "billing";
  if (CATEGORY_PREFIXES.integrations(eventType)) return "integrations";
  if (CATEGORY_PREFIXES.workspace(eventType))    return "workspace";
  return "all";
}

// ── Visual event chip styling ─────────────────────────────────────────────────

function eventChipStyle(eventType: string): { background: string; color: string } {
  if (
    eventType.includes("removed") ||
    eventType.includes("deleted") ||
    eventType.includes("revoked")
  ) {
    return { background: "rgba(248,113,113,0.10)", color: "#f87171" };
  }
  if (
    eventType.includes("created") ||
    eventType.includes("invited") ||
    eventType.includes("accepted") ||
    eventType.includes("connected")
  ) {
    return { background: "rgba(74,222,128,0.10)", color: "#4ade80" };
  }
  if (
    eventType.includes("billing") ||
    eventType.includes("plan") ||
    eventType.includes("subscription") ||
    eventType.includes("checkout")
  ) {
    return { background: "rgba(251,191,36,0.10)", color: "#fbbf24" };
  }
  if (
    eventType.includes("renamed") ||
    eventType.includes("changed") ||
    eventType.includes("triggered") ||
    eventType.includes("updated")
  ) {
    return { background: "rgba(96,165,250,0.10)", color: "#60a5fa" };
  }
  return { background: "rgba(139,144,160,0.10)", color: "#8b90a0" };
}

// ── Date/actor helpers ────────────────────────────────────────────────────────

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return iso;
  }
}

function actorLabel(log: WorkspaceAuditLog): string {
  if (log.actor_email)        return log.actor_email;
  if (log.actor_display_name) return log.actor_display_name;
  if (log.actor_user_id)      return log.actor_user_id.slice(0, 8) + "…";
  return "System";
}

// ── Filter pills ──────────────────────────────────────────────────────────────

const CATEGORY_LABELS: { id: EventCategory; label: string }[] = [
  { id: "all",          label: "All" },
  { id: "members",      label: "Members" },
  { id: "billing",      label: "Billing" },
  { id: "integrations", label: "Integrations" },
  { id: "workspace",    label: "Workspace" },
];

function FilterPills({
  active,
  onSelect,
}: {
  active: EventCategory;
  onSelect: (c: EventCategory) => void;
}) {
  return (
    <div
      role="group"
      aria-label="Filter audit events by category"
      style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "16px" }}
    >
      {CATEGORY_LABELS.map(({ id, label }) => {
        const isActive = active === id;
        return (
          <button
            key={id}
            onClick={() => onSelect(id)}
            aria-pressed={isActive}
            style={{
              background: isActive ? "#4f80f7" : "transparent",
              color: isActive ? "#ffffff" : "#8b90a0",
              border: `1px solid ${isActive ? "#4f80f7" : "#2a2d38"}`,
              borderRadius: "4px",
              padding: "3px 10px",
              fontSize: "11px",
              cursor: "pointer",
              fontFamily: "inherit",
              fontWeight: isActive ? 500 : 400,
            }}
          >
            {label}
          </button>
        );
      })}
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AuditLogPage() {
  const { getToken } = useAuth();
  const { selectedWorkspace } = useWorkspace();

  const [logs, setLogs]         = useState<WorkspaceAuditLog[]>([]);
  const [total, setTotal]       = useState(0);
  const [page, setPage]         = useState(0);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState<string | null>(null);
  const [category, setCategory] = useState<EventCategory>("all");

  useEffect(() => {
    if (!selectedWorkspace) return;
    setLoading(true);
    setError(null);
    getToken()
      .then((token) =>
        getWorkspaceAuditLogs(selectedWorkspace.id, token, {
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
        }),
      )
      .then((data) => {
        setLogs(data.logs);
        setTotal(data.total);
      })
      .catch((err) =>
        setError(err instanceof Error ? err.message : "Failed to load audit log."),
      )
      .finally(() => setLoading(false));
  }, [selectedWorkspace, page]);

  // Client-side category filter (within the loaded page).
  const filteredLogs = useMemo(() => {
    if (category === "all") return logs;
    const predicate = CATEGORY_PREFIXES[category];
    return logs.filter((log) => predicate(log.event_type));
  }, [logs, category]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <>
      <PageHeader
        title="Audit Log"
        description={selectedWorkspace ? `Events for ${selectedWorkspace.name}.` : "Workspace event history."}
      />

      <div className="px-6 pb-8" style={{ maxWidth: "860px" }}>
        {/* Error */}
        {error && (
          <div
            role="alert"
            style={{
              background: "#2a1a1a",
              border: "1px solid #7a2a2a",
              borderRadius: "6px",
              padding: "10px 14px",
              color: "#f87171",
              fontSize: "13px",
              marginBottom: "16px",
            }}
          >
            {error}
          </div>
        )}

        {/* Category filters */}
        <FilterPills active={category} onSelect={(c) => { setCategory(c); setPage(0); }} />

        {/* Loading */}
        {loading && (
          <div style={{ color: "#565b6e", fontSize: "13px", padding: "20px 0" }}>
            Loading…
          </div>
        )}

        {/* Log table */}
        {!loading && (
          <section
            aria-label="Audit log entries"
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "8px",
              overflow: "hidden",
            }}
          >
            {filteredLogs.length === 0 ? (
              <div
                style={{
                  padding: "40px 20px",
                  textAlign: "center",
                  color: "#565b6e",
                  fontSize: "13px",
                }}
              >
                {category === "all"
                  ? "No audit events recorded yet."
                  : `No ${category} events on this page.`}
              </div>
            ) : (
              <table
                style={{ width: "100%", borderCollapse: "collapse" }}
                aria-label="Audit events"
              >
                <thead>
                  <tr
                    style={{
                      borderBottom: "1px solid #2a2d38",
                      background: "#0f1117",
                    }}
                  >
                    {["When", "Event", "Actor", "Target"].map((h) => (
                      <th
                        key={h}
                        scope="col"
                        style={{
                          textAlign: "left",
                          padding: "10px 14px",
                          fontSize: "10px",
                          fontWeight: 500,
                          color: "#565b6e",
                          textTransform: "uppercase",
                          letterSpacing: "0.06em",
                        }}
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.map((log) => {
                    const chip = eventChipStyle(log.event_type);
                    return (
                      <tr
                        key={log.id}
                        style={{ borderBottom: "1px solid #1e2130" }}
                      >
                        {/* When */}
                        <td
                          style={{
                            padding: "10px 14px",
                            fontSize: "12px",
                            color: "#8b90a0",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {formatDate(log.created_at)}
                        </td>

                        {/* Event */}
                        <td style={{ padding: "10px 14px" }}>
                          <span
                            style={{
                              display: "inline-block",
                              background: chip.background,
                              color: chip.color,
                              borderRadius: "4px",
                              padding: "2px 8px",
                              fontSize: "11px",
                              fontWeight: 500,
                              whiteSpace: "nowrap",
                            }}
                          >
                            {eventLabel(log.event_type)}
                          </span>
                        </td>

                        {/* Actor */}
                        <td
                          style={{
                            padding: "10px 14px",
                            fontSize: "12px",
                            color: "#c4c8d4",
                            maxWidth: "200px",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {actorLabel(log)}
                        </td>

                        {/* Target */}
                        <td
                          style={{
                            padding: "10px 14px",
                            fontSize: "12px",
                            color: "#8b90a0",
                            maxWidth: "200px",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {log.target_display_name ?? log.target_id ?? "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </section>
        )}

        {/* Pagination */}
        {!loading && totalPages > 1 && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "12px",
              marginTop: "16px",
            }}
          >
            <button
              disabled={page === 0}
              onClick={() => setPage((p) => p - 1)}
              aria-label="Previous page"
              style={{
                background: "none",
                border: "1px solid #2a2d38",
                borderRadius: "5px",
                padding: "5px 12px",
                fontSize: "12px",
                color: page === 0 ? "#3a3d4a" : "#8b90a0",
                cursor: page === 0 ? "not-allowed" : "pointer",
                fontFamily: "inherit",
              }}
            >
              ← Previous
            </button>
            <span style={{ fontSize: "12px", color: "#565b6e" }}>
              Page {page + 1} of {totalPages}
            </span>
            <button
              disabled={page + 1 >= totalPages}
              onClick={() => setPage((p) => p + 1)}
              aria-label="Next page"
              style={{
                background: "none",
                border: "1px solid #2a2d38",
                borderRadius: "5px",
                padding: "5px 12px",
                fontSize: "12px",
                color: page + 1 >= totalPages ? "#3a3d4a" : "#8b90a0",
                cursor: page + 1 >= totalPages ? "not-allowed" : "pointer",
                fontFamily: "inherit",
              }}
            >
              Next →
            </button>
          </div>
        )}

        {/* Total count */}
        {!loading && total > 0 && (
          <p
            style={{
              textAlign: "center",
              fontSize: "11px",
              color: "#565b6e",
              marginTop: "8px",
            }}
          >
            {total} event{total !== 1 ? "s" : ""} total
            {category !== "all" && filteredLogs.length !== logs.length && (
              <> · {filteredLogs.length} matching on this page</>
            )}
          </p>
        )}
      </div>
    </>
  );
}
