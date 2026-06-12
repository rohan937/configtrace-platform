"use client";

/**
 * Activity Events (M66.5).
 *
 * Evidence viewer for normalized GitHub audit activity (M66.2) — the control-
 * plane events that power Incident Signals.
 *
 * CLAIM DISCIPLINE: these are control-plane audit events / activity metadata.
 * This page must never state that a breach, attacker, compromise, or
 * unauthorized access has been confirmed.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type { SecurityActivityEvent, SecurityActivitySyncResponse } from "@/types";
import { getSecurityActivityEvents, syncSecurityActivity } from "@/lib/api";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { formatRelativeTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";

const EVENT_TYPE_OPTIONS = [
  "github.branch_protection.disabled",
  "github.branch_protection.updated",
  "github.branch_protection.created",
  "github.deploy_key.added",
  "github.deploy_key.removed",
  "github.webhook.created",
  "github.webhook.updated",
  "github.webhook.deleted",
  "github.collaborator.added",
  "github.collaborator.removed",
  "github.app.installed",
  "github.app.permissions_changed",
  "github.ruleset.changed",
  "github.secret_scanning_alert.created",
  "github.secret_scanning_alert.resolved",
];

const LIMIT_OPTIONS = [25, 50, 100];

export default function ActivityEventsPage() {
  const { getToken } = useAuth();
  const { isAdmin, roleLoaded } = useWorkspace();

  const [events, setEvents] = useState<SecurityActivityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [eventType, setEventType] = useState("");
  const [limit, setLimit] = useState(50);

  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<SecurityActivitySyncResponse | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const res = await getSecurityActivityEvents(
        { provider: "github", event_type: eventType || undefined, page_size: limit },
        token,
      );
      setEvents(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch {
      setError("Could not load activity events. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [getToken, eventType, limit]);

  useEffect(() => {
    void load();
  }, [load]);

  const onSync = useCallback(async () => {
    setSyncing(true);
    setSyncError(null);
    setSyncResult(null);
    try {
      const token = await getToken();
      const res = await syncSecurityActivity(token);
      setSyncResult(res);
      await load();
    } catch {
      setSyncError("Could not sync GitHub activity. Please try again.");
    } finally {
      setSyncing(false);
    }
  }, [getToken, load]);

  const metrics = useMemo(() => {
    const github = events.filter((e) => e.provider === "github").length;
    const types = new Set(events.map((e) => e.event_type)).size;
    const latest = events.reduce<string | null>((acc, e) => {
      const t = e.occurred_at ?? e.ingested_at;
      if (!t) return acc;
      if (!acc || Date.parse(t) > Date.parse(acc)) return t;
      return acc;
    }, null);
    return { github, types, latest };
  }, [events]);

  return (
    <div>
      <Hero />

      <SyncBar
        isAdmin={isAdmin}
        roleLoaded={roleLoaded}
        syncing={syncing}
        syncResult={syncResult}
        syncError={syncError}
        onSync={onSync}
      />

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
          gap: "14px",
          marginBottom: "24px",
        }}
      >
        <Metric label="Visible events" value={events.length} accent="#6b9cf8" />
        <Metric label="GitHub events" value={metrics.github} accent="#6b9cf8" />
        <Metric label="Event types" value={metrics.types} accent="#f5a623" />
        <Metric
          label="Latest activity"
          text={metrics.latest ? formatRelativeTime(metrics.latest) : "—"}
          accent="#3ccf7e"
        />
      </div>

      <div
        style={{
          display: "flex",
          gap: "10px",
          flexWrap: "wrap",
          alignItems: "center",
          marginBottom: "18px",
        }}
      >
        <span style={{ fontSize: "12px", color: "#565b6e" }}>
          Provider: <strong style={{ color: "#8b90a0" }}>GitHub</strong>
        </span>
        <Select label="Event type" value={eventType} onChange={setEventType} options={EVENT_TYPE_OPTIONS} />
        <label style={{ fontSize: "12px", color: "#8b90a0", display: "flex", alignItems: "center", gap: "6px" }}>
          Limit
          <select
            value={String(limit)}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="bg-surface1 border border-border"
            style={{ fontSize: "12px", color: "#c4c8d4", borderRadius: "6px", padding: "5px 8px" }}
          >
            {LIMIT_OPTIONS.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
      </div>

      {loading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState message={error} />
      ) : events.length === 0 ? (
        <EmptyState isAdmin={isAdmin} />
      ) : (
        <>
          <SectionLabel>
            {total} event{total === 1 ? "" : "s"}
          </SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {events.map((e) => (
              <EventRow key={e.id} event={e} />
            ))}
          </div>
        </>
      )}

      <p style={{ margin: "26px 0 0", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        These are control-plane audit events. They do not by themselves confirm
        breach, attacker presence, or unauthorized access. They are evidence for
        review and the basis for Incident Signals.
      </p>
    </div>
  );
}

// ── Hero ────────────────────────────────────────────────────────────────────

function Hero() {
  return (
    <>
      <PageHeader
        title="Activity Events"
        description="Normalized GitHub audit activity used as evidence for Incident Signals."
      />
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "20px" }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>GitHub beta</span>
          <span
            style={{
              fontSize: "9px",
              fontWeight: 700,
              letterSpacing: "0.05em",
              textTransform: "uppercase",
              color: "#6b9cf8",
              border: "1px solid rgba(107,156,248,0.4)",
              borderRadius: "5px",
              padding: "1px 6px",
            }}
          >
            Beta
          </span>
        </div>
        <p style={{ margin: 0, fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
          These are control-plane audit events. They do not by themselves confirm
          breach, attacker presence, or unauthorized access.
        </p>
      </div>
    </>
  );
}

// ── Sync bar ──────────────────────────────────────────────────────────────────

function SyncBar({
  isAdmin,
  roleLoaded,
  syncing,
  syncResult,
  syncError,
  onSync,
}: {
  isAdmin: boolean;
  roleLoaded: boolean;
  syncing: boolean;
  syncResult: SecurityActivitySyncResponse | null;
  syncError: string | null;
  onSync: () => void;
}) {
  return (
    <div
      className="bg-surface1 border border-border"
      style={{
        borderRadius: "12px",
        padding: "14px 16px",
        marginBottom: "20px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "12px",
        flexWrap: "wrap",
      }}
    >
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: "13px", fontWeight: 600, color: "#e8eaf0" }}>Sync GitHub activity</div>
        <div style={{ fontSize: "12px", color: "#8b90a0", marginTop: "2px" }}>
          Ingests recent GitHub audit-log activity into normalized events.
          {!isAdmin && roleLoaded && " Only workspace admins can sync activity."}
        </div>
        {syncResult && (
          <div
            style={{
              fontSize: "12px",
              color: syncResult.permission_limited ? "#f5a623" : "#3ccf7e",
              marginTop: "6px",
            }}
          >
            {syncResult.permission_limited
              ? "GitHub audit-log access is limited for this account/plan. "
              : ""}
            Seen {syncResult.events_seen} · inserted {syncResult.events_inserted} · skipped{" "}
            {syncResult.events_updated_or_skipped}.
            {syncResult.error_message ? ` (${syncResult.error_message})` : ""}
          </div>
        )}
        {syncError && (
          <div style={{ fontSize: "12px", color: "#e84040", marginTop: "6px" }}>{syncError}</div>
        )}
      </div>
      <button
        onClick={onSync}
        disabled={!isAdmin || syncing}
        title={!isAdmin ? "Only workspace admins can sync activity." : undefined}
        style={{
          fontSize: "13px",
          fontWeight: 500,
          color: isAdmin ? "#0b0d12" : "#565b6e",
          background: isAdmin ? "#6b9cf8" : "#1e2030",
          border: "none",
          padding: "8px 16px",
          borderRadius: "8px",
          cursor: !isAdmin || syncing ? "not-allowed" : "pointer",
          opacity: syncing ? 0.7 : 1,
          whiteSpace: "nowrap",
        }}
      >
        {syncing ? "Syncing…" : "Sync GitHub activity"}
      </button>
    </div>
  );
}

// ── Event row ─────────────────────────────────────────────────────────────────

function EventRow({ event }: { event: SecurityActivityEvent }) {
  const when = event.occurred_at ?? event.ingested_at;
  const resource =
    event.resource_id ?? (event.resource_type ? event.resource_type : null);
  return (
    <Link
      href={`/security/activity/${event.id}`}
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", textDecoration: "none", display: "block", padding: "14px 16px" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
        <span
          style={{
            fontSize: "12.5px",
            fontWeight: 600,
            color: "#e8eaf0",
            fontFamily: "monospace",
            flex: 1,
            minWidth: 0,
          }}
        >
          {event.event_type}
        </span>
        <span style={{ fontSize: "12px", color: "#6b9cf8" }}>View event →</span>
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          flexWrap: "wrap",
          marginTop: "8px",
          fontSize: "12px",
          color: "#8b90a0",
        }}
      >
        <span>{event.provider}</span>
        <span style={{ color: "#3a3d48" }}>·</span>
        <span>{event.source}</span>
        {event.actor_id && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <span>actor: {event.actor_id}</span>
          </>
        )}
        {resource && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <span>{resource}</span>
          </>
        )}
        {when && (
          <>
            <span style={{ color: "#3a3d48" }}>·</span>
            <span>{formatRelativeTime(when)}</span>
          </>
        )}
      </div>
    </Link>
  );
}

// ── Small helpers ─────────────────────────────────────────────────────────────

function Metric({
  label,
  value,
  text,
  accent,
}: {
  label: string;
  value?: number;
  text?: string;
  accent: string;
}) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px" }}>
      <div style={{ fontSize: "12px", color: "#8b90a0", fontWeight: 500 }}>{label}</div>
      <div
        style={{
          fontSize: text ? "16px" : "28px",
          fontWeight: 700,
          color: accent,
          marginTop: "8px",
          letterSpacing: "-0.02em",
        }}
      >
        {text ?? value ?? 0}
      </div>
    </div>
  );
}

function Select({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: string[];
}) {
  return (
    <label style={{ fontSize: "12px", color: "#8b90a0", display: "flex", alignItems: "center", gap: "6px" }}>
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="bg-surface1 border border-border"
        style={{ fontSize: "12px", color: "#c4c8d4", borderRadius: "6px", padding: "5px 8px" }}
      >
        <option value="">All</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function EmptyState({ isAdmin }: { isAdmin: boolean }) {
  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "32px 24px", textAlign: "center" }}
    >
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#e8eaf0" }}>No activity events yet.</div>
      <p style={{ margin: "8px auto 0", maxWidth: "470px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
        {isAdmin
          ? "Run GitHub activity sync above to ingest recent audit activity."
          : "An admin can run GitHub activity sync to ingest recent audit activity."}
      </p>
    </div>
  );
}
