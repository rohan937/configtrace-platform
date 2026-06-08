"use client";

/**
 * Exposure Timeline (M60.8).
 *
 * Turns persisted security findings (GET /security/findings) into a lifecycle
 * view: when exposures opened, persisted, resolved, and reappeared. Read-only;
 * all events are derived from existing finding fields (see lib/securityTimeline).
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type { SecurityFinding, SecurityFindingSeverity } from "@/types";
import { getSecurityFindings, getIntegrations } from "@/lib/api";
import { getProviderMeta } from "@/lib/providers";
import { formatAbsoluteTime, formatRelativeTime } from "@/lib/utils";
import {
  buildTimelineEvents,
  deriveTimelineMetrics,
  EVENT_LABEL,
  EventTypeFilter,
  filterEventsByType,
  groupEventsByDay,
  TimelineEvent,
  TimelineEventType,
} from "@/lib/securityTimeline";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import {
  FindingStatusBadge,
  SeverityBadge,
  sevColor,
} from "@/components/security/findingDisplay";

// How many findings to pull into the timeline window (API caps page_size at 100).
const FINDING_WINDOW = 100;
// How many derived events to show per page.
const EVENTS_PER_PAGE = 50;

type StatusFilter = "all" | "active" | "resolved";

const SEVERITY_OPTIONS: SecurityFindingSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const EVENT_DOT: Record<TimelineEventType, string> = {
  opened: "#f5632a",
  reopened: "#f5a623",
  still_active: "#6b9cf8",
  resolved: "#3ccf7e",
  accepted_risk: "#f5a623",
};

// ── Page ─────────────────────────────────────────────────────────────────────

export default function ExposureTimelinePage() {
  const { getToken } = useAuth();

  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hasIntegrations, setHasIntegrations] = useState<boolean | null>(null);

  // Filters (status/severity/provider applied server-side; event type client-side).
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [providerFilter, setProviderFilter] = useState<string>("all");
  const [eventTypeFilter, setEventTypeFilter] = useState<EventTypeFilter>("all");
  const [providerOptions, setProviderOptions] = useState<string[]>([]);
  const [page, setPage] = useState(1);

  // Connected-integrations probe (drives the no-data empty state).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const token = await getToken();
        const res = await getIntegrations(token);
        if (cancelled) return;
        const list = res.integrations ?? [];
        setHasIntegrations(list.length > 0);
        setProviderOptions([...new Set(list.map((i) => i.provider))].sort());
      } catch {
        if (!cancelled) setHasIntegrations(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [getToken]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const params: Parameters<typeof getSecurityFindings>[0] = {
        page: 1,
        page_size: FINDING_WINDOW,
      };
      if (statusFilter !== "all") params.status = statusFilter;
      if (severityFilter !== "all") params.severity = severityFilter;
      if (providerFilter !== "all") params.provider = providerFilter;
      const res = await getSecurityFindings(params, token);
      setFindings(res.items ?? []);
    } catch {
      setError("Could not load the exposure timeline. Please try again.");
      setFindings([]);
    } finally {
      setLoading(false);
    }
  }, [getToken, statusFilter, severityFilter, providerFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const metrics = useMemo(() => deriveTimelineMetrics(findings), [findings]);

  const allEvents = useMemo(
    () => filterEventsByType(buildTimelineEvents(findings), eventTypeFilter),
    [findings, eventTypeFilter],
  );

  const totalPages = Math.max(1, Math.ceil(allEvents.length / EVENTS_PER_PAGE));
  const pageEvents = useMemo(
    () => allEvents.slice((page - 1) * EVENTS_PER_PAGE, page * EVENTS_PER_PAGE),
    [allEvents, page],
  );
  const dayGroups = useMemo(() => groupEventsByDay(pageEvents), [pageEvents]);

  const onFilterChange = useCallback((apply: () => void) => {
    apply();
    setPage(1);
  }, []);

  return (
    <div>
      <PageHeader
        title="Exposure Timeline"
        description="Track when security exposures open, persist, resolve, and reappear."
      />

      <p
        style={{
          margin: "-12px 0 24px",
          fontSize: "13px",
          color: "#8b90a0",
          lineHeight: 1.6,
          maxWidth: "760px",
        }}
      >
        Exposure Timeline turns current security findings into a lifecycle view. It
        helps answer how long a risky state was open and what changed around it.
      </p>

      {/* Metrics */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
          gap: "14px",
          marginBottom: "24px",
        }}
      >
        <Metric label="Opened this week" value={metrics.openedThisWeek} accent="#f5632a" />
        <Metric label="Active now" value={metrics.activeNow} accent="#e84040" />
        <Metric label="Resolved this week" value={metrics.resolvedThisWeek} accent="#3ccf7e" />
        <Metric label="Longest open" value={metrics.longestOpen} accent="#6b9cf8" />
        <Metric label="Critical / high" value={metrics.criticalHigh} accent="#f5a623" />
      </div>

      {/* Filters */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "12px",
          alignItems: "center",
          marginBottom: "18px",
        }}
      >
        <FilterSelect
          label="Status"
          value={statusFilter}
          onChange={(v) => onFilterChange(() => setStatusFilter(v as StatusFilter))}
          options={[
            { value: "all", label: "All" },
            { value: "active", label: "Active" },
            { value: "resolved", label: "Resolved" },
          ]}
        />
        <FilterSelect
          label="Severity"
          value={severityFilter}
          onChange={(v) => onFilterChange(() => setSeverityFilter(v))}
          options={[
            { value: "all", label: "All severities" },
            ...SEVERITY_OPTIONS.map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) })),
          ]}
        />
        <FilterSelect
          label="Provider"
          value={providerFilter}
          onChange={(v) => onFilterChange(() => setProviderFilter(v))}
          options={[
            { value: "all", label: "All providers" },
            ...providerOptions.map((p) => ({ value: p, label: getProviderMeta(p).shortLabel })),
          ]}
        />
        <FilterSelect
          label="Event"
          value={eventTypeFilter}
          onChange={(v) => onFilterChange(() => setEventTypeFilter(v as EventTypeFilter))}
          options={[
            { value: "all", label: "All events" },
            { value: "opened", label: "Opened" },
            { value: "still_active", label: "Still active" },
            { value: "resolved", label: "Resolved" },
            { value: "accepted_risk", label: "Risk accepted" },
          ]}
        />
      </div>

      {/* Body */}
      {loading ? (
        <LoadingState message="Loading exposure timeline…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : allEvents.length === 0 ? (
        <EmptyState hasIntegrations={hasIntegrations} hasFindings={findings.length > 0} />
      ) : (
        <>
          {dayGroups.map((group) => (
            <div key={group.day} style={{ marginBottom: "26px" }}>
              <div
                style={{
                  fontSize: "12px",
                  fontWeight: 600,
                  letterSpacing: "0.04em",
                  textTransform: "uppercase",
                  color: "#565b6e",
                  marginBottom: "10px",
                }}
              >
                {group.label}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {group.events.map((e) => (
                  <TimelineRow key={e.key} event={e} />
                ))}
              </div>
            </div>
          ))}

          {totalPages > 1 ? (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "16px",
                marginTop: "12px",
              }}
            >
              <PagerButton disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
                ← Newer
              </PagerButton>
              <span style={{ fontSize: "12px", color: "#565b6e" }}>
                Page {page} of {totalPages} · {allEvents.length} events
              </span>
              <PagerButton
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Older →
              </PagerButton>
            </div>
          ) : null}

          {findings.length >= FINDING_WINDOW ? (
            <p style={{ marginTop: "16px", fontSize: "11.5px", color: "#565b6e", textAlign: "center" }}>
              Showing the {FINDING_WINDOW} most recent findings. Narrow filters to see older exposures.
            </p>
          ) : null}
        </>
      )}
    </div>
  );
}

// ── Row ──────────────────────────────────────────────────────────────────────

function TimelineRow({ event }: { event: TimelineEvent }) {
  const f = event.finding;
  const provider = getProviderMeta(f.provider);
  const dot = EVENT_DOT[event.type];
  const sev = sevColor(f.severity);

  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", overflow: "hidden", display: "flex" }}
    >
      <div style={{ width: "3px", background: sev, flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0, padding: "13px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0, flexWrap: "wrap" }}>
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "7px",
                fontSize: "12px",
                fontWeight: 600,
                color: dot,
              }}
            >
              <span style={{ width: "8px", height: "8px", borderRadius: "5px", background: dot }} />
              {EVENT_LABEL[event.type]}
            </span>
            <SeverityBadge severity={f.severity} />
            <span style={{ fontSize: "12px", color: provider.color, fontWeight: 600 }}>
              {provider.shortLabel}
            </span>
          </div>
          <span
            style={{ fontSize: "11px", color: "#565b6e", whiteSpace: "nowrap" }}
            title={formatAbsoluteTime(event.at)}
          >
            {formatRelativeTime(event.at)}
          </span>
        </div>

        <div style={{ fontSize: "14px", fontWeight: 600, color: "#e8eaf0", marginTop: "8px" }}>
          {f.title}
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "8px",
            marginTop: "6px",
            fontSize: "12px",
            color: "#8b90a0",
          }}
        >
          <FindingStatusBadge status={f.status} />
          {f.resource_id ? (
            <>
              <span style={{ color: "#3a3d4a" }}>·</span>
              <span style={{ fontFamily: "monospace", fontSize: "11px", color: "#565b6e" }}>
                {f.resource_id}
              </span>
            </>
          ) : null}
        </div>

        {f.description ? (
          <div style={{ fontSize: "12.5px", color: "#8b90a0", lineHeight: 1.5, marginTop: "6px" }}>
            {f.description}
          </div>
        ) : null}

        <div style={{ display: "flex", gap: "14px", marginTop: "10px" }}>
          <Link
            href={`/security/exposures/${f.id}`}
            style={{ fontSize: "12px", color: "#6b9cf8", textDecoration: "none", fontWeight: 600 }}
          >
            View exposure →
          </Link>
          {f.linked_change_id ? (
            <Link
              href={`/changes/${f.linked_change_id}`}
              style={{ fontSize: "12px", color: "#8b90a0", textDecoration: "none" }}
            >
              View linked drift →
            </Link>
          ) : null}
        </div>
      </div>
    </div>
  );
}

// ── Building blocks ───────────────────────────────────────────────────────────

function Metric({ label, value, accent }: { label: string; value: number | string; accent: string }) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px" }}>
      <div style={{ fontSize: "12px", color: "#8b90a0", fontWeight: 500 }}>{label}</div>
      <div style={{ fontSize: "26px", fontWeight: 700, color: accent, marginTop: "8px", letterSpacing: "-0.02em" }}>
        {value}
      </div>
    </div>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
      <span style={{ fontSize: "12px", color: "#565b6e" }}>{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{
          fontSize: "13px",
          color: "#e8eaf0",
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "8px",
          padding: "7px 10px",
          cursor: "pointer",
        }}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function PagerButton({
  disabled,
  onClick,
  children,
}: {
  disabled: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      disabled={disabled}
      onClick={onClick}
      style={{
        fontSize: "13px",
        color: disabled ? "#3a3d4a" : "#c4c8d4",
        background: "transparent",
        border: "1px solid #2a2d38",
        borderRadius: "8px",
        padding: "7px 14px",
        cursor: disabled ? "default" : "pointer",
      }}
    >
      {children}
    </button>
  );
}

function EmptyState({
  hasIntegrations,
  hasFindings,
}: {
  hasIntegrations: boolean | null;
  hasFindings: boolean;
}) {
  // Findings exist but filters hid them all.
  const filtered = hasFindings;
  const headline = filtered
    ? "No timeline events match these filters."
    : "No exposure timeline yet.";
  const subtext = filtered
    ? "Try adjusting status, severity, provider, or event type."
    : hasIntegrations === false
      ? "Connect providers and run a sync. When ConfigTrace detects risky current states, their lifecycle will appear here."
      : "Connect providers and run a sync. When ConfigTrace detects risky current states, their lifecycle will appear here.";

  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "40px 28px", textAlign: "center" }}
    >
      <div style={{ fontSize: "16px", fontWeight: 600, color: "#e8eaf0" }}>{headline}</div>
      <div style={{ fontSize: "13px", color: "#8b90a0", marginTop: "8px", lineHeight: 1.6 }}>
        {subtext}
      </div>
    </div>
  );
}
