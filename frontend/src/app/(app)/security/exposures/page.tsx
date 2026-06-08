"use client";

/**
 * Active Exposures (M60.5).
 *
 * The real Security Exposure queue, backed by the M60.3/M60.4 findings API
 * (GET /security/findings via getSecurityFindings). Drift Detection shows what
 * changed; this page shows what is still dangerous right now.
 *
 * No new tables, migrations, rules, or mutations — read-only consumption of the
 * existing findings API with inline expandable rows.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type {
  Integration,
  SecurityFinding,
  SecurityFindingSeverity,
  SecurityFindingStatus,
} from "@/types";
import { getSecurityFindings, getIntegrations } from "@/lib/api";
import { getProviderMeta } from "@/lib/providers";
import { formatRelativeTime, formatAbsoluteTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { ExposureRow, PreviewBanner, SectionLabel } from "@/components/security/previews";
import {
  SEVERITY_LABEL,
  SEVERITY_RANK,
  sevColor,
  SeverityBadge,
  FindingStatusBadge,
  EvidenceBlock,
  RemediationBlock,
} from "@/components/security/findingDisplay";

// ── Constants / helpers ─────────────────────────────────────────────────────

const PAGE_SIZE = 25;

type StatusFilter = "active" | "resolved" | "accepted_risk" | "all";

// Severity/status tokens, masking, and the Evidence/Remediation/badge
// renderers are shared with the Exposure Detail page (M60.6) — see
// components/security/findingDisplay.tsx.
const SEVERITY_OPTIONS: SecurityFindingSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

// ── Page ─────────────────────────────────────────────────────────────────────

export default function ActiveExposuresPage() {
  const { getToken } = useAuth();

  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [hasIntegrations, setHasIntegrations] = useState<boolean | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("active");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [providerFilter, setProviderFilter] = useState<string>("all");

  // Summary metrics (loaded independently of table filters, real API totals).
  const [metrics, setMetrics] = useState({
    active: 0,
    critical: 0,
    high: 0,
    recentlyOpened: 0,
    resolved: 0,
  });

  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleExpanded = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  // Load integrations once (drives the no-integrations empty state).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const token = await getToken();
        const res = await getIntegrations(token);
        if (!cancelled) setHasIntegrations((res.integrations ?? []).length > 0);
      } catch {
        if (!cancelled) setHasIntegrations(null); // unknown; don't block page
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [getToken]);

  // Load summary metrics from real API totals (independent of table filters).
  const loadMetrics = useCallback(async () => {
    try {
      const token = await getToken();
      const [activeRes, critRes, highRes, resolvedRes, recentRes] =
        await Promise.allSettled([
          getSecurityFindings({ status: "active", page_size: 1 }, token),
          getSecurityFindings({ status: "active", severity: "critical", page_size: 1 }, token),
          getSecurityFindings({ status: "active", severity: "high", page_size: 1 }, token),
          getSecurityFindings({ status: "resolved", page_size: 1 }, token),
          getSecurityFindings({ status: "active", page_size: 100 }, token),
        ]);

      const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
      const recentlyOpened =
        recentRes.status === "fulfilled"
          ? (recentRes.value.items ?? []).filter((f) => {
              const t = Date.parse(f.first_detected_at);
              return !Number.isNaN(t) && t >= sevenDaysAgo;
            }).length
          : 0;

      setMetrics({
        active: activeRes.status === "fulfilled" ? activeRes.value.total : 0,
        critical: critRes.status === "fulfilled" ? critRes.value.total : 0,
        high: highRes.status === "fulfilled" ? highRes.value.total : 0,
        resolved: resolvedRes.status === "fulfilled" ? resolvedRes.value.total : 0,
        recentlyOpened,
      });
    } catch {
      // Metrics are non-critical; leave at zeros.
    }
  }, [getToken]);

  useEffect(() => {
    void loadMetrics();
  }, [loadMetrics]);

  // Load the table for the current filters + page.
  const loadFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const params: Parameters<typeof getSecurityFindings>[0] = {
        page,
        page_size: PAGE_SIZE,
      };
      if (statusFilter !== "all") params.status = statusFilter;
      if (severityFilter !== "all") params.severity = severityFilter;
      if (providerFilter !== "all") params.provider = providerFilter;

      const res = await getSecurityFindings(params, token);
      setFindings(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch {
      setError("Could not load security findings. Please try again.");
      setFindings([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [getToken, page, statusFilter, severityFilter, providerFilter]);

  useEffect(() => {
    void loadFindings();
  }, [loadFindings]);

  // Reset to page 1 whenever a filter changes.
  const onFilterChange = useCallback(
    (apply: () => void) => {
      apply();
      setPage(1);
      setExpanded(new Set());
    },
    [],
  );

  // Client-side ordering within the loaded page: severity-first, then most
  // recently seen. Backend already orders by last_seen_at DESC; this layers the
  // requested severity priority on top as a stable refinement.
  const orderedFindings = useMemo(() => {
    return [...findings].sort((a, b) => {
      const ra = SEVERITY_RANK[a.severity] ?? 99;
      const rb = SEVERITY_RANK[b.severity] ?? 99;
      if (ra !== rb) return ra - rb;
      return Date.parse(b.last_seen_at) - Date.parse(a.last_seen_at);
    });
  }, [findings]);

  // Distinct providers for the filter dropdown (from connected integrations).
  const [providerOptions, setProviderOptions] = useState<string[]>([]);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const token = await getToken();
        const res = await getIntegrations(token);
        if (cancelled) return;
        const set = new Set<string>();
        for (const i of res.integrations ?? []) set.add(i.provider);
        setProviderOptions([...set].sort());
      } catch {
        /* leave empty */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [getToken]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <PageHeader
        title="Active Exposures"
        description="Current risky states that may expose production systems or weaken security controls."
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
        Security Exposure shows risky current states from connected provider
        configuration. Drift Detection shows what changed. Active Exposures shows
        what is still dangerous right now.
      </p>

      {/* Summary metrics */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
          gap: "14px",
          marginBottom: "24px",
        }}
      >
        <Metric label="Active exposures" value={metrics.active} accent="#f5632a" />
        <Metric label="Critical" value={metrics.critical} accent="#e84040" />
        <Metric label="High" value={metrics.high} accent="#f5632a" />
        <Metric label="Recently opened (7d)" value={metrics.recentlyOpened} accent="#6b9cf8" />
        <Metric label="Resolved" value={metrics.resolved} accent="#3ccf7e" />
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
            { value: "active", label: "Active" },
            { value: "accepted_risk", label: "Accepted risk" },
            { value: "resolved", label: "Resolved" },
            { value: "all", label: "All" },
          ]}
        />
        <FilterSelect
          label="Severity"
          value={severityFilter}
          onChange={(v) => onFilterChange(() => setSeverityFilter(v))}
          options={[
            { value: "all", label: "All severities" },
            ...SEVERITY_OPTIONS.map((s) => ({ value: s, label: SEVERITY_LABEL[s] })),
          ]}
        />
        <FilterSelect
          label="Provider"
          value={providerFilter}
          onChange={(v) => onFilterChange(() => setProviderFilter(v))}
          options={[
            { value: "all", label: "All providers" },
            ...providerOptions.map((p) => ({
              value: p,
              label: getProviderMeta(p).shortLabel,
            })),
          ]}
        />
        <button
          onClick={() => {
            void loadFindings();
            void loadMetrics();
          }}
          style={{
            marginLeft: "auto",
            fontSize: "12px",
            color: "#8b90a0",
            background: "transparent",
            border: "1px solid #2a2d38",
            borderRadius: "8px",
            padding: "7px 12px",
            cursor: "pointer",
          }}
        >
          Refresh
        </button>
      </div>

      {/* Body */}
      {loading ? (
        <LoadingState message="Loading security findings…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : orderedFindings.length === 0 ? (
        <EmptyState
          statusFilter={statusFilter}
          hasIntegrations={hasIntegrations}
        />
      ) : (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {orderedFindings.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                expanded={expanded.has(f.id)}
                onToggle={() => toggleExpanded(f.id)}
              />
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 ? (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "16px",
                marginTop: "22px",
              }}
            >
              <PagerButton
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                ← Previous
              </PagerButton>
              <span style={{ fontSize: "12px", color: "#565b6e" }}>
                Page {page} of {totalPages} · {total} total
              </span>
              <PagerButton
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next →
              </PagerButton>
            </div>
          ) : null}
        </>
      )}

      <p
        style={{
          marginTop: "26px",
          fontSize: "12px",
          color: "#565b6e",
          lineHeight: 1.6,
        }}
      >
        ConfigTrace reports security-relevant configuration exposure from provider
        settings. It does not detect breaches or monitor live traffic.
      </p>
    </div>
  );
}

// ── Subcomponents ────────────────────────────────────────────────────────────

function Metric({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent: string;
}) {
  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "16px 18px" }}
    >
      <div style={{ fontSize: "12px", color: "#8b90a0", fontWeight: 500 }}>
        {label}
      </div>
      <div
        style={{
          fontSize: "28px",
          fontWeight: 700,
          color: accent,
          marginTop: "8px",
          letterSpacing: "-0.02em",
        }}
      >
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

function FindingCard({
  finding,
  expanded,
  onToggle,
}: {
  finding: SecurityFinding;
  expanded: boolean;
  onToggle: () => void;
}) {
  const provider = getProviderMeta(finding.provider);
  const c = sevColor(finding.severity);
  const resourceLabel = finding.resource_id ? finding.resource_id : "—";

  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", overflow: "hidden", display: "flex" }}
    >
      <div style={{ width: "3px", background: c, flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        {/* Header row (clickable to expand) */}
        <button
          onClick={onToggle}
          aria-expanded={expanded}
          style={{
            width: "100%",
            textAlign: "left",
            background: "transparent",
            border: "none",
            cursor: "pointer",
            padding: "14px 16px",
            display: "flex",
            flexDirection: "column",
            gap: "8px",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "12px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
              <SeverityBadge severity={finding.severity} />
              <span
                style={{
                  fontSize: "14px",
                  fontWeight: 600,
                  color: "#e8eaf0",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {finding.title}
              </span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
              <FindingStatusBadge status={finding.status} />
              <span style={{ fontSize: "16px", color: "#565b6e" }}>
                {expanded ? "▾" : "▸"}
              </span>
            </div>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "8px",
              fontSize: "12px",
              color: "#8b90a0",
            }}
          >
            <span
              style={{
                color: provider.color,
                fontWeight: 600,
              }}
            >
              {provider.shortLabel}
            </span>
            <span style={{ color: "#3a3d4a" }}>·</span>
            <span
              style={{ fontFamily: "monospace", fontSize: "11px", color: "#565b6e" }}
              title={finding.finding_key}
            >
              {finding.finding_key}
            </span>
            <span style={{ color: "#3a3d4a" }}>·</span>
            <span title={formatAbsoluteTime(finding.last_seen_at)}>
              last seen {formatRelativeTime(finding.last_seen_at)}
            </span>
          </div>

          {finding.description ? (
            <div style={{ fontSize: "12.5px", color: "#8b90a0", lineHeight: 1.5 }}>
              {finding.description}
            </div>
          ) : null}
        </button>

        {/* Expanded detail */}
        {expanded ? (
          <div
            style={{
              borderTop: "1px solid #2a2d38",
              padding: "16px",
              display: "flex",
              flexDirection: "column",
              gap: "18px",
            }}
          >
            <Link
              href={`/security/exposures/${finding.id}`}
              style={{
                alignSelf: "flex-start",
                fontSize: "13px",
                fontWeight: 600,
                color: "#0e0f11",
                background: "#4f80f7",
                borderRadius: "8px",
                padding: "7px 14px",
                textDecoration: "none",
              }}
            >
              View full detail →
            </Link>

            <DetailGrid finding={finding} resourceLabel={resourceLabel} />

            {finding.remediation ? (
              <RemediationBlock remediation={finding.remediation} />
            ) : null}

            {finding.evidence ? <EvidenceBlock evidence={finding.evidence} /> : null}

            {finding.linked_change_id ? (
              <div>
                <SectionLabel>Linked change</SectionLabel>
                <Link
                  href={`/changes/${finding.linked_change_id}`}
                  style={{
                    fontSize: "13px",
                    color: "#6b9cf8",
                    textDecoration: "none",
                    fontFamily: "monospace",
                  }}
                >
                  View drift change {finding.linked_change_id.slice(0, 8)}… →
                </Link>
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function DetailGrid({
  finding,
  resourceLabel,
}: {
  finding: SecurityFinding;
  resourceLabel: string;
}) {
  const rows: { label: string; value: string; mono?: boolean }[] = [
    { label: "Resource", value: resourceLabel, mono: true },
    { label: "First detected", value: formatAbsoluteTime(finding.first_detected_at) },
    { label: "Last seen", value: formatAbsoluteTime(finding.last_seen_at) },
  ];
  if (finding.status === "resolved" && finding.resolved_at) {
    rows.push({ label: "Resolved at", value: formatAbsoluteTime(finding.resolved_at) });
  }
  if (finding.status === "accepted_risk" && finding.accepted_until) {
    rows.push({ label: "Accepted until", value: formatAbsoluteTime(finding.accepted_until) });
  }
  return (
    <div>
      <SectionLabel>Why it matters</SectionLabel>
      <div style={{ fontSize: "13px", color: "#c4c8d4", lineHeight: 1.6, marginBottom: "14px" }}>
        {finding.description || "No description available."}
      </div>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "10px",
        }}
      >
        {rows.map((r) => (
          <div key={r.label}>
            <div style={{ fontSize: "11px", color: "#565b6e", marginBottom: "2px" }}>
              {r.label}
            </div>
            <div
              style={{
                fontSize: "12.5px",
                color: "#c4c8d4",
                fontFamily: r.mono ? "monospace" : undefined,
                wordBreak: "break-all",
              }}
            >
              {r.value}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EmptyState({
  statusFilter,
  hasIntegrations,
}: {
  statusFilter: StatusFilter;
  hasIntegrations: boolean | null;
}) {
  // No integrations connected at all → educational empty state with clearly
  // labelled EXAMPLES (never presented as real findings).
  if (hasIntegrations === false) {
    return (
      <div>
        <div
          className="bg-surface1 border border-border"
          style={{
            borderRadius: "12px",
            padding: "28px",
            textAlign: "center",
            marginBottom: "24px",
          }}
        >
          <div style={{ fontSize: "16px", fontWeight: 600, color: "#e8eaf0" }}>
            No providers connected yet
          </div>
          <div style={{ fontSize: "13px", color: "#8b90a0", marginTop: "8px", lineHeight: 1.6 }}>
            Connect providers and run a sync. ConfigTrace will surface risky
            current states here.
          </div>
          <Link
            href="/integrations"
            style={{
              display: "inline-block",
              marginTop: "16px",
              fontSize: "13px",
              color: "#0e0f11",
              background: "#4f80f7",
              borderRadius: "8px",
              padding: "8px 16px",
              textDecoration: "none",
              fontWeight: 600,
            }}
          >
            Connect a provider
          </Link>
        </div>

        <PreviewBanner>
          The examples below illustrate the kinds of exposures ConfigTrace will
          detect once providers are connected. They are not real findings.
        </PreviewBanner>
        <SectionLabel>Example exposures</SectionLabel>
        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          <ExposureRow
            severity="critical"
            title="GitHub webhook uses HTTP"
            provider="GitHub"
            detail="Webhook delivery URL is plain http:// — payloads may be sent in cleartext"
          />
          <ExposureRow
            severity="critical"
            title="AWS security group exposes admin port"
            provider="AWS"
            detail="Port 22 open to 0.0.0.0/0 — administrative access reachable from the internet"
          />
          <ExposureRow
            severity="high"
            title="Supabase RLS disabled"
            provider="Supabase"
            detail="Row Level Security is off on a public table — rows may be broadly readable"
          />
        </div>
      </div>
    );
  }

  // Integrations exist (or unknown) but no findings for the current filter.
  const headline =
    statusFilter === "active"
      ? "No active exposures found."
      : statusFilter === "resolved"
        ? "No resolved exposures."
        : "No exposures match these filters.";

  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "40px 28px", textAlign: "center" }}
    >
      <div style={{ fontSize: "16px", fontWeight: 600, color: "#e8eaf0" }}>
        {headline}
      </div>
      <div style={{ fontSize: "13px", color: "#8b90a0", marginTop: "8px", lineHeight: 1.6 }}>
        Connect providers and run a sync. ConfigTrace will surface risky current
        states here.
      </div>
    </div>
  );
}
