"use client";

/**
 * Affected Assets (M61.4).
 *
 * Groups security findings (GET /security/findings) by the asset/resource they
 * may affect, so users can see which systems currently carry configuration
 * exposure. Frontend-only: no new tables, migrations, rules, or mutations —
 * grouping is derived in lib/securityAssets.ts.
 *
 * Careful wording throughout: findings "may affect" an asset; we never claim a
 * breach, compromise, or attack path.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type {
  SecurityFinding,
  SecurityFindingSeverity,
} from "@/types";
import { getSecurityFindings, getIntegrations } from "@/lib/api";
import { getProviderMeta } from "@/lib/providers";
import { formatAbsoluteTime, formatRelativeTime } from "@/lib/utils";
import {
  groupFindingsByAsset,
  assetTypeOptions,
  type AffectedAsset,
} from "@/lib/securityAssets";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import {
  SEVERITY_LABEL,
  SEVERITY_RANK,
  sevColor,
  SeverityBadge,
  FindingStatusBadge,
} from "@/components/security/findingDisplay";

const FETCH_SIZE = 100;

type StatusFilter = "active" | "accepted_risk" | "snoozed" | "resolved" | "all";

const SEVERITY_OPTIONS: SecurityFindingSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

function statusMatches(status: string, filter: StatusFilter): boolean {
  return filter === "all" || status === filter;
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function AffectedAssetsPage() {
  const { getToken } = useAuth();

  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hasIntegrations, setHasIntegrations] = useState<boolean | null>(null);

  const [statusFilter, setStatusFilter] = useState<StatusFilter>("active");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [providerFilter, setProviderFilter] = useState<string>("all");
  const [assetTypeFilter, setAssetTypeFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const toggle = useCallback((key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  // Load integrations (drives the no-integrations empty state).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const token = await getToken();
        const res = await getIntegrations(token);
        if (!cancelled) setHasIntegrations((res.integrations ?? []).length > 0);
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
      // Fetch a broad batch across all statuses so per-asset breakdowns are
      // accurate; filtering happens client-side.
      const res = await getSecurityFindings({ page_size: FETCH_SIZE }, token);
      setFindings(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch {
      setError("Could not load affected assets. Please try again.");
      setFindings([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [getToken]);

  useEffect(() => {
    void load();
  }, [load]);

  // Group all loaded findings into assets (full per-asset posture).
  const allAssets = useMemo(() => groupFindingsByAsset(findings), [findings]);

  // Provider + asset-type dropdown options derived from the data.
  const providerOptions = useMemo(
    () => [...new Set(allAssets.map((a) => a.provider))].sort(),
    [allAssets],
  );
  const typeOptions = useMemo(() => assetTypeOptions(allAssets), [allAssets]);

  // Summary cards are based on ACTIVE exposure — stable regardless of UI filters.
  const summary = useMemo(() => {
    const activeAssets = allAssets.filter((a) => a.active_count > 0);
    const providers = new Set(activeAssets.map((a) => a.provider));
    let critical = 0;
    let high = 0;
    let activeExposures = 0;
    for (const a of activeAssets) {
      // Highest severity among this asset's ACTIVE findings.
      let rank = 99;
      for (const f of a.findings) {
        if (f.status === "active") {
          const r = SEVERITY_RANK[f.severity] ?? 99;
          if (r < rank) rank = r;
          activeExposures += 1;
        }
      }
      if (rank === (SEVERITY_RANK["critical"] ?? 0)) critical += 1;
      else if (rank === (SEVERITY_RANK["high"] ?? 1)) high += 1;
    }
    return {
      affected: activeAssets.length,
      critical,
      high,
      activeExposures,
      providers: providers.size,
    };
  }, [allAssets]);

  // Apply filters to produce the visible asset list.
  const q = search.trim().toLowerCase();
  const visibleAssets = useMemo(() => {
    return allAssets.filter((a) => {
      if (providerFilter !== "all" && a.provider !== providerFilter) return false;
      if (assetTypeFilter !== "all" && a.asset_type !== assetTypeFilter) return false;

      // The asset must have at least one finding matching status + severity.
      const matchingFindings = a.findings.filter(
        (f) =>
          statusMatches(f.status, statusFilter) &&
          (severityFilter === "all" || f.severity === severityFilter),
      );
      if (matchingFindings.length === 0) return false;

      if (q) {
        const hay = [
          a.asset_label,
          a.asset_type,
          a.provider,
          getProviderMeta(a.provider).label,
          ...a.findings.map((f) => f.title),
        ]
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [allAssets, providerFilter, assetTypeFilter, statusFilter, severityFilter, q]);

  // Findings shown when an asset is expanded (respect status + severity).
  const findingsForAsset = useCallback(
    (a: AffectedAsset) =>
      a.findings.filter(
        (f) =>
          statusMatches(f.status, statusFilter) &&
          (severityFilter === "all" || f.severity === severityFilter),
      ),
    [statusFilter, severityFilter],
  );

  const truncated = total > findings.length;

  return (
    <div>
      <PageHeader
        title="Affected Assets"
        description="Group active exposures by the systems, resources, and provider assets they may affect."
      />

      <p style={{ margin: "-12px 0 24px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6, maxWidth: "780px" }}>
        Affected Assets helps you understand which repositories, domains, webhooks,
        security groups, buckets, tables, rulesets, and projects currently carry
        security exposure.
      </p>

      {/* Summary cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
          gap: "14px",
          marginBottom: "24px",
        }}
      >
        <Metric label="Affected assets" value={summary.affected} accent="#f5632a" />
        <Metric label="Critical assets" value={summary.critical} accent="#e84040" />
        <Metric label="High-risk assets" value={summary.high} accent="#f5632a" />
        <Metric label="Active exposures" value={summary.activeExposures} accent="#6b9cf8" />
        <Metric label="Providers affected" value={summary.providers} accent="#3ccf7e" />
      </div>

      {/* Filters */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", alignItems: "center", marginBottom: "18px" }}>
        <FilterSelect
          label="Status"
          value={statusFilter}
          onChange={(v) => { setStatusFilter(v as StatusFilter); setExpanded(new Set()); }}
          options={[
            { value: "active", label: "Active" },
            { value: "accepted_risk", label: "Accepted risk" },
            { value: "snoozed", label: "Snoozed" },
            { value: "resolved", label: "Resolved" },
            { value: "all", label: "All" },
          ]}
        />
        <FilterSelect
          label="Severity"
          value={severityFilter}
          onChange={(v) => { setSeverityFilter(v); setExpanded(new Set()); }}
          options={[
            { value: "all", label: "All severities" },
            ...SEVERITY_OPTIONS.map((s) => ({ value: s, label: SEVERITY_LABEL[s] })),
          ]}
        />
        <FilterSelect
          label="Provider"
          value={providerFilter}
          onChange={(v) => { setProviderFilter(v); setExpanded(new Set()); }}
          options={[
            { value: "all", label: "All providers" },
            ...providerOptions.map((p) => ({ value: p, label: getProviderMeta(p).shortLabel })),
          ]}
        />
        <FilterSelect
          label="Asset type"
          value={assetTypeFilter}
          onChange={(v) => { setAssetTypeFilter(v); setExpanded(new Set()); }}
          options={[
            { value: "all", label: "All asset types" },
            ...typeOptions.map((t) => ({ value: t, label: t })),
          ]}
        />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search asset, provider, or finding…"
          style={{
            fontSize: "13px", color: "#e8eaf0", background: "#13151a",
            border: "1px solid #2a2d38", borderRadius: "8px", padding: "7px 10px",
            minWidth: "220px", flex: "1 1 220px", maxWidth: "320px",
          }}
        />
        <button
          onClick={() => void load()}
          style={{
            marginLeft: "auto", fontSize: "12px", color: "#8b90a0",
            background: "transparent", border: "1px solid #2a2d38",
            borderRadius: "8px", padding: "7px 12px", cursor: "pointer",
          }}
        >
          Refresh
        </button>
      </div>

      {/* Body */}
      {loading ? (
        <LoadingState message="Loading affected assets…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : allAssets.length === 0 ? (
        <EmptyNoAssets hasIntegrations={hasIntegrations} />
      ) : visibleAssets.length === 0 ? (
        <EmptyFiltered />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {visibleAssets.map((a) => (
            <AssetCard
              key={a.asset_key}
              asset={a}
              visibleFindings={findingsForAsset(a)}
              expanded={expanded.has(a.asset_key)}
              onToggle={() => toggle(a.asset_key)}
            />
          ))}
        </div>
      )}

      {truncated && !loading && !error ? (
        <p style={{ marginTop: "18px", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
          Showing the {findings.length} most recent findings of {total}. Use the
          status, severity, or provider filters to narrow the set.
        </p>
      ) : null}

      <p style={{ marginTop: "26px", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        Assets are grouped from provider configuration findings and may affect the
        listed systems. ConfigTrace reports configuration exposure; it does not
        detect breaches or monitor live traffic.
      </p>
    </div>
  );
}

// ── Subcomponents ────────────────────────────────────────────────────────────

function Metric({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px" }}>
      <div style={{ fontSize: "12px", color: "#8b90a0", fontWeight: 500 }}>{label}</div>
      <div style={{ fontSize: "28px", fontWeight: 700, color: accent, marginTop: "8px", letterSpacing: "-0.02em" }}>
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
          fontSize: "13px", color: "#e8eaf0", background: "#13151a",
          border: "1px solid #2a2d38", borderRadius: "8px", padding: "7px 10px",
          cursor: "pointer",
        }}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </label>
  );
}

function StatusChip({ label, count, color }: { label: string; count: number; color: string }) {
  if (count <= 0) return null;
  return (
    <span style={{ fontSize: "11px", fontWeight: 600, color, background: `${color}1f`, borderRadius: "6px", padding: "2px 8px" }}>
      {count} {label}
    </span>
  );
}

function AssetCard({
  asset,
  visibleFindings,
  expanded,
  onToggle,
}: {
  asset: AffectedAsset;
  visibleFindings: SecurityFinding[];
  expanded: boolean;
  onToggle: () => void;
}) {
  const provider = getProviderMeta(asset.provider);
  const c = sevColor(asset.highest_severity);
  const top = visibleFindings.slice(0, 3);

  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", overflow: "hidden", display: "flex" }}>
      <div style={{ width: "3px", background: c, flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <button
          onClick={onToggle}
          aria-expanded={expanded}
          style={{
            width: "100%", textAlign: "left", background: "transparent", border: "none",
            cursor: "pointer", padding: "14px 16px", display: "flex", flexDirection: "column", gap: "10px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
              <SeverityBadge severity={asset.highest_severity} />
              <span style={{ fontSize: "14px", fontWeight: 600, color: "#e8eaf0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {asset.asset_label}
              </span>
              <span style={{ fontSize: "11px", color: "#8b90a0", border: "1px solid #2a2d38", borderRadius: "6px", padding: "2px 7px", whiteSpace: "nowrap" }}>
                {asset.asset_type}
              </span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
              <span style={{ fontSize: "12px", fontWeight: 600, color: provider.color }}>{provider.shortLabel}</span>
              <span style={{ fontSize: "12px", color: "#8b90a0" }}>
                {asset.exposure_count} {asset.exposure_count === 1 ? "finding" : "findings"}
              </span>
              <span style={{ fontSize: "16px", color: "#565b6e" }}>{expanded ? "▾" : "▸"}</span>
            </div>
          </div>

          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", alignItems: "center" }}>
            <StatusChip label="active" count={asset.active_count} color="#f5632a" />
            <StatusChip label="accepted risk" count={asset.accepted_count} color="#f5a623" />
            <StatusChip label="snoozed" count={asset.snoozed_count} color="#8b90a0" />
            <StatusChip label="resolved" count={asset.resolved_count} color="#3ccf7e" />
          </div>

          <div style={{ display: "flex", flexWrap: "wrap", gap: "14px", fontSize: "12px", color: "#565b6e" }}>
            {asset.first_detected_at ? <span>First detected {formatAbsoluteTime(asset.first_detected_at)}</span> : null}
            {asset.last_seen_at ? <span>Last seen {formatRelativeTime(asset.last_seen_at)}</span> : null}
          </div>

          {!expanded && top.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "4px", marginTop: "2px" }}>
              {top.map((f) => (
                <div key={f.id} style={{ display: "flex", alignItems: "center", gap: "8px", minWidth: 0 }}>
                  <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: sevColor(f.severity), flexShrink: 0 }} />
                  <span style={{ fontSize: "12.5px", color: "#8b90a0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {f.title}
                  </span>
                </div>
              ))}
            </div>
          ) : null}
        </button>

        {expanded ? (
          <div style={{ borderTop: "1px solid #1d1f27", padding: "12px 16px", display: "flex", flexDirection: "column", gap: "8px" }}>
            {visibleFindings.map((f) => (
              <Link
                key={f.id}
                href={`/security/exposures/${f.id}`}
                style={{
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                  gap: "12px", textDecoration: "none", padding: "8px 10px",
                  borderRadius: "8px", border: "1px solid #1d1f27",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
                  <SeverityBadge severity={f.severity} />
                  <span style={{ fontSize: "13px", color: "#c4c8d4", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {f.title}
                  </span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
                  <FindingStatusBadge status={f.status} />
                  <span style={{ fontSize: "11px", color: "#565b6e", whiteSpace: "nowrap" }}>
                    {formatRelativeTime(f.last_seen_at)}
                  </span>
                  <span style={{ fontSize: "12px", color: "#6b9cf8", whiteSpace: "nowrap" }}>View →</span>
                </div>
              </Link>
            ))}
            <div style={{ marginTop: "2px" }}>
              <span style={{ fontSize: "12px", color: "#565b6e" }}>
                {asset.exposure_count} associated{" "}
                {asset.exposure_count === 1 ? "finding" : "findings"} on this asset.
              </span>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

function EmptyNoAssets({ hasIntegrations }: { hasIntegrations: boolean | null }) {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "40px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#c4c8d4" }}>No affected assets yet.</div>
      <p style={{ fontSize: "13px", color: "#8b90a0", marginTop: "8px", lineHeight: 1.6 }}>
        {hasIntegrations === false
          ? "Connect a provider and run a sync. Assets with security exposure will appear here."
          : "Connect providers and run a sync. Assets with security exposure will appear here."}
      </p>
    </div>
  );
}

function EmptyFiltered() {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "40px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#c4c8d4" }}>No assets match these filters.</div>
      <p style={{ fontSize: "13px", color: "#8b90a0", marginTop: "8px", lineHeight: 1.6 }}>
        Try adjusting status, severity, provider, asset type, or search.
      </p>
    </div>
  );
}
