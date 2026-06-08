"use client";

/**
 * Incident Review (M61.5).
 *
 * A READ-ONLY investigation workspace. It does NOT detect incidents or breaches.
 * It correlates security exposure findings, drift changes, and affected assets
 * that overlap a user-selected time window so teams can reason about what
 * security-relevant configuration changed around a suspected incident.
 *
 * Frontend-only: composes GET /security/findings + GET /changes with the
 * existing securityTimeline / securityAssets helpers. No backend changes, no AI.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type {
  ChangeListItem,
  SecurityFinding,
  SecurityFindingSeverity,
} from "@/types";
import { getSecurityFindings, getChanges, getIntegrations } from "@/lib/api";
import { trackSecurityBetaEvent } from "@/lib/securityBetaEvents";
import { getProviderMeta } from "@/lib/providers";
import { formatAbsoluteTime, formatRelativeTime } from "@/lib/utils";
import {
  type TimeWindow,
  type IncidentEvent,
  findingInWindow,
  exposureEvents,
  driftEvents,
  mergeIncidentEvents,
  buildSummary,
  assetsInWindow,
  buildChecklist,
  toLocalInput,
  fromLocalInput,
  PRESETS,
  severityRank,
} from "@/lib/securityIncidentReview";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";
import {
  SEVERITY_LABEL,
  sevColor,
  SeverityBadge,
  FindingStatusBadge,
} from "@/components/security/findingDisplay";

const FETCH_SIZE = 100;
const SEVERITY_OPTIONS: SecurityFindingSeverity[] = ["critical", "high", "medium", "low", "info"];
const CHANGE_RISK_LEVELS = new Set(["critical", "high", "medium", "low"]);

function defaultStart(): string {
  return toLocalInput(new Date(Date.now() - 24 * 60 * 60 * 1000));
}
function defaultEnd(): string {
  return toLocalInput(new Date());
}

export default function IncidentReviewPage() {
  const { getToken } = useAuth();

  const [startInput, setStartInput] = useState<string>(defaultStart);
  const [endInput, setEndInput] = useState<string>(defaultEnd);
  const [providerFilter, setProviderFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [changes, setChanges] = useState<ChangeListItem[]>([]);
  const [providerByIntegration, setProviderByIntegration] = useState<Record<string, string>>({});
  const [providerOptions, setProviderOptions] = useState<string[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const startMs = fromLocalInput(startInput);
  const endMs = fromLocalInput(endInput);
  const windowValid = startMs !== null && endMs !== null && startMs < endMs;
  const window: TimeWindow = useMemo(
    () => ({ start: startMs ?? 0, end: endMs ?? 0 }),
    [startMs, endMs],
  );

  // Load integrations once (provider map + provider dropdown).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const token = await getToken();
        const res = await getIntegrations(token);
        if (cancelled) return;
        const map: Record<string, string> = {};
        const set = new Set<string>();
        for (const i of res.integrations ?? []) {
          map[i.id] = i.provider;
          set.add(i.provider);
        }
        setProviderByIntegration(map);
        setProviderOptions([...set].sort());
      } catch {
        /* leave empty */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [getToken]);

  const load = useCallback(async () => {
    if (!windowValid) {
      setError("Choose a valid time window (start must be before end).");
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const startISO = new Date(window.start).toISOString();
      const endISO = new Date(window.end).toISOString();

      const findingParams: Parameters<typeof getSecurityFindings>[0] = { page_size: FETCH_SIZE };
      if (providerFilter !== "all") findingParams.provider = providerFilter;
      if (severityFilter !== "all") findingParams.severity = severityFilter;

      const changeParams: Parameters<typeof getChanges>[0] = {
        since: startISO,
        until: endISO,
        page_size: FETCH_SIZE,
      };
      if (providerFilter !== "all") changeParams.provider = providerFilter;
      if (CHANGE_RISK_LEVELS.has(severityFilter)) changeParams.risk_level = severityFilter;

      const [fRes, cRes] = await Promise.allSettled([
        getSecurityFindings(findingParams, token),
        getChanges(changeParams, token),
      ]);

      if (fRes.status === "fulfilled") {
        setFindings(fRes.value.items ?? []);
        setFindingsTotal(fRes.value.total ?? 0);
      } else {
        setFindings([]);
        setFindingsTotal(0);
      }
      // Drift changes are best-effort; a failure here should not break the page.
      setChanges(cRes.status === "fulfilled" ? (cRes.value.items ?? []) : []);
    } catch {
      setError("Could not load incident review data. Please try again.");
      setFindings([]);
      setChanges([]);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [getToken, window.start, window.end, providerFilter, severityFilter, windowValid]);

  useEffect(() => {
    void load();
  }, [load]);

  // ── Client-side composition ──────────────────────────────────────────────
  const q = search.trim().toLowerCase();

  const windowFindings = useMemo(() => {
    return findings
      .filter((f) => findingInWindow(f, window))
      .filter((f) => severityFilter === "all" || f.severity === severityFilter)
      .filter((f) => {
        if (!q) return true;
        return `${f.title} ${f.provider} ${f.finding_key} ${f.resource_id ?? ""}`
          .toLowerCase()
          .includes(q);
      })
      .sort((a, b) => {
        const r = severityRank(a.severity) - severityRank(b.severity);
        if (r !== 0) return r;
        return Date.parse(b.last_seen_at) - Date.parse(a.last_seen_at);
      });
  }, [findings, window, severityFilter, q]);

  const windowChanges = useMemo(() => {
    return changes.filter((c) => {
      if (q) {
        const prov = providerByIntegration[c.integration_id] ?? "";
        const hay = `${c.risk_reason ?? ""} ${c.record_identifier} ${prov} ${c.field_path ?? ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [changes, q, providerByIntegration]);

  const drift = useMemo(
    () => driftEvents(windowChanges, providerByIntegration, window),
    [windowChanges, providerByIntegration, window],
  );
  const exposures = useMemo(() => exposureEvents(windowFindings, window), [windowFindings, window]);
  const timeline = useMemo(() => mergeIncidentEvents(exposures, drift), [exposures, drift]);
  const assets = useMemo(() => assetsInWindow(windowFindings), [windowFindings]);
  const summary = useMemo(
    () => buildSummary(windowFindings, drift.length, assets, window),
    [windowFindings, drift.length, assets, window],
  );
  const checklist = useMemo(
    () => buildChecklist({ windowFindings, driftCount: drift.length, assets, window }),
    [windowFindings, drift.length, assets, window],
  );

  const nothingLoaded = windowFindings.length === 0 && drift.length === 0;
  const filtersActive = providerFilter !== "all" || severityFilter !== "all" || q.length > 0;

  function applyPreset(hours: number) {
    const now = new Date();
    setStartInput(toLocalInput(new Date(now.getTime() - hours * 60 * 60 * 1000)));
    setEndInput(toLocalInput(now));
  }

  return (
    <div>
      <PageHeader
        title="Incident Review"
        description="Investigate security-relevant configuration activity around a time window."
      />

      <p style={{ margin: "-12px 0 24px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6, maxWidth: "800px" }}>
        Incident Review helps connect exposure findings, drift events, and affected
        assets so teams can understand what changed around a suspected incident.
        It is an investigation workspace for configuration drift and security
        exposures — not breach detection.
      </p>

      {/* 1. Review controls */}
      <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "22px" }}>
        <SectionLabel>Review window</SectionLabel>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", margin: "10px 0 14px" }}>
          {PRESETS.map((p) => (
            <button
              key={p.hours}
              type="button"
              onClick={() => applyPreset(p.hours)}
              style={{
                fontSize: "12px", fontWeight: 600, color: "#8b90a0", background: "none",
                border: "1px solid #2a2d38", borderRadius: "6px", padding: "6px 11px", cursor: "pointer",
              }}
            >
              {p.label}
            </button>
          ))}
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", alignItems: "center" }}>
          <FieldLabel label="Start">
            <input type="datetime-local" value={startInput} onChange={(e) => setStartInput(e.target.value)} style={inputStyle} />
          </FieldLabel>
          <FieldLabel label="End">
            <input type="datetime-local" value={endInput} onChange={(e) => setEndInput(e.target.value)} style={inputStyle} />
          </FieldLabel>
          <FilterSelect
            label="Provider"
            value={providerFilter}
            onChange={setProviderFilter}
            options={[
              { value: "all", label: "All providers" },
              ...providerOptions.map((p) => ({ value: p, label: getProviderMeta(p).shortLabel })),
            ]}
          />
          <FilterSelect
            label="Severity"
            value={severityFilter}
            onChange={setSeverityFilter}
            options={[
              { value: "all", label: "All severities" },
              ...SEVERITY_OPTIONS.map((s) => ({ value: s, label: SEVERITY_LABEL[s] })),
            ]}
          />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search title, resource, provider…"
            style={{ ...inputStyle, minWidth: "200px", flex: "1 1 200px", maxWidth: "300px" }}
          />
          <button
            type="button"
            onClick={() => {
              trackSecurityBetaEvent(
                "security_incident_review_run",
                { action: "refresh", provider: providerFilter, severity: severityFilter },
                { getToken, pagePath: "/security/incident-review" },
              );
              void load();
            }}
            style={{
              marginLeft: "auto", fontSize: "12px", color: "#8b90a0", background: "transparent",
              border: "1px solid #2a2d38", borderRadius: "8px", padding: "7px 12px", cursor: "pointer",
            }}
          >
            Refresh
          </button>
        </div>
        {!windowValid ? (
          <p style={{ fontSize: "12px", color: "#e07a5f", margin: "10px 0 0" }}>
            Start time must be before end time.
          </p>
        ) : null}
      </div>

      {/* 2. Summary cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
          gap: "14px",
          marginBottom: "24px",
        }}
      >
        <Metric label="Exposures opened" value={summary.openedInWindow} accent="#f5632a" />
        <Metric label="Critical / high" value={summary.criticalHighInWindow} accent="#e84040" />
        <Metric label="Resolved in window" value={summary.resolvedInWindow} accent="#3ccf7e" />
        <Metric label="Drift events" value={summary.driftInWindow} accent="#6b9cf8" />
        <Metric label="Affected assets" value={summary.affectedAssets} accent="#f5a623" />
      </div>

      {loading ? (
        <LoadingState message="Loading incident review…" />
      ) : error ? (
        <ErrorState message={error} />
      ) : nothingLoaded ? (
        filtersActive ? <EmptyFiltered /> : <EmptyNoActivity />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "26px" }}>
          {/* 3. Investigation timeline */}
          <Section title="Configuration activity around this window" count={timeline.length}>
            {timeline.length === 0 ? (
              <Muted>No timeline events in this window.</Muted>
            ) : (
              <div style={{ display: "flex", flexDirection: "column" }}>
                {timeline.map((e, i) => (
                  <TimelineRow key={e.key} event={e} first={i === 0} />
                ))}
              </div>
            )}
          </Section>

          {/* 4. Findings in window */}
          <Section title="Findings in window" count={windowFindings.length}>
            {windowFindings.length === 0 ? (
              <Muted>No exposure findings overlap this window.</Muted>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {windowFindings.map((f) => (
                  <FindingRow key={f.id} finding={f} />
                ))}
              </div>
            )}
          </Section>

          {/* 5. Drift events in window */}
          <Section title="Drift events in window" count={drift.length}>
            {drift.length === 0 ? (
              <Muted>No security-relevant drift changes in this window.</Muted>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {drift.map((e) => (
                  <DriftRow key={e.key} event={e} />
                ))}
              </div>
            )}
          </Section>

          {/* 6. Affected assets in window */}
          <Section title="Affected assets in window" count={assets.length}>
            {assets.length === 0 ? (
              <Muted>No affected assets in this window.</Muted>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {assets.map((a) => (
                  <AssetRow key={a.asset_key} asset={a} />
                ))}
              </div>
            )}
          </Section>

          {/* 7. Suggested investigation checklist */}
          <Section title="Possible investigation leads">
            <p style={{ fontSize: "12px", color: "#565b6e", margin: "0 0 12px", lineHeight: 1.6 }}>
              Suggested checks based on the data in this window. These are leads to
              review, not conclusions.
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {checklist.map((c) => (
                <div key={c.id} style={{ display: "flex", gap: "10px", alignItems: "flex-start" }}>
                  <span
                    style={{
                      width: "7px", height: "7px", borderRadius: "50%", marginTop: "6px", flexShrink: 0,
                      background: c.relevant ? "#f5a623" : "#3a3d4a",
                    }}
                  />
                  <span style={{ fontSize: "13px", color: c.relevant ? "#c4c8d4" : "#8b90a0", lineHeight: 1.55 }}>
                    {c.text}
                  </span>
                </div>
              ))}
            </div>
          </Section>
        </div>
      )}

      {findingsTotal > findings.length && !loading && !error ? (
        <p style={{ marginTop: "18px", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
          Showing the {findings.length} most recent findings of {findingsTotal}. Narrow
          the window or filters for a complete view of a specific period.
        </p>
      ) : null}

      <p style={{ marginTop: "26px", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
        Incident Review correlates configuration exposure and drift around a window.
        ConfigTrace reports configuration activity; it does not detect breaches or
        monitor live traffic.
      </p>
    </div>
  );
}

// ── Subcomponents ────────────────────────────────────────────────────────────

const inputStyle: React.CSSProperties = {
  fontSize: "13px", color: "#e8eaf0", background: "#13151a",
  border: "1px solid #2a2d38", borderRadius: "8px", padding: "7px 10px",
};

function FieldLabel({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: "8px" }}>
      <span style={{ fontSize: "12px", color: "#565b6e" }}>{label}</span>
      {children}
    </label>
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
      <select value={value} onChange={(e) => onChange(e.target.value)} style={{ ...inputStyle, cursor: "pointer" }}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </label>
  );
}

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

function Section({ title, count, children }: { title: string; count?: number; children: React.ReactNode }) {
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
        <SectionLabel>{title}</SectionLabel>
        {typeof count === "number" ? (
          <span style={{ fontSize: "12px", color: "#565b6e" }}>({count})</span>
        ) : null}
      </div>
      {children}
    </div>
  );
}

function Muted({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: "12.5px", color: "#565b6e" }}>{children}</div>;
}

function TimelineRow({ event, first }: { event: IncidentEvent; first: boolean }) {
  const color = event.severity ? sevColor(event.severity) : "#6b9cf8";
  return (
    <Link
      href={event.href}
      style={{
        display: "flex", gap: "10px", padding: "10px 0", textDecoration: "none",
        borderTop: first ? "none" : "1px solid #1d1f27",
      }}
    >
      <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: color, marginTop: "5px", flexShrink: 0 }} />
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: "10px", alignItems: "baseline" }}>
          <span style={{ fontSize: "13px", fontWeight: 600, color: "#e2e5ef" }}>
            {event.label}
            <span style={{ fontSize: "11px", fontWeight: 500, color: "#565b6e", marginLeft: "8px" }}>
              {event.kind === "drift" ? "Drift" : "Exposure"}
            </span>
          </span>
          <span style={{ fontSize: "11px", color: "#565b6e", flexShrink: 0 }}>{formatAbsoluteTime(event.at)}</span>
        </div>
        <div style={{ fontSize: "12.5px", color: "#c4c8d4", marginTop: "2px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {event.title}
        </div>
        <div style={{ display: "flex", gap: "10px", marginTop: "2px", fontSize: "11px", color: "#565b6e" }}>
          <span style={{ color: getProviderMeta(event.provider).color, fontWeight: 600 }}>
            {getProviderMeta(event.provider).shortLabel}
          </span>
          {event.severity ? <span>{event.severity}</span> : null}
        </div>
      </div>
    </Link>
  );
}

function FindingRow({ finding }: { finding: SecurityFinding }) {
  const provider = getProviderMeta(finding.provider);
  return (
    <Link
      href={`/security/exposures/${finding.id}`}
      className="bg-surface1 border border-border"
      style={{
        display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px",
        textDecoration: "none", borderRadius: "10px", padding: "10px 14px",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
        <SeverityBadge severity={finding.severity} />
        <span style={{ fontSize: "13.5px", color: "#e8eaf0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {finding.title}
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
        <span style={{ fontSize: "12px", color: provider.color, fontWeight: 600 }}>{provider.shortLabel}</span>
        <FindingStatusBadge status={finding.status} />
        <span style={{ fontSize: "11px", color: "#565b6e", whiteSpace: "nowrap" }}>
          {formatRelativeTime(finding.last_seen_at)}
        </span>
      </div>
    </Link>
  );
}

function DriftRow({ event }: { event: IncidentEvent }) {
  const provider = getProviderMeta(event.provider);
  const color = event.severity ? sevColor(event.severity) : "#6b9cf8";
  return (
    <Link
      href={event.href}
      className="bg-surface1 border border-border"
      style={{
        display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px",
        textDecoration: "none", borderRadius: "10px", padding: "10px 14px",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
        <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: color, flexShrink: 0 }} />
        <span style={{ fontSize: "13.5px", color: "#e8eaf0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {event.title}
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
        <span style={{ fontSize: "12px", color: provider.color, fontWeight: 600 }}>{provider.shortLabel}</span>
        {event.severity ? <span style={{ fontSize: "11px", color }}>{event.severity}</span> : null}
        <span style={{ fontSize: "11px", color: "#565b6e", whiteSpace: "nowrap" }}>{formatRelativeTime(event.at)}</span>
      </div>
    </Link>
  );
}

function AssetRow({ asset }: { asset: ReturnType<typeof assetsInWindow>[number] }) {
  const provider = getProviderMeta(asset.provider);
  return (
    <div
      className="bg-surface1 border border-border"
      style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px", borderRadius: "10px", padding: "10px 14px" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
        <SeverityBadge severity={asset.highest_severity} />
        <span style={{ fontSize: "13.5px", color: "#e8eaf0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {asset.asset_label}
        </span>
        <span style={{ fontSize: "11px", color: "#8b90a0", border: "1px solid #2a2d38", borderRadius: "6px", padding: "2px 7px", whiteSpace: "nowrap" }}>
          {asset.asset_type}
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
        <span style={{ fontSize: "12px", color: provider.color, fontWeight: 600 }}>{provider.shortLabel}</span>
        <span style={{ fontSize: "12px", color: "#8b90a0" }}>
          {asset.exposure_count} {asset.exposure_count === 1 ? "finding" : "findings"}
        </span>
      </div>
    </div>
  );
}

function EmptyNoActivity() {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "40px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#c4c8d4" }}>
        No security exposure activity found in this window.
      </div>
      <p style={{ fontSize: "13px", color: "#8b90a0", marginTop: "8px", lineHeight: 1.6, maxWidth: "520px", marginLeft: "auto", marginRight: "auto" }}>
        Try expanding the time range or adjusting filters. ConfigTrace will show
        findings and drift events here when they overlap the selected window.
      </p>
    </div>
  );
}

function EmptyFiltered() {
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "40px 24px", textAlign: "center" }}>
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#c4c8d4" }}>
        No incident review results match these filters.
      </div>
      <p style={{ fontSize: "13px", color: "#8b90a0", marginTop: "8px", lineHeight: 1.6 }}>
        Try adjusting provider, severity, search, or time range.
      </p>
    </div>
  );
}
