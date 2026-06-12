"use client";

/**
 * SecurityPostureSummaryCard (M62.6).
 *
 * A compact Configuration Risk summary for the main dashboard so posture is
 * visible without switching into the Security sidebar. Self-contained and
 * non-blocking: its fetches never break the dashboard, and any failure degrades
 * to a small "summary unavailable" fallback.
 *
 * Conservative wording: summarizes "risky current states" / "needs review" —
 * never claims safe/secure/compliant.
 */

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";

import { useAuth } from "@clerk/nextjs";
import {
  getSecurityFindings,
  getSecurityCoverage,
  getSecurityDemoDataStatus,
  getIntegrations,
} from "@/lib/api";
import {
  buildPostureSummary,
  type PostureSummary,
} from "@/lib/securityPostureSummary";

const CARD: React.CSSProperties = {
  background: "#13151a",
  border: "1px solid #2a2d38",
  borderRadius: "6px",
  padding: "20px 22px",
  marginBottom: "20px",
};

const LABEL: React.CSSProperties = {
  fontSize: "11px",
  color: "#565b6e",
  textTransform: "uppercase",
  letterSpacing: "0.06em",
  fontWeight: 500,
};

export default function SecurityPostureSummaryCard() {
  const { getToken, isLoaded } = useAuth();
  const [summary, setSummary] = useState<PostureSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  const load = useCallback(async () => {
    try {
      const token = await getToken();
      const [findings, active, coverage, demo, ints] = await Promise.allSettled([
        getSecurityFindings({ page_size: 100 }, token),
        getSecurityFindings({ status: "active", page_size: 1 }, token),
        getSecurityCoverage(token),
        getSecurityDemoDataStatus(token),
        getIntegrations(token),
      ]);
      const val = <T,>(r: PromiseSettledResult<T>): T | null =>
        r.status === "fulfilled" ? r.value : null;

      // If the core findings call failed, treat the whole card as unavailable.
      if (findings.status !== "fulfilled") {
        setFailed(true);
        return;
      }
      setSummary(
        buildPostureSummary({
          integrations: val(ints)?.integrations ?? null,
          findings: val(findings)?.items ?? null,
          activeTotal: val(active)?.total ?? null,
          coverage: val(coverage)?.providers ?? null,
          demo: val(demo),
        }),
      );
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }, [getToken]);

  useEffect(() => {
    if (isLoaded) void load();
  }, [isLoaded, load]);

  if (loading) {
    return (
      <div style={CARD}>
        <Header />
        <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "12px" }}>Loading…</div>
      </div>
    );
  }

  if (failed || !summary) {
    return (
      <div style={CARD}>
        <Header />
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px", marginTop: "12px", flexWrap: "wrap" }}>
          <span style={{ fontSize: "12.5px", color: "#8b90a0" }}>Security summary unavailable.</span>
          <Link href="/security" style={ctaLink}>Open Security →</Link>
        </div>
      </div>
    );
  }

  const s = summary;

  // Empty state: nothing connected and nothing to show.
  if (!s.connected && !s.hasAnyData) {
    return (
      <div style={CARD}>
        <Header />
        <p style={{ fontSize: "13px", color: "#c4c8d4", margin: "12px 0 4px", fontWeight: 600 }}>
          Configuration Risk is not set up yet.
        </p>
        <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "0 0 14px", lineHeight: 1.6 }}>
          Connect providers or load demo data to preview configuration risk workflows.
        </p>
        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
          <Link href="/integrations" style={ctaButton}>Connect provider</Link>
          <Link href="/security" style={ctaLink}>Try demo data →</Link>
        </div>
      </div>
    );
  }

  return (
    <div style={CARD}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "10px" }}>
        <Header />
        {s.demoLoaded ? (
          <span
            title="Demo findings are not from connected providers."
            style={{
              fontSize: "10px", fontWeight: 700, letterSpacing: "0.03em", textTransform: "uppercase",
              color: "#6b9cf8", background: "rgba(107,156,248,0.12)", border: "1px solid rgba(107,156,248,0.4)",
              borderRadius: "6px", padding: "2px 8px", whiteSpace: "nowrap",
            }}
          >
            Demo data loaded
          </span>
        ) : null}
      </div>

      {/* Critical/high alert strip */}
      {s.hasCriticalOrHigh ? (
        <div
          role="status"
          style={{
            display: "flex", alignItems: "center", gap: "8px", marginTop: "12px",
            padding: "8px 12px", borderRadius: "8px",
            background: "rgba(232,64,64,0.08)", border: "1px solid rgba(232,64,64,0.32)",
          }}
        >
          <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: "#e84040", flexShrink: 0 }} />
          <span style={{ fontSize: "12.5px", color: "#e2e5ef" }}>
            Critical or high configuration risks need review.
          </span>
          <Link href="/security/risks" style={{ ...ctaLink, marginLeft: "auto" }}>Review →</Link>
        </div>
      ) : null}

      {/* Metrics */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(110px, 1fr))",
          gap: "12px",
          marginTop: "14px",
        }}
      >
        <Metric label="Active risks" value={s.activeCount} accent={s.activeCount > 0 ? "#f5632a" : "#3ccf7e"} />
        <Metric label="Critical" value={s.criticalActiveCount} accent={s.criticalActiveCount > 0 ? "#e84040" : "#8b90a0"} />
        <Metric label="High" value={s.highActiveCount} accent={s.highActiveCount > 0 ? "#f5632a" : "#8b90a0"} />
        <Metric label="Accepted risk" value={s.acceptedCount} accent="#f5a623" />
        <Metric label="Snoozed" value={s.snoozedCount} accent="#8b90a0" />
      </div>

      {/* Coverage line */}
      <div style={{ fontSize: "12px", color: "#8b90a0", marginTop: "12px" }}>
        Coverage: {s.coverage.good} good · {s.coverage.limited} limited · {s.coverage.needs_attention} needs sync · {s.coverage.not_connected} not connected
      </div>
      {s.hasLimitedCoverage ? (
        <div style={{ fontSize: "12px", color: "#f5a623", marginTop: "6px", display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
          Some provider coverage is limited.
          <Link href="/security/coverage" style={ctaLink}>View Coverage →</Link>
        </div>
      ) : null}

      {/* CTAs */}
      <div style={{ display: "flex", gap: "16px", marginTop: "14px", flexWrap: "wrap" }}>
        <Link href="/security" style={ctaLink}>Security Overview →</Link>
        <Link href="/security/risks" style={ctaLink}>Active Risks →</Link>
        <Link href="/security/coverage" style={ctaLink}>Coverage →</Link>
      </div>
    </div>
  );
}

const ctaLink: React.CSSProperties = {
  fontSize: "12px",
  color: "#4f80f7",
  textDecoration: "none",
  whiteSpace: "nowrap",
};

const ctaButton: React.CSSProperties = {
  fontSize: "12.5px",
  fontWeight: 600,
  color: "#fff",
  background: "#6b9cf8",
  border: "1px solid #6b9cf8",
  borderRadius: "8px",
  padding: "6px 14px",
  textDecoration: "none",
};

function Header() {
  return (
    <div>
      <p style={LABEL}>Configuration Risk</p>
      <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "4px 0 0" }}>
        Monitor risky current states across connected cloud and SaaS configuration.
      </p>
    </div>
  );
}

function Metric({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div>
      <div style={{ fontSize: "24px", fontWeight: 700, color: accent, lineHeight: 1, letterSpacing: "-0.02em" }}>
        {value}
      </div>
      <div style={{ fontSize: "11.5px", color: "#8b90a0", marginTop: "5px" }}>{label}</div>
    </div>
  );
}
