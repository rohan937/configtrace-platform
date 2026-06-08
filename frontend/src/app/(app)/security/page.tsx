"use client";

/**
 * Security Overview (M60.2).
 *
 * The landing page for the Security Exposure product mode. M60.1 shipped a
 * static placeholder; M60.2 makes it data-aware by re-interpreting EXISTING
 * change / integration data through a security-exposure lens.
 *
 * Honesty: the persistent active-exposure findings engine arrives in
 * M60.3/M60.4. This page summarises *security-relevant drift* from existing
 * change data and provider coverage — never "confirmed exposures".
 *
 * No backend, no new tables, no migrations.
 */

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import type { ChangeListItem, Integration } from "@/types";
import {
  getChanges,
  getNeedsReviewChanges,
  getIntegrations,
  getSecurityFindings,
} from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import {
  buildSecurityFeed,
  deriveSecurityOverviewMetrics,
  getProviderSecurityCoverage,
  SECURITY_SEVERITY_COLOR,
  type SecuritySeverity,
} from "@/lib/securityExposure";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import SecurityDemoBanner from "@/components/security/SecurityDemoBanner";
import { PreviewBanner, SectionLabel } from "@/components/security/previews";

// How many recent changes to pull into the security window.
const WINDOW_SIZE = 100;

const SEV_LABEL: Record<SecuritySeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  info: "Info",
};

const REVIEW_LABEL: Record<string, string> = {
  needs_review: "Needs review",
  acknowledged: "Acknowledged",
  expected: "Expected",
  snoozed: "Snoozed",
};

// ── Page ──────────────────────────────────────────────────────────────────────

export default function SecurityOverviewPage() {
  const { getToken } = useAuth();

  const [changes, setChanges] = useState<ChangeListItem[]>([]);
  const [needsReview, setNeedsReview] = useState<ChangeListItem[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // M60.4: live active-exposure count from the real findings engine. Null until
  // known; the page still works entirely on M60.2 derived data if this fails.
  const [liveActiveCount, setLiveActiveCount] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const token = await getToken();
        // Defensive: each source is independent; a partial failure degrades
        // gracefully rather than breaking the whole page.
        const [changesRes, needsRes, intRes, findingsRes] =
          await Promise.allSettled([
            getChanges({ page_size: WINDOW_SIZE }, token),
            getNeedsReviewChanges({ page_size: WINDOW_SIZE }, token),
            getIntegrations(token),
            // M60.4: prefer real active-finding metrics when the engine has run.
            getSecurityFindings({ status: "active", page_size: 1 }, token),
          ]);
        if (cancelled) return;

        if (changesRes.status === "fulfilled") {
          setChanges(changesRes.value.items ?? []);
        }
        if (needsRes.status === "fulfilled") {
          setNeedsReview(needsRes.value.items ?? []);
        }
        if (intRes.status === "fulfilled") {
          setIntegrations(intRes.value.integrations ?? []);
        }
        if (findingsRes.status === "fulfilled") {
          setLiveActiveCount(findingsRes.value.total ?? 0);
        }

        // Only hard-error if literally everything failed.
        if (
          changesRes.status === "rejected" &&
          needsRes.status === "rejected" &&
          intRes.status === "rejected"
        ) {
          setError("Could not load security data. Please try again.");
        }
      } catch {
        if (!cancelled) setError("Could not load security data. Please try again.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [getToken]);

  const metrics = useMemo(
    () =>
      deriveSecurityOverviewMetrics({
        changes,
        needsReviewChanges: needsReview,
        integrations,
      }),
    [changes, needsReview, integrations],
  );

  const feed = useMemo(() => buildSecurityFeed(changes, 12), [changes]);
  const coverage = useMemo(
    () => getProviderSecurityCoverage(integrations),
    [integrations],
  );

  const hasIntegrations = metrics.connectedProviders > 0;
  const hasFeed = feed.length > 0;

  if (loading) {
    return (
      <div>
        <Hero />
        <LoadingState />
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <Hero />
        <ErrorState message={error} />
      </div>
    );
  }

  return (
    <div>
      <Hero />

      {/* M62.2: opt-in demo data control. */}
      <SecurityDemoBanner
        findingsEmpty={liveActiveCount === 0}
        onChanged={() => window.location.reload()}
      />

      {liveActiveCount !== null && liveActiveCount > 0 ? (
        <div
          role="status"
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            padding: "12px 14px",
            borderRadius: "10px",
            background: "rgba(232, 64, 64, 0.08)",
            border: "1px solid rgba(232, 64, 64, 0.32)",
            marginBottom: "16px",
          }}
        >
          <span
            aria-hidden
            style={{
              width: "8px",
              height: "8px",
              borderRadius: "5px",
              background: "#e84040",
              flexShrink: 0,
            }}
          />
          <span style={{ fontSize: "13px", color: "#e8eaf0" }}>
            <strong>{liveActiveCount}</strong> active security{" "}
            {liveActiveCount === 1 ? "exposure" : "exposures"} detected by the
            findings engine.{" "}
            <Link
              href="/security/exposures"
              style={{ color: "#6b9cf8", textDecoration: "none" }}
            >
              View active exposures →
            </Link>
          </span>
        </div>
      ) : (
        <PreviewBanner>
          Active exposure findings arrive in M60.3/M60.4. This overview currently
          summarizes <strong>security-relevant drift</strong> from your recent
          change data — not confirmed exposures.
        </PreviewBanner>
      )}

      {/* B. Summary metric cards */}
      <SectionLabel>Exposure summary</SectionLabel>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "14px",
        }}
      >
        <MetricCard
          label="Critical security-relevant changes"
          value={metrics.criticalCount}
          accent="#e84040"
          subtext="From recent change data"
        />
        <MetricCard
          label="High-risk security-relevant changes"
          value={metrics.highCount}
          accent="#f5632a"
          subtext="From recent change data"
        />
        <MetricCard
          label="Needs security review"
          value={metrics.needsSecurityReview}
          accent="#f5a623"
          subtext="Unreviewed security drift"
        />
        <MetricCard
          label="Connected providers"
          value={metrics.connectedProviders}
          accent="#6b9cf8"
          subtext="Active integrations"
        />
        <MetricCard
          label="Recently reviewed"
          value={metrics.recentlyReviewed}
          accent="#3ccf7e"
          subtext="From recent change data"
        />
      </div>

      {/* C. Security-relevant change feed */}
      <div style={{ marginTop: "32px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
            gap: "12px",
          }}
        >
          <SectionLabel>Recent security-relevant drift</SectionLabel>
          <Link
            href="/needs-review"
            style={{ fontSize: "12px", color: "#6b9cf8", textDecoration: "none" }}
          >
            View needs-review queue →
          </Link>
        </div>

        {hasFeed ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {feed.map((item) => (
              <FeedRow key={item.change.id} item={item} />
            ))}
          </div>
        ) : (
          <EmptyFeedState hasIntegrations={hasIntegrations} />
        )}
      </div>

      {/* D. Provider security coverage */}
      <div style={{ marginTop: "32px" }}>
        <SectionLabel>Security coverage by provider</SectionLabel>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            gap: "14px",
          }}
        >
          {coverage.map((c) => (
            <CoverageCard key={c.providerId} coverage={c} />
          ))}
        </div>
      </div>

      {/* F. Preview note */}
      <div style={{ marginTop: "28px" }}>
        <p style={{ margin: 0, fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
          Active exposure findings arrive in M60.3/M60.4. This overview currently
          summarizes security-relevant drift from existing change data — it does
          not evaluate persistent risky current states yet.
        </p>
      </div>
    </div>
  );
}

// ── Hero ──────────────────────────────────────────────────────────────────────

function Hero() {
  return (
    <>
      <PageHeader
        title="Security Exposure"
        description="Find risky current states across connected cloud and SaaS tools."
      />
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "20px 22px", marginBottom: "24px" }}
      >
        <p style={{ margin: 0, fontSize: "15px", color: "#c4c8d4", lineHeight: 1.6 }}>
          <span style={{ color: "#e8eaf0", fontWeight: 600 }}>
            Drift Detection tells you what changed. Security Exposure tells you
            what may be dangerous right now.
          </span>{" "}
          ConfigTrace re-reads your existing change history through a security
          lens — webhooks, branch protection, public access, security groups,
          DNS, and other settings that affect your production posture.
        </p>
      </div>
    </>
  );
}

// ── Metric card ────────────────────────────────────────────────────────────────

function MetricCard({
  label,
  value,
  accent,
  subtext,
}: {
  label: string;
  value: number | null;
  accent: string;
  subtext: string;
}) {
  const display = value == null ? "—" : value;
  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "16px 18px" }}
    >
      <div style={{ fontSize: "12px", color: "#8b90a0", fontWeight: 500 }}>{label}</div>
      <div
        style={{
          fontSize: "28px",
          fontWeight: 700,
          color: accent,
          marginTop: "8px",
          letterSpacing: "-0.02em",
          opacity: value == null ? 0.55 : 1,
        }}
      >
        {display}
      </div>
      <div
        style={{ fontSize: "11px", color: "#565b6e", marginTop: "4px" }}
        title={
          value == null
            ? "Available after the security findings engine is added (M60.3/M60.4)."
            : undefined
        }
      >
        {value == null ? "Available after security findings engine is added" : subtext}
      </div>
    </div>
  );
}

// ── Feed row ───────────────────────────────────────────────────────────────────

function FeedRow({ item }: { item: ReturnType<typeof buildSecurityFeed>[number] }) {
  const c = SECURITY_SEVERITY_COLOR[item.severity];
  const reviewLabel = item.reviewStatus
    ? REVIEW_LABEL[item.reviewStatus] ?? item.reviewStatus
    : "Needs review";

  return (
    <Link
      href={`/changes/${item.change.id}`}
      className="bg-surface1 border border-border"
      style={{
        borderRadius: "12px",
        overflow: "hidden",
        display: "flex",
        textDecoration: "none",
        transition: "border-color 120ms ease",
      }}
    >
      <div style={{ width: "3px", background: c, flexShrink: 0 }} />
      <div style={{ flex: 1, padding: "14px 16px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "12px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
            <span
              style={{
                fontSize: "10px",
                fontWeight: 700,
                letterSpacing: "0.04em",
                textTransform: "uppercase",
                color: c,
                background: `${c}1f`,
                border: `1px solid ${c}55`,
                borderRadius: "999px",
                padding: "3px 9px",
                flexShrink: 0,
              }}
            >
              {SEV_LABEL[item.severity]}
            </span>
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
              {item.title}
            </span>
          </div>
          <span style={{ fontSize: "12px", color: "#6b9cf8", flexShrink: 0 }}>
            View change →
          </span>
        </div>
        <div
          style={{
            fontSize: "12px",
            color: "#8b90a0",
            marginTop: "7px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
            flexWrap: "wrap",
          }}
        >
          <span>{item.providerLabel}</span>
          {item.category && (
            <>
              <span style={{ color: "#3a3d48" }}>·</span>
              <span>{item.category}</span>
            </>
          )}
          <span style={{ color: "#3a3d48" }}>·</span>
          <span>{formatRelativeTime(item.change.created_at)}</span>
          <span style={{ color: "#3a3d48" }}>·</span>
          <span>{reviewLabel}</span>
        </div>
        {item.change.record_identifier && (
          <div
            style={{
              fontSize: "11px",
              color: "#565b6e",
              marginTop: "4px",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {item.change.record_identifier}
          </div>
        )}
      </div>
    </Link>
  );
}

// ── Coverage card ──────────────────────────────────────────────────────────────

function CoverageCard({
  coverage,
}: {
  coverage: ReturnType<typeof getProviderSecurityCoverage>[number];
}) {
  const connected = coverage.connected;
  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "16px 18px", opacity: connected ? 1 : 0.78 }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "10px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "9px" }}>
          <span
            aria-hidden
            style={{
              width: "9px",
              height: "9px",
              borderRadius: "5px",
              background: connected ? "#3ccf7e" : "#565b6e",
              flexShrink: 0,
            }}
          />
          <span style={{ fontSize: "14px", fontWeight: 600, color: "#e8eaf0" }}>
            {coverage.label}
          </span>
        </div>
        <span
          style={{
            fontSize: "10px",
            fontWeight: 600,
            letterSpacing: "0.04em",
            textTransform: "uppercase",
            color: connected ? "#3ccf7e" : "#8b90a0",
            border: `1px solid ${connected ? "rgba(60,207,126,0.4)" : "#2a2d38"}`,
            borderRadius: "6px",
            padding: "2px 8px",
          }}
        >
          {connected ? "Connected" : "Not connected"}
        </span>
      </div>

      <div style={{ fontSize: "11px", color: "#565b6e", marginTop: "8px" }}>
        {connected
          ? coverage.lastSyncedAt
            ? `Last synced ${formatRelativeTime(coverage.lastSyncedAt)}`
            : "Never synced"
          : "Connect to monitor these surfaces"}
      </div>

      {coverage.surfaces.length > 0 && (
        <ul
          style={{
            margin: "12px 0 0",
            paddingLeft: "16px",
            color: "#8b90a0",
            fontSize: "12px",
            lineHeight: 1.7,
          }}
        >
          {coverage.surfaces.slice(0, 4).map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
      )}

      <Link
        href="/integrations"
        style={{
          display: "inline-block",
          marginTop: "12px",
          fontSize: "12px",
          color: "#6b9cf8",
          textDecoration: "none",
        }}
      >
        {connected ? "Manage integration →" : "Connect in Integrations →"}
      </Link>
    </div>
  );
}

// ── Empty state ────────────────────────────────────────────────────────────────

function EmptyFeedState({ hasIntegrations }: { hasIntegrations: boolean }) {
  return (
    <div
      className="bg-surface1 border border-border"
      style={{
        borderRadius: "12px",
        padding: "32px 24px",
        textAlign: "center",
      }}
    >
      <div style={{ fontSize: "15px", fontWeight: 600, color: "#e8eaf0" }}>
        No active security-relevant drift found yet.
      </div>
      <p
        style={{
          margin: "8px auto 0",
          maxWidth: "460px",
          fontSize: "13px",
          color: "#8b90a0",
          lineHeight: 1.6,
        }}
      >
        {hasIntegrations
          ? "Run a sync to capture new changes. M60.3/M60.4 will add persistent active exposure findings."
          : "Connect providers and run a sync. M60.3/M60.4 will add persistent active exposure findings."}
      </p>
      {!hasIntegrations && (
        <Link
          href="/integrations"
          style={{
            display: "inline-block",
            marginTop: "16px",
            fontSize: "13px",
            fontWeight: 500,
            color: "#0b0d12",
            background: "#6b9cf8",
            padding: "8px 16px",
            borderRadius: "8px",
            textDecoration: "none",
          }}
        >
          Connect a provider
        </Link>
      )}
    </div>
  );
}
