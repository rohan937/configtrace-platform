"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { ChangeListItem, Integration, ResourceListItem } from "@/types";
import { getChanges, getIntegrations, getResources } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import StatBlock from "@/components/common/StatBlock";
import ChangeList from "@/components/changes/ChangeList";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { formatAbsoluteTime, formatRelativeTime } from "@/lib/utils";

// ── Inline guide component ────────────────────────────────────────────────────
// Used for contextual empty states that tell the user exactly what to do next.

interface NextStepGuideProps {
  title: string;
  body: string;
  actionLabel?: string;
  actionHref?: string;
}

function NextStepGuide({
  title,
  body,
  actionLabel,
  actionHref,
}: NextStepGuideProps) {
  return (
    <div
      style={{
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        padding: "24px",
        display: "flex",
        flexDirection: "column",
        gap: "8px",
      }}
    >
      <p style={{ margin: 0, fontSize: "14px", color: "#e8eaf0" }}>{title}</p>
      <p style={{ margin: 0, fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
        {body}
      </p>
      {actionLabel && actionHref && (
        <Link
          href={actionHref}
          style={{
            marginTop: "4px",
            fontSize: "13px",
            color: "#4f80f7",
            textDecoration: "none",
          }}
        >
          {actionLabel} →
        </Link>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [changes, setChanges] = useState<ChangeListItem[]>([]);
  const [totalChanges, setTotalChanges] = useState(0);
  const [resources, setResources] = useState<ResourceListItem[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [changesData, resourcesData, integrationsData] = await Promise.all([
          getChanges({ page_size: 20 }),
          getResources({ page_size: 100 }),
          getIntegrations(),
        ]);
        if (!cancelled) {
          setChanges(changesData.items);
          setTotalChanges(changesData.total);
          setResources(resourcesData.items);
          setIntegrations(integrationsData.integrations);
        }
      } catch (err) {
        if (!cancelled)
          setError(
            err instanceof Error ? err.message : "Failed to load dashboard data.",
          );
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  // ── Derived stats ─────────────────────────────────────────────────────────

  // critical / high counts are derived from the loaded page — fine for a
  // dashboard approximation (20 most-recent changes).
  const criticalCount = changes.filter((c) => c.risk_level === "critical").length;
  const highCount = changes.filter((c) => c.risk_level === "high").length;
  const lastChange = changes[0] ?? null;

  // ── Empty-state logic ─────────────────────────────────────────────────────

  const ready = !loading && !error;
  const noIntegrations = ready && integrations.length === 0;
  // Integration connected but no resources yet → first sync hasn't run
  const noResources = ready && integrations.length > 0 && resources.length === 0;
  // Resources exist (baseline snapshot taken) but no changes yet
  const baselineOnly = ready && resources.length > 0 && totalChanges === 0;
  // Normal data state
  const hasChanges = ready && totalChanges > 0;

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Overview of recent configuration changes and monitored resources."
      />

      {/* ── Summary bar ──────────────────────────────────────────────── */}
      <div
        className="flex flex-wrap items-center gap-8 px-6 py-4"
        style={{ borderBottom: "1px solid #2a2d38" }}
      >
        <StatBlock
          value={loading ? "—" : resources.length}
          label="Resources monitored"
        />

        <div style={{ width: "1px", height: "36px", background: "#2a2d38" }} />

        <StatBlock
          value={loading ? "—" : totalChanges}
          label="Changes detected"
        />

        <div style={{ width: "1px", height: "36px", background: "#2a2d38" }} />

        <StatBlock
          value={loading ? "—" : criticalCount}
          label="Critical"
          valueColor={!loading && criticalCount > 0 ? "#e84040" : undefined}
        />

        <div style={{ width: "1px", height: "36px", background: "#2a2d38" }} />

        <StatBlock
          value={loading ? "—" : highCount}
          label="High risk"
          valueColor={!loading && highCount > 0 ? "#f5632a" : undefined}
        />

        {/* Last change time — only shown once data loads and changes exist */}
        {!loading && lastChange && (
          <>
            <div style={{ width: "1px", height: "36px", background: "#2a2d38" }} />
            <div className="flex flex-col gap-1">
              <span
                className="font-semibold leading-none"
                style={{ fontSize: "24px", color: "#e8eaf0" }}
                title={formatAbsoluteTime(lastChange.created_at)}
              >
                {formatRelativeTime(lastChange.created_at)}
              </span>
              <span
                className="leading-none"
                style={{ fontSize: "12px", color: "#8b90a0" }}
              >
                Last change
              </span>
            </div>
          </>
        )}
      </div>

      {/* ── Recent changes section ────────────────────────────────────── */}
      <div className="px-6 py-6">
        <div
          className="flex items-center justify-between"
          style={{ marginBottom: "16px" }}
        >
          <h2
            style={{
              fontSize: "13px",
              color: "#8b90a0",
              textTransform: "uppercase",
              letterSpacing: "0.06em",
            }}
          >
            Recent Changes
          </h2>
          {hasChanges && totalChanges > changes.length && (
            <Link
              href="/timeline"
              style={{ fontSize: "12px", color: "#4f80f7", textDecoration: "none" }}
            >
              View all {totalChanges} →
            </Link>
          )}
        </div>

        {loading && <LoadingState />}

        {!loading && error && <ErrorState message={error} />}

        {noIntegrations && (
          <NextStepGuide
            title="No integrations connected."
            body="Connect a Cloudflare zone to start monitoring DNS configuration changes. ConfigTrace will snapshot your DNS zone on each sync and highlight what changed."
            actionLabel="Connect Cloudflare"
            actionHref="/integrations"
          />
        )}

        {noResources && (
          <NextStepGuide
            title="Integration connected — run your first sync."
            body="Your Cloudflare integration is ready. Click Sync Now to take a baseline snapshot of your DNS zone. Future syncs will compare against this baseline and surface any changes here."
            actionLabel="Go to Integrations"
            actionHref="/integrations"
          />
        )}

        {baselineOnly && (
          <NextStepGuide
            title="Baseline captured."
            body="ConfigTrace has your current DNS state. Make a change in Cloudflare — add, remove, or modify a record — then click Sync Now. Detected changes will appear here with a risk classification."
            actionLabel="Run another sync"
            actionHref="/integrations"
          />
        )}

        {hasChanges && (
          <ChangeList
            changes={changes}
            emptyTitle="No changes recorded yet."
            emptyDescription="Run a sync to detect configuration changes."
          />
        )}
      </div>
    </>
  );
}
