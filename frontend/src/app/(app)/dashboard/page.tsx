"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import type { ChangeListItem, Integration, ResourceListItem } from "@/types";
import { getChanges, getIntegrations, getResources } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import StatBlock from "@/components/common/StatBlock";
import ChangeList from "@/components/changes/ChangeList";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { formatAbsoluteTime, formatRelativeTime } from "@/lib/utils";

// ── Onboarding panel ──────────────────────────────────────────────────────────
// Full three-step checklist shown when the user has zero integrations.
// Steps are numbered and colour-coded: active step is white, pending are dimmed.

interface OnboardingStep {
  num: number;
  label: string;
  body: string;
  done?: boolean;
}

function OnboardingPanel({
  steps,
  actionLabel,
  actionHref,
  note,
}: {
  steps: OnboardingStep[];
  actionLabel: string;
  actionHref: string;
  note?: string;
}) {
  return (
    <div
      style={{
        background: "#13151a",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        padding: "28px 28px 24px",
      }}
    >
      <p
        style={{
          margin: "0 0 20px",
          fontSize: "15px",
          fontWeight: 600,
          color: "#e8eaf0",
          lineHeight: 1.4,
        }}
      >
        Start monitoring your first configuration surface.
      </p>

      {/* Steps */}
      <div style={{ display: "flex", flexDirection: "column", gap: "14px", marginBottom: "24px" }}>
        {steps.map((step) => (
          <div key={step.num} style={{ display: "flex", gap: "14px", alignItems: "flex-start" }}>
            {/* Step indicator */}
            <div
              style={{
                flexShrink: 0,
                width: "22px",
                height: "22px",
                borderRadius: "50%",
                background: step.done ? "#4f80f7" : "#1e2030",
                border: step.done ? "none" : "1px solid #3a3d4a",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "11px",
                fontWeight: 700,
                color: step.done ? "#ffffff" : "#565b6e",
                marginTop: "1px",
              }}
            >
              {step.done ? "✓" : step.num}
            </div>

            {/* Step text */}
            <div>
              <p
                style={{
                  margin: "0 0 2px",
                  fontSize: "13px",
                  fontWeight: 500,
                  color: step.done ? "#8b90a0" : "#e8eaf0",
                }}
              >
                {step.label}
              </p>
              <p
                style={{
                  margin: 0,
                  fontSize: "12px",
                  color: "#565b6e",
                  lineHeight: 1.6,
                }}
              >
                {step.body}
              </p>
            </div>
          </div>
        ))}
      </div>

      {/* CTA */}
      <Link
        href={actionHref}
        style={{
          display: "inline-block",
          background: "#4f80f7",
          color: "#ffffff",
          textDecoration: "none",
          borderRadius: "6px",
          padding: "8px 18px",
          fontSize: "13px",
          fontWeight: 500,
        }}
      >
        {actionLabel}
      </Link>

      {/* Note */}
      {note && (
        <p
          style={{
            margin: "16px 0 0",
            fontSize: "12px",
            color: "#565b6e",
            lineHeight: 1.6,
          }}
        >
          {note}
        </p>
      )}
    </div>
  );
}

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
  const { getToken, isLoaded } = useAuth();

  useEffect(() => {
    if (!isLoaded) return;
    let cancelled = false;

    async function load() {
      try {
        const token = await getToken();
        const [changesData, resourcesData, integrationsData] = await Promise.all([
          getChanges({ page_size: 20 }, token),
          getResources({ page_size: 100 }, token),
          getIntegrations(token),
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
  }, [isLoaded, getToken]);

  // ── Derived stats ─────────────────────────────────────────────────────────

  // critical / high counts are derived from the loaded page — fine for a
  // dashboard approximation (20 most-recent changes).
  const criticalCount = changes.filter((c) => c.risk_level === "critical").length;
  const highCount = changes.filter((c) => c.risk_level === "high").length;
  const lastChange = changes[0] ?? null;

  // ── Empty-state logic ─────────────────────────────────────────────────────
  //
  // The integration_service creates a Resource row inline with the Integration,
  // so `resources.length > 0` is true the moment the user connects Cloudflare —
  // BEFORE any sync runs.  We therefore key the "baseline captured" state on
  // last_snapshot_at, which is only set after the first successful sync writes
  // a Snapshot row.  Resources still in their pre-sync state (no snapshot yet)
  // fall into the "noSnapshots" branch, which tells the user to run the first
  // sync to create a baseline.

  const ready = !loading && !error;
  const hasAnySnapshot = resources.some((r) => r.last_snapshot_at !== null);

  const noIntegrations = ready && integrations.length === 0;
  // Integration exists but no snapshot has been written yet — first sync pending
  const noSnapshots =
    ready && integrations.length > 0 && !hasAnySnapshot;
  // Snapshot(s) exist but no changes detected — the normal post-baseline state
  const baselineOnly =
    ready && hasAnySnapshot && totalChanges === 0;
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
          <OnboardingPanel
            steps={[
              {
                num: 1,
                label: "Connect Cloudflare",
                body: "Add a scoped API token and Zone ID — ConfigTrace only needs Zone DNS Read access.",
              },
              {
                num: 2,
                label: "Create a baseline",
                body: "The first sync snapshots your current DNS state. Nothing is flagged as changed on this run — it establishes the comparison point.",
              },
              {
                num: 3,
                label: "Track changes hourly",
                body: "ConfigTrace syncs every hour and shows exactly what DNS records changed and how risky each change is.",
              },
            ]}
            actionLabel="Connect Cloudflare →"
            actionHref="/integrations"
            note="High-risk and critical DNS changes are emailed to the integration owner automatically."
          />
        )}

        {noSnapshots && (
          <OnboardingPanel
            steps={[
              {
                num: 1,
                label: "Connect Cloudflare",
                body: "Integration connected.",
                done: true,
              },
              {
                num: 2,
                label: "Create a baseline",
                body: "Run your first sync to snapshot current DNS state. No changes are detected on this run — it's the starting point.",
              },
              {
                num: 3,
                label: "Track changes hourly",
                body: "ConfigTrace syncs every hour and surfaces DNS changes automatically.",
              },
            ]}
            actionLabel="Go to Integrations →"
            actionHref="/integrations"
            note="Syncs also run automatically every hour once your baseline is in place."
          />
        )}

        {baselineOnly && (
          <NextStepGuide
            title="Baseline active — ConfigTrace is monitoring your DNS."
            body="Your current DNS state is on record. Changes will appear here on the next sync. To test the loop now, modify a DNS record in Cloudflare, then click Sync Now on the Integrations page."
            actionLabel="Go to Integrations"
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
