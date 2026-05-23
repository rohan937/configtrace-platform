"use client";

import { useParams } from "next/navigation";
import { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import type { ChangeDetail, DnsRecord } from "@/types";
import { getChange } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import RiskBadge from "@/components/common/RiskBadge";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import DnsRecordView from "@/components/changes/DnsRecordView";
import {
  formatRelativeTime,
  formatAbsoluteTime,
  changeTypeLabel,
  formatDiffValue,
  formatSnapshotHash,
} from "@/lib/utils";

// ── Risk panel background colors ──────────────────────────────────────────────

const RISK_PANEL_BG: Record<string, string> = {
  critical: "rgba(232,64,64,0.07)",
  high:     "rgba(245,99,42,0.07)",
  medium:   "rgba(245,166,35,0.07)",
  low:      "rgba(107,156,248,0.07)",
  unknown:  "rgba(86,91,110,0.10)",
};

const RISK_PANEL_BORDER: Record<string, string> = {
  critical: "rgba(232,64,64,0.25)",
  high:     "rgba(245,99,42,0.25)",
  medium:   "rgba(245,166,35,0.25)",
  low:      "rgba(107,156,248,0.25)",
  unknown:  "#2a2d38",
};

// ── Small layout helpers ──────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p
      style={{
        fontSize: "11px",
        color: "#565b6e",
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        marginBottom: "8px",
        fontWeight: 500,
      }}
    >
      {children}
    </p>
  );
}

function Panel({
  children,
  bg = "#13151a",
  border = "#2a2d38",
}: {
  children: React.ReactNode;
  bg?: string;
  border?: string;
}) {
  return (
    <div
      style={{
        background: bg,
        border: `1px solid ${border}`,
        borderRadius: "6px",
        padding: "16px",
      }}
    >
      {children}
    </div>
  );
}

function MetaRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-3" style={{ marginBottom: "4px" }}>
      <span
        style={{
          width: "120px",
          flexShrink: 0,
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}
      >
        {label}
      </span>
      <span style={{ fontSize: "13px", color: "#8b90a0" }}>{children}</span>
    </div>
  );
}

// ── Diff panel — modified ─────────────────────────────────────────────────────

function ModifiedDiffPanel({ change }: { change: ChangeDetail }) {
  const prevText = formatDiffValue(change.prev_value);
  const newText  = formatDiffValue(change.new_value);
  const isMultiline = prevText.includes("\n") || newText.includes("\n");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
      {change.field_path && (
        <p style={{ fontSize: "12px", color: "#565b6e", marginBottom: "4px" }}>
          Field:{" "}
          <span
            style={{
              fontFamily: "monospace",
              color: "#8b90a0",
              background: "#1c1e26",
              padding: "1px 5px",
              borderRadius: "3px",
            }}
          >
            {change.field_path}
          </span>
        </p>
      )}

      {/* Before */}
      <div
        style={{
          background: "rgba(232,64,64,0.07)",
          border: "1px solid rgba(232,64,64,0.20)",
          borderRadius: "4px",
          padding: "10px 12px",
        }}
      >
        <span
          style={{
            fontSize: "10px",
            color: "#e84040",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            display: "block",
            marginBottom: "4px",
          }}
        >
          Before
        </span>
        <pre
          style={{
            fontFamily: "monospace",
            fontSize: "13px",
            color: "#e8eaf0",
            margin: 0,
            whiteSpace: isMultiline ? "pre-wrap" : "pre",
            wordBreak: "break-all",
          }}
        >
          {prevText}
        </pre>
      </div>

      {/* After */}
      <div
        style={{
          background: "rgba(60,207,126,0.06)",
          border: "1px solid rgba(60,207,126,0.20)",
          borderRadius: "4px",
          padding: "10px 12px",
        }}
      >
        <span
          style={{
            fontSize: "10px",
            color: "#3ccf7e",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            display: "block",
            marginBottom: "4px",
          }}
        >
          After
        </span>
        <pre
          style={{
            fontFamily: "monospace",
            fontSize: "13px",
            color: "#e8eaf0",
            margin: 0,
            whiteSpace: isMultiline ? "pre-wrap" : "pre",
            wordBreak: "break-all",
          }}
        >
          {newText}
        </pre>
      </div>
    </div>
  );
}

// ── Diff panel — added / removed ──────────────────────────────────────────────

function AddedRemovedPanel({
  change,
  isGitHub = false,
}: {
  change: ChangeDetail;
  isGitHub?: boolean;
}) {
  const isAdded   = change.change_type === "added";
  const record    = isAdded ? change.new_value : change.prev_value;
  const tint      = isAdded ? "add" : "remove";
  const label     = isAdded
    ? isGitHub ? "Configuration Added" : "DNS Record Added"
    : isGitHub ? "Configuration Removed" : "DNS Record Removed";
  const labelColor = isAdded ? "#3ccf7e" : "#e84040";

  const isDnsRecord =
    record !== null &&
    record !== undefined &&
    typeof record === "object" &&
    !Array.isArray(record);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
      <p style={{ fontSize: "13px", color: labelColor, fontWeight: 500 }}>
        {label}
      </p>
      {isDnsRecord ? (
        <DnsRecordView
          record={record as Record<string, unknown>}
          tint={tint}
        />
      ) : (
        <div
          style={{
            background: "#1c1e26",
            border: "1px solid #2a2d38",
            borderRadius: "4px",
            padding: "10px 12px",
          }}
        >
          <pre
            style={{
              fontFamily: "monospace",
              fontSize: "12px",
              color: "#8b90a0",
              margin: 0,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
          >
            {formatDiffValue(record)}
          </pre>
        </div>
      )}
    </div>
  );
}

// ── Provider-aware helpers ────────────────────────────────────────────────────

/** "Cloudflare DNS" | "GitHub repo configuration" | "Unknown" */
function getProviderLabel(change: ChangeDetail): string {
  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();
  if (rt.startsWith("github_")) return "GitHub repo configuration";
  if (change.provider_metadata?.record_type) return "Cloudflare DNS";
  return "Cloudflare DNS";
}

/** One-sentence description of what happened. */
function getChangeSummary(change: ChangeDetail): string {
  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();
  const rn = (change.provider_metadata?.record_name as string | undefined) ?? "";
  const fp = change.field_path ?? "";
  const nv = change.new_value;
  const pv = change.prev_value;

  // GitHub
  if (rt === "github_actions_secret") {
    const label = rn ? `The Actions secret ${rn}` : "An Actions secret";
    if (change.change_type === "removed") return `${label} was deleted.`;
    if (change.change_type === "added")   return `A new Actions secret${rn ? ` ${rn}` : ""} was added.`;
    return `${label} was rotated.`;
  }
  if (rt === "github_branch_protection") {
    if (change.change_type === "removed") return "A branch protection rule was deleted.";
    if (change.change_type === "added")   return "A branch protection rule was added.";
    return `A branch protection setting changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "github_repo_settings") {
    if (fp === "visibility") return `Repository visibility changed to ${String(nv)}.`;
    if (fp === "default_branch") return `The default branch changed from ${String(pv)} to ${String(nv)}.`;
    if (fp === "archived") return "The repository was archived.";
    return `A repository setting changed${fp ? ` (${fp})` : ""}.`;
  }
  if (rt === "github_webhook") {
    if (change.change_type === "removed") return "A repository webhook was deleted.";
    if (change.change_type === "added")   return "A new repository webhook was added.";
    if (fp === "url") return "The webhook delivery URL changed.";
    return "A webhook setting changed.";
  }
  if (rt === "github_deploy_key") {
    if (change.change_type === "removed") return "A deploy key was removed.";
    if (change.change_type === "added") {
      const rec = typeof nv === "object" && nv !== null ? nv as Record<string, unknown> : {};
      const access = rec.read_only === false ? "write-enabled" : "read-only";
      return `A ${access} deploy key was added.`;
    }
    return "A deploy key was modified.";
  }
  if (rt.startsWith("github_")) {
    return `A GitHub configuration record changed (${rt}).`;
  }

  // Cloudflare DNS
  const recordLabel = rn
    ? `${(change.provider_metadata?.record_type as string | undefined) ?? ""} ${rn}`.trim()
    : change.record_identifier;

  if (change.change_type === "removed") return `${recordLabel} was removed from Cloudflare DNS.`;
  if (change.change_type === "added")   return `${recordLabel} was added to Cloudflare DNS.`;
  if (fp === "content") {
    const recType = ((change.provider_metadata?.record_type as string | undefined) ?? "").toUpperCase();
    if (recType === "CNAME") return `The CNAME target for ${rn || change.record_identifier} changed.`;
    if (recType === "A" || recType === "AAAA") return `The IP address for ${rn || change.record_identifier} changed.`;
  }
  return `${recordLabel} was modified.`;
}

/** Suggested next steps for high/critical changes. Returns [] for low/medium. */
function getSuggestedChecks(change: ChangeDetail): string[] {
  const riskKey = (change.risk_level ?? "").toLowerCase();
  if (riskKey !== "high" && riskKey !== "critical") return [];

  const rt = (
    (change.provider_metadata?.record_type as string | undefined) ?? ""
  ).toLowerCase();

  if (rt === "github_actions_secret") {
    return [
      "Confirm the rotation was intentional.",
      "Verify workflows or deployments using this secret still pass.",
      "Check GitHub audit logs for who made the change.",
      "Roll back or update dependent services if needed.",
    ];
  }
  if (rt === "github_webhook") {
    return [
      "Confirm the change was intentional.",
      "Verify the webhook endpoint is under your control.",
      "Check GitHub audit logs for who made the change.",
      "Test that events are being received by the correct endpoint.",
      "Restore the previous URL if this was accidental.",
    ];
  }
  if (rt === "github_branch_protection") {
    return [
      "Confirm the change was intentional.",
      "Review branch protection rules in GitHub repository settings.",
      "Check GitHub audit logs for who made the change.",
      "Verify that CI/CD gates and merge requirements are still in place.",
      "Re-enable protection if this was accidental.",
    ];
  }
  if (rt === "github_repo_settings") {
    return [
      "Confirm this change was intentional.",
      "Review whether sensitive data or proprietary code may be exposed.",
      "Check GitHub audit logs for who made the change.",
      "Change visibility back to private if this was accidental.",
    ];
  }
  if (rt.startsWith("github_")) {
    return [
      "Confirm the change was intentional.",
      "Review GitHub repository settings.",
      "Check GitHub audit logs for who made the change.",
      "Verify workflows and deployments still pass.",
      "Restore the previous setting if this was accidental.",
    ];
  }

  // Cloudflare DNS
  const recordType = ((change.provider_metadata?.record_type as string | undefined) ?? "").toUpperCase();
  const recordName = ((change.provider_metadata?.record_name as string | undefined) ?? "").toLowerCase();
  const isEmailAuth =
    (recordType === "MX") ||
    (recordType === "TXT" && ["_dmarc", "_domainkey", "spf"].some((kw) => recordName.includes(kw)));

  if (isEmailAuth) {
    return [
      "Confirm this change was intentional.",
      "Test email delivery to verify SPF, DKIM, and DMARC are still valid.",
      "Verify your email provider's DNS configuration is intact.",
      "Check Cloudflare audit logs for who made the change.",
      "Restore the record if this was accidental.",
    ];
  }
  return [
    "Confirm this change was intentional.",
    "Test the affected hostname (dig, nslookup, or browser).",
    "Verify the new target or IP address is correct.",
    "Check Cloudflare audit logs for who made the change.",
    "Roll back the DNS record if this was accidental.",
  ];
}

// ── Provider metadata context ─────────────────────────────────────────────────

const META_DISPLAY_KEYS: Array<{ key: string; label: string }> = [
  { key: "provider",      label: "Provider"      },
  { key: "resource_type", label: "Resource type" },
  { key: "record_type",   label: "Record type"   },
  { key: "record_name",   label: "Record name"   },
  { key: "record_content",label: "Content"       },
  { key: "zone_name",     label: "Zone"          },
  { key: "zone_id",       label: "Zone ID"       },
];

function ProviderMetaRows({
  metadata,
}: {
  metadata: Record<string, unknown> | null | undefined;
}) {
  if (!metadata) return null;

  const known = META_DISPLAY_KEYS.filter(
    (k) => metadata[k.key] !== undefined && metadata[k.key] !== null,
  );

  if (known.length === 0) return null;

  return (
    <div style={{ marginTop: "12px" }}>
      <p
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "6px",
          fontWeight: 500,
        }}
      >
        Context
      </p>
      {known.map(({ key, label }) => (
        <div
          key={key}
          className="flex items-baseline gap-2"
          style={{ marginBottom: "3px" }}
        >
          <span
            style={{
              width: "96px",
              flexShrink: 0,
              fontSize: "11px",
              color: "#565b6e",
            }}
          >
            {label}
          </span>
          <span
            style={{
              fontSize: "12px",
              color: "#8b90a0",
              fontFamily: "monospace",
            }}
          >
            {String(metadata[key])}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── Snapshot context panel ────────────────────────────────────────────────────

function SnapshotContextPanel({ change }: { change: ChangeDetail }) {
  const hasPrev = Boolean(change.prev_snapshot_id);
  const hasNew  = Boolean(change.new_snapshot_id);

  if (!hasPrev && !hasNew) return null;

  // Try to find the specific record within a snapshot state array.
  function findRecord(
    state: DnsRecord[] | null,
  ): Record<string, unknown> | null {
    if (!state || state.length === 0) return null;

    // 1. Match by provider external_id / record_id
    const extId =
      (change.provider_metadata as Record<string, unknown> | null)
        ?.external_id ?? null;
    if (extId) {
      const hit = state.find(
        (r) => r.record_id === extId || (r as Record<string, unknown>).id === extId,
      );
      if (hit) return hit as Record<string, unknown>;
    }

    // 2. Match by record_identifier against name field
    const hit = state.find((r) => r.name === change.record_identifier);
    if (hit) return hit as Record<string, unknown>;

    return null;
  }

  const prevRecord = findRecord(change.prev_snapshot_state ?? null);
  const newRecord  = findRecord(change.new_snapshot_state ?? null);
  const showRecords = change.change_type === "modified" && (prevRecord || newRecord);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
      {/* Snapshot timestamps + IDs */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "12px",
        }}
      >
        {hasPrev && (
          <div
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "10px 12px",
            }}
          >
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                marginBottom: "4px",
              }}
            >
              Before snapshot
            </p>
            <p
              style={{ fontSize: "13px", color: "#e8eaf0", marginBottom: "2px" }}
              title={
                change.prev_snapshot_created_at
                  ? formatAbsoluteTime(change.prev_snapshot_created_at)
                  : undefined
              }
            >
              {change.prev_snapshot_created_at
                ? formatRelativeTime(change.prev_snapshot_created_at)
                : "—"}
            </p>
            {change.prev_snapshot_id && (
              <p
                style={{
                  fontFamily: "monospace",
                  fontSize: "11px",
                  color: "#565b6e",
                }}
              >
                {formatSnapshotHash(change.prev_snapshot_id)}
              </p>
            )}
          </div>
        )}

        {hasNew && (
          <div
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              padding: "10px 12px",
            }}
          >
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                marginBottom: "4px",
              }}
            >
              After snapshot
            </p>
            <p
              style={{ fontSize: "13px", color: "#e8eaf0", marginBottom: "2px" }}
              title={
                change.new_snapshot_created_at
                  ? formatAbsoluteTime(change.new_snapshot_created_at)
                  : undefined
              }
            >
              {change.new_snapshot_created_at
                ? formatRelativeTime(change.new_snapshot_created_at)
                : "—"}
            </p>
            {change.new_snapshot_id && (
              <p
                style={{
                  fontFamily: "monospace",
                  fontSize: "11px",
                  color: "#565b6e",
                }}
              >
                {formatSnapshotHash(change.new_snapshot_id)}
              </p>
            )}
          </div>
        )}
      </div>

      {/* Specific record in both snapshots — only for "modified" changes */}
      {showRecords && (
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          <p style={{ fontSize: "12px", color: "#565b6e" }}>
            Record state at each snapshot:
          </p>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "12px",
            }}
          >
            <div>
              <p
                style={{
                  fontSize: "11px",
                  color: "#565b6e",
                  marginBottom: "6px",
                }}
              >
                Before
              </p>
              {prevRecord ? (
                <DnsRecordView record={prevRecord} tint="remove" />
              ) : (
                <p style={{ fontSize: "12px", color: "#565b6e", fontStyle: "italic" }}>
                  Record not found in snapshot.
                </p>
              )}
            </div>
            <div>
              <p
                style={{
                  fontSize: "11px",
                  color: "#565b6e",
                  marginBottom: "6px",
                }}
              >
                After
              </p>
              {newRecord ? (
                <DnsRecordView record={newRecord} tint="add" />
              ) : (
                <p style={{ fontSize: "12px", color: "#565b6e", fontStyle: "italic" }}>
                  Record not found in snapshot.
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Raw / debug section ───────────────────────────────────────────────────────

function RawSection({ change }: { change: ChangeDetail }) {
  const raw = {
    prev_value:        change.prev_value,
    new_value:         change.new_value,
    provider_metadata: change.provider_metadata,
  };

  return (
    <details
      style={{
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        overflow: "hidden",
      }}
    >
      <summary
        style={{
          padding: "10px 14px",
          fontSize: "12px",
          color: "#565b6e",
          cursor: "pointer",
          userSelect: "none",
          background: "#13151a",
          listStyle: "none",
          display: "flex",
          alignItems: "center",
          gap: "6px",
        }}
      >
        <span>▶</span>
        <span>Raw change data</span>
      </summary>
      <div style={{ background: "#0e0f11", padding: "12px 14px" }}>
        <pre
          style={{
            fontFamily: "monospace",
            fontSize: "12px",
            color: "#565b6e",
            margin: 0,
            whiteSpace: "pre-wrap",
            wordBreak: "break-all",
          }}
        >
          {JSON.stringify(raw, null, 2)}
        </pre>
      </div>
    </details>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ChangeDetailPage() {
  const params   = useParams();
  const changeId = params.changeId as string;

  const [change,  setChange]  = useState<ChangeDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);
  const { getToken, isLoaded } = useAuth();

  useEffect(() => {
    if (!changeId || !isLoaded) return;
    let cancelled = false;

    setLoading(true);
    setError(null);

    (async () => {
      try {
        const token = await getToken();
        const data = await getChange(changeId, token);
        if (!cancelled) setChange(data);
      } catch (err) {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load change.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => { cancelled = true; };
  }, [changeId, isLoaded, getToken]);

  // ── Loading ────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <>
        <PageHeader title="Change Detail" />
        <div className="px-6 py-6">
          <LoadingState />
        </div>
      </>
    );
  }

  // ── Error / 404 ────────────────────────────────────────────────────────

  if (error || !change) {
    const is404 =
      error?.includes("404") ||
      error?.toLowerCase().includes("not found");

    return (
      <>
        <PageHeader title="Change Detail" />
        <div className="px-6 py-6">
          <ErrorState
            message={
              is404
                ? "Change not found. It may belong to a different account or the ID is invalid."
                : (error ?? "An unknown error occurred.")
            }
          />
          <div className="mt-4">
            <Link
              href="/timeline"
              style={{ fontSize: "13px", color: "#4f80f7", textDecoration: "none" }}
            >
              ← Back to Timeline
            </Link>
          </div>
        </div>
      </>
    );
  }

  // ── Render ─────────────────────────────────────────────────────────────

  const riskKey       = (change.risk_level ?? "unknown").toLowerCase();
  const riskBg        = RISK_PANEL_BG[riskKey]     ?? RISK_PANEL_BG.unknown;
  const riskBorder    = RISK_PANEL_BORDER[riskKey] ?? RISK_PANEL_BORDER.unknown;
  const providerLabel = getProviderLabel(change);
  const summary       = getChangeSummary(change);
  const checks        = getSuggestedChecks(change);
  const isGitHub      = providerLabel === "GitHub repo configuration";

  return (
    <>
      <PageHeader
        title={change.record_identifier}
        description={`${changeTypeLabel(change.change_type)}${change.field_path ? ` · ${change.field_path}` : ""}`}
      />

      <div
        className="px-6 pb-10"
        style={{ display: "flex", flexDirection: "column", gap: "20px" }}
      >
        {/* ── Back link ──────────────────────────────────────────────── */}
        <div>
          <Link
            href="/timeline"
            style={{ fontSize: "13px", color: "#565b6e", textDecoration: "none" }}
          >
            ← Timeline
          </Link>
        </div>

        {/* ── Change header ───────────────────────────────────────────── */}
        <Panel>
          {/* Top row: identifier + risk badge */}
          <div
            className="flex items-start justify-between gap-4"
            style={{ marginBottom: "12px" }}
          >
            <span
              className="font-mono"
              style={{ fontSize: "15px", color: "#e8eaf0", fontWeight: 600, wordBreak: "break-all" }}
            >
              {change.record_identifier}
            </span>
            <div style={{ flexShrink: 0 }}>
              <RiskBadge level={change.risk_level} />
            </div>
          </div>

          {/* Provider label pill */}
          <div style={{ marginBottom: "10px" }}>
            <span
              style={{
                display: "inline-block",
                fontSize: "11px",
                color: "#8b90a0",
                background: "#1c1e26",
                border: "1px solid #2a2d38",
                borderRadius: "4px",
                padding: "2px 8px",
                letterSpacing: "0.03em",
              }}
            >
              {providerLabel}
            </span>
          </div>

          {/* Metadata rows */}
          <MetaRow label="Change type">
            <span
              className="uppercase tracking-wider"
              style={{ fontSize: "11px", color: "#b0b5c4" }}
            >
              {changeTypeLabel(change.change_type)}
            </span>
          </MetaRow>

          {change.field_path && (
            <MetaRow label="Field">
              <span className="font-mono" style={{ color: "#b0b5c4", fontSize: "12px" }}>
                {change.field_path}
              </span>
            </MetaRow>
          )}

          <MetaRow label="Detected">
            <span
              title={formatAbsoluteTime(change.created_at)}
              style={{ color: "#8b90a0", fontSize: "12px" }}
            >
              {formatRelativeTime(change.created_at)}{" "}
              <span style={{ color: "#565b6e" }}>
                ({formatAbsoluteTime(change.created_at)})
              </span>
            </span>
          </MetaRow>
        </Panel>

        {/* ── Summary card ────────────────────────────────────────────── */}
        <Panel>
          <p
            style={{
              fontSize: "13px",
              color: "#b0b5c4",
              lineHeight: 1.6,
              margin: 0,
            }}
          >
            {summary}
          </p>
        </Panel>

        {/* ── Risk explanation ────────────────────────────────────────── */}
        <div>
          <SectionLabel>Risk explanation</SectionLabel>
          <Panel bg={riskBg} border={riskBorder}>
            <div className="flex items-start gap-3" style={{ marginBottom: checks.length > 0 ? "14px" : "0" }}>
              <div style={{ flexShrink: 0, paddingTop: "2px" }}>
                <RiskBadge level={change.risk_level} />
              </div>
              <p
                style={{
                  fontSize: "13px",
                  color: change.risk_reason ? "#b0b5c4" : "#565b6e",
                  lineHeight: 1.6,
                  fontStyle: change.risk_reason ? "normal" : "italic",
                }}
              >
                {change.risk_reason ?? "No risk reason recorded."}
              </p>
            </div>

            {/* Suggested checks for high/critical */}
            {checks.length > 0 && (
              <div
                style={{
                  borderTop: `1px solid ${riskBorder}`,
                  paddingTop: "12px",
                  marginTop: "4px",
                }}
              >
                <p
                  style={{
                    fontSize: "11px",
                    color: "#565b6e",
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    marginBottom: "8px",
                    fontWeight: 500,
                  }}
                >
                  Suggested checks
                </p>
                <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
                  {checks.map((check, i) => (
                    <li
                      key={i}
                      style={{
                        fontSize: "13px",
                        color: "#8b90a0",
                        lineHeight: 1.6,
                        display: "flex",
                        gap: "8px",
                        marginBottom: "4px",
                      }}
                    >
                      <span style={{ flexShrink: 0, color: "#565b6e" }}>•</span>
                      <span>{check}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <ProviderMetaRows metadata={change.provider_metadata} />
          </Panel>
        </div>

        {/* ── Field-level diff ────────────────────────────────────────── */}
        <div>
          <SectionLabel>
            {change.change_type === "modified"
              ? "What changed"
              : change.change_type === "added"
              ? isGitHub ? "Configuration added" : "DNS record added"
              : isGitHub ? "Configuration removed" : "DNS record removed"}
          </SectionLabel>

          <Panel>
            {change.change_type === "modified" ? (
              <ModifiedDiffPanel change={change} />
            ) : (
              <AddedRemovedPanel change={change} isGitHub={isGitHub} />
            )}
          </Panel>
        </div>

        {/* ── Snapshot context ────────────────────────────────────────── */}
        {(change.prev_snapshot_id || change.new_snapshot_id) && (
          <div>
            <SectionLabel>Snapshot context</SectionLabel>
            <SnapshotContextPanel change={change} />
          </div>
        )}

        {/* ── Technical details (collapsed) ────────────────────────────── */}
        <div>
          <details
            style={{
              border: "1px solid #2a2d38",
              borderRadius: "6px",
              overflow: "hidden",
            }}
          >
            <summary
              style={{
                padding: "10px 14px",
                fontSize: "12px",
                color: "#565b6e",
                cursor: "pointer",
                userSelect: "none",
                background: "#13151a",
                listStyle: "none",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              <span>▶</span>
              <span>Technical details</span>
            </summary>
            <div style={{ background: "#0e0f11", padding: "14px 16px" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                {[
                  { label: "Change ID",       value: String(change.id) },
                  { label: "Resource ID",     value: change.resource_id },
                  { label: "Integration ID",  value: change.integration_id },
                  ...(change.prev_snapshot_id
                    ? [{ label: "Before snapshot", value: change.prev_snapshot_id }]
                    : []),
                  ...(change.new_snapshot_id
                    ? [{ label: "After snapshot",  value: change.new_snapshot_id }]
                    : []),
                ].map(({ label, value }) => (
                  <div key={label} className="flex items-baseline gap-3">
                    <span
                      style={{
                        width: "120px",
                        flexShrink: 0,
                        fontSize: "11px",
                        color: "#565b6e",
                        textTransform: "uppercase",
                        letterSpacing: "0.06em",
                      }}
                    >
                      {label}
                    </span>
                    <span
                      className="font-mono"
                      style={{ fontSize: "11px", color: "#565b6e", wordBreak: "break-all" }}
                    >
                      {value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </details>
        </div>

        {/* ── Raw / debug ─────────────────────────────────────────────── */}
        <div>
          <RawSection change={change} />
        </div>
      </div>
    </>
  );
}
