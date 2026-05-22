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

function AddedRemovedPanel({ change }: { change: ChangeDetail }) {
  const isAdded   = change.change_type === "added";
  const record    = isAdded ? change.new_value : change.prev_value;
  const tint      = isAdded ? "add" : "remove";
  const label     = isAdded ? "Record Added" : "Record Removed";
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

  const riskKey    = (change.risk_level ?? "unknown").toLowerCase();
  const riskBg     = RISK_PANEL_BG[riskKey]     ?? RISK_PANEL_BG.unknown;
  const riskBorder = RISK_PANEL_BORDER[riskKey] ?? RISK_PANEL_BORDER.unknown;

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

          <MetaRow label="Resource ID">
            <span className="font-mono" style={{ color: "#565b6e", fontSize: "11px" }}>
              {change.resource_id}
            </span>
          </MetaRow>

          <MetaRow label="Integration">
            <span className="font-mono" style={{ color: "#565b6e", fontSize: "11px" }}>
              {change.integration_id}
            </span>
          </MetaRow>
        </Panel>

        {/* ── Risk explanation ────────────────────────────────────────── */}
        <div>
          <SectionLabel>Risk explanation</SectionLabel>
          <Panel bg={riskBg} border={riskBorder}>
            <div className="flex items-start gap-3">
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

            <ProviderMetaRows metadata={change.provider_metadata} />
          </Panel>
        </div>

        {/* ── Field-level diff ────────────────────────────────────────── */}
        <div>
          <SectionLabel>
            {change.change_type === "modified"
              ? "Field change"
              : change.change_type === "added"
              ? "Added record"
              : "Removed record"}
          </SectionLabel>

          <Panel>
            {change.change_type === "modified" ? (
              <ModifiedDiffPanel change={change} />
            ) : (
              <AddedRemovedPanel change={change} />
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

        {/* ── Raw / debug ─────────────────────────────────────────────── */}
        <div>
          <RawSection change={change} />
        </div>
      </div>
    </>
  );
}
