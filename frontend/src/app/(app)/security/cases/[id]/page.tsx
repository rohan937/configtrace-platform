"use client";

/**
 * Case detail (M66.8).
 *
 * A human-managed investigation: grouped evidence, an evidence timeline, and
 * status actions (investigating / dismissed / resolved / confirmed-by-user).
 *
 * CLAIM DISCIPLINE: a case may contain evidence that may require review.
 * ConfigTrace does not automatically confirm breaches or unauthorized access.
 * "Confirmed by user" is a human workflow status, never "confirmed breach".
 */

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "@clerk/nextjs";

import type { SecurityCaseDetail, SecurityCaseLink } from "@/types";
import { getSecurityCase, updateSecurityCase } from "@/lib/api";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { formatRelativeTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";
import { SeverityBadge, ConfidenceBadge } from "@/components/security/findingDisplay";
import { CaseStatusBadge } from "@/components/security/signalDisplay";
import CaseReportExport from "@/components/security/CaseReportExport";

const LINK_ROUTE: Record<string, string> = {
  signal: "/security/signals",
  correlation: "/security/correlations",
  finding: "/security/risks",
  activity_event: "/security/activity",
};
const LINK_LABEL: Record<string, string> = {
  signal: "Incident signals",
  correlation: "Correlations",
  finding: "Configuration risks",
  activity_event: "Activity events",
};
const GROUP_ORDER = ["signal", "correlation", "finding", "activity_event"];

export default function CaseDetailPage() {
  const params = useParams();
  const id = Array.isArray(params?.id) ? params.id[0] : (params?.id as string);
  const { getToken } = useAuth();
  const { isAdmin } = useWorkspace();

  const [detail, setDetail] = useState<SecurityCaseDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const res = await getSecurityCase(id, token);
      setDetail(res);
    } catch {
      setError("This case could not be found, or you do not have access to it.");
    } finally {
      setLoading(false);
    }
  }, [getToken, id]);

  useEffect(() => {
    void load();
  }, [load]);

  const setStatus = useCallback(
    async (status: string) => {
      setBusy(true);
      setActionError(null);
      try {
        const token = await getToken();
        await updateSecurityCase(id, { status }, token);
        await load();
      } catch {
        setActionError(
          status === "confirmed_by_user"
            ? "Could not confirm. Only workspace admins can confirm a case."
            : "Could not update the case. Please try again.",
        );
      } finally {
        setBusy(false);
      }
    },
    [getToken, id, load],
  );

  return (
    <div>
      <Link href="/security/cases" style={{ fontSize: "13px", color: "#6b9cf8", textDecoration: "none" }}>
        ← Back to Cases
      </Link>

      {loading ? (
        <div style={{ marginTop: "16px" }}>
          <LoadingState message="Loading case…" />
        </div>
      ) : error || !detail ? (
        <div style={{ marginTop: "16px" }}>
          <ErrorState message={error ?? "Case not found."} />
        </div>
      ) : (
        <Body
          detail={detail}
          isAdmin={isAdmin}
          busy={busy}
          actionError={actionError}
          onStatus={setStatus}
        />
      )}
    </div>
  );
}

function Body({
  detail,
  isAdmin,
  busy,
  actionError,
  onStatus,
}: {
  detail: SecurityCaseDetail;
  isAdmin: boolean;
  busy: boolean;
  actionError: string | null;
  onStatus: (status: string) => void;
}) {
  const c = detail.case;
  const links = detail.links;
  const grouped = GROUP_ORDER.map((t) => ({
    type: t,
    items: links.filter((l) => l.linked_object_type === t),
  })).filter((g) => g.items.length > 0);

  return (
    <div style={{ marginTop: "12px" }}>
      <PageHeader title={c.title} />

      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "18px" }}>
        <SeverityBadge severity={c.severity} />
        <CaseStatusBadge status={c.status} />
        <ConfidenceBadge confidence={c.confidence} />
        {c.provider && <Chip>{c.provider}</Chip>}
        <Chip>{links.length} linked</Chip>
      </div>

      {c.summary && (
        <div className="bg-surface1 border border-border" style={{ borderRadius: "12px", padding: "16px 18px", marginBottom: "18px" }}>
          <p style={{ margin: 0, fontSize: "14px", color: "#c4c8d4", lineHeight: 1.6 }}>{c.summary}</p>
        </div>
      )}

      {/* Status actions */}
      <div style={{ marginBottom: "22px" }}>
        <SectionLabel>Investigation status</SectionLabel>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginTop: "8px" }}>
          <ActionButton label="Mark investigating" onClick={() => onStatus("investigating")} disabled={busy} />
          <ActionButton label="Resolve" onClick={() => onStatus("resolved")} disabled={busy} />
          <ActionButton label="Dismiss" onClick={() => onStatus("dismissed")} disabled={busy} />
          <ActionButton
            label="Confirm by user"
            onClick={() => onStatus("confirmed_by_user")}
            disabled={busy || !isAdmin}
            title={!isAdmin ? "Only workspace admins can confirm a case." : undefined}
            accent
          />
        </div>
        {!isAdmin && (
          <div style={{ fontSize: "11.5px", color: "#565b6e", marginTop: "6px" }}>
            Only workspace admins can mark a case “confirmed by user”.
          </div>
        )}
        {actionError && <div style={{ fontSize: "12px", color: "#e84040", marginTop: "6px" }}>{actionError}</div>}
        {(c.confirmed_at || c.dismissed_at || c.resolved_at) && (
          <div style={{ fontSize: "11.5px", color: "#8b90a0", marginTop: "8px" }}>
            {c.confirmed_at && <div>Confirmed by user {formatRelativeTime(c.confirmed_at)}.</div>}
            {c.dismissed_at && <div>Dismissed {formatRelativeTime(c.dismissed_at)}.</div>}
            {c.resolved_at && <div>Resolved {formatRelativeTime(c.resolved_at)}.</div>}
          </div>
        )}
      </div>

      {/* Evidence report export (M66.9) */}
      <CaseReportExport caseId={c.id} />

      {/* Linked evidence, grouped */}
      {grouped.length === 0 ? (
        <div style={{ marginBottom: "22px" }}>
          <SectionLabel>Linked evidence</SectionLabel>
          <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>
            No evidence linked yet. Open an incident signal or correlation and
            choose “Create case”, or link evidence by id.
          </div>
        </div>
      ) : (
        grouped.map((g) => (
          <div key={g.type} style={{ marginBottom: "18px" }}>
            <SectionLabel>{LINK_LABEL[g.type] ?? g.type}</SectionLabel>
            <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "8px" }}>
              {g.items.map((l) => (
                <LinkRow key={l.id} link={l} />
              ))}
            </div>
          </div>
        ))
      )}

      {/* Evidence timeline */}
      <div style={{ marginBottom: "22px" }}>
        <SectionLabel>Evidence timeline</SectionLabel>
        <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "8px" }}>
          <TimelineRow when={c.created_at} label="Case created" />
          {[...links]
            .sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at))
            .map((l) => (
              <TimelineRow
                key={l.id}
                when={l.created_at}
                label={`Linked ${LINK_LABEL[l.linked_object_type]?.toLowerCase() ?? l.linked_object_type}`}
              />
            ))}
          {c.confirmed_at && <TimelineRow when={c.confirmed_at} label="Confirmed by user" />}
          {c.dismissed_at && <TimelineRow when={c.dismissed_at} label="Dismissed" />}
          {c.resolved_at && <TimelineRow when={c.resolved_at} label="Resolved" />}
        </div>
      </div>

      {/* Claim note */}
      <div style={{ borderRadius: "10px", background: "rgba(107,156,248,0.06)", border: "1px solid rgba(107,156,248,0.22)", padding: "12px 14px" }}>
        <p style={{ margin: 0, fontSize: "12.5px", color: "#8b90a0", lineHeight: 1.6 }}>
          This case groups evidence that may require review. ConfigTrace does not
          automatically confirm compromise or unauthorized access. “Confirmed by
          user” reflects a human decision, not an automated breach determination.
        </p>
      </div>
    </div>
  );
}

function LinkRow({ link }: { link: SecurityCaseLink }) {
  const base = LINK_ROUTE[link.linked_object_type];
  const href = base ? `${base}/${link.linked_object_id}` : null;
  return (
    <div className="bg-surface1 border border-border" style={{ borderRadius: "10px", padding: "10px 12px", display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
      <span style={{ fontSize: "12px", color: "#8b90a0", fontFamily: "monospace", flex: 1, minWidth: 0, wordBreak: "break-all" }}>
        {link.linked_object_id}
      </span>
      {href && (
        <Link href={href} style={{ fontSize: "12px", color: "#6b9cf8", textDecoration: "none" }}>
          Open →
        </Link>
      )}
    </div>
  );
}

function TimelineRow({ when, label }: { when: string | null; label: string }) {
  return (
    <div style={{ display: "flex", gap: "10px", fontSize: "12.5px", flexWrap: "wrap" }}>
      <span style={{ color: "#565b6e", minWidth: "150px" }}>{when ? formatRelativeTime(when) : "—"}</span>
      <span style={{ color: "#c4c8d4" }}>{label}</span>
    </div>
  );
}

function ActionButton({
  label,
  onClick,
  disabled,
  title,
  accent,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  title?: string;
  accent?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="bg-surface1 border border-border"
      style={{
        fontSize: "12.5px",
        fontWeight: 500,
        color: disabled ? "#565b6e" : accent ? "#e84040" : "#c4c8d4",
        borderRadius: "8px",
        padding: "7px 14px",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.6 : 1,
      }}
    >
      {label}
    </button>
  );
}

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span style={{ fontSize: "11px", fontWeight: 600, color: "#8b90a0", background: "rgba(139,144,160,0.12)", borderRadius: "6px", padding: "2px 8px", whiteSpace: "nowrap" }}>
      {children}
    </span>
  );
}
