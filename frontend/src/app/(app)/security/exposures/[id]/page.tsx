"use client";

/**
 * Exposure Detail (M60.6).
 *
 * A deep-linkable investigation packet for a single security exposure finding,
 * backed by GET /security/findings/{id} (getSecurityFinding). Read-only:
 * mutation/review workflows (acknowledge/snooze/accept) arrive in a later
 * milestone and are shown here only as informational placeholders.
 */

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "@clerk/nextjs";

import type {
  SecurityFinding,
  SecurityFindingNote,
  SecurityFindingActivityItem,
} from "@/types";
import {
  getSecurityFinding,
  acceptSecurityFindingRisk,
  acknowledgeSecurityFinding,
  snoozeSecurityFinding,
  getSecurityFindingNotes,
  createSecurityFindingNote,
  getSecurityFindingActivity,
} from "@/lib/api";
import { getProviderMeta } from "@/lib/providers";
import { trackSecurityBetaEvent } from "@/lib/securityBetaEvents";
import { formatAbsoluteTime } from "@/lib/utils";

import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";
import { SectionLabel } from "@/components/security/previews";
import {
  EvidenceBlock,
  FindingStatusBadge,
  ConfidenceBadge,
  CONFIDENCE_LABEL,
  RemediationBlock,
  SeverityBadge,
  formatExposureDuration,
  sevColor,
} from "@/components/security/findingDisplay";

// ── Page ─────────────────────────────────────────────────────────────────────

export default function ExposureDetailPage() {
  const params = useParams();
  const id = Array.isArray(params?.id) ? params.id[0] : (params?.id as string);
  const { getToken } = useAuth();

  const [finding, setFinding] = useState<SecurityFinding | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const f = await getSecurityFinding(id, token);
      setFinding(f);
      trackSecurityBetaEvent(
        "security_exposure_opened",
        { finding_id: f.id, severity: f.severity, status: f.status, provider: f.provider },
        { getToken, pagePath: "/security/exposures/[id]" },
      );
    } catch {
      // 404 / unauthorized / network all surface as a not-found state.
      setError("This exposure could not be found, or you do not have access to it.");
      setFinding(null);
    } finally {
      setLoading(false);
    }
  }, [id, getToken]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div>
      <BackLink />

      {loading ? (
        <>
          <PageHeader title="Exposure Detail" />
          <LoadingState message="Loading exposure…" />
        </>
      ) : error || !finding ? (
        <>
          <PageHeader title="Exposure Detail" />
          <ErrorState message={error ?? "Exposure not found."} />
        </>
      ) : (
        <ExposureBody finding={finding} onUpdated={setFinding} />
      )}
    </div>
  );
}

function BackLink() {
  return (
    <Link
      href="/security/exposures"
      style={{
        display: "inline-block",
        fontSize: "13px",
        color: "#6b9cf8",
        textDecoration: "none",
        marginBottom: "16px",
      }}
    >
      ← Back to Active Exposures
    </Link>
  );
}

// ── Body ──────────────────────────────────────────────────────────────────────

function ExposureBody({
  finding,
  onUpdated,
}: {
  finding: SecurityFinding;
  onUpdated: (f: SecurityFinding) => void;
}) {
  const provider = getProviderMeta(finding.provider);
  const c = sevColor(finding.severity);
  const duration = formatExposureDuration(finding);
  const resourceLabel = finding.resource_id ?? "—";
  const isAccepted = finding.status === "accepted_risk";
  const isSnoozed = finding.status === "snoozed";

  return (
    <div>
      {/* Header */}
      <div
        className="bg-surface1 border border-border"
        style={{
          borderRadius: "12px",
          overflow: "hidden",
          display: "flex",
          marginBottom: "20px",
        }}
      >
        <div style={{ width: "4px", background: c, flexShrink: 0 }} />
        <div style={{ flex: 1, padding: "18px 20px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
            <SeverityBadge severity={finding.severity} />
            <FindingStatusBadge status={finding.status} />
            <span style={{ fontSize: "12px", color: provider.color, fontWeight: 600 }}>
              {provider.shortLabel}
            </span>
          </div>
          <h1
            style={{
              fontSize: "22px",
              fontWeight: 600,
              color: "#e8eaf0",
              margin: "12px 0 0",
              letterSpacing: "-0.01em",
            }}
          >
            {finding.title}
          </h1>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "8px",
              marginTop: "10px",
              fontSize: "12px",
              color: "#8b90a0",
            }}
          >
            <span style={{ fontFamily: "monospace", color: "#565b6e" }}>
              {finding.finding_key}
            </span>
            {duration ? (
              <>
                <span style={{ color: "#3a3d4a" }}>·</span>
                <span>{duration}</span>
              </>
            ) : null}
          </div>
        </div>
      </div>

      {/* Header facts grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: "12px",
          marginBottom: "24px",
        }}
      >
        <Fact label="Provider" value={provider.shortLabel} />
        <Fact label="Status" value={finding.status} />
        <Fact label="Resource" value={resourceLabel} mono />
        <Fact label="First detected" value={formatAbsoluteTime(finding.first_detected_at)} />
        <Fact label="Last seen" value={formatAbsoluteTime(finding.last_seen_at)} />
        {finding.status === "resolved" && finding.resolved_at ? (
          <Fact label="Resolved at" value={formatAbsoluteTime(finding.resolved_at)} />
        ) : null}
        {isAccepted && finding.accepted_until ? (
          <Fact label="Accepted until" value={formatAbsoluteTime(finding.accepted_until)} />
        ) : null}
        {isSnoozed && finding.snoozed_until ? (
          <Fact label="Snoozed until" value={formatAbsoluteTime(finding.snoozed_until)} />
        ) : null}
      </div>

      {/* 1. What is exposed */}
      <Panel>
        <SectionLabel>What is exposed?</SectionLabel>
        <p style={{ fontSize: "14px", color: "#c4c8d4", lineHeight: 1.6, marginTop: "8px" }}>
          {finding.description || finding.title}
        </p>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: "10px",
            marginTop: "14px",
          }}
        >
          <Fact label="Provider" value={provider.label} inset />
          <Fact label="Finding key" value={finding.finding_key} mono inset />
          <Fact label="Resource" value={resourceLabel} mono inset />
          <Fact label="Integration" value={finding.integration_id} mono inset />
        </div>
      </Panel>

      {/* 2. Why it matters */}
      <Panel severity={finding.severity}>
        <SectionLabel>Why it matters</SectionLabel>
        <p style={{ fontSize: "14px", color: "#c4c8d4", lineHeight: 1.65, marginTop: "8px" }}>
          {finding.description ||
            "This configuration state may weaken security controls. Review the evidence below to confirm the impact."}
        </p>
        <p style={{ fontSize: "12px", color: "#565b6e", lineHeight: 1.6, marginTop: "12px" }}>
          ConfigTrace reports security-relevant configuration exposure from provider
          settings. This is a risky current state, not a confirmed compromise.
        </p>
      </Panel>

      {/* 2b. Confidence & safeguards (M62.4) */}
      <Panel>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <SectionLabel>Confidence &amp; safeguards</SectionLabel>
          <ConfidenceBadge confidence={finding.confidence} />
        </div>
        <p style={{ fontSize: "13px", color: "#c4c8d4", lineHeight: 1.6, marginTop: "10px" }}>
          {CONFIDENCE_LABEL[finding.confidence] ?? finding.confidence}.{" "}
          {finding.confidence_reason ||
            "Backed by provider configuration metadata."}
        </p>
        {finding.false_positive_guard ? (
          <p style={{ fontSize: "12.5px", color: "#8b90a0", lineHeight: 1.6, marginTop: "8px" }}>
            <span style={{ color: "#565b6e" }}>How this rule avoids noisy cases: </span>
            {finding.false_positive_guard}
          </p>
        ) : null}
        <p style={{ fontSize: "12px", color: "#565b6e", lineHeight: 1.6, marginTop: "10px" }}>
          Confidence describes how ConfigTrace reached this finding from provider
          metadata. It is not a measure of severity and not proof of an exploit.
        </p>
      </Panel>

      {/* 3. Evidence */}
      <Panel>
        {finding.evidence ? (
          <EvidenceBlock evidence={finding.evidence} />
        ) : (
          <>
            <SectionLabel>Evidence</SectionLabel>
            <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>
              No evidence was recorded for this finding.
            </div>
          </>
        )}
      </Panel>

      {/* 4. Suggested remediation */}
      <Panel>
        {finding.remediation ? (
          <RemediationBlock remediation={finding.remediation} />
        ) : (
          <>
            <SectionLabel>Suggested remediation</SectionLabel>
            <div style={{ fontSize: "12.5px", color: "#565b6e", marginTop: "6px" }}>
              No remediation guidance is available for this finding.
            </div>
          </>
        )}
      </Panel>

      {/* 5. Exposure lifecycle */}
      <Panel>
        <SectionLabel>Exposure lifecycle</SectionLabel>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
            gap: "10px",
            marginTop: "12px",
          }}
        >
          <Fact label="Status" value={finding.status} inset />
          <Fact label="First detected" value={formatAbsoluteTime(finding.first_detected_at)} inset />
          <Fact label="Last seen" value={formatAbsoluteTime(finding.last_seen_at)} inset />
          {finding.resolved_at ? (
            <Fact label="Resolved at" value={formatAbsoluteTime(finding.resolved_at)} inset />
          ) : null}
        </div>
        {duration ? (
          <div
            style={{
              marginTop: "14px",
              display: "inline-block",
              fontSize: "13px",
              fontWeight: 600,
              color: finding.status === "resolved" ? "#3ccf7e" : c,
              background: finding.status === "resolved" ? "rgba(60,207,126,0.12)" : `${c}1f`,
              border: `1px solid ${finding.status === "resolved" ? "rgba(60,207,126,0.4)" : `${c}55`}`,
              borderRadius: "8px",
              padding: "6px 12px",
            }}
          >
            {duration}
          </div>
        ) : null}
      </Panel>

      {/* 6. Linked drift event */}
      <Panel>
        <SectionLabel>Linked drift event</SectionLabel>
        {finding.linked_change_id ? (
          <div style={{ marginTop: "10px" }}>
            <p style={{ fontSize: "13px", color: "#c4c8d4", lineHeight: 1.6, marginBottom: "10px" }}>
              This exposure was associated with a configuration change.
            </p>
            <Link
              href={`/changes/${finding.linked_change_id}`}
              style={{
                display: "inline-block",
                fontSize: "13px",
                fontWeight: 600,
                color: "#6b9cf8",
                textDecoration: "none",
                border: "1px solid #2a2d38",
                borderRadius: "8px",
                padding: "8px 14px",
              }}
            >
              View drift change {finding.linked_change_id.slice(0, 8)}… →
            </Link>
          </div>
        ) : (
          <p style={{ fontSize: "13px", color: "#8b90a0", lineHeight: 1.6, marginTop: "8px" }}>
            No linked drift event was attached. This can happen when the risky state
            existed at baseline or no matching change was available.
          </p>
        )}
      </Panel>

      {/* 7. Accepted risk record (shown once a risk has been accepted) */}
      {isAccepted ? (
        <Panel>
          <SectionLabel>Accepted risk</SectionLabel>
          <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "8px 0 12px", lineHeight: 1.6 }}>
            The team is intentionally carrying this exposure until the date below.
            Accepting risk does not mark the exposure fixed.
          </p>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: "10px",
            }}
          >
            {finding.accepted_until ? (
              <Fact label="Accepted until" value={formatAbsoluteTime(finding.accepted_until)} inset />
            ) : null}
            {finding.reviewed_at ? (
              <Fact label="Accepted at" value={formatAbsoluteTime(finding.reviewed_at)} inset />
            ) : null}
          </div>
          {finding.acceptance_reason ? (
            <div style={{ marginTop: "12px" }}>
              <SectionLabel>Reason</SectionLabel>
              <p style={{ fontSize: "13px", color: "#c4c8d4", lineHeight: 1.6, marginTop: "6px", whiteSpace: "pre-wrap" }}>
                {finding.acceptance_reason}
              </p>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {/* 7b. Snoozed record (shown while a finding is snoozed) */}
      {isSnoozed ? (
        <Panel>
          <SectionLabel>Snoozed</SectionLabel>
          <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "8px 0 12px", lineHeight: 1.6 }}>
            Active attention on this exposure is paused until the time below.
            Snoozing does not accept the risk or mark the exposure fixed.
          </p>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: "10px",
            }}
          >
            {finding.snoozed_until ? (
              <Fact label="Snoozed until" value={formatAbsoluteTime(finding.snoozed_until)} inset />
            ) : null}
            {finding.reviewed_at ? (
              <Fact label="Snoozed at" value={formatAbsoluteTime(finding.reviewed_at)} inset />
            ) : null}
          </div>
        </Panel>
      ) : null}

      {/* 8. Review actions */}
      <Panel>
        <SectionLabel>Review actions</SectionLabel>
        <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "8px 0 14px", lineHeight: 1.6 }}>
          None of these mark the exposure fixed or resolved.
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <AcknowledgeAction finding={finding} onUpdated={onUpdated} />
          <SnoozeAction finding={finding} onUpdated={onUpdated} />
          <AcceptRiskAction finding={finding} onUpdated={onUpdated} />
        </div>
      </Panel>

      {/* 9. Review notes + activity (M61.3) */}
      <NotesAndActivity finding={finding} />
    </div>
  );
}

// ── Accept Risk action ────────────────────────────────────────────────────────

function defaultAcceptedUntil(): string {
  // Default the date picker to 30 days out (local date, YYYY-MM-DD).
  const d = new Date();
  d.setDate(d.getDate() + 30);
  return d.toISOString().slice(0, 10);
}

function AcceptRiskAction({
  finding,
  onUpdated,
}: {
  finding: SecurityFinding;
  onUpdated: (f: SecurityFinding) => void;
}) {
  const { getToken } = useAuth();
  const isAccepted = finding.status === "accepted_risk";
  const isResolved = finding.status === "resolved";

  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState(defaultAcceptedUntil());
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const reasonValid = reason.trim().length >= 5;
  const untilValid = (() => {
    if (!until) return false;
    const t = new Date(`${until}T23:59:59`).getTime();
    return !Number.isNaN(t) && t > Date.now();
  })();

  async function submit() {
    if (!reasonValid || !untilValid) return;
    setBusy(true);
    setErr(null);
    trackSecurityBetaEvent("security_exposure_action_clicked", { action: "accept_risk", finding_id: finding.id }, { getToken, pagePath: "/security/exposures/[id]" });
    try {
      const token = await getToken();
      // Send end-of-day in the user's local zone so "today" is never in the past.
      const acceptedUntilIso = new Date(`${until}T23:59:59`).toISOString();
      const updated = await acceptSecurityFindingRisk(
        finding.id,
        { reason: reason.trim(), accepted_until: acceptedUntilIso },
        token,
      );
      onUpdated(updated);
      setOpen(false);
      setReason("");
      trackSecurityBetaEvent("security_exposure_action_completed", { action: "accept_risk", finding_id: finding.id, result: "ok" }, { getToken, pagePath: "/security/exposures/[id]" });
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to accept risk.");
    } finally {
      setBusy(false);
    }
  }

  if (isResolved) {
    return (
      <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "8px 0 0", lineHeight: 1.6 }}>
        This exposure is resolved. Resolved exposures cannot be accepted as risk.
      </p>
    );
  }

  const btnPrimary: React.CSSProperties = {
    fontSize: "13px",
    fontWeight: 600,
    color: "#f5a623",
    background: "rgba(245,166,35,0.12)",
    border: "1px solid rgba(245,166,35,0.4)",
    borderRadius: "8px",
    padding: "8px 14px",
    cursor: "pointer",
    fontFamily: "inherit",
  };
  const inputStyle: React.CSSProperties = {
    background: "#1c1e26",
    border: "1px solid #3a3d4a",
    borderRadius: "6px",
    padding: "8px 10px",
    fontSize: "13px",
    color: "#e2e5ef",
    fontFamily: "inherit",
    width: "100%",
    boxSizing: "border-box",
  };

  if (!open) {
    return (
      <div style={{ marginTop: "8px" }}>
        <button type="button" style={btnPrimary} onClick={() => { setOpen(true); setErr(null); }}>
          {isAccepted ? "Update accepted risk" : "Accept risk"}
        </button>
        <p style={{ fontSize: "12px", color: "#8b90a0", margin: "10px 0 0", lineHeight: 1.6 }}>
          Accepting risk does not mark the exposure fixed. It records that the team
          is intentionally carrying this risk until the chosen date.
        </p>
      </div>
    );
  }

  return (
    <div
      style={{
        marginTop: "10px",
        background: "#1a1d28",
        border: "1px solid #3a3d4a",
        borderRadius: "8px",
        padding: "14px",
      }}
    >
      <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "0 0 12px", lineHeight: 1.6 }}>
        Accepting risk does not mark the exposure fixed. It records that the team is
        intentionally carrying this risk until the chosen date.
      </p>

      <label style={{ display: "block", fontSize: "12px", color: "#8b90a0", marginBottom: "5px" }}>
        Reason <span style={{ color: "#f5a623" }}>*</span>
      </label>
      <textarea
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        rows={3}
        maxLength={1000}
        placeholder="Why is the team intentionally carrying this risk?"
        style={{ ...inputStyle, resize: "vertical", marginBottom: "4px" }}
      />
      <p style={{ fontSize: "11px", color: reasonValid ? "#565b6e" : "#e07a5f", margin: "0 0 12px" }}>
        At least 5 characters required.
      </p>

      <label style={{ display: "block", fontSize: "12px", color: "#8b90a0", marginBottom: "5px" }}>
        Accepted until <span style={{ color: "#f5a623" }}>*</span>
      </label>
      <input
        type="date"
        value={until}
        onChange={(e) => setUntil(e.target.value)}
        style={{ ...inputStyle, marginBottom: "4px" }}
      />
      <p style={{ fontSize: "11px", color: untilValid ? "#565b6e" : "#e07a5f", margin: "0 0 12px" }}>
        Must be a future date.
      </p>

      {err ? (
        <p style={{ fontSize: "12px", color: "#e07a5f", margin: "0 0 10px" }}>{err}</p>
      ) : null}

      <div style={{ display: "flex", gap: "8px" }}>
        <button
          type="button"
          style={{ ...btnPrimary, opacity: busy || !reasonValid || !untilValid ? 0.5 : 1, cursor: busy || !reasonValid || !untilValid ? "not-allowed" : "pointer" }}
          disabled={busy || !reasonValid || !untilValid}
          onClick={submit}
        >
          {busy ? "Saving…" : isAccepted ? "Update acceptance" : "Confirm accept risk"}
        </button>
        <button
          type="button"
          style={{
            fontSize: "13px",
            fontWeight: 600,
            color: "#8b90a0",
            background: "none",
            border: "1px solid #2a2d38",
            borderRadius: "8px",
            padding: "8px 14px",
            cursor: "pointer",
            fontFamily: "inherit",
          }}
          onClick={() => { setOpen(false); setErr(null); }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ── Acknowledge action ────────────────────────────────────────────────────────

function AcknowledgeAction({
  finding,
  onUpdated,
}: {
  finding: SecurityFinding;
  onUpdated: (f: SecurityFinding) => void;
}) {
  const { getToken } = useAuth();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Acknowledge applies only to active findings (accepted_risk / snoozed /
  // resolved are already explicit states — the backend rejects them).
  if (finding.status !== "active") return null;

  const alreadyAcknowledged = finding.reviewed_at != null;

  async function submit() {
    setBusy(true);
    setErr(null);
    trackSecurityBetaEvent("security_exposure_action_clicked", { action: "acknowledge", finding_id: finding.id }, { getToken, pagePath: "/security/exposures/[id]" });
    try {
      const token = await getToken();
      const updated = await acknowledgeSecurityFinding(finding.id, token);
      onUpdated(updated);
      setOpen(false);
      trackSecurityBetaEvent("security_exposure_action_completed", { action: "acknowledge", finding_id: finding.id, result: "ok" }, { getToken, pagePath: "/security/exposures/[id]" });
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to acknowledge.");
    } finally {
      setBusy(false);
    }
  }

  const btn: React.CSSProperties = {
    fontSize: "13px",
    fontWeight: 600,
    color: "#3ccf7e",
    background: "rgba(60,207,126,0.12)",
    border: "1px solid rgba(60,207,126,0.4)",
    borderRadius: "8px",
    padding: "8px 14px",
    cursor: "pointer",
    fontFamily: "inherit",
  };

  if (!open) {
    return (
      <div>
        <button type="button" style={btn} onClick={() => { setOpen(true); setErr(null); }}>
          {alreadyAcknowledged ? "Re-acknowledge" : "Acknowledge"}
        </button>
        {alreadyAcknowledged && finding.reviewed_at ? (
          <p style={{ fontSize: "12px", color: "#3ccf7e", margin: "8px 0 0" }}>
            ✓ Acknowledged {formatAbsoluteTime(finding.reviewed_at)} — still active.
          </p>
        ) : (
          <p style={{ fontSize: "12px", color: "#8b90a0", margin: "8px 0 0", lineHeight: 1.6 }}>
            Records that your team has reviewed the exposure. It does not mark the
            exposure fixed.
          </p>
        )}
      </div>
    );
  }

  return (
    <div
      style={{
        background: "#1a1d28",
        border: "1px solid #3a3d4a",
        borderRadius: "8px",
        padding: "14px",
      }}
    >
      <p style={{ fontSize: "13px", color: "#c4c8d4", margin: "0 0 4px", fontWeight: 600 }}>
        Acknowledge this exposure?
      </p>
      <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "0 0 12px", lineHeight: 1.6 }}>
        This records that your team has reviewed the exposure. It does not mark the
        exposure fixed. The exposure stays active.
      </p>
      {err ? <p style={{ fontSize: "12px", color: "#e07a5f", margin: "0 0 10px" }}>{err}</p> : null}
      <div style={{ display: "flex", gap: "8px" }}>
        <button
          type="button"
          style={{ ...btn, opacity: busy ? 0.5 : 1, cursor: busy ? "not-allowed" : "pointer" }}
          disabled={busy}
          onClick={submit}
        >
          {busy ? "Saving…" : "Confirm acknowledge"}
        </button>
        <button
          type="button"
          style={{
            fontSize: "13px", fontWeight: 600, color: "#8b90a0", background: "none",
            border: "1px solid #2a2d38", borderRadius: "8px", padding: "8px 14px",
            cursor: "pointer", fontFamily: "inherit",
          }}
          onClick={() => { setOpen(false); setErr(null); }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ── Snooze action ─────────────────────────────────────────────────────────────

function plusHoursLocal(hours: number): string {
  // Returns a value suitable for <input type="datetime-local"> (local, no tz).
  const d = new Date();
  d.setHours(d.getHours() + hours);
  d.setSeconds(0, 0);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function SnoozeAction({
  finding,
  onUpdated,
}: {
  finding: SecurityFinding;
  onUpdated: (f: SecurityFinding) => void;
}) {
  const { getToken } = useAuth();
  const [open, setOpen] = useState(false);
  const [until, setUntil] = useState(() => plusHoursLocal(24 * 7));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Snooze applies only to active findings (the backend rejects resolved and
  // accepted_risk; a snoozed finding already shows its snooze elsewhere).
  if (finding.status !== "active") return null;

  const untilValid = (() => {
    if (!until) return false;
    const t = new Date(until).getTime();
    return !Number.isNaN(t) && t > Date.now();
  })();

  async function submit() {
    if (!untilValid) return;
    setBusy(true);
    setErr(null);
    trackSecurityBetaEvent("security_exposure_action_clicked", { action: "snooze", finding_id: finding.id }, { getToken, pagePath: "/security/exposures/[id]" });
    try {
      const token = await getToken();
      const snoozedUntilIso = new Date(until).toISOString();
      const updated = await snoozeSecurityFinding(
        finding.id,
        { snoozed_until: snoozedUntilIso },
        token,
      );
      onUpdated(updated);
      setOpen(false);
      trackSecurityBetaEvent("security_exposure_action_completed", { action: "snooze", finding_id: finding.id, result: "ok" }, { getToken, pagePath: "/security/exposures/[id]" });
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to snooze.");
    } finally {
      setBusy(false);
    }
  }

  const btn: React.CSSProperties = {
    fontSize: "13px",
    fontWeight: 600,
    color: "#8b90a0",
    background: "rgba(148,163,184,0.08)",
    border: "1px solid #3a3d4a",
    borderRadius: "8px",
    padding: "8px 14px",
    cursor: "pointer",
    fontFamily: "inherit",
  };
  const quick: React.CSSProperties = {
    fontSize: "12px", fontWeight: 600, color: "#8b90a0", background: "none",
    border: "1px solid #2a2d38", borderRadius: "6px", padding: "5px 10px",
    cursor: "pointer", fontFamily: "inherit",
  };
  const inputStyle: React.CSSProperties = {
    background: "#1c1e26", border: "1px solid #3a3d4a", borderRadius: "6px",
    padding: "8px 10px", fontSize: "13px", color: "#e2e5ef", fontFamily: "inherit",
    width: "100%", boxSizing: "border-box",
  };

  if (!open) {
    return (
      <div>
        <button type="button" style={btn} onClick={() => { setOpen(true); setErr(null); }}>
          Snooze
        </button>
        <p style={{ fontSize: "12px", color: "#8b90a0", margin: "8px 0 0", lineHeight: 1.6 }}>
          Pauses active attention until the selected time. It does not accept the
          risk or mark it fixed.
        </p>
      </div>
    );
  }

  return (
    <div
      style={{
        background: "#1a1d28", border: "1px solid #3a3d4a", borderRadius: "8px",
        padding: "14px",
      }}
    >
      <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "0 0 12px", lineHeight: 1.6 }}>
        Snoozing pauses active attention on this exposure until the selected time.
        It does not accept the risk or mark it fixed.
      </p>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginBottom: "10px" }}>
        <button type="button" style={quick} onClick={() => setUntil(plusHoursLocal(24))}>24 hours</button>
        <button type="button" style={quick} onClick={() => setUntil(plusHoursLocal(24 * 7))}>7 days</button>
        <button type="button" style={quick} onClick={() => setUntil(plusHoursLocal(24 * 30))}>30 days</button>
      </div>
      <label style={{ display: "block", fontSize: "12px", color: "#8b90a0", marginBottom: "5px" }}>
        Snooze until <span style={{ color: "#8b90a0" }}>*</span>
      </label>
      <input
        type="datetime-local"
        value={until}
        onChange={(e) => setUntil(e.target.value)}
        style={{ ...inputStyle, marginBottom: "4px" }}
      />
      <p style={{ fontSize: "11px", color: untilValid ? "#565b6e" : "#e07a5f", margin: "0 0 12px" }}>
        Must be a future time.
      </p>
      {err ? <p style={{ fontSize: "12px", color: "#e07a5f", margin: "0 0 10px" }}>{err}</p> : null}
      <div style={{ display: "flex", gap: "8px" }}>
        <button
          type="button"
          style={{ ...btn, opacity: busy || !untilValid ? 0.5 : 1, cursor: busy || !untilValid ? "not-allowed" : "pointer" }}
          disabled={busy || !untilValid}
          onClick={submit}
        >
          {busy ? "Saving…" : "Confirm snooze"}
        </button>
        <button
          type="button"
          style={{
            fontSize: "13px", fontWeight: 600, color: "#8b90a0", background: "none",
            border: "1px solid #2a2d38", borderRadius: "8px", padding: "8px 14px",
            cursor: "pointer", fontFamily: "inherit",
          }}
          onClick={() => { setOpen(false); setErr(null); }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ── Review notes + activity (M61.3) ───────────────────────────────────────────

const _NOTE_MAX = 2000;

function actorLabel(actorUserId: string | null): string {
  return actorUserId ? "Team member" : "ConfigTrace";
}

function NotesAndActivity({ finding }: { finding: SecurityFinding }) {
  const { getToken } = useAuth();
  const [notes, setNotes] = useState<SecurityFindingNote[]>([]);
  const [activity, setActivity] = useState<SecurityFindingActivityItem[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Re-fetch whenever the finding identity or its lifecycle stamp changes, so
  // the activity feed reflects acknowledge/snooze/accept actions immediately.
  const stamp = `${finding.id}:${finding.status}:${finding.reviewed_at ?? ""}:${finding.resolved_at ?? ""}`;

  const load = useCallback(async () => {
    try {
      const token = await getToken();
      const [n, a] = await Promise.all([
        getSecurityFindingNotes(finding.id, token),
        getSecurityFindingActivity(finding.id, token),
      ]);
      setNotes(n.items);
      setActivity(a.items);
    } catch {
      // Non-fatal — leave existing state; the add-note path surfaces errors.
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finding.id, getToken, stamp]);

  useEffect(() => {
    void load();
  }, [load]);

  const draftTrimmed = draft.trim();
  const draftValid = draftTrimmed.length >= 2 && draftTrimmed.length <= _NOTE_MAX;

  async function addNote() {
    if (!draftValid) return;
    setBusy(true);
    setErr(null);
    try {
      const token = await getToken();
      const created = await createSecurityFindingNote(finding.id, draftTrimmed, token);
      setNotes((prev) => [...prev, created]);
      setDraft("");
      trackSecurityBetaEvent("security_note_added", { finding_id: finding.id }, { getToken, pagePath: "/security/exposures/[id]" });
      // Refresh activity so the new note appears in the feed too.
      void load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to add note.");
    } finally {
      setBusy(false);
    }
  }

  const inputStyle: React.CSSProperties = {
    background: "#1c1e26", border: "1px solid #3a3d4a", borderRadius: "6px",
    padding: "8px 10px", fontSize: "13px", color: "#e2e5ef", fontFamily: "inherit",
    width: "100%", boxSizing: "border-box", resize: "vertical",
  };

  return (
    <>
      {/* Review notes */}
      <Panel>
        <SectionLabel>Review notes</SectionLabel>
        <p style={{ fontSize: "12px", color: "#565b6e", margin: "6px 0 12px", lineHeight: 1.6 }}>
          Capture investigation context without changing the finding status.
        </p>

        {notes.length === 0 ? (
          <div style={{ fontSize: "12.5px", color: "#565b6e", marginBottom: "14px" }}>
            <div style={{ color: "#8b90a0", fontWeight: 600 }}>No review notes yet.</div>
            <div style={{ marginTop: "4px" }}>
              Use notes to capture investigation context without changing the
              finding status.
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginBottom: "14px" }}>
            {notes.map((n) => (
              <div
                key={n.id}
                style={{
                  background: "#16181f", border: "1px solid #23252e",
                  borderRadius: "8px", padding: "10px 12px",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", gap: "10px", marginBottom: "4px" }}>
                  <span style={{ fontSize: "12px", fontWeight: 600, color: "#c4c8d4" }}>
                    {actorLabel(n.author_user_id)}
                  </span>
                  <span style={{ fontSize: "11px", color: "#565b6e" }}>
                    {formatAbsoluteTime(n.created_at)}
                  </span>
                </div>
                <p style={{ fontSize: "13px", color: "#c4c8d4", lineHeight: 1.6, margin: 0, whiteSpace: "pre-wrap" }}>
                  {n.body}
                </p>
              </div>
            ))}
          </div>
        )}

        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={3}
          maxLength={_NOTE_MAX}
          placeholder="Add investigation context, owner handoff, or follow-up notes…"
          style={{ ...inputStyle, marginBottom: "6px" }}
        />
        {err ? <p style={{ fontSize: "12px", color: "#e07a5f", margin: "0 0 8px" }}>{err}</p> : null}
        <button
          type="button"
          onClick={addNote}
          disabled={busy || !draftValid}
          style={{
            fontSize: "13px", fontWeight: 600, color: "#6b9cf8",
            background: "rgba(107,156,248,0.12)", border: "1px solid rgba(107,156,248,0.4)",
            borderRadius: "8px", padding: "8px 14px", fontFamily: "inherit",
            opacity: busy || !draftValid ? 0.5 : 1,
            cursor: busy || !draftValid ? "not-allowed" : "pointer",
          }}
        >
          {busy ? "Adding…" : "Add note"}
        </button>
      </Panel>

      {/* Activity */}
      <Panel>
        <SectionLabel>Activity</SectionLabel>
        <p style={{ fontSize: "12px", color: "#565b6e", margin: "6px 0 12px", lineHeight: 1.6 }}>
          A chronological record of review and lifecycle actions, newest first.
        </p>
        {activity.length === 0 ? (
          <div style={{ fontSize: "12.5px", color: "#565b6e" }}>No activity yet.</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "0" }}>
            {activity.map((item, i) => (
              <div
                key={`${item.type}:${item.timestamp ?? ""}:${i}`}
                style={{
                  display: "flex", gap: "10px", padding: "8px 0",
                  borderTop: i === 0 ? "none" : "1px solid #1d1f27",
                }}
              >
                <span
                  style={{
                    width: "7px", height: "7px", borderRadius: "50%",
                    background: ACTIVITY_DOT[item.type] ?? "#8b90a0",
                    marginTop: "6px", flexShrink: 0,
                  }}
                />
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: "10px" }}>
                    <span style={{ fontSize: "13px", fontWeight: 600, color: "#e2e5ef" }}>
                      {item.title}
                    </span>
                    <span style={{ fontSize: "11px", color: "#565b6e", flexShrink: 0 }}>
                      {item.timestamp ? formatAbsoluteTime(item.timestamp) : "—"}
                    </span>
                  </div>
                  {item.description ? (
                    <p style={{ fontSize: "12.5px", color: "#8b90a0", lineHeight: 1.55, margin: "2px 0 0", whiteSpace: "pre-wrap" }}>
                      {item.description}
                    </p>
                  ) : null}
                  <span style={{ fontSize: "11px", color: "#565b6e" }}>
                    {actorLabel(item.actor_user_id)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}

const ACTIVITY_DOT: Record<string, string> = {
  exposure_opened: "#f5632a",
  acknowledged: "#3ccf7e",
  snoozed: "#8b90a0",
  accepted_risk: "#f5a623",
  resolved: "#3ccf7e",
  note_added: "#6b9cf8",
};

// ── Small building blocks ─────────────────────────────────────────────────────

function Panel({
  children,
  severity,
}: {
  children: React.ReactNode;
  severity?: string;
}) {
  const border = severity ? `${sevColor(severity)}55` : "#2a2d38";
  return (
    <div
      className="bg-surface1"
      style={{
        border: `1px solid ${border}`,
        borderRadius: "12px",
        padding: "18px 20px",
        marginBottom: "16px",
      }}
    >
      {children}
    </div>
  );
}

function Fact({
  label,
  value,
  mono,
  inset,
}: {
  label: string;
  value: string;
  mono?: boolean;
  inset?: boolean;
}) {
  return (
    <div
      className={inset ? undefined : "bg-surface1 border border-border"}
      style={
        inset
          ? undefined
          : { borderRadius: "10px", padding: "12px 14px" }
      }
    >
      <div style={{ fontSize: "11px", color: "#565b6e", marginBottom: "3px" }}>
        {label}
      </div>
      <div
        style={{
          fontSize: "13px",
          color: "#c4c8d4",
          fontFamily: mono ? "monospace" : undefined,
          wordBreak: "break-all",
          textTransform: mono ? undefined : "capitalize",
        }}
      >
        {value}
      </div>
    </div>
  );
}
