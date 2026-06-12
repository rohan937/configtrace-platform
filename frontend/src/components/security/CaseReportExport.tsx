"use client";

/**
 * CaseReportExport (M66.9).
 *
 * Export buttons for a case's metadata-only evidence report: Markdown / JSON
 * download + copy executive summary. Fetches the server-built report payload
 * (already privacy-filtered) and formats it client-side.
 */

import { useState, useCallback } from "react";
import { useAuth } from "@clerk/nextjs";

import { getSecurityCaseReport } from "@/lib/api";
import {
  caseReportToMarkdown,
  caseReportToJSON,
  caseReportExecutiveSummary,
  caseReportFileStem,
  downloadText,
} from "@/lib/caseReportExport";
import { SectionLabel } from "@/components/security/previews";

export default function CaseReportExport({ caseId }: { caseId: string }) {
  const { getToken } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const run = useCallback(
    async (kind: "markdown" | "json" | "summary") => {
      setBusy(true);
      setError(null);
      setNote(null);
      try {
        const token = await getToken();
        const report = await getSecurityCaseReport(caseId, token);
        const stem = caseReportFileStem(report);
        if (kind === "markdown") {
          downloadText(`${stem}.md`, caseReportToMarkdown(report), "text/markdown");
          setNote("Report generated from metadata-only evidence.");
        } else if (kind === "json") {
          downloadText(`${stem}.json`, caseReportToJSON(report), "application/json");
          setNote("Report generated from metadata-only evidence.");
        } else {
          await navigator.clipboard.writeText(caseReportExecutiveSummary(report));
          setNote("Executive summary copied.");
        }
      } catch {
        setError("Could not generate the report. Please try again.");
      } finally {
        setBusy(false);
      }
    },
    [getToken, caseId],
  );

  return (
    <div style={{ marginBottom: "22px" }}>
      <SectionLabel>Evidence report</SectionLabel>
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginTop: "8px" }}>
        <Btn label="Export Markdown" onClick={() => run("markdown")} disabled={busy} />
        <Btn label="Export JSON" onClick={() => run("json")} disabled={busy} />
        <Btn label="Copy executive summary" onClick={() => run("summary")} disabled={busy} />
      </div>
      {note && <div style={{ fontSize: "11.5px", color: "#3ccf7e", marginTop: "6px" }}>{note}</div>}
      {error && <div style={{ fontSize: "12px", color: "#e84040", marginTop: "6px" }}>{error}</div>}
    </div>
  );
}

function Btn({ label, onClick, disabled }: { label: string; onClick: () => void; disabled?: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="bg-surface1 border border-border"
      style={{
        fontSize: "12.5px",
        fontWeight: 500,
        color: disabled ? "#565b6e" : "#c4c8d4",
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
