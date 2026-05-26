"use client";

/**
 * IaC Awareness settings page — M58.18.
 *
 * Allows workspace admins to:
 * - Register GitHub repositories for Terraform scanning
 * - View scan status and discovered resource mappings
 * - Trigger manual scans
 *
 * Safety notice (shown in UI):
 * - Only safe metadata is stored: file paths, resource block types/names, line ranges
 * - Full file contents are NEVER stored
 * - tfstate/tfvars files are NEVER read
 * - No secrets or credentials are stored
 */

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import type { IacRepository, IacScanResult } from "@/types";
import {
  listIacRepositories,
  registerIacRepository,
  scanIacRepository,
} from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import LoadingState from "@/components/common/LoadingState";

// ── Style helpers ─────────────────────────────────────────────────────────────

const CARD: React.CSSProperties = {
  background: "#13151a",
  border: "1px solid #2a2d38",
  borderRadius: "6px",
  padding: "18px 20px",
  marginBottom: "16px",
};

const LABEL: React.CSSProperties = {
  fontSize: "11px",
  color: "#565b6e",
  fontWeight: 600,
  textTransform: "uppercase",
  letterSpacing: "0.06em",
  marginBottom: "12px",
};

// ── Scan status badge ─────────────────────────────────────────────────────────

const SCAN_STATUS_STYLE: Record<string, { color: string; label: string }> = {
  success:       { color: "#3ccf7e", label: "Scanned" },
  pending:       { color: "#f5a623", label: "Pending" },
  no_integration:{ color: "#f5a623", label: "No integration" },
  no_access:     { color: "#f5632a", label: "No access" },
  no_tf_files:   { color: "#8b90a0", label: "No .tf files" },
  error:         { color: "#f5632a", label: "Error" },
};

function ScanStatusBadge({ status }: { status: string | null }) {
  if (!status) return <span style={{ fontSize: "12px", color: "#565b6e" }}>Not scanned</span>;
  const s = SCAN_STATUS_STYLE[status] ?? { color: "#8b90a0", label: status };
  return (
    <span style={{ fontSize: "11px", color: s.color, fontWeight: 600 }}>
      {s.label}
    </span>
  );
}

// ── Repository card ───────────────────────────────────────────────────────────

function RepositoryCard({
  repo,
  onScan,
  scanning,
  scanResult,
}: {
  repo: IacRepository;
  onScan: (repoId: string) => void;
  scanning: boolean;
  scanResult: IacScanResult | null;
}) {
  return (
    <div
      style={{
        background: "#0d0f14",
        border: "1px solid #2a2d38",
        borderRadius: "5px",
        padding: "14px 16px",
        marginBottom: "10px",
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "12px" }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <p style={{ margin: 0, fontSize: "13px", color: "#c4c8d4", fontWeight: 500 }}>
            {repo.repo_full_name}
          </p>
          <p style={{ margin: "2px 0 0", fontSize: "12px", color: "#565b6e" }}>
            Branch: {repo.default_branch ?? "main"} ·{" "}
            <ScanStatusBadge status={repo.last_scan_status} />
            {repo.last_scan_at && (
              <span style={{ color: "#3a3d4a" }}>
                {" · "}Last scanned{" "}
                {new Date(repo.last_scan_at).toLocaleDateString()}
              </span>
            )}
          </p>
          {repo.last_error && (
            <p style={{ margin: "4px 0 0", fontSize: "11px", color: "#f5632a" }}>
              {repo.last_error}
            </p>
          )}
          {scanResult && (
            <p
              style={{
                margin: "6px 0 0",
                fontSize: "11px",
                color: scanResult.status === "success" ? "#3ccf7e" : "#f5a623",
              }}
            >
              {scanResult.message}
              {scanResult.status === "success" && (
                <span>
                  {" "}· {scanResult.resources_found} resource block(s) found in{" "}
                  {scanResult.files_scanned} file(s).
                </span>
              )}
            </p>
          )}
          {repo.last_scan_status === "no_access" && (
            <p style={{ margin: "6px 0 0", fontSize: "11px", color: "#f5a623" }}>
              IaC scanning requires GitHub Contents read permission on the linked integration.
            </p>
          )}
        </div>
        <button
          onClick={() => onScan(repo.id)}
          disabled={scanning}
          style={{
            background: scanning ? "#1e2130" : "#1a2a4a",
            color: scanning ? "#565b6e" : "#4f80f7",
            border: "1px solid #2a3d5a",
            borderRadius: "5px",
            padding: "6px 12px",
            fontSize: "12px",
            cursor: scanning ? "not-allowed" : "pointer",
            fontFamily: "inherit",
            flexShrink: 0,
          }}
        >
          {scanning ? "Scanning…" : "Scan now"}
        </button>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function IacSettingsPage() {
  const { getToken } = useAuth();
  const { selectedWorkspace } = useWorkspace();

  const [repos, setRepos] = useState<IacRepository[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Register form state
  const [registering, setRegistering] = useState(false);
  const [repoName, setRepoName] = useState("");
  const [busy, setBusy] = useState(false);

  // Per-repo scan state
  const [scanningRepo, setScanningRepo] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<Record<string, IacScanResult>>({});

  const loadRepos = useCallback(async () => {
    if (!selectedWorkspace) return;
    try {
      const token = await getToken();
      const resp = await listIacRepositories(selectedWorkspace.id, token);
      setRepos(resp.repositories);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load repositories.");
    } finally {
      setLoading(false);
    }
  }, [selectedWorkspace, getToken]);

  useEffect(() => {
    void loadRepos();
  }, [loadRepos]);

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedWorkspace || !repoName.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const token = await getToken();
      await registerIacRepository(
        selectedWorkspace.id,
        { repo_full_name: repoName.trim(), scanning_enabled: true },
        token,
      );
      setSuccess(`Repository "${repoName.trim()}" registered.`);
      setRepoName("");
      setRegistering(false);
      await loadRepos();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to register repository.");
    } finally {
      setBusy(false);
    }
  }

  async function handleScan(repoId: string) {
    if (!selectedWorkspace) return;
    setScanningRepo(repoId);
    setError(null);
    try {
      const token = await getToken();
      const result = await scanIacRepository(selectedWorkspace.id, repoId, token);
      setScanResults((prev) => ({ ...prev, [repoId]: result }));
      // Refresh the list to pick up updated scan status
      await loadRepos();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed.");
    } finally {
      setScanningRepo(null);
    }
  }

  return (
    <>
      <PageHeader
        title="IaC Awareness"
        description="Map monitored resources to Terraform files so risky drift can be fixed in code."
      />

      <div className="px-6 pb-8" style={{ maxWidth: "700px" }}>
        {/* ── Back link ──────────────────────────────────────────────── */}
        <div style={{ marginBottom: "16px" }}>
          <Link
            href="/settings/workspace"
            style={{ fontSize: "13px", color: "#565b6e", textDecoration: "none" }}
          >
            ← Workspace settings
          </Link>
        </div>

        {/* ── Safety notice ─────────────────────────────────────────── */}
        <div
          style={{
            background: "#0e1120",
            border: "1px solid #252a42",
            borderRadius: "6px",
            padding: "12px 16px",
            marginBottom: "20px",
          }}
        >
          <p style={{ ...LABEL, marginBottom: "6px" }}>Data safety</p>
          <ul style={{ margin: 0, padding: "0 0 0 16px", fontSize: "12px", color: "#8b90a0", lineHeight: 1.8 }}>
            <li>Only safe metadata is stored: file paths, resource block types, names, and approximate line numbers.</li>
            <li>Full Terraform file contents are <strong>never</strong> stored.</li>
            <li>
              <code style={{ fontFamily: "monospace", fontSize: "11px" }}>.tfstate</code>,{" "}
              <code style={{ fontFamily: "monospace", fontSize: "11px" }}>.tfvars</code>, and{" "}
              <code style={{ fontFamily: "monospace", fontSize: "11px" }}>.terraform/</code> files are{" "}
              <strong>never</strong> read.
            </li>
            <li>No secrets, credentials, or provider API keys are stored.</li>
            <li>IaC context is advisory only — ConfigTrace does not execute Terraform or mutate provider resources.</li>
          </ul>
        </div>

        {/* ── Error / success ────────────────────────────────────────── */}
        {error && (
          <div
            style={{
              background: "#2a1a1a",
              border: "1px solid #7a2a2a",
              borderRadius: "5px",
              padding: "10px 14px",
              color: "#f87171",
              fontSize: "13px",
              marginBottom: "14px",
            }}
          >
            {error}
          </div>
        )}
        {success && (
          <div
            style={{
              background: "#1a2a1a",
              border: "1px solid #2a5a2a",
              borderRadius: "5px",
              padding: "10px 14px",
              color: "#4ade80",
              fontSize: "13px",
              marginBottom: "14px",
            }}
          >
            {success}
          </div>
        )}

        {/* ── Repositories ───────────────────────────────────────────── */}
        <div style={CARD}>
          <p style={LABEL}>Registered repositories</p>

          {loading && <LoadingState />}

          {!loading && repos.length === 0 && (
            <p style={{ fontSize: "13px", color: "#565b6e", margin: "0 0 12px" }}>
              No repositories registered yet. Add a GitHub repository below to begin IaC scanning.
            </p>
          )}

          {!loading && repos.map((repo) => (
            <RepositoryCard
              key={repo.id}
              repo={repo}
              onScan={handleScan}
              scanning={scanningRepo === repo.id}
              scanResult={scanResults[repo.id] ?? null}
            />
          ))}

          {/* Register form */}
          {!registering ? (
            <button
              onClick={() => { setRegistering(true); setSuccess(null); }}
              style={{
                background: "#4f80f7",
                color: "#fff",
                border: "none",
                borderRadius: "5px",
                padding: "8px 16px",
                fontSize: "13px",
                cursor: "pointer",
                fontFamily: "inherit",
                marginTop: repos.length > 0 ? "8px" : "0",
              }}
            >
              + Add repository
            </button>
          ) : (
            <form onSubmit={handleRegister} style={{ display: "flex", flexDirection: "column", gap: "10px", marginTop: "12px" }}>
              <div>
                <label
                  htmlFor="repo-name-input"
                  style={{ fontSize: "12px", color: "#8b90a0", display: "block", marginBottom: "4px" }}
                >
                  GitHub repository (owner/repo)
                </label>
                <input
                  id="repo-name-input"
                  placeholder="acme/infrastructure"
                  value={repoName}
                  onChange={(e) => setRepoName(e.target.value)}
                  style={{
                    width: "100%",
                    background: "#1a1d28",
                    border: "1px solid #3a3d4a",
                    borderRadius: "5px",
                    padding: "7px 10px",
                    fontSize: "13px",
                    color: "#e2e5ef",
                    fontFamily: "inherit",
                    boxSizing: "border-box",
                  }}
                  autoFocus
                />
                <p style={{ fontSize: "11px", color: "#565b6e", margin: "4px 0 0" }}>
                  The repository must be linked to an active GitHub integration for scanning to work.
                </p>
              </div>
              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  type="submit"
                  disabled={busy || !repoName.trim()}
                  style={{
                    background: "#4f80f7",
                    color: "#fff",
                    border: "none",
                    borderRadius: "5px",
                    padding: "7px 16px",
                    fontSize: "13px",
                    cursor: busy || !repoName.trim() ? "not-allowed" : "pointer",
                    opacity: busy ? 0.7 : 1,
                    fontFamily: "inherit",
                  }}
                >
                  Register
                </button>
                <button
                  type="button"
                  onClick={() => setRegistering(false)}
                  style={{
                    background: "none",
                    color: "#8b90a0",
                    border: "1px solid #2a2d38",
                    borderRadius: "5px",
                    padding: "7px 12px",
                    fontSize: "13px",
                    cursor: "pointer",
                    fontFamily: "inherit",
                  }}
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>

        {/* ── Coming soon note ───────────────────────────────────────── */}
        <div
          style={{
            background: "#0e1120",
            border: "1px solid #252a42",
            borderRadius: "6px",
            padding: "14px 16px",
          }}
        >
          <p style={{ ...LABEL, marginBottom: "6px" }}>Coming in M58.19+</p>
          <ul style={{ margin: 0, padding: "0 0 0 16px", fontSize: "12px", color: "#565b6e", lineHeight: 1.8 }}>
            <li><strong style={{ color: "#8b90a0" }}>M58.19</strong> — Terraform fix suggestion preview</li>
            <li><strong style={{ color: "#8b90a0" }}>M58.20</strong> — GitHub PR draft flow</li>
            <li><strong style={{ color: "#8b90a0" }}>M58.21</strong> — Full Terraform / GitHub PR suggestions</li>
          </ul>
        </div>
      </div>
    </>
  );
}
