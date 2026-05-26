"use client";

import { useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { createWorkspace, patchWorkspace } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";

// ── Hub card definitions ──────────────────────────────────────────────────────

const HUB_CARDS = [
  {
    href: "/settings/workspace/members",
    title: "Members & Invites",
    description: "Manage team members, roles, and pending invitations.",
    color: "#4f80f7",
  },
  {
    href: "/settings/workspace/audit",
    title: "Audit Log",
    description: "Review workspace events: member changes, integrations, billing.",
    color: "#3ccf7e",
  },
  {
    href: "/settings/workspace/billing",
    title: "Billing & Plan",
    description: "View your current plan, usage limits, and upgrade options.",
    color: "#f5a623",
  },
  {
    href: "/settings/workspace/notifications",
    title: "Notifications",
    description: "Configure Slack and webhook alerts for configuration drift.",
    color: "#8b5cf6",
  },
  {
    href: "/settings/workspace/data-access",
    title: "Trust Center",
    description: "Review provider permissions, read boundaries, and export a security packet.",
    color: "#b0b5c4",
  },
  {
    href: "/settings/workspace/policies",
    title: "Policies",
    description: "Enable or disable built-in policy checks for configuration drift violations.",
    color: "#e84040",
  },
  {
    href: "/settings/workspace/expected-changes",
    title: "Expected Changes",
    description: "Approve planned change windows so expected drift is annotated, not alarming.",
    color: "#3ccf7e",
  },
  {
    href: "/dashboard",
    title: "Drift Control Score",
    description: "See your workspace's 0–100 drift control score — review hygiene and alert coverage at a glance.",
    color: "#4f80f7",
  },
  {
    href: "/settings/workspace/iac",
    title: "IaC Awareness",
    description: "Map monitored resources to Terraform files so risky drift can be fixed in code.",
    color: "#8b5cf6",
  },
] as const;

// ── Inline message banners ────────────────────────────────────────────────────

function ErrorBanner({ message }: { message: string }) {
  return (
    <div
      role="alert"
      style={{
        background: "#2a1a1a",
        border: "1px solid #7a2a2a",
        borderRadius: "6px",
        padding: "10px 14px",
        color: "#f87171",
        fontSize: "13px",
        marginBottom: "16px",
      }}
    >
      {message}
    </div>
  );
}

function SuccessBanner({ message }: { message: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        background: "#1a2a1a",
        border: "1px solid #2a5a2a",
        borderRadius: "6px",
        padding: "10px 14px",
        color: "#4ade80",
        fontSize: "13px",
        marginBottom: "16px",
      }}
    >
      {message}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function WorkspaceSettingsPage() {
  const { getToken } = useAuth();
  const {
    workspaces,
    selectedWorkspace,
    selectWorkspace,
    refreshWorkspaces,
  } = useWorkspace();

  const [renaming, setRenaming]     = useState(false);
  const [newName, setNewName]       = useState("");
  const [creating, setCreating]     = useState(false);
  const [createName, setCreateName] = useState("");
  const [error, setError]           = useState<string | null>(null);
  const [success, setSuccess]       = useState<string | null>(null);
  const [busy, setBusy]             = useState(false);

  async function handleRename(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedWorkspace || !newName.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const token = await getToken();
      await patchWorkspace(selectedWorkspace.id, newName.trim(), token);
      await refreshWorkspaces();
      setRenaming(false);
      setSuccess("Workspace renamed.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to rename.");
    } finally {
      setBusy(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!createName.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const token = await getToken();
      const ws = await createWorkspace(createName.trim(), token);
      await refreshWorkspaces();
      selectWorkspace(ws.id);
      setCreating(false);
      setCreateName("");
      setSuccess(`Workspace "${ws.name}" created and selected.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Workspace"
        description="Manage your team, audit log, billing, and data access settings."
      />

      <div className="px-6 pb-8" style={{ maxWidth: "680px" }}>
        {error   && <ErrorBanner   message={error}   />}
        {success && <SuccessBanner message={success} />}

        {/* ── Current workspace ─────────────────────────────────────── */}
        {selectedWorkspace && (
          <section
            aria-labelledby="section-current-ws"
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: "8px",
              padding: "20px",
              marginBottom: "20px",
            }}
          >
            {/* Name row */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: renaming ? "12px" : "16px",
              }}
            >
              <div>
                <p
                  id="section-current-ws"
                  style={{ fontSize: "11px", color: "#565b6e", margin: "0 0 3px" }}
                >
                  Current workspace
                </p>
                <p
                  style={{ fontSize: "17px", fontWeight: 600, color: "#e8eaf0", margin: 0 }}
                >
                  {selectedWorkspace.name}
                </p>
              </div>
              {!renaming && (
                <button
                  onClick={() => {
                    setRenaming(true);
                    setNewName(selectedWorkspace.name);
                    setSuccess(null);
                  }}
                  style={{
                    fontSize: "12px",
                    color: "#4f80f7",
                    background: "none",
                    border: "1px solid rgba(79,128,247,0.40)",
                    borderRadius: "5px",
                    padding: "4px 10px",
                    cursor: "pointer",
                    fontFamily: "inherit",
                  }}
                >
                  Rename
                </button>
              )}
            </div>

            {/* Rename form */}
            {renaming && (
              <form onSubmit={handleRename} style={{ display: "flex", gap: "8px", marginBottom: "16px" }}>
                <input
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  aria-label="New workspace name"
                  style={{
                    flex: 1,
                    background: "#1a1d28",
                    border: "1px solid #3a3d4a",
                    borderRadius: "5px",
                    padding: "6px 10px",
                    fontSize: "13px",
                    color: "#e2e5ef",
                    fontFamily: "inherit",
                    outline: "none",
                  }}
                  autoFocus
                />
                <button
                  type="submit"
                  disabled={busy || !newName.trim()}
                  style={{
                    background: "#4f80f7",
                    color: "#fff",
                    border: "none",
                    borderRadius: "5px",
                    padding: "6px 14px",
                    fontSize: "13px",
                    cursor: busy || !newName.trim() ? "not-allowed" : "pointer",
                    opacity: busy ? 0.7 : 1,
                    fontFamily: "inherit",
                  }}
                >
                  Save
                </button>
                <button
                  type="button"
                  onClick={() => setRenaming(false)}
                  style={{
                    background: "none",
                    color: "#8b90a0",
                    border: "1px solid #2a2d38",
                    borderRadius: "5px",
                    padding: "6px 10px",
                    fontSize: "13px",
                    cursor: "pointer",
                    fontFamily: "inherit",
                  }}
                >
                  Cancel
                </button>
              </form>
            )}

            {/* Hub cards */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "10px",
              }}
            >
              {HUB_CARDS.map((card) => (
                <Link
                  key={card.href}
                  href={card.href}
                  style={{
                    display: "block",
                    background: "#1a1d28",
                    border: "1px solid #2a2d38",
                    borderRadius: "6px",
                    padding: "12px 14px",
                    textDecoration: "none",
                    transition: "border-color 0.15s",
                  }}
                  className="hover:bg-surface3"
                >
                  <div
                    style={{
                      fontSize: "13px",
                      fontWeight: 500,
                      color: card.color,
                      marginBottom: "4px",
                    }}
                  >
                    {card.title} →
                  </div>
                  <div
                    style={{
                      fontSize: "12px",
                      color: "#565b6e",
                      lineHeight: 1.5,
                    }}
                  >
                    {card.description}
                  </div>
                </Link>
              ))}
            </div>
          </section>
        )}

        {/* ── All workspaces ────────────────────────────────────────── */}
        <section
          aria-labelledby="section-all-ws"
          style={{
            background: "#13151a",
            border: "1px solid #2a2d38",
            borderRadius: "8px",
            padding: "20px",
            marginBottom: "20px",
          }}
        >
          <h2
            id="section-all-ws"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: "#c4c8d4",
              margin: "0 0 12px",
            }}
          >
            All workspaces ({workspaces.length})
          </h2>

          {workspaces.length === 0 ? (
            <p style={{ fontSize: "13px", color: "#565b6e", margin: 0 }}>
              No workspaces found.
            </p>
          ) : (
            <ul role="list" style={{ margin: 0, padding: 0, listStyle: "none" }}>
              {workspaces.map((ws, i) => (
                <li
                  key={ws.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "8px 0",
                    borderBottom: i < workspaces.length - 1 ? "1px solid #1e2130" : "none",
                  }}
                >
                  <span style={{ fontSize: "13px", color: "#c4c8d4" }}>
                    {ws.name}
                  </span>
                  {ws.id === selectedWorkspace?.id ? (
                    <span style={{ fontSize: "11px", color: "#4f80f7", padding: "2px 6px" }}>
                      ✓ Selected
                    </span>
                  ) : (
                    <button
                      onClick={() => {
                        selectWorkspace(ws.id);
                        setSuccess(`Switched to "${ws.name}".`);
                      }}
                      style={{
                        fontSize: "11px",
                        color: "#4f80f7",
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                        padding: "2px 6px",
                        fontFamily: "inherit",
                      }}
                    >
                      Switch
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* ── Create workspace ──────────────────────────────────────── */}
        <section
          aria-labelledby="section-create-ws"
          style={{
            background: "#13151a",
            border: "1px solid #2a2d38",
            borderRadius: "8px",
            padding: "20px",
          }}
        >
          <h2
            id="section-create-ws"
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: "#c4c8d4",
              margin: "0 0 12px",
            }}
          >
            Create a new workspace
          </h2>
          {!creating ? (
            <button
              onClick={() => { setCreating(true); setSuccess(null); }}
              style={{
                background: "#4f80f7",
                color: "#fff",
                border: "none",
                borderRadius: "6px",
                padding: "8px 18px",
                fontSize: "13px",
                cursor: "pointer",
                fontFamily: "inherit",
              }}
            >
              + New workspace
            </button>
          ) : (
            <form onSubmit={handleCreate} style={{ display: "flex", gap: "8px" }}>
              <input
                placeholder="Workspace name"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                aria-label="New workspace name"
                style={{
                  flex: 1,
                  background: "#1a1d28",
                  border: "1px solid #3a3d4a",
                  borderRadius: "5px",
                  padding: "6px 10px",
                  fontSize: "13px",
                  color: "#e2e5ef",
                  fontFamily: "inherit",
                }}
                autoFocus
              />
              <button
                type="submit"
                disabled={busy || !createName.trim()}
                style={{
                  background: "#4f80f7",
                  color: "#fff",
                  border: "none",
                  borderRadius: "5px",
                  padding: "6px 14px",
                  fontSize: "13px",
                  cursor: busy || !createName.trim() ? "not-allowed" : "pointer",
                  opacity: busy ? 0.7 : 1,
                  fontFamily: "inherit",
                }}
              >
                Create
              </button>
              <button
                type="button"
                onClick={() => setCreating(false)}
                style={{
                  background: "none",
                  color: "#8b90a0",
                  border: "1px solid #2a2d38",
                  borderRadius: "5px",
                  padding: "6px 10px",
                  fontSize: "13px",
                  cursor: "pointer",
                  fontFamily: "inherit",
                }}
              >
                Cancel
              </button>
            </form>
          )}
        </section>
      </div>
    </>
  );
}
