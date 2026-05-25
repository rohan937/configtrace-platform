"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@clerk/nextjs";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { createWorkspace, patchWorkspace } from "@/lib/api";

export default function WorkspaceSettingsPage() {
  const { getToken } = useAuth();
  const router = useRouter();
  const {
    workspaces,
    selectedWorkspace,
    selectWorkspace,
    refreshWorkspaces,
  } = useWorkspace();

  const [renaming, setRenaming] = useState(false);
  const [newName, setNewName] = useState("");
  const [creating, setCreating] = useState(false);
  const [createName, setCreateName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
    <main style={{ maxWidth: 640, margin: "0 auto", padding: "32px 24px" }}>
      <h1
        style={{
          fontSize: "20px",
          fontWeight: 600,
          color: "#e2e5ef",
          marginBottom: "24px",
        }}
      >
        Workspaces
      </h1>

      {error && (
        <div
          style={{
            background: "#2a1a1a",
            border: "1px solid #7a2a2a",
            borderRadius: 6,
            padding: "10px 14px",
            color: "#f87171",
            fontSize: 13,
            marginBottom: 16,
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
            borderRadius: 6,
            padding: "10px 14px",
            color: "#4ade80",
            fontSize: 13,
            marginBottom: 16,
          }}
        >
          {success}
        </div>
      )}

      {/* Current workspace */}
      {selectedWorkspace && (
        <section
          style={{
            background: "#13151a",
            border: "1px solid #2a2d38",
            borderRadius: 8,
            padding: "20px",
            marginBottom: "20px",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: "12px",
            }}
          >
            <div>
              <div style={{ fontSize: 11, color: "#565b6e", marginBottom: 2 }}>
                Current workspace
              </div>
              <div
                style={{ fontSize: 16, fontWeight: 600, color: "#e2e5ef" }}
              >
                {selectedWorkspace.name}
              </div>
            </div>
            <button
              onClick={() => {
                setRenaming(true);
                setNewName(selectedWorkspace.name);
                setSuccess(null);
              }}
              style={{
                fontSize: 12,
                color: "#4f80f7",
                background: "none",
                border: "1px solid #4f80f7",
                borderRadius: 5,
                padding: "4px 10px",
                cursor: "pointer",
              }}
            >
              Rename
            </button>
          </div>

          {renaming && (
            <form onSubmit={handleRename} style={{ display: "flex", gap: 8 }}>
              <input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                style={{
                  flex: 1,
                  background: "#1a1d28",
                  border: "1px solid #3a3d4a",
                  borderRadius: 5,
                  padding: "6px 10px",
                  fontSize: 13,
                  color: "#e2e5ef",
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
                  borderRadius: 5,
                  padding: "6px 14px",
                  fontSize: 13,
                  cursor: "pointer",
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
                  borderRadius: 5,
                  padding: "6px 10px",
                  fontSize: 13,
                  cursor: "pointer",
                }}
              >
                Cancel
              </button>
            </form>
          )}

          <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button
              onClick={() => router.push("/settings/workspace/members")}
              style={{
                fontSize: 12,
                color: "#8b90a0",
                background: "none",
                border: "1px solid #2a2d38",
                borderRadius: 5,
                padding: "6px 12px",
                cursor: "pointer",
              }}
            >
              Manage members &amp; invites →
            </button>
            <button
              onClick={() => router.push("/settings/workspace/billing")}
              style={{
                fontSize: 12,
                color: "#8b90a0",
                background: "none",
                border: "1px solid #2a2d38",
                borderRadius: 5,
                padding: "6px 12px",
                cursor: "pointer",
              }}
            >
              Billing &amp; plan →
            </button>
            <button
              onClick={() => router.push("/settings/workspace/audit")}
              style={{
                fontSize: 12,
                color: "#8b90a0",
                background: "none",
                border: "1px solid #2a2d38",
                borderRadius: 5,
                padding: "6px 12px",
                cursor: "pointer",
              }}
            >
              Audit log →
            </button>
          </div>
        </section>
      )}

      {/* All workspaces list */}
      <section
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: 8,
          padding: "20px",
          marginBottom: "20px",
        }}
      >
        <div
          style={{
            fontSize: 13,
            fontWeight: 500,
            color: "#c4c8d4",
            marginBottom: 12,
          }}
        >
          All workspaces ({workspaces.length})
        </div>
        {workspaces.map((ws) => (
          <div
            key={ws.id}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "8px 0",
              borderBottom: "1px solid #1e2130",
            }}
          >
            <span style={{ fontSize: 13, color: "#c4c8d4" }}>{ws.name}</span>
            {ws.id !== selectedWorkspace?.id && (
              <button
                onClick={() => {
                  selectWorkspace(ws.id);
                  setSuccess(`Switched to "${ws.name}".`);
                }}
                style={{
                  fontSize: 11,
                  color: "#4f80f7",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  padding: "2px 6px",
                }}
              >
                Switch
              </button>
            )}
            {ws.id === selectedWorkspace?.id && (
              <span
                style={{ fontSize: 11, color: "#4f80f7", padding: "2px 6px" }}
              >
                ✓ Selected
              </span>
            )}
          </div>
        ))}
      </section>

      {/* Create workspace */}
      <section
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: 8,
          padding: "20px",
        }}
      >
        <div
          style={{
            fontSize: 13,
            fontWeight: 500,
            color: "#c4c8d4",
            marginBottom: 12,
          }}
        >
          Create a new workspace
        </div>
        {!creating ? (
          <button
            onClick={() => {
              setCreating(true);
              setSuccess(null);
            }}
            style={{
              background: "#4f80f7",
              color: "#fff",
              border: "none",
              borderRadius: 6,
              padding: "8px 18px",
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            + New workspace
          </button>
        ) : (
          <form onSubmit={handleCreate} style={{ display: "flex", gap: 8 }}>
            <input
              placeholder="Workspace name"
              value={createName}
              onChange={(e) => setCreateName(e.target.value)}
              style={{
                flex: 1,
                background: "#1a1d28",
                border: "1px solid #3a3d4a",
                borderRadius: 5,
                padding: "6px 10px",
                fontSize: 13,
                color: "#e2e5ef",
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
                borderRadius: 5,
                padding: "6px 14px",
                fontSize: 13,
                cursor: "pointer",
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
                borderRadius: 5,
                padding: "6px 10px",
                fontSize: 13,
                cursor: "pointer",
              }}
            >
              Cancel
            </button>
          </form>
        )}
      </section>
    </main>
  );
}
