"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import {
  getWorkspaceMembers,
  getWorkspaceInvites,
  createInvite,
  removeMember,
  updateMemberRole,
  revokeInvite,
} from "@/lib/api";
import type {
  WorkspaceMember,
  WorkspaceInvite,
  WorkspaceRole,
  InviteRole,
} from "@/types";

const ROLE_LABELS: Record<string, string> = {
  owner: "Owner",
  admin: "Admin",
  member: "Member",
};

const ROLE_COLORS: Record<string, string> = {
  owner: "#fbbf24",
  admin: "#4f80f7",
  member: "#8b90a0",
};

export default function MembersPage() {
  const { getToken } = useAuth();
  const { selectedWorkspace } = useWorkspace();

  const [members, setMembers] = useState<WorkspaceMember[]>([]);
  const [invites, setInvites] = useState<WorkspaceInvite[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Invite form
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<InviteRole>("member");
  const [inviteBusy, setInviteBusy] = useState(false);
  const [newInviteToken, setNewInviteToken] = useState<string | null>(null);
  const [newInviteUrl, setNewInviteUrl] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!selectedWorkspace) return;
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const [mResp, iResp] = await Promise.all([
        getWorkspaceMembers(selectedWorkspace.id, token),
        getWorkspaceInvites(selectedWorkspace.id, true, token),
      ]);
      setMembers(mResp.members);
      setInvites(iResp.invites);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load.");
    } finally {
      setLoading(false);
    }
  }, [selectedWorkspace, getToken]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedWorkspace || !inviteEmail.trim()) return;
    setInviteBusy(true);
    setError(null);
    setNewInviteToken(null);
    setNewInviteUrl(null);
    try {
      const token = await getToken();
      const resp = await createInvite(
        selectedWorkspace.id,
        inviteEmail.trim(),
        inviteRole,
        token,
      );
      // Use the invite_url from the backend (built from FRONTEND_URL config).
      // Fall back to window.location.origin if the backend returned an API URL.
      const backendUrl = resp.invite_url || "";
      const isApiUrl =
        backendUrl.includes("/api.") ||
        backendUrl.includes(":8000") ||
        backendUrl.includes("localhost:800");
      const frontendInviteUrl = isApiUrl
        ? `${typeof window !== "undefined" ? window.location.origin : ""}/invites/${resp.invite_token}`
        : backendUrl;

      setNewInviteToken(resp.invite_token);
      setNewInviteUrl(frontendInviteUrl);
      setInviteEmail("");
      if (resp.email_sent) {
        setSuccess(
          `Invite email sent to ${resp.email}. If they don't receive it, copy and share the link below.`,
        );
      } else {
        setSuccess(
          `Invite created for ${resp.email}. Email could not be sent — copy and share the link below.`,
        );
      }
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to invite.");
    } finally {
      setInviteBusy(false);
    }
  }

  async function handleRemoveMember(member: WorkspaceMember) {
    if (!selectedWorkspace) return;
    if (
      !confirm(
        `Remove ${member.email ?? member.user_id} from this workspace?`,
      )
    )
      return;
    try {
      const token = await getToken();
      await removeMember(selectedWorkspace.id, member.id, token);
      setSuccess("Member removed.");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove.");
    }
  }

  async function handleRoleChange(member: WorkspaceMember, newRole: WorkspaceRole) {
    if (!selectedWorkspace) return;
    try {
      const token = await getToken();
      await updateMemberRole(selectedWorkspace.id, member.id, newRole, token);
      setSuccess("Role updated.");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update role.");
    }
  }

  async function handleRevokeInvite(invite: WorkspaceInvite) {
    if (!selectedWorkspace) return;
    try {
      const token = await getToken();
      await revokeInvite(selectedWorkspace.id, invite.id, token);
      setSuccess("Invite revoked.");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke.");
    }
  }

  if (!selectedWorkspace) {
    return (
      <main style={{ padding: "32px 24px", color: "#8b90a0" }}>
        No workspace selected.
      </main>
    );
  }

  return (
    <main style={{ maxWidth: 720, margin: "0 auto", padding: "32px 24px" }}>
      <h1
        style={{
          fontSize: "20px",
          fontWeight: 600,
          color: "#e2e5ef",
          marginBottom: "4px",
        }}
      >
        {selectedWorkspace.name}
      </h1>
      <p style={{ fontSize: 13, color: "#565b6e", marginBottom: "28px" }}>
        Members &amp; Invites
      </p>

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

      {/* New invite token reveal */}
      {newInviteToken && newInviteUrl && (
        <div
          style={{
            background: "#1a1d28",
            border: "1px solid #4f80f7",
            borderRadius: 8,
            padding: "16px",
            marginBottom: 20,
          }}
        >
          <div
            style={{
              fontSize: 13,
              color: "#c4c8d4",
              fontWeight: 500,
              marginBottom: 8,
            }}
          >
            Invite link (copy and share — shown only once)
          </div>
          <code
            style={{
              display: "block",
              background: "#13151a",
              borderRadius: 5,
              padding: "8px 12px",
              fontSize: 12,
              color: "#4f80f7",
              wordBreak: "break-all",
              cursor: "pointer",
            }}
            onClick={() => navigator.clipboard.writeText(newInviteUrl)}
            title="Click to copy"
          >
            {newInviteUrl}
          </code>
          <button
            onClick={() => {
              setNewInviteToken(null);
              setNewInviteUrl(null);
            }}
            style={{
              marginTop: 8,
              fontSize: 11,
              color: "#565b6e",
              background: "none",
              border: "none",
              cursor: "pointer",
            }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Members table */}
      <section style={{ marginBottom: 28 }}>
        <div
          style={{
            fontSize: 13,
            fontWeight: 500,
            color: "#c4c8d4",
            marginBottom: 12,
          }}
        >
          Members ({members.length})
        </div>
        {loading ? (
          <div style={{ color: "#565b6e", fontSize: 13 }}>Loading…</div>
        ) : (
          <div
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: 8,
              overflow: "hidden",
            }}
          >
            {members.map((m, i) => (
              <div
                key={m.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  padding: "12px 16px",
                  borderBottom:
                    i < members.length - 1 ? "1px solid #1e2130" : "none",
                  gap: 12,
                }}
              >
                {/* Avatar placeholder */}
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: "50%",
                    background: "#252836",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: 13,
                    color: "#8b90a0",
                    flexShrink: 0,
                  }}
                >
                  {(m.email ?? "?")[0].toUpperCase()}
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: 13,
                      color: "#c4c8d4",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {m.display_name || m.email}
                  </div>
                  {m.display_name && (
                    <div
                      style={{
                        fontSize: 11,
                        color: "#565b6e",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {m.email}
                    </div>
                  )}
                </div>

                {/* Role badge */}
                <span
                  style={{
                    fontSize: 11,
                    color: ROLE_COLORS[m.role] ?? "#8b90a0",
                    background: "#1a1d28",
                    border: `1px solid ${ROLE_COLORS[m.role] ?? "#3a3d4a"}`,
                    borderRadius: 4,
                    padding: "2px 8px",
                    fontWeight: 500,
                  }}
                >
                  {ROLE_LABELS[m.role] ?? m.role}
                </span>

                {/* Actions (hidden for owners for safety) */}
                {m.role !== "owner" && (
                  <button
                    onClick={() => handleRemoveMember(m)}
                    style={{
                      fontSize: 11,
                      color: "#7a2a2a",
                      background: "none",
                      border: "1px solid #3a1a1a",
                      borderRadius: 4,
                      padding: "2px 8px",
                      cursor: "pointer",
                    }}
                  >
                    Remove
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Invite form */}
      <section style={{ marginBottom: 28 }}>
        <div
          style={{
            fontSize: 13,
            fontWeight: 500,
            color: "#c4c8d4",
            marginBottom: 12,
          }}
        >
          Invite a teammate
        </div>
        <form
          onSubmit={handleInvite}
          style={{ display: "flex", gap: 8, flexWrap: "wrap" }}
        >
          <input
            type="email"
            placeholder="teammate@company.com"
            value={inviteEmail}
            onChange={(e) => setInviteEmail(e.target.value)}
            style={{
              flex: "1 1 200px",
              background: "#1a1d28",
              border: "1px solid #3a3d4a",
              borderRadius: 5,
              padding: "8px 12px",
              fontSize: 13,
              color: "#e2e5ef",
            }}
          />
          <select
            value={inviteRole}
            onChange={(e) => setInviteRole(e.target.value as InviteRole)}
            style={{
              background: "#1a1d28",
              border: "1px solid #3a3d4a",
              borderRadius: 5,
              padding: "8px 12px",
              fontSize: 13,
              color: "#e2e5ef",
            }}
          >
            <option value="member">Member</option>
            <option value="admin">Admin</option>
          </select>
          <button
            type="submit"
            disabled={inviteBusy || !inviteEmail.trim()}
            style={{
              background: "#4f80f7",
              color: "#fff",
              border: "none",
              borderRadius: 5,
              padding: "8px 18px",
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            Send invite
          </button>
        </form>
      </section>

      {/* Pending invites */}
      {invites.length > 0 && (
        <section>
          <div
            style={{
              fontSize: 13,
              fontWeight: 500,
              color: "#c4c8d4",
              marginBottom: 12,
            }}
          >
            Pending invites ({invites.length})
          </div>
          <div
            style={{
              background: "#13151a",
              border: "1px solid #2a2d38",
              borderRadius: 8,
              overflow: "hidden",
            }}
          >
            {invites.map((inv, i) => (
              <div
                key={inv.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  padding: "10px 16px",
                  borderBottom:
                    i < invites.length - 1 ? "1px solid #1e2130" : "none",
                  gap: 12,
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: 13,
                      color: "#c4c8d4",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {inv.email}
                  </div>
                  <div style={{ fontSize: 11, color: "#565b6e" }}>
                    Expires{" "}
                    {new Date(inv.expires_at).toLocaleDateString()}
                  </div>
                </div>
                <span
                  style={{
                    fontSize: 11,
                    color: ROLE_COLORS[inv.role] ?? "#8b90a0",
                    background: "#1a1d28",
                    border: `1px solid ${ROLE_COLORS[inv.role] ?? "#3a3d4a"}`,
                    borderRadius: 4,
                    padding: "2px 8px",
                  }}
                >
                  {ROLE_LABELS[inv.role] ?? inv.role}
                </span>
                <button
                  onClick={() => handleRevokeInvite(inv)}
                  style={{
                    fontSize: 11,
                    color: "#7a3a1a",
                    background: "none",
                    border: "1px solid #3a2a1a",
                    borderRadius: 4,
                    padding: "2px 8px",
                    cursor: "pointer",
                  }}
                >
                  Revoke
                </button>
              </div>
            ))}
          </div>
        </section>
      )}
    </main>
  );
}
