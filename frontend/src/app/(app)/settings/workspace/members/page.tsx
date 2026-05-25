"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { useRouter } from "next/navigation";
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
import PageHeader from "@/components/common/PageHeader";

// ── Role metadata ─────────────────────────────────────────────────────────────

const ROLE_META: Record<string, { label: string; color: string; description: string }> = {
  owner: {
    label: "Owner",
    color: "#fbbf24",
    description: "Full access: billing, members, integrations, and all settings.",
  },
  admin: {
    label: "Admin",
    color: "#4f80f7",
    description: "Manage integrations and invites. Cannot remove owners or change billing.",
  },
  member: {
    label: "Member",
    color: "#8b90a0",
    description: "View workspace resources, changes, and timeline.",
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Detect member-limit plan errors from the API message. */
function isMemberLimitError(msg: string): boolean {
  return (
    msg.toLowerCase().includes("member limit") ||
    msg.toLowerCase().includes("max_members") ||
    msg.toLowerCase().includes("upgrade") && msg.toLowerCase().includes("member")
  );
}

function formatExpiry(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

// ── Small reusable components ─────────────────────────────────────────────────

function RoleBadge({ role }: { role: string }) {
  const meta = ROLE_META[role] ?? { label: role, color: "#8b90a0", description: "" };
  return (
    <span
      title={meta.description}
      aria-label={`Role: ${meta.label}`}
      style={{
        fontSize: "11px",
        color: meta.color,
        background: "#1a1d28",
        border: `1px solid ${meta.color}33`,
        borderRadius: "4px",
        padding: "2px 8px",
        fontWeight: 500,
        whiteSpace: "nowrap",
        flexShrink: 0,
      }}
    >
      {meta.label}
    </span>
  );
}

function ErrorBanner({ message, onBillingCta }: { message: string; onBillingCta?: () => void }) {
  const isLimit = isMemberLimitError(message);
  return (
    <div
      role="alert"
      style={{
        background: "#2a1a1a",
        border: "1px solid #7a2a2a",
        borderRadius: "6px",
        padding: "12px 14px",
        color: "#f87171",
        fontSize: "13px",
        marginBottom: "16px",
        lineHeight: 1.6,
      }}
    >
      {isLimit ? (
        <span>
          {"You've reached your plan's member limit. "}
          {onBillingCta && (
            <button
              onClick={onBillingCta}
              style={{
                background: "none",
                border: "none",
                color: "#fbbf24",
                cursor: "pointer",
                fontSize: "13px",
                padding: 0,
                fontFamily: "inherit",
                textDecoration: "underline",
              }}
            >
              Upgrade your plan
            </button>
          )}
          {onBillingCta ? " to invite more teammates." : "Upgrade to Team to invite more teammates."}
        </span>
      ) : (
        message
      )}
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

// ── Page ──────────────────────────────────────────────────────────────────────

export default function MembersPage() {
  const { getToken } = useAuth();
  const router = useRouter();
  const { selectedWorkspace } = useWorkspace();

  const [members, setMembers] = useState<WorkspaceMember[]>([]);
  const [invites, setInvites] = useState<WorkspaceInvite[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Invite form state
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole]   = useState<InviteRole>("member");
  const [inviteBusy, setInviteBusy]   = useState(false);
  const [newInviteUrl, setNewInviteUrl] = useState<string | null>(null);
  const [inviteEmailSent, setInviteEmailSent] = useState<boolean | null>(null);
  const [copiedLink, setCopiedLink] = useState(false);

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
      setError(err instanceof Error ? err.message : "Failed to load members.");
    } finally {
      setLoading(false);
    }
  }, [selectedWorkspace, getToken]);

  useEffect(() => { load(); }, [load]);

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedWorkspace || !inviteEmail.trim()) return;
    setInviteBusy(true);
    setError(null);
    setNewInviteUrl(null);
    setInviteEmailSent(null);
    try {
      const token = await getToken();
      const resp = await createInvite(
        selectedWorkspace.id,
        inviteEmail.trim(),
        inviteRole,
        token,
      );

      // Build frontend-routed URL (in case backend returned API host).
      const backendUrl = resp.invite_url || "";
      const isApiUrl =
        backendUrl.includes("/api.") ||
        backendUrl.includes(":8000") ||
        backendUrl.includes("localhost:800");
      const frontendUrl = isApiUrl
        ? `${typeof window !== "undefined" ? window.location.origin : ""}/invites/${resp.invite_token}`
        : backendUrl;

      setNewInviteUrl(frontendUrl);
      setInviteEmailSent(resp.email_sent);
      setInviteEmail("");
      setSuccess(
        resp.email_sent
          ? `Invite email sent to ${resp.email}.`
          : `Invite created for ${resp.email}. Copy and share the link below.`,
      );
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to send invite.");
    } finally {
      setInviteBusy(false);
    }
  }

  async function handleRemoveMember(member: WorkspaceMember) {
    if (!selectedWorkspace) return;
    const label = member.display_name || member.email || member.user_id;
    if (!confirm(`Remove ${label} from this workspace?`)) return;
    setError(null);
    try {
      const token = await getToken();
      await removeMember(selectedWorkspace.id, member.id, token);
      setSuccess("Member removed.");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove member.");
    }
  }

  async function handleRoleChange(member: WorkspaceMember, newRole: WorkspaceRole) {
    if (!selectedWorkspace) return;
    setError(null);
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
    setError(null);
    try {
      const token = await getToken();
      await revokeInvite(selectedWorkspace.id, invite.id, token);
      setSuccess("Invite revoked.");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke invite.");
    }
  }

  async function copyInviteLink() {
    if (!newInviteUrl) return;
    try {
      await navigator.clipboard.writeText(newInviteUrl);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2500);
    } catch {
      // Fallback: select text
    }
  }

  // ── No workspace guard ─────────────────────────────────────────────────────

  if (!selectedWorkspace) {
    return (
      <main style={{ padding: "32px 24px", color: "#8b90a0" }}>
        No workspace selected. Go to{" "}
        <button
          onClick={() => router.push("/settings/workspace")}
          style={{
            background: "none",
            border: "none",
            color: "#4f80f7",
            cursor: "pointer",
            fontSize: "inherit",
            padding: 0,
            fontFamily: "inherit",
          }}
        >
          Workspace settings
        </button>{" "}
        to select one.
      </main>
    );
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <>
      <PageHeader
        title="Members & Invites"
        description={`Manage access to the ${selectedWorkspace.name} workspace.`}
      />

      <div className="px-6 pb-8" style={{ maxWidth: "720px" }}>
        {/* Messages */}
        {error   && <ErrorBanner   message={error}   onBillingCta={() => router.push("/settings/workspace/billing")} />}
        {success && <SuccessBanner message={success} />}

        {/* ── Invite link reveal ─────────────────────────────────────── */}
        {newInviteUrl && (
          <div
            role="region"
            aria-label="New invite link"
            style={{
              background: "#1a1d28",
              border: "1px solid #4f80f7",
              borderRadius: "8px",
              padding: "16px",
              marginBottom: "20px",
            }}
          >
            {/* Email status */}
            <p
              style={{
                margin: "0 0 10px",
                fontSize: "13px",
                color: inviteEmailSent ? "#4ade80" : "#f5a623",
                fontWeight: 500,
              }}
            >
              {inviteEmailSent
                ? "✓ Invite email sent."
                : "⚠ Email could not be sent. Copy and share this link manually."}
            </p>

            {/* Link + copy button */}
            <div style={{ display: "flex", gap: "8px", alignItems: "stretch" }}>
              <code
                style={{
                  flex: 1,
                  display: "block",
                  background: "#13151a",
                  borderRadius: "5px",
                  padding: "8px 12px",
                  fontSize: "12px",
                  color: "#8b90a0",
                  wordBreak: "break-all",
                  lineHeight: 1.5,
                  border: "1px solid #2a2d38",
                }}
              >
                {newInviteUrl}
              </code>
              <button
                onClick={copyInviteLink}
                aria-label={copiedLink ? "Link copied" : "Copy invite link"}
                style={{
                  flexShrink: 0,
                  background: copiedLink ? "#1a3a1a" : "#4f80f7",
                  color: copiedLink ? "#4ade80" : "#fff",
                  border: "none",
                  borderRadius: "5px",
                  padding: "8px 14px",
                  fontSize: "12px",
                  cursor: "pointer",
                  fontFamily: "inherit",
                  fontWeight: 500,
                  transition: "background 0.2s",
                  whiteSpace: "nowrap",
                }}
              >
                {copiedLink ? "Copied!" : "Copy link"}
              </button>
            </div>

            <p style={{ margin: "8px 0 0", fontSize: "11px", color: "#565b6e" }}>
              This link is shown only once. Share it with your teammate.
            </p>

            <button
              onClick={() => { setNewInviteUrl(null); setInviteEmailSent(null); }}
              style={{
                marginTop: "8px",
                fontSize: "11px",
                color: "#565b6e",
                background: "none",
                border: "none",
                cursor: "pointer",
                padding: 0,
                fontFamily: "inherit",
              }}
            >
              Dismiss
            </button>
          </div>
        )}

        {/* ── Members list ──────────────────────────────────────────── */}
        <section aria-labelledby="section-members" style={{ marginBottom: "28px" }}>
          <h2
            id="section-members"
            style={{ fontSize: "13px", fontWeight: 600, color: "#c4c8d4", margin: "0 0 12px" }}
          >
            Members ({members.length})
          </h2>

          {loading ? (
            <div style={{ color: "#565b6e", fontSize: "13px" }}>Loading…</div>
          ) : members.length === 0 ? (
            <div
              style={{
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "8px",
                padding: "24px",
                textAlign: "center",
                color: "#565b6e",
                fontSize: "13px",
              }}
            >
              No members found.
            </div>
          ) : (
            <div
              role="list"
              aria-label="Workspace members"
              style={{
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "8px",
                overflow: "hidden",
              }}
            >
              {members.map((m, i) => (
                <div
                  key={m.id}
                  role="listitem"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    padding: "12px 16px",
                    borderBottom: i < members.length - 1 ? "1px solid #1e2130" : "none",
                    gap: "12px",
                  }}
                >
                  {/* Avatar initials */}
                  <div
                    aria-hidden="true"
                    style={{
                      width: "32px",
                      height: "32px",
                      borderRadius: "50%",
                      background: "#252836",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontSize: "13px",
                      color: "#8b90a0",
                      flexShrink: 0,
                    }}
                  >
                    {(m.email ?? m.display_name ?? "?")[0].toUpperCase()}
                  </div>

                  {/* Name + email */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontSize: "13px",
                        color: "#c4c8d4",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {m.display_name || m.email}
                    </div>
                    {m.display_name && m.email && (
                      <div
                        style={{
                          fontSize: "11px",
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
                  <RoleBadge role={m.role} />

                  {/* Remove (non-owners only) */}
                  {m.role !== "owner" && (
                    <button
                      onClick={() => handleRemoveMember(m)}
                      aria-label={`Remove ${m.display_name || m.email || "member"} from workspace`}
                      style={{
                        fontSize: "11px",
                        color: "#8b90a0",
                        background: "none",
                        border: "1px solid #2a2d38",
                        borderRadius: "4px",
                        padding: "2px 8px",
                        cursor: "pointer",
                        fontFamily: "inherit",
                        whiteSpace: "nowrap",
                      }}
                      onMouseOver={(e) => {
                        (e.currentTarget as HTMLButtonElement).style.color = "#f87171";
                        (e.currentTarget as HTMLButtonElement).style.borderColor = "#7a2a2a";
                      }}
                      onMouseOut={(e) => {
                        (e.currentTarget as HTMLButtonElement).style.color = "#8b90a0";
                        (e.currentTarget as HTMLButtonElement).style.borderColor = "#2a2d38";
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

        {/* ── Invite form ───────────────────────────────────────────── */}
        <section aria-labelledby="section-invite" style={{ marginBottom: "28px" }}>
          <h2
            id="section-invite"
            style={{ fontSize: "13px", fontWeight: 600, color: "#c4c8d4", margin: "0 0 6px" }}
          >
            Invite a teammate
          </h2>

          {/* Role descriptions */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap: "8px",
              marginBottom: "14px",
            }}
          >
            {(["owner", "admin", "member"] as const).map((role) => {
              const meta = ROLE_META[role];
              return (
                <div
                  key={role}
                  style={{
                    background: "#13151a",
                    border: "1px solid #2a2d38",
                    borderRadius: "6px",
                    padding: "8px 10px",
                  }}
                >
                  <div
                    style={{
                      fontSize: "11px",
                      fontWeight: 600,
                      color: meta.color,
                      marginBottom: "3px",
                    }}
                  >
                    {meta.label}
                  </div>
                  <div style={{ fontSize: "11px", color: "#565b6e", lineHeight: 1.5 }}>
                    {meta.description}
                  </div>
                </div>
              );
            })}
          </div>

          <form
            onSubmit={handleInvite}
            style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}
          >
            <input
              type="email"
              placeholder="teammate@company.com"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              aria-label="Teammate email address"
              style={{
                flex: "1 1 200px",
                background: "#1a1d28",
                border: "1px solid #3a3d4a",
                borderRadius: "5px",
                padding: "8px 12px",
                fontSize: "13px",
                color: "#e2e5ef",
                fontFamily: "inherit",
                outline: "none",
              }}
            />
            <select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value as InviteRole)}
              aria-label="Role for invite"
              style={{
                background: "#1a1d28",
                border: "1px solid #3a3d4a",
                borderRadius: "5px",
                padding: "8px 12px",
                fontSize: "13px",
                color: "#e2e5ef",
                cursor: "pointer",
                fontFamily: "inherit",
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
                borderRadius: "5px",
                padding: "8px 18px",
                fontSize: "13px",
                cursor: inviteBusy || !inviteEmail.trim() ? "not-allowed" : "pointer",
                opacity: inviteBusy ? 0.7 : 1,
                fontFamily: "inherit",
              }}
            >
              {inviteBusy ? "Sending…" : "Send invite"}
            </button>
          </form>
        </section>

        {/* ── Pending invites ───────────────────────────────────────── */}
        <section aria-labelledby="section-pending-invites">
          <h2
            id="section-pending-invites"
            style={{ fontSize: "13px", fontWeight: 600, color: "#c4c8d4", margin: "0 0 12px" }}
          >
            Pending invites
          </h2>

          {invites.length === 0 ? (
            <div
              style={{
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "8px",
                padding: "20px",
                textAlign: "center",
                color: "#565b6e",
                fontSize: "13px",
              }}
            >
              No pending invites.
            </div>
          ) : (
            <div
              role="list"
              aria-label="Pending invitations"
              style={{
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "8px",
                overflow: "hidden",
              }}
            >
              {invites.map((inv, i) => (
                <div
                  key={inv.id}
                  role="listitem"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    padding: "10px 16px",
                    borderBottom: i < invites.length - 1 ? "1px solid #1e2130" : "none",
                    gap: "12px",
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontSize: "13px",
                        color: "#c4c8d4",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {inv.email}
                    </div>
                    <div style={{ fontSize: "11px", color: "#565b6e" }}>
                      Expires {formatExpiry(inv.expires_at)}
                    </div>
                  </div>
                  <RoleBadge role={inv.role} />
                  <button
                    onClick={() => handleRevokeInvite(inv)}
                    aria-label={`Revoke invite for ${inv.email}`}
                    style={{
                      fontSize: "11px",
                      color: "#8b90a0",
                      background: "none",
                      border: "1px solid #2a2d38",
                      borderRadius: "4px",
                      padding: "2px 8px",
                      cursor: "pointer",
                      fontFamily: "inherit",
                      whiteSpace: "nowrap",
                    }}
                    onMouseOver={(e) => {
                      (e.currentTarget as HTMLButtonElement).style.color = "#f87171";
                      (e.currentTarget as HTMLButtonElement).style.borderColor = "#7a2a2a";
                    }}
                    onMouseOut={(e) => {
                      (e.currentTarget as HTMLButtonElement).style.color = "#8b90a0";
                      (e.currentTarget as HTMLButtonElement).style.borderColor = "#2a2d38";
                    }}
                  >
                    Revoke invite
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </>
  );
}
