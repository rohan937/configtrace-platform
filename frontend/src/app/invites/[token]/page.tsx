"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuth } from "@clerk/nextjs";
import { getInvitePreview, acceptInvite } from "@/lib/api";
import type { InvitePreview } from "@/types";

export default function AcceptInvitePage() {
  const { token } = useParams<{ token: string }>();
  const router = useRouter();
  const { getToken, isSignedIn, isLoaded } = useAuth();

  const [preview, setPreview] = useState<InvitePreview | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [accepting, setAccepting] = useState(false);
  const [acceptError, setAcceptError] = useState<string | null>(null);
  const [accepted, setAccepted] = useState(false);

  // Load invite preview (no auth required)
  useEffect(() => {
    if (!token) return;
    getInvitePreview(token)
      .then(setPreview)
      .catch((err) =>
        setLoadError(
          err instanceof Error ? err.message : "Invite not found.",
        ),
      );
  }, [token]);

  async function handleAccept() {
    if (!token || !isSignedIn) return;
    setAccepting(true);
    setAcceptError(null);
    try {
      const authToken = await getToken();
      await acceptInvite(token, authToken);
      setAccepted(true);
      // Redirect to dashboard after a moment.
      setTimeout(() => router.push("/dashboard"), 1500);
    } catch (err) {
      setAcceptError(
        err instanceof Error ? err.message : "Failed to accept invite.",
      );
    } finally {
      setAccepting(false);
    }
  }

  // ── Loading / not found ───────────────────────────────────────────────────
  if (!preview && !loadError) {
    return (
      <div style={containerStyle}>
        <p style={{ color: "#8b90a0", fontSize: 14 }}>Loading invite…</p>
      </div>
    );
  }

  if (loadError) {
    return (
      <div style={containerStyle}>
        <h2 style={headingStyle}>Invite not found</h2>
        <p style={{ color: "#8b90a0", fontSize: 14 }}>{loadError}</p>
        <button
          onClick={() => router.push("/dashboard")}
          style={btnStyle}
        >
          Go to dashboard
        </button>
      </div>
    );
  }

  if (!preview!.is_active) {
    const reason = "This invite has expired, been revoked, or already accepted.";
    return (
      <div style={containerStyle}>
        <h2 style={headingStyle}>Invite unavailable</h2>
        <p style={{ color: "#8b90a0", fontSize: 14 }}>{reason}</p>
        <button
          onClick={() => router.push("/dashboard")}
          style={btnStyle}
        >
          Go to dashboard
        </button>
      </div>
    );
  }

  // ── Accepted ──────────────────────────────────────────────────────────────
  if (accepted) {
    return (
      <div style={containerStyle}>
        <h2 style={{ ...headingStyle, color: "#4ade80" }}>
          Welcome to {preview!.workspace_name}!
        </h2>
        <p style={{ color: "#8b90a0", fontSize: 14 }}>
          You've joined as <strong>{preview!.role}</strong>. Redirecting…
        </p>
      </div>
    );
  }

  // ── Main invite view ──────────────────────────────────────────────────────
  return (
    <div style={containerStyle}>
      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: 12,
          padding: "32px",
          width: "100%",
          maxWidth: 420,
        }}
      >
        <h1 style={{ ...headingStyle, marginBottom: 8 }}>
          You're invited to join
        </h1>
        <h2
          style={{
            fontSize: 22,
            fontWeight: 700,
            color: "#4f80f7",
            marginBottom: 20,
          }}
        >
          {preview!.workspace_name}
        </h2>

        <div
          style={{
            background: "#1a1d28",
            borderRadius: 6,
            padding: "12px 16px",
            marginBottom: 20,
          }}
        >
          {preview!.inviter_email && (
            <p style={{ color: "#8b90a0", fontSize: 13, marginBottom: 4 }}>
              Invited by{" "}
              <span style={{ color: "#c4c8d4" }}>{preview!.inviter_email}</span>
            </p>
          )}
          <p style={{ color: "#8b90a0", fontSize: 13, marginBottom: 4 }}>
            Role:{" "}
            <span style={{ color: "#c4c8d4", textTransform: "capitalize" }}>
              {preview!.role}
            </span>
          </p>
          <p style={{ color: "#8b90a0", fontSize: 13 }}>
            Invited email:{" "}
            <span style={{ color: "#c4c8d4" }}>{preview!.email}</span>
          </p>
        </div>

        {acceptError && (
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
            {acceptError}
          </div>
        )}

        {!isLoaded ? (
          <p style={{ color: "#565b6e", fontSize: 13 }}>Loading…</p>
        ) : !isSignedIn ? (
          <div>
            <p style={{ color: "#8b90a0", fontSize: 13, marginBottom: 12 }}>
              Sign in to accept this invite.
            </p>
            <button
              onClick={() =>
                router.push(`/sign-in?redirect_url=/invites/${token}`)
              }
              style={btnStyle}
            >
              Sign in
            </button>
          </div>
        ) : (
          <button
            onClick={handleAccept}
            disabled={accepting}
            style={btnStyle}
          >
            {accepting ? "Joining…" : "Accept invite"}
          </button>
        )}
      </div>
    </div>
  );
}

const containerStyle: React.CSSProperties = {
  minHeight: "100vh",
  background: "#0d0f14",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: "24px",
  flexDirection: "column",
  gap: "16px",
};

const headingStyle: React.CSSProperties = {
  fontSize: 18,
  fontWeight: 600,
  color: "#e2e5ef",
  marginBottom: 16,
};

const btnStyle: React.CSSProperties = {
  width: "100%",
  background: "#4f80f7",
  color: "#fff",
  border: "none",
  borderRadius: 6,
  padding: "10px 0",
  fontSize: 14,
  fontWeight: 500,
  cursor: "pointer",
};
