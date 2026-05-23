"use client";

/**
 * GitHubAppConnectCard — M31.
 *
 * Recommended GitHub connection method: GitHub App installation.
 * Shown as the primary option on the Integrations page.
 *
 * Flow:
 *   1. User clicks "Connect via GitHub App".
 *   2. Frontend calls GET /integrations/github/app/install-url.
 *   3. Stores the state token in sessionStorage (CSRF protection).
 *   4. Redirects the user to the GitHub App install page.
 *   5. GitHub redirects back to /integrations/github/callback.
 *
 * Security: the state token is stored only in sessionStorage (tab-scoped,
 * cleared on tab close) and validated server-side on the callback.
 */

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@clerk/nextjs";
import { getGitHubAppInstallUrl } from "@/lib/api";

// Key used to stash the state token between redirect and callback.
const STATE_KEY = "github_app_oauth_state";

interface GitHubAppConnectCardProps {
  onCancel: () => void;
}

export default function GitHubAppConnectCard({ onCancel }: GitHubAppConnectCardProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { getToken } = useAuth();
  const router = useRouter();

  async function handleConnect() {
    setLoading(true);
    setError(null);
    try {
      const token = await getToken();
      const { install_url, state } = await getGitHubAppInstallUrl(token);

      // Store the state token before redirecting — validated on return.
      sessionStorage.setItem(STATE_KEY, state);

      // Full-page redirect to GitHub's App install page.
      // router.push() is insufficient here because GitHub may set cookies
      // that require a full navigation context.
      window.location.href = install_url;
    } catch (err) {
      setLoading(false);
      const msg =
        err instanceof Error
          ? err.message
          : "Failed to start GitHub App installation.";
      if (msg.includes("503") || msg.toLowerCase().includes("not configured")) {
        setError(
          "GitHub App integration is not enabled on this server. " +
            "Contact your administrator or use the Personal Access Token option below."
        );
      } else {
        setError(msg);
      }
    }
  }

  return (
    <div
      style={{
        background: "#1c1e26",
        border: "1px solid #2a2d38",
        borderRadius: "6px",
        padding: "20px 24px",
        marginBottom: "24px",
      }}
    >
      {/* Header */}
      <div style={{ marginBottom: "14px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <p
            style={{
              fontSize: "13px",
              color: "#e8eaf0",
              fontWeight: 600,
              margin: 0,
            }}
          >
            Connect via GitHub App
          </p>
          <span
            style={{
              fontSize: "10px",
              color: "#4f80f7",
              background: "rgba(79,128,247,0.12)",
              border: "1px solid rgba(79,128,247,0.3)",
              borderRadius: "4px",
              padding: "1px 6px",
              fontWeight: 600,
              letterSpacing: "0.04em",
              textTransform: "uppercase",
            }}
          >
            Recommended
          </span>
        </div>
        <p style={{ fontSize: "12px", color: "#8b90a0", margin: 0, lineHeight: 1.6 }}>
          Uses short-lived installation tokens — no long-lived credentials to manage.
          GitHub handles permission scoping automatically.
        </p>
      </div>

      {/* Benefits list */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: "5px",
          marginBottom: "16px",
        }}
      >
        {[
          "Tokens rotate automatically — nothing to store or rotate manually",
          "Scoped to exactly the repositories you select during install",
          "Read-only access — ConfigTrace cannot modify your repository",
        ].map((text) => (
          <div key={text} style={{ display: "flex", alignItems: "baseline", gap: "8px" }}>
            <span style={{ color: "#3ccf7e", fontSize: "11px", flexShrink: 0 }}>✓</span>
            <span style={{ fontSize: "12px", color: "#8b90a0" }}>{text}</span>
          </div>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div
          style={{
            padding: "10px 12px",
            marginBottom: "14px",
            background: "rgba(232,64,64,0.06)",
            border: "1px solid rgba(232,64,64,0.2)",
            borderRadius: "4px",
            fontSize: "12px",
            color: "#e84040",
          }}
        >
          {error}
        </div>
      )}

      {/* Buttons */}
      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        <button
          onClick={handleConnect}
          disabled={loading}
          style={{
            background: loading ? "#2a3050" : "#4f80f7",
            color: "#ffffff",
            border: "none",
            borderRadius: "6px",
            padding: "8px 16px",
            fontSize: "13px",
            fontWeight: 500,
            cursor: loading ? "not-allowed" : "pointer",
            opacity: loading ? 0.7 : 1,
            fontFamily: "inherit",
          }}
        >
          {loading ? "Redirecting to GitHub…" : "Connect via GitHub App →"}
        </button>
        <button
          type="button"
          onClick={onCancel}
          disabled={loading}
          style={{
            background: "transparent",
            color: "#8b90a0",
            border: "1px solid #2a2d38",
            borderRadius: "6px",
            padding: "8px 14px",
            fontSize: "13px",
            cursor: loading ? "not-allowed" : "pointer",
            fontFamily: "inherit",
          }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
