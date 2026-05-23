"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { reconnectIntegration } from "@/lib/api";
import type { Integration } from "@/types";

interface ReconnectIntegrationModalProps {
  integration: Integration;
  onClose: () => void;
  onSuccess: (updated: Integration) => void;
}

export default function ReconnectIntegrationModal({
  integration,
  onClose,
  onSuccess,
}: ReconnectIntegrationModalProps) {
  const [token, setToken] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { getToken } = useAuth();

  const isCloudflare = integration.provider === "cloudflare";
  const fieldLabel = isCloudflare ? "Cloudflare API token" : "GitHub Personal Access Token";
  const placeholder = isCloudflare ? "cf-token-…" : "github_pat_…";

  async function handleSave() {
    const trimmed = token.trim();
    if (!trimmed) return;
    setSaving(true);
    setError(null);
    try {
      const authToken = await getToken();
      const payload = isCloudflare
        ? { api_token: trimmed }
        : { github_token: trimmed };
      const updated = await reconnectIntegration(integration.id, payload, authToken);
      onSuccess(updated);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to update credentials.",
      );
      setSaving(false);
    }
  }

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "8px",
          padding: "24px",
          width: "440px",
          maxWidth: "90vw",
        }}
      >
        <h2 style={{ margin: "0 0 10px", fontSize: "15px", color: "#e8eaf0", fontWeight: 600 }}>
          Update token
        </h2>

        <p style={{ margin: "0 0 16px", fontSize: "12px", color: "#8b90a0", lineHeight: 1.6 }}>
          We&apos;ll validate the new token before saving.{" "}
          <span style={{ color: "#565b6e" }}>
            This integration will keep pointing at the same{" "}
            {isCloudflare ? "Cloudflare zone" : "repository"}.
            The token is never stored in plaintext or returned by the API.
          </span>
        </p>

        <label style={{ display: "block", fontSize: "12px", color: "#8b90a0", marginBottom: "6px" }}>
          {fieldLabel}
        </label>
        <input
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") handleSave(); if (e.key === "Escape") onClose(); }}
          placeholder={placeholder}
          autoFocus
          autoComplete="new-password"
          style={{
            width: "100%",
            background: "#1c1e26",
            border: "1px solid #3a3d4a",
            borderRadius: "6px",
            padding: "8px 10px",
            fontSize: "13px",
            color: "#e8eaf0",
            fontFamily: "monospace",
            outline: "none",
            boxSizing: "border-box",
          }}
        />

        {error && (
          <p style={{ margin: "8px 0 0", fontSize: "12px", color: "#e84040" }}>
            {error.includes("Authentication") || error.includes("401") || error.includes("403")
              ? "Token is invalid or lacks required permissions."
              : error.includes("502") || error.includes("Could not reach")
              ? `Could not reach ${isCloudflare ? "Cloudflare" : "GitHub"}. Try again.`
              : error}
          </p>
        )}

        <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end", marginTop: "20px" }}>
          <button
            onClick={onClose}
            disabled={saving}
            style={{
              background: "transparent",
              border: "1px solid #3a3d4a",
              color: "#8b90a0",
              borderRadius: "6px",
              padding: "7px 14px",
              fontSize: "13px",
              cursor: saving ? "not-allowed" : "pointer",
              fontFamily: "inherit",
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving || !token.trim()}
            style={{
              background: saving || !token.trim() ? "#2a3050" : "#4f80f7",
              border: "none",
              color: "#ffffff",
              borderRadius: "6px",
              padding: "7px 14px",
              fontSize: "13px",
              fontWeight: 500,
              cursor: saving || !token.trim() ? "not-allowed" : "pointer",
              fontFamily: "inherit",
            }}
          >
            {saving ? "Validating…" : "Update token"}
          </button>
        </div>
      </div>
    </div>
  );
}
