"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { deleteIntegration } from "@/lib/api";
import type { Integration } from "@/types";

interface DeleteIntegrationModalProps {
  integration: Integration;
  onClose: () => void;
  onSuccess: () => void;
}

export default function DeleteIntegrationModal({
  integration,
  onClose,
  onSuccess,
}: DeleteIntegrationModalProps) {
  const [confirmText, setConfirmText] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { getToken } = useAuth();

  const canDelete = confirmText === integration.display_name;

  async function handleDelete() {
    if (!canDelete) return;
    setDeleting(true);
    setError(null);
    try {
      const token = await getToken();
      await deleteIntegration(integration.id, token);
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete.");
      setDeleting(false);
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
        <h2 style={{ margin: "0 0 12px", fontSize: "15px", color: "#e8eaf0", fontWeight: 600 }}>
          Delete integration
        </h2>

        <p style={{ margin: "0 0 8px", fontSize: "13px", color: "#8b90a0", lineHeight: 1.6 }}>
          Scheduled syncing will stop.{" "}
          <span style={{ color: "#b0b5c4" }}>
            Historical changes for this integration will remain visible in the timeline.
          </span>
        </p>

        <p style={{ margin: "0 0 16px", fontSize: "12px", color: "#565b6e", lineHeight: 1.6 }}>
          This action cannot be undone from the UI.
        </p>

        <label style={{ display: "block", fontSize: "12px", color: "#8b90a0", marginBottom: "6px" }}>
          Type{" "}
          <span
            style={{
              fontFamily: "monospace",
              background: "#1c1e26",
              padding: "1px 4px",
              borderRadius: "3px",
              color: "#b0b5c4",
            }}
          >
            {integration.display_name}
          </span>{" "}
          to confirm
        </label>
        <input
          type="text"
          value={confirmText}
          onChange={(e) => setConfirmText(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && canDelete) handleDelete(); if (e.key === "Escape") onClose(); }}
          autoFocus
          placeholder={integration.display_name}
          style={{
            width: "100%",
            background: "#1c1e26",
            border: "1px solid #3a3d4a",
            borderRadius: "6px",
            padding: "8px 10px",
            fontSize: "13px",
            color: "#e8eaf0",
            fontFamily: "inherit",
            outline: "none",
            boxSizing: "border-box",
          }}
        />

        {error && (
          <p style={{ margin: "8px 0 0", fontSize: "12px", color: "#e84040" }}>{error}</p>
        )}

        <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end", marginTop: "20px" }}>
          <button
            onClick={onClose}
            disabled={deleting}
            style={{
              background: "transparent",
              border: "1px solid #3a3d4a",
              color: "#8b90a0",
              borderRadius: "6px",
              padding: "7px 14px",
              fontSize: "13px",
              cursor: deleting ? "not-allowed" : "pointer",
              fontFamily: "inherit",
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleDelete}
            disabled={!canDelete || deleting}
            style={{
              background: canDelete && !deleting ? "rgba(232,64,64,0.85)" : "#2a2d38",
              border: "none",
              color: canDelete && !deleting ? "#ffffff" : "#565b6e",
              borderRadius: "6px",
              padding: "7px 14px",
              fontSize: "13px",
              fontWeight: 500,
              cursor: !canDelete || deleting ? "not-allowed" : "pointer",
              fontFamily: "inherit",
            }}
          >
            {deleting ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>
    </div>
  );
}
