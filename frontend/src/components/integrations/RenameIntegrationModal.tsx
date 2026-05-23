"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { patchIntegration } from "@/lib/api";
import type { Integration } from "@/types";

interface RenameIntegrationModalProps {
  integration: Integration;
  onClose: () => void;
  onSuccess: (updated: Integration) => void;
}

export default function RenameIntegrationModal({
  integration,
  onClose,
  onSuccess,
}: RenameIntegrationModalProps) {
  const [name, setName] = useState(integration.display_name);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSave() {
    const trimmed = name.trim();
    if (!trimmed) return;
    setSaving(true);
    setError(null);
    try {
      const token = await getToken();
      const updated = await patchIntegration(
        integration.id,
        { display_name: trimmed },
        token,
      );
      onSuccess(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to rename.");
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
          width: "420px",
          maxWidth: "90vw",
        }}
      >
        <h2 style={{ margin: "0 0 16px", fontSize: "15px", color: "#e8eaf0", fontWeight: 600 }}>
          Rename integration
        </h2>

        <label style={{ display: "block", fontSize: "12px", color: "#8b90a0", marginBottom: "6px" }}>
          Display name
        </label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") handleSave(); if (e.key === "Escape") onClose(); }}
          maxLength={200}
          autoFocus
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
            disabled={saving || !name.trim()}
            style={{
              background: saving ? "#2a3050" : "#4f80f7",
              border: "none",
              color: "#ffffff",
              borderRadius: "6px",
              padding: "7px 14px",
              fontSize: "13px",
              fontWeight: 500,
              cursor: saving || !name.trim() ? "not-allowed" : "pointer",
              fontFamily: "inherit",
            }}
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
