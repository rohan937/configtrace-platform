"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useWorkspace } from "@/contexts/WorkspaceContext";

export default function WorkspaceSwitcher() {
  const { workspaces, selectedWorkspace, selectWorkspace, loading } =
    useWorkspace();
  const [open, setOpen] = useState(false);
  const router = useRouter();

  if (loading) {
    return (
      <div
        style={{
          padding: "10px 16px",
          borderBottom: "1px solid #2a2d38",
          fontSize: "12px",
          color: "#565b6e",
        }}
      >
        Loading…
      </div>
    );
  }

  if (workspaces.length === 0) {
    return null;
  }

  return (
    <div
      style={{
        padding: "8px 12px",
        borderBottom: "1px solid #2a2d38",
        position: "relative",
      }}
    >
      {/* Trigger */}
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          width: "100%",
          background: open ? "#1e2130" : "transparent",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          padding: "6px 10px",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "6px",
        }}
      >
        <div style={{ minWidth: 0, textAlign: "left" }}>
          <div
            style={{
              fontSize: "10px",
              color: "#565b6e",
              letterSpacing: "0.06em",
              textTransform: "uppercase",
              marginBottom: "1px",
            }}
          >
            Workspace
          </div>
          <div
            style={{
              fontSize: "12px",
              color: "#c4c8d4",
              fontWeight: 500,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={selectedWorkspace?.name ?? ""}
          >
            {selectedWorkspace?.name ?? "—"}
          </div>
        </div>
        <svg
          width="10"
          height="10"
          viewBox="0 0 10 10"
          fill="none"
          style={{
            flexShrink: 0,
            transform: open ? "rotate(180deg)" : "none",
            transition: "transform 0.15s",
          }}
        >
          <path
            d="M2 3.5L5 6.5L8 3.5"
            stroke="#565b6e"
            strokeWidth="1.5"
            strokeLinecap="round"
          />
        </svg>
      </button>

      {/* Dropdown */}
      {open && (
        <div
          style={{
            position: "absolute",
            top: "100%",
            left: "12px",
            right: "12px",
            background: "#1a1d28",
            border: "1px solid #2a2d38",
            borderRadius: "6px",
            zIndex: 50,
            overflow: "hidden",
            boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
          }}
        >
          {workspaces.map((ws) => (
            <button
              key={ws.id}
              onClick={() => {
                selectWorkspace(ws.id);
                setOpen(false);
              }}
              style={{
                width: "100%",
                padding: "8px 12px",
                background:
                  ws.id === selectedWorkspace?.id ? "#252836" : "transparent",
                border: "none",
                borderBottom: "1px solid #1e2130",
                cursor: "pointer",
                textAlign: "left",
                fontSize: "12px",
                color: ws.id === selectedWorkspace?.id ? "#e2e5ef" : "#8b90a0",
                display: "flex",
                alignItems: "center",
                gap: "8px",
              }}
            >
              {ws.id === selectedWorkspace?.id && (
                <span style={{ color: "#4f80f7", fontSize: "10px" }}>✓</span>
              )}
              <span
                style={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {ws.name}
              </span>
            </button>
          ))}

          {/* Divider + create link */}
          <button
            onClick={() => {
              setOpen(false);
              router.push("/settings/workspace");
            }}
            style={{
              width: "100%",
              padding: "8px 12px",
              background: "transparent",
              border: "none",
              cursor: "pointer",
              textAlign: "left",
              fontSize: "11px",
              color: "#565b6e",
              display: "flex",
              alignItems: "center",
              gap: "6px",
            }}
          >
            <span>+ Manage workspaces</span>
          </button>
        </div>
      )}
    </div>
  );
}
