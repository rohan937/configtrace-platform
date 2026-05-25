"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { createIntegration } from "@/lib/api";

interface FirebaseIntegrationFormProps {
  /** Called after a successful integration creation so the parent can refresh. */
  onCreated: () => void;
  /** Called when the user dismisses / cancels the form. */
  onCancel: () => void;
}

const INPUT_STYLE: React.CSSProperties = {
  width: "100%",
  background: "#1c1e26",
  border: "1px solid #2a2d38",
  borderRadius: "6px",
  color: "#e8eaf0",
  fontSize: "13px",
  padding: "8px 10px",
  outline: "none",
  fontFamily: "inherit",
  boxSizing: "border-box",
};

const TEXTAREA_STYLE: React.CSSProperties = {
  ...INPUT_STYLE,
  fontFamily: "monospace",
  fontSize: "11px",
  lineHeight: 1.5,
  resize: "vertical",
  minHeight: "140px",
};

const LABEL_STYLE: React.CSSProperties = {
  display: "block",
  fontSize: "11px",
  color: "#8b90a0",
  textTransform: "uppercase",
  letterSpacing: "0.06em",
  marginBottom: "6px",
};

const HELPER_STYLE: React.CSSProperties = {
  fontSize: "12px",
  color: "#565b6e",
  marginTop: "5px",
};

/**
 * Inline form for connecting a Firebase project integration.
 *
 * The service account JSON (including the private_key) is sent to the backend
 * once and immediately cleared from state on success.  It is never logged,
 * never stored in localStorage or sessionStorage, and never rendered after
 * submission.
 *
 * SECURITY: Only project-level configuration is monitored.  Firestore
 * documents, Storage file contents, and Auth user data are NEVER fetched
 * or stored by ConfigTrace.
 */
export default function FirebaseIntegrationForm({
  onCreated,
  onCancel,
}: FirebaseIntegrationFormProps) {
  const [displayName, setDisplayName] = useState("");
  const [serviceAccountJson, setServiceAccountJson] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const { getToken } = useAuth();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!displayName.trim()) {
      setError("Display name is required.");
      return;
    }
    if (!serviceAccountJson.trim()) {
      setError("Service account JSON is required.");
      return;
    }

    // Client-side JSON parse check — surfaces obvious paste errors before
    // the round-trip to the backend.
    try {
      JSON.parse(serviceAccountJson.trim());
    } catch {
      setError(
        "The text you pasted is not valid JSON. " +
          "Paste the complete contents of the service account key file."
      );
      return;
    }

    setSubmitting(true);

    try {
      const token = await getToken();
      await createIntegration(
        {
          provider: "firebase",
          display_name: displayName.trim(),
          // sent once; cleared below immediately after success
          firebase_service_account_json: serviceAccountJson.trim(),
        },
        token
      );

      // Clear the sensitive field immediately — do not keep it in state.
      setServiceAccountJson("");
      setSuccessMsg("Firebase project connected.");
      onCreated();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to connect integration. Check your service account JSON and try again."
      );
    } finally {
      setSubmitting(false);
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
      {/* Section heading */}
      <div
        style={{
          fontSize: "11px",
          color: "#8b90a0",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "16px",
        }}
      >
        Connect Firebase Integration
      </div>

      <form onSubmit={handleSubmit} autoComplete="off" noValidate>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

          {/* Display name */}
          <div>
            <label htmlFor="firebase-display-name" style={LABEL_STYLE}>
              Display Name
            </label>
            <input
              id="firebase-display-name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Production Firebase"
              disabled={submitting}
              style={{ ...INPUT_STYLE, opacity: submitting ? 0.6 : 1 }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = "#4f80f7";
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = "#2a2d38";
              }}
            />
            <p style={HELPER_STYLE}>
              A label for this connection — pick something you&apos;ll recognise
              later, e.g. &ldquo;Production Firebase&rdquo;.
            </p>
          </div>

          {/* Service account JSON */}
          <div>
            <label htmlFor="firebase-sa-json" style={LABEL_STYLE}>
              Service Account JSON
              <span
                style={{
                  marginLeft: "6px",
                  background: "rgba(79,128,247,0.15)",
                  color: "#4f80f7",
                  borderRadius: "3px",
                  padding: "1px 5px",
                  fontSize: "9px",
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  verticalAlign: "middle",
                }}
              >
                Encrypted at rest
              </span>
            </label>
            <textarea
              id="firebase-sa-json"
              value={serviceAccountJson}
              onChange={(e) => setServiceAccountJson(e.target.value)}
              placeholder={`{\n  "type": "service_account",\n  "project_id": "my-project",\n  ...\n}`}
              disabled={submitting}
              autoComplete="off"
              spellCheck={false}
              style={{
                ...TEXTAREA_STYLE,
                opacity: submitting ? 0.6 : 1,
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = "#4f80f7";
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = "#2a2d38";
              }}
            />
            <p style={HELPER_STYLE}>
              Paste the complete contents of the{" "}
              <code style={{ fontSize: "11px" }}>.json</code> key file you
              downloaded from Firebase Console.
            </p>

            {/* Permissions note */}
            <div
              style={{
                marginTop: "8px",
                background: "#13151a",
                border: "1px solid #2a2d38",
                borderRadius: "4px",
                padding: "10px 12px",
                fontSize: "11px",
                color: "#565b6e",
                lineHeight: 1.75,
              }}
            >
              <span
                style={{
                  color: "#8b90a0",
                  display: "block",
                  marginBottom: "4px",
                  fontWeight: 500,
                }}
              >
                Required IAM role for service account (read-only):
              </span>
              <span style={{ color: "#6b7080" }}>
                ✓{" "}
                <code style={{ fontSize: "10px" }}>
                  roles/viewer
                </code>{" "}
                — or a custom role with{" "}
                <code style={{ fontSize: "10px" }}>firebase.readonly</code>{" "}
                scope
              </span>
              <br />
              <span style={{ color: "#6b7080" }}>
                ✓{" "}
                <code style={{ fontSize: "10px" }}>
                  roles/firebaserules.viewer
                </code>{" "}
                — for Security Rules monitoring{" "}
                <span style={{ color: "#3a3d4a", fontStyle: "italic" }}>
                  (optional)
                </span>
              </span>
              <br />
              <span
                style={{
                  color: "#3a3d4a",
                  marginTop: "4px",
                  display: "block",
                }}
              >
                Firestore documents, Storage file contents, and Auth user data
                are never accessed.
              </span>
            </div>
          </div>

          {/* Inline error */}
          {error && (
            <p style={{ fontSize: "13px", color: "#e84040", margin: 0 }}>
              {error}
            </p>
          )}

          {/* Inline success */}
          {successMsg && (
            <p style={{ fontSize: "13px", color: "#3ccf7e", margin: 0 }}>
              {successMsg}
            </p>
          )}

          {/* Buttons */}
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <button
              type="submit"
              disabled={submitting}
              style={{
                background: submitting ? "#2a3050" : "#4f80f7",
                color: "#ffffff",
                border: "none",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: 500,
                cursor: submitting ? "not-allowed" : "pointer",
                opacity: submitting ? 0.7 : 1,
                fontFamily: "inherit",
              }}
            >
              {submitting ? "Validating…" : "Connect Firebase"}
            </button>

            <button
              type="button"
              onClick={onCancel}
              disabled={submitting}
              style={{
                background: "transparent",
                color: "#8b90a0",
                border: "1px solid #2a2d38",
                borderRadius: "6px",
                padding: "8px 16px",
                fontSize: "13px",
                cursor: submitting ? "not-allowed" : "pointer",
                fontFamily: "inherit",
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
