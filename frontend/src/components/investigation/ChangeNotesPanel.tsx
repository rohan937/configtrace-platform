"use client";

/**
 * ChangeNotesPanel — M58.8
 *
 * Team investigation notes for a change.  Notes are append-only (no edit/delete).
 * Plain text only, max 2000 characters.
 *
 * Empty state: "No team notes yet."
 */

import { useState, useEffect, useCallback } from "react";
import type { ChangeNote } from "@/types";
import { getChangeNotes, createChangeNote } from "@/lib/api";
import { formatAbsoluteTime, formatRelativeTime } from "@/lib/utils";

const MAX_NOTE_LEN = 2000;

// ── Sub-components ────────────────────────────────────────────────────────────

function NoteCard({ note }: { note: ChangeNote }) {
  return (
    <div
      style={{
        background: "#0e0f11",
        border: "1px solid #2a2d38",
        borderRadius: "4px",
        padding: "10px 12px",
      }}
    >
      {/* Body — rendered as pre-wrap to preserve line breaks */}
      <p
        style={{
          fontSize: "13px",
          color: "#b0b5c4",
          lineHeight: 1.6,
          margin: "0 0 6px",
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
        }}
      >
        {note.body}
      </p>

      {/* Metadata row */}
      <p
        style={{
          fontSize: "11px",
          color: "#565b6e",
          margin: 0,
        }}
        title={formatAbsoluteTime(note.created_at)}
      >
        {formatRelativeTime(note.created_at)}
      </p>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface ChangeNotesPanelProps {
  changeId: string;
  token: string | null;
}

export default function ChangeNotesPanel({
  changeId,
  token,
}: ChangeNotesPanelProps) {
  const [notes, setNotes] = useState<ChangeNote[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draftBody, setDraftBody] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // ── Load notes ──────────────────────────────────────────────────────────

  const loadNotes = useCallback(async () => {
    try {
      const res = await getChangeNotes(changeId, token);
      setNotes(res.items);
      setLoadError(null);
    } catch (err) {
      setLoadError(
        err instanceof Error ? err.message : "Failed to load notes.",
      );
    }
  }, [changeId, token]);

  useEffect(() => {
    loadNotes();
  }, [loadNotes]);

  // ── Submit new note ─────────────────────────────────────────────────────

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = draftBody.trim();
    if (!trimmed) return;
    if (trimmed.length > MAX_NOTE_LEN) return;

    setSubmitting(true);
    setSubmitError(null);
    try {
      const created = await createChangeNote(changeId, trimmed, token);
      setNotes((prev) => [...prev, created]);
      setDraftBody("");
    } catch (err) {
      setSubmitError(
        err instanceof Error ? err.message : "Failed to add note.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  // ── Render ──────────────────────────────────────────────────────────────

  const remaining = MAX_NOTE_LEN - draftBody.length;
  const isOverLimit = remaining < 0;
  const canSubmit = draftBody.trim().length > 0 && !isOverLimit && !submitting;

  return (
    <section aria-labelledby="section-notes">
      <h2
        id="section-notes"
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          margin: "0 0 8px",
          fontWeight: 500,
        }}
      >
        Team notes
      </h2>

      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          padding: "16px",
          display: "flex",
          flexDirection: "column",
          gap: "12px",
        }}
      >
        {/* Notes list */}
        {loadError ? (
          <p style={{ fontSize: "13px", color: "#f5632a", margin: 0 }}>
            {loadError}
          </p>
        ) : notes.length === 0 ? (
          <p
            style={{
              fontSize: "13px",
              color: "#565b6e",
              fontStyle: "italic",
              margin: 0,
            }}
          >
            No team notes yet.
          </p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {notes.map((note) => (
              <NoteCard key={note.id} note={note} />
            ))}
          </div>
        )}

        {/* Divider */}
        <div style={{ borderTop: "1px solid #2a2d38" }} />

        {/* Add note form */}
        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          <textarea
            value={draftBody}
            onChange={(e) => setDraftBody(e.target.value)}
            placeholder="Add a team note…"
            rows={3}
            disabled={submitting}
            style={{
              width: "100%",
              background: "#0e0f11",
              border: `1px solid ${isOverLimit ? "#e84040" : "#2a2d38"}`,
              borderRadius: "4px",
              color: "#e8eaf0",
              fontSize: "13px",
              padding: "8px 10px",
              resize: "vertical",
              outline: "none",
              lineHeight: 1.5,
              boxSizing: "border-box",
              fontFamily: "inherit",
              opacity: submitting ? 0.6 : 1,
            }}
          />

          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "8px",
            }}
          >
            {/* Character count */}
            <span
              style={{
                fontSize: "11px",
                color: isOverLimit ? "#e84040" : "#565b6e",
              }}
            >
              {isOverLimit
                ? `${Math.abs(remaining)} characters over limit`
                : `${remaining} characters remaining`}
            </span>

            <button
              type="submit"
              disabled={!canSubmit}
              style={{
                padding: "6px 14px",
                fontSize: "12px",
                fontWeight: 600,
                background: canSubmit ? "#4f80f7" : "#1e2030",
                color: canSubmit ? "#fff" : "#565b6e",
                border: "none",
                borderRadius: "4px",
                cursor: canSubmit ? "pointer" : "not-allowed",
                transition: "background 0.15s",
                flexShrink: 0,
              }}
            >
              {submitting ? "Adding…" : "Add note"}
            </button>
          </div>

          {submitError && (
            <p style={{ fontSize: "12px", color: "#f5632a", margin: 0 }}>
              {submitError}
            </p>
          )}
        </form>
      </div>
    </section>
  );
}
