/**
 * DnsRecordView — structured key-value display for a single DNS record object.
 *
 * Used on the change detail page to show the full record for "added" and
 * "removed" changes without dumping raw JSON.
 */

// ── Field definitions ─────────────────────────────────────────────────────────

const DNS_FIELDS: Array<{ key: string; label: string; mono?: boolean }> = [
  { key: "record_type", label: "Type",     mono: true  },
  { key: "name",        label: "Name",     mono: true  },
  { key: "content",     label: "Content",  mono: true  },
  { key: "ttl",         label: "TTL"                   },
  { key: "proxied",     label: "Proxied"               },
  { key: "priority",    label: "Priority"              },
  { key: "comment",     label: "Comment"               },
];

function formatFieldValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

// ── Component ─────────────────────────────────────────────────────────────────

interface DnsRecordViewProps {
  /** The DNS record object (from new_value / prev_value on added/removed changes). */
  record: Record<string, unknown>;
  /**
   * Visual tint applied to the panel background.
   * "remove" — faint red (for the "before" / removed state)
   * "add"    — faint green (for the "after" / added state)
   * "neutral" — no tint (default)
   */
  tint?: "remove" | "add" | "neutral";
}

const TINT_BG: Record<string, string> = {
  remove:  "rgba(232,64,64,0.06)",
  add:     "rgba(60,207,126,0.06)",
  neutral: "transparent",
};

const TINT_BORDER: Record<string, string> = {
  remove:  "rgba(232,64,64,0.20)",
  add:     "rgba(60,207,126,0.20)",
  neutral: "#2a2d38",
};

export default function DnsRecordView({
  record,
  tint = "neutral",
}: DnsRecordViewProps) {
  const bg     = TINT_BG[tint]     ?? "transparent";
  const border = TINT_BORDER[tint] ?? "#2a2d38";

  // Only render rows where the value is present (skip completely absent fields
  // to keep the view tidy).
  const visibleFields = DNS_FIELDS.filter(
    (f) => record[f.key] !== undefined,
  );

  return (
    <div
      style={{
        background: bg,
        border: `1px solid ${border}`,
        borderRadius: "6px",
        overflow: "hidden",
      }}
    >
      {visibleFields.map((field, i) => {
        const raw   = record[field.key];
        const value = formatFieldValue(raw);
        const isEmpty = value === "—";

        return (
          <div
            key={field.key}
            className="flex items-baseline gap-3"
            style={{
              padding: "7px 12px",
              borderBottom:
                i < visibleFields.length - 1 ? `1px solid ${border}` : "none",
            }}
          >
            {/* Label */}
            <span
              style={{
                width: "72px",
                flexShrink: 0,
                fontSize: "11px",
                color: "#565b6e",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
              }}
            >
              {field.label}
            </span>

            {/* Value */}
            <span
              style={{
                fontSize: "13px",
                color: isEmpty ? "#3a3d4a" : "#e8eaf0",
                fontFamily: field.mono ? "monospace" : "inherit",
                wordBreak: "break-all",
              }}
              title={isEmpty ? undefined : value}
            >
              {value}
            </span>
          </div>
        );
      })}

      {visibleFields.length === 0 && (
        <p
          style={{
            padding: "12px",
            fontSize: "13px",
            color: "#565b6e",
            fontStyle: "italic",
          }}
        >
          No recognisable DNS fields in this record.
        </p>
      )}
    </div>
  );
}
