"use client";

/**
 * RelatedChangesPanel — M58.8
 *
 * Shows up to 5 changes from the same integration within ±72 hours of the
 * current change, excluding the current change itself.
 *
 * Uses the existing GET /changes endpoint with integration_id + since/until
 * filters — no new API endpoint required.
 *
 * Empty state: "No nearby changes detected in this integration."
 */

import { useState, useEffect } from "react";
import Link from "next/link";
import type { ChangeListItem } from "@/types";
import { getChanges } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import RiskBadge from "@/components/common/RiskBadge";
import { getTimelineEventTitle, getTimelineProvider } from "@/lib/timeline";
import { getProviderMeta } from "@/lib/providers";

const WINDOW_HOURS = 72;
const MAX_RESULTS = 5;

// ── Helpers ───────────────────────────────────────────────────────────────────

function addHours(iso: string, hours: number): string {
  const d = new Date(iso);
  d.setTime(d.getTime() + hours * 60 * 60 * 1000);
  return d.toISOString();
}

// ── Sub-components ────────────────────────────────────────────────────────────

function RelatedChangeRow({ item }: { item: ChangeListItem }) {
  const title = getTimelineEventTitle(item);
  const provider = getTimelineProvider(item);
  const providerMeta = getProviderMeta(provider);

  return (
    <Link
      href={`/changes/${item.id}`}
      style={{ textDecoration: "none" }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          padding: "8px 0",
          borderBottom: "1px solid #1a1d26",
        }}
      >
        {/* Risk badge */}
        <div style={{ flexShrink: 0 }}>
          <RiskBadge level={item.risk_level} />
        </div>

        {/* Title + meta */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <p
            style={{
              fontSize: "13px",
              color: "#c8ccd8",
              margin: 0,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {title}
          </p>
          <p
            style={{
              fontSize: "11px",
              color: "#565b6e",
              margin: "2px 0 0",
            }}
          >
            <span style={{ color: providerMeta.color }}>{providerMeta.shortLabel}</span>
            {" · "}
            {formatRelativeTime(item.created_at)}
          </p>
        </div>

        {/* Arrow */}
        <span
          style={{
            fontSize: "12px",
            color: "#565b6e",
            flexShrink: 0,
          }}
        >
          →
        </span>
      </div>
    </Link>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface RelatedChangesPanelProps {
  /** The current change — used to derive integration_id and timestamp window. */
  currentChangeId: string;
  integrationId: string;
  detectedAt: string;
  token: string | null;
}

export default function RelatedChangesPanel({
  currentChangeId,
  integrationId,
  detectedAt,
  token,
}: RelatedChangesPanelProps) {
  const [items, setItems] = useState<ChangeListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        setLoading(true);
        const since = addHours(detectedAt, -WINDOW_HOURS);
        const until = addHours(detectedAt, WINDOW_HOURS);

        const result = await getChanges(
          {
            integration_id: integrationId,
            since,
            until,
            page: 1,
            page_size: MAX_RESULTS + 1, // +1 so we can filter out the current change
          },
          token,
        );

        if (!cancelled) {
          const filtered = result.items
            .filter((c) => c.id !== currentChangeId)
            .slice(0, MAX_RESULTS);
          setItems(filtered);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : "Failed to load related changes.",
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [currentChangeId, integrationId, detectedAt, token]);

  return (
    <section aria-labelledby="section-related">
      <h2
        id="section-related"
        style={{
          fontSize: "11px",
          color: "#565b6e",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          margin: "0 0 8px",
          fontWeight: 500,
        }}
      >
        Nearby changes
      </h2>

      <div
        style={{
          background: "#13151a",
          border: "1px solid #2a2d38",
          borderRadius: "6px",
          padding: "12px 16px",
        }}
      >
        {loading ? (
          <p style={{ fontSize: "13px", color: "#565b6e", margin: 0 }}>
            Loading…
          </p>
        ) : error ? (
          <p style={{ fontSize: "13px", color: "#f5632a", margin: 0 }}>
            {error}
          </p>
        ) : items.length === 0 ? (
          <p
            style={{
              fontSize: "13px",
              color: "#565b6e",
              fontStyle: "italic",
              margin: 0,
            }}
          >
            No nearby changes detected in this integration.
          </p>
        ) : (
          <div>
            {items.map((item) => (
              <RelatedChangeRow key={item.id} item={item} />
            ))}
            <p
              style={{
                fontSize: "11px",
                color: "#565b6e",
                margin: "8px 0 0",
              }}
            >
              Changes within ±{WINDOW_HOURS}h in the same integration
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
