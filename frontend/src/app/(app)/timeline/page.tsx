"use client";

import { useEffect, useState } from "react";
import type { ChangeListItem } from "@/types";
import { getChanges } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import ChangeList from "@/components/changes/ChangeList";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";

const PAGE_SIZE = 50;

export default function TimelinePage() {
  const [changes, setChanges] = useState<ChangeListItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    getChanges({ page, page_size: PAGE_SIZE })
      .then((data) => {
        if (!cancelled) {
          setChanges(data.items);
          setTotal(data.total);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load changes.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, [page]);

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <>
      <PageHeader
        title="Timeline"
        description="Full change history across all integrations and resources."
      />

      <div className="px-6 py-6">
        {/* Result count */}
        {!loading && !error && (
          <p
            className="mb-4"
            style={{ fontSize: "13px", color: "#8b90a0" }}
          >
            {total === 0
              ? "No changes recorded yet."
              : `${total} change${total === 1 ? "" : "s"} total`}
          </p>
        )}

        {loading && <LoadingState />}
        {!loading && error && <ErrorState message={error} />}
        {!loading && !error && (
          <ChangeList
            changes={changes}
            emptyMessage="No changes recorded yet. Run a sync to capture your first snapshot."
          />
        )}

        {/* Pagination */}
        {!loading && !error && totalPages > 1 && (
          <div className="flex items-center justify-end gap-3 mt-4">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1 rounded text-sm"
              style={{
                background: "#1e2030",
                border: "1px solid #3a3d4a",
                color: page === 1 ? "#8b90a0" : "#b0b5c4",
                cursor: page === 1 ? "not-allowed" : "pointer",
              }}
            >
              Prev
            </button>
            <span style={{ fontSize: "13px", color: "#8b90a0" }}>
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="px-3 py-1 rounded text-sm"
              style={{
                background: "#1e2030",
                border: "1px solid #3a3d4a",
                color: page === totalPages ? "#8b90a0" : "#b0b5c4",
                cursor: page === totalPages ? "not-allowed" : "pointer",
              }}
            >
              Next
            </button>
          </div>
        )}
      </div>
    </>
  );
}
