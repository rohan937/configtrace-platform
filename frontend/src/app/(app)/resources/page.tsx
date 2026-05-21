"use client";

import { useEffect, useState } from "react";
import type { ResourceListItem } from "@/types";
import { getResources } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import ResourceList from "@/components/resources/ResourceList";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";

export default function ResourcesPage() {
  const [resources, setResources] = useState<ResourceListItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getResources({ page_size: 100 })
      .then((data) => {
        if (!cancelled) {
          setResources(data.items);
          setTotal(data.total);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load resources.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, []);

  return (
    <>
      <PageHeader
        title="Resources"
        description="All monitored DNS zones and records across your integrations."
      />

      <div className="px-6 py-6">
        {!loading && !error && total > 0 && (
          <p className="mb-4" style={{ fontSize: "13px", color: "#8b90a0" }}>
            {total} resource{total === 1 ? "" : "s"} monitored
          </p>
        )}

        {loading && <LoadingState />}
        {!loading && error && <ErrorState message={error} />}
        {!loading && !error && <ResourceList resources={resources} />}
      </div>
    </>
  );
}
