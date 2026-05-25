"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
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
  const { getToken, isLoaded } = useAuth();

  useEffect(() => {
    if (!isLoaded) return;
    let cancelled = false;

    (async () => {
      try {
        const token = await getToken();
        const data = await getResources({ page_size: 100 }, token);
        if (!cancelled) {
          setResources(data.items);
          setTotal(data.total);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load resources.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => { cancelled = true; };
  }, [isLoaded, getToken]);

  return (
    <>
      <PageHeader
        title="Resources"
        description="Configuration surfaces monitored by ConfigTrace — zones, repositories, projects, accounts, and more across all connected providers."
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
