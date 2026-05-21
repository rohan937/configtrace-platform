"use client";

import { useEffect, useState } from "react";
import type { ChangeListItem, ResourceListItem } from "@/types";
import { getChanges, getResources } from "@/lib/api";
import PageHeader from "@/components/common/PageHeader";
import StatBlock from "@/components/common/StatBlock";
import ChangeList from "@/components/changes/ChangeList";
import LoadingState from "@/components/common/LoadingState";
import ErrorState from "@/components/common/ErrorState";

export default function DashboardPage() {
  const [changes, setChanges] = useState<ChangeListItem[]>([]);
  const [resources, setResources] = useState<ResourceListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [changesData, resourcesData] = await Promise.all([
          getChanges({ page_size: 10 }),
          getResources({ page_size: 100 }),
        ]);
        if (!cancelled) {
          setChanges(changesData.items);
          setResources(resourcesData.items);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load data.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => { cancelled = true; };
  }, []);

  // Derive stats from loaded data
  const criticalCount = changes.filter((c) => c.risk_level === "critical").length;
  const highCount = changes.filter((c) => c.risk_level === "high").length;

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Overview of recent configuration changes and monitored resources."
      />

      {/* Summary bar */}
      <div
        className="flex items-center gap-8 px-6 py-4"
        style={{ borderBottom: "1px solid #2a2d38" }}
      >
        <StatBlock
          value={loading ? "—" : resources.length}
          label="Resources monitored"
        />
        <div style={{ width: "1px", height: "36px", background: "#2a2d38" }} />
        <StatBlock
          value={loading ? "—" : changes.length > 0 ? `${changes.length}+` : "0"}
          label="Recent changes"
        />
        <div style={{ width: "1px", height: "36px", background: "#2a2d38" }} />
        <StatBlock
          value={loading ? "—" : criticalCount}
          label="Critical"
        />
        <div style={{ width: "1px", height: "36px", background: "#2a2d38" }} />
        <StatBlock
          value={loading ? "—" : highCount}
          label="High risk"
        />
      </div>

      {/* Recent changes */}
      <div className="px-6 py-6">
        <h2
          className="mb-4"
          style={{ fontSize: "13px", color: "#8b90a0", textTransform: "uppercase", letterSpacing: "0.06em" }}
        >
          Recent Changes
        </h2>

        {loading && <LoadingState />}
        {!loading && error && <ErrorState message={error} />}
        {!loading && !error && <ChangeList changes={changes} emptyMessage="No changes yet. Run a sync to see results." />}
      </div>
    </>
  );
}
