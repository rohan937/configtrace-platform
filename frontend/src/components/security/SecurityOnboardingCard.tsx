"use client";

/**
 * SecurityOnboardingCard (M62.5).
 *
 * A lightweight, deterministic Security Exposure setup checklist for the
 * /security overview. Completion is derived from real data via existing APIs
 * (see lib/securityOnboarding). No persistence, no AI, no fake completion.
 *
 * Collapses to a small "set up" card once all required steps are done.
 */

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@clerk/nextjs";

import {
  getIntegrations,
  getSecurityFindings,
  getSecurityCoverage,
  getSecurityRuleSettings,
  getSecurityDemoDataStatus,
  getWorkspaces,
  getNotificationSettings,
  listPushSubscriptions,
  seedSecurityDemoData,
} from "@/lib/api";
import {
  buildOnboarding,
  type ChecklistItem,
  type OnboardingSummary,
} from "@/lib/securityOnboarding";
import { SectionLabel } from "@/components/security/previews";
import { trackSecurityBetaEvent } from "@/lib/securityBetaEvents";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { canManageDemoData } from "@/lib/workspacePermissions";

export default function SecurityOnboardingCard({ onChanged }: { onChanged?: () => void }) {
  const { getToken } = useAuth();
  const { role } = useWorkspace();
  const canManageDemo = canManageDemoData(role);
  const [summary, setSummary] = useState<OnboardingSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const token = await getToken();
      // Resolve a workspace for the notification-settings + push checks.
      let wsId: string | null = null;
      try {
        const ws = await getWorkspaces(token);
        wsId = ws.workspaces[0]?.id ?? null;
      } catch {
        wsId = null;
      }

      const [ints, findings, active, coverage, rules, demo, notif, push] =
        await Promise.allSettled([
          getIntegrations(token),
          getSecurityFindings({ page_size: 100 }, token),
          getSecurityFindings({ status: "active", page_size: 1 }, token),
          getSecurityCoverage(token),
          getSecurityRuleSettings(token),
          getSecurityDemoDataStatus(token),
          wsId ? getNotificationSettings(wsId, token) : Promise.reject(),
          wsId ? listPushSubscriptions(wsId, token) : Promise.reject(),
        ]);

      const val = <T,>(r: PromiseSettledResult<T>): T | null =>
        r.status === "fulfilled" ? r.value : null;

      setSummary(
        buildOnboarding({
          integrations: val(ints)?.integrations ?? null,
          findings: val(findings)?.items ?? null,
          activeCount: val(active)?.total ?? null,
          coverage: val(coverage)?.providers ?? null,
          ruleSettings: val(rules)?.items ?? null,
          demo: val(demo),
          notif: val(notif),
          pushSubs: val(push)?.subscriptions ?? null,
        }),
      );
    } catch {
      setError("Could not load the setup checklist.");
    } finally {
      setLoading(false);
    }
  }, [getToken]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleLoadDemo = useCallback(async () => {
    setSeeding(true);
    setError(null);
    trackSecurityBetaEvent("security_demo_seed_clicked", { action: "onboarding" }, { getToken, pagePath: "/security" });
    try {
      const token = await getToken();
      await seedSecurityDemoData(token);
      await load();
      trackSecurityBetaEvent("security_demo_seed_completed", { action: "onboarding", result: "ok" }, { getToken, pagePath: "/security" });
      onChanged?.();
    } catch {
      setError("Could not load demo data.");
    } finally {
      setSeeding(false);
    }
  }, [getToken, load, onChanged]);

  const handleCtaClick = useCallback(
    (itemId: string) => {
      trackSecurityBetaEvent("security_onboarding_cta_clicked", { checklist_item_id: itemId }, { getToken, pagePath: "/security" });
    },
    [getToken],
  );

  if (loading || !summary) return null; // stay quiet until ready; never blocks page
  if (summary.items.length === 0) return null;

  // Collapsed state once all required steps are done.
  if (summary.allRequiredComplete) {
    return (
      <div
        className="bg-surface1 border border-border"
        style={{ borderRadius: "12px", padding: "12px 16px", marginBottom: "16px", display: "flex", alignItems: "center", gap: "10px" }}
      >
        <CheckIcon done />
        <span style={{ fontSize: "13px", color: "#c4c8d4" }}>
          Security Exposure is set up. {summary.completed} of {summary.total} steps complete.
        </span>
        <Link href="/security/exposures" style={{ marginLeft: "auto", fontSize: "12.5px", color: "#6b9cf8", textDecoration: "none" }}>
          View exposures →
        </Link>
      </div>
    );
  }

  return (
    <div
      className="bg-surface1 border border-border"
      style={{ borderRadius: "12px", padding: "18px 20px", marginBottom: "20px" }}
    >
      <SectionLabel>Security Exposure setup</SectionLabel>
      <p style={{ fontSize: "13px", color: "#8b90a0", margin: "6px 0 14px", lineHeight: 1.6, maxWidth: "720px" }}>
        A short checklist to get from connected providers to reviewed findings and
        routed alerts.
      </p>

      {/* Progress */}
      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px" }}>
        <div style={{ flex: 1, height: "6px", background: "#1d1f27", borderRadius: "999px", overflow: "hidden", maxWidth: "320px" }}>
          <div style={{ width: `${summary.percent}%`, height: "100%", background: "#3ccf7e", transition: "width 200ms" }} />
        </div>
        <span style={{ fontSize: "12px", color: "#8b90a0", whiteSpace: "nowrap" }}>
          {summary.completed} of {summary.total} complete
        </span>
      </div>

      {error ? <p style={{ fontSize: "12px", color: "#e07a5f", margin: "0 0 12px" }}>{error}</p> : null}

      <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
        {summary.items.map((item) => (
          <ChecklistRow key={item.id} item={item} seeding={seeding} onLoadDemo={handleLoadDemo} onCtaClick={handleCtaClick} canManageDemo={canManageDemo} />
        ))}
      </div>
    </div>
  );
}

function ChecklistRow({
  item,
  seeding,
  onLoadDemo,
  onCtaClick,
  canManageDemo,
}: {
  item: ChecklistItem;
  seeding: boolean;
  onLoadDemo: () => void;
  onCtaClick: (itemId: string) => void;
  canManageDemo: boolean;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: "12px",
        padding: "10px 0",
        borderTop: "1px solid #1a1c23",
      }}
    >
      <CheckIcon done={item.complete} />
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
          <span style={{ fontSize: "13.5px", fontWeight: 600, color: item.complete ? "#8b90a0" : "#e8eaf0" }}>
            {item.title}
          </span>
          {item.optional ? (
            <span style={{ fontSize: "10px", fontWeight: 600, color: "#565b6e", border: "1px solid #2a2d38", borderRadius: "5px", padding: "1px 6px" }}>
              Optional
            </span>
          ) : null}
        </div>
        <div style={{ fontSize: "12px", color: "#8b90a0", marginTop: "2px", lineHeight: 1.5 }}>
          {item.description}
        </div>
        <div style={{ fontSize: "11.5px", color: "#565b6e", marginTop: "3px" }}>{item.statusText}</div>
      </div>
      <div style={{ flexShrink: 0 }}>
        {item.complete ? (
          <span style={{ fontSize: "12px", color: "#3ccf7e", fontWeight: 600 }}>Done</span>
        ) : item.action === "load_demo" ? (
          canManageDemo ? (
            <button
              type="button"
              onClick={onLoadDemo}
              disabled={seeding}
              style={{
                fontSize: "12.5px", fontWeight: 600, color: "#6b9cf8",
                background: "rgba(107,156,248,0.12)", border: "1px solid rgba(107,156,248,0.4)",
                borderRadius: "8px", padding: "6px 12px",
                cursor: seeding ? "wait" : "pointer", opacity: seeding ? 0.6 : 1, fontFamily: "inherit",
              }}
            >
              {seeding ? "Loading…" : item.ctaLabel}
            </button>
          ) : (
            <span style={{ fontSize: "11.5px", color: "#8b90a0", maxWidth: "180px", textAlign: "right" }}>
              Ask a workspace admin to load demo data.
            </span>
          )
        ) : (
          <Link
            href={item.ctaHref}
            onClick={() => onCtaClick(item.id)}
            style={{
              fontSize: "12.5px", fontWeight: 600, color: "#6b9cf8",
              textDecoration: "none", border: "1px solid #2a2d38",
              borderRadius: "8px", padding: "6px 12px", whiteSpace: "nowrap",
            }}
          >
            {item.ctaLabel}
          </Link>
        )}
      </div>
    </div>
  );
}

function CheckIcon({ done }: { done: boolean }) {
  return (
    <span
      style={{
        width: "18px",
        height: "18px",
        borderRadius: "50%",
        flexShrink: 0,
        marginTop: "2px",
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: "11px",
        fontWeight: 700,
        color: done ? "#0e0f11" : "#565b6e",
        background: done ? "#3ccf7e" : "transparent",
        border: done ? "1px solid #3ccf7e" : "1px solid #3a3d4a",
      }}
    >
      {done ? "✓" : ""}
    </span>
  );
}
