/**
 * securityOnboarding.ts — derive the Configuration Risk onboarding checklist (M62.5).
 *
 * Pure and deterministic: given data already fetched from existing APIs, it
 * returns a checklist of setup steps with completion state. No backend, no
 * persistence, no AI — completion is inferred from real data only (never faked).
 *
 * Required steps drive the progress bar; "optional" steps are shown but excluded
 * from the denominator. The demo step appears only when there is nothing real to
 * look at yet.
 */

import type {
  Integration,
  SecurityFinding,
  SecurityCoverageProvider,
  SecurityRuleSetting,
  SecurityDemoDataStatus,
  WorkspaceNotificationSettings,
  PushSubscriptionResponse,
} from "@/types";

export interface ChecklistItem {
  id: string;
  title: string;
  description: string;
  complete: boolean;
  optional: boolean;
  ctaLabel: string;
  ctaHref: string;
  statusText: string;
  /** Special action handled by the host (e.g. seed demo data) instead of a link. */
  action?: "load_demo";
  /** When false, the item is not rendered (e.g. demo step once real data exists). */
  visible: boolean;
}

export interface OnboardingSummary {
  completed: number;
  total: number; // required (non-optional, visible) items
  percent: number;
  items: ChecklistItem[];
  allRequiredComplete: boolean;
}

export interface OnboardingInputs {
  integrations: Integration[] | null;
  findings: SecurityFinding[] | null; // sample across statuses
  activeCount: number | null;
  coverage: SecurityCoverageProvider[] | null;
  ruleSettings: SecurityRuleSetting[] | null;
  demo: SecurityDemoDataStatus | null;
  notif: WorkspaceNotificationSettings | null;
  pushSubs: PushSubscriptionResponse[] | null;
}

const NOTIF_HREF = "/settings/workspace/notifications";

/** Real = excludes the hidden demo integration and soft-deleted rows. */
function realIntegrations(integrations: Integration[] | null): Integration[] {
  return (integrations ?? []).filter(
    (i) => i.provider !== "demo" && i.status !== "deleted",
  );
}

export function buildOnboarding(inp: OnboardingInputs): OnboardingSummary {
  const real = realIntegrations(inp.integrations);
  const connected = real.length > 0;
  const synced = real.some((i) => !!i.last_synced_at);

  // Review: only meaningful once connected. Complete when there is nothing
  // active to review, or at least one finding has been acted on.
  const findings = inp.findings ?? [];
  const anyReviewed = findings.some(
    (f) =>
      f.reviewed_at != null ||
      f.status === "accepted_risk" ||
      f.status === "snoozed" ||
      f.status === "resolved",
  );
  const reviewComplete =
    connected && ((inp.activeCount ?? 0) === 0 || anyReviewed);

  // Alerts: any security channel opted in (Slack / email / browser push).
  const pushSecurity = (inp.pushSubs ?? []).some(
    (s) => s.enabled && s.security_push_enabled,
  );
  const alertsComplete = !!(
    inp.notif?.slack_security_alerts_enabled ||
    inp.notif?.email_security_alerts_enabled ||
    pushSecurity
  );

  // Coverage: any provider with usable (good/limited) coverage.
  const coverageComplete = (inp.coverage ?? []).some(
    (p) => p.coverage_status === "good" || p.coverage_status === "limited",
  );

  // Rules: an explicit enable/disable choice has been made (optional step).
  const rulesTuned = (inp.ruleSettings ?? []).some((r) => r.explicit_setting);

  const demoLoaded = !!inp.demo?.exists;
  const hasRealFindings = (inp.activeCount ?? 0) > 0 || findings.length > 0;
  // Demo step only when there is nothing real to look at and demo not loaded.
  const showDemo = !connected && !hasRealFindings;

  const items: ChecklistItem[] = [
    {
      id: "connect",
      title: "Connect a provider",
      description: "Link a provider so ConfigTrace can read its configuration.",
      complete: connected,
      optional: false,
      ctaLabel: "Connect",
      ctaHref: "/integrations",
      statusText: connected
        ? `${real.length} provider${real.length === 1 ? "" : "s"} connected`
        : "No providers connected yet",
      visible: true,
    },
    {
      id: "sync",
      title: "Run a sync",
      description: "Run the first sync to collect provider metadata.",
      complete: synced,
      optional: false,
      ctaLabel: "Run a sync",
      ctaHref: "/integrations",
      statusText: synced
        ? "At least one provider has synced"
        : connected
          ? "Connected, not synced yet"
          : "Connect a provider first",
      visible: true,
    },
    {
      id: "review",
      title: "Review exposures",
      description: "Look at active risks and acknowledge, snooze, or accept risk.",
      complete: reviewComplete,
      optional: false,
      ctaLabel: "Review exposures",
      ctaHref: "/security/risks",
      statusText: !connected
        ? "Connect a provider first"
        : (inp.activeCount ?? 0) === 0
          ? "No active risks to review"
          : anyReviewed
            ? "Findings reviewed"
            : `${inp.activeCount} active exposure${(inp.activeCount ?? 0) === 1 ? "" : "s"} to review`,
      visible: true,
    },
    {
      id: "alerts",
      title: "Route alerts",
      description: "Turn on Configuration Risk alerts over Slack, email, or browser push.",
      complete: alertsComplete,
      optional: false,
      ctaLabel: "Route alerts",
      ctaHref: NOTIF_HREF,
      statusText: alertsComplete
        ? "Security alerts enabled"
        : "Security alerts are off",
      visible: true,
    },
    {
      id: "coverage",
      title: "Check coverage",
      description: "Confirm ConfigTrace is collecting the metadata its rules need.",
      complete: coverageComplete,
      optional: false,
      ctaLabel: "Check coverage",
      ctaHref: "/security/coverage",
      statusText: coverageComplete
        ? "At least one provider has coverage"
        : "No provider coverage yet",
      visible: true,
    },
    {
      id: "rules",
      title: "Tune rules",
      description: "Enable or disable specific rules for this workspace.",
      complete: rulesTuned,
      optional: true,
      ctaLabel: "Tune rules",
      ctaHref: "/security/rules",
      statusText: rulesTuned ? "Rule choices saved" : "Optional",
      visible: true,
    },
    {
      id: "report",
      title: "Export a report",
      description: "Export a metadata-only summary of findings and coverage.",
      complete: false,
      optional: true,
      ctaLabel: "Export report",
      ctaHref: "/security/reports",
      statusText: "Optional",
      visible: true,
    },
    {
      id: "demo",
      title: "Try demo data",
      description: "Explore the product with a safe demo dataset, no providers needed.",
      complete: demoLoaded,
      optional: true,
      ctaLabel: demoLoaded ? "Demo data loaded" : "Load demo data",
      ctaHref: "/security/risks",
      statusText: demoLoaded ? "Demo data loaded" : "Optional",
      action: "load_demo",
      visible: showDemo || demoLoaded,
    },
  ];

  const required = items.filter((i) => i.visible && !i.optional);
  const completed = required.filter((i) => i.complete).length;
  const total = required.length;
  const percent = total === 0 ? 0 : Math.round((completed / total) * 100);

  return {
    completed,
    total,
    percent,
    items: items.filter((i) => i.visible),
    allRequiredComplete: completed === total,
  };
}
