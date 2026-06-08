"use client";

/**
 * SecurityDemoWalkthrough (M62.9).
 *
 * A lightweight, dismissible guided tour of the Security Exposure workflow.
 * Floats bottom-right on Security pages only, so a prospect can preview the
 * full workflow in 2–3 minutes even when real findings already exist.
 *
 * It does NOT auto-load demo data — seeding/clearing only happen on an explicit
 * click via the existing M62.2 endpoints. No new APIs, no notifications, no
 * mutation of real findings. Copy stays demo-safe: "demo dataset", "sample
 * findings", "not from connected providers", "preview workflow".
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@clerk/nextjs";

import type { SecurityDemoDataStatus } from "@/types";
import {
  getSecurityDemoDataStatus,
  seedSecurityDemoData,
  clearSecurityDemoData,
  getSecurityFindings,
} from "@/lib/api";
import { trackSecurityBetaEvent, normalizeSecurityPath } from "@/lib/securityBetaEvents";
import { useWorkspace } from "@/contexts/WorkspaceContext";
import { canManageDemoData } from "@/lib/workspacePermissions";

// ── Pure step builder (exported for testing) ──────────────────────────────────

export interface WalkStep {
  id: string;
  href: string;
  title: string;
  copy: string;
  cta: string;
  secondaryHref?: string;
  secondaryCta?: string;
}

export function buildWalkthroughSteps(sampleFindingId: string | null): WalkStep[] {
  return [
    {
      id: "overview",
      href: "/security",
      title: "Start with Security Overview",
      copy: "See active exposures, provider coverage, and setup progress in one place.",
      cta: "Open overview",
    },
    {
      id: "exposures",
      href: "/security/exposures",
      title: "Review active exposures",
      copy: "Find risky current states across cloud and SaaS configuration.",
      cta: "View exposures",
    },
    {
      id: "detail",
      href: sampleFindingId ? `/security/exposures/${sampleFindingId}` : "/security/exposures",
      title: "Inspect one exposure",
      copy: "Open a finding to review status, confidence, safeguards, remediation, notes, and actions.",
      cta: "Open sample exposure",
    },
    {
      id: "assets",
      href: "/security/assets",
      title: "Group by affected asset",
      copy: "See which repositories, buckets, webhooks, security groups, tables, or projects carry exposure.",
      cta: "View assets",
    },
    {
      id: "timeline",
      href: "/security/timeline",
      title: "Follow the exposure timeline",
      copy: "See when findings opened, resolved, were acknowledged, snoozed, or accepted.",
      cta: "Open timeline",
    },
    {
      id: "rules",
      href: "/security/rules",
      secondaryHref: "/security/coverage",
      title: "Understand checks and coverage",
      copy: "Review what ConfigTrace checks and whether provider metadata is sufficient.",
      cta: "View rules",
      secondaryCta: "View coverage",
    },
    {
      id: "incident-review",
      href: "/security/incident-review",
      title: "Investigate a time window",
      copy: "Connect exposures and drift events around a selected period.",
      cta: "Open Incident Review",
    },
    {
      id: "reports",
      href: "/security/reports",
      title: "Export a review packet",
      copy: "Generate a metadata-only security exposure report for internal review or customer feedback.",
      cta: "Open reports",
    },
  ];
}

// ── LocalStorage helpers (SSR-safe) ───────────────────────────────────────────

const LS_COLLAPSED = "ct.securityDemoWalkthrough.collapsed";
const LS_STEP = "ct.securityDemoWalkthrough.step";
const LS_DISMISSED = "ct.securityDemoWalkthrough.dismissed";

function lsGet(key: string): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}
function lsSet(key: string, value: string): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* private mode / disabled storage — non-fatal */
  }
}

function isSecurityPath(pathname: string | null): boolean {
  if (!pathname) return false;
  return pathname === "/security" || pathname.startsWith("/security/");
}

// ── Widget ────────────────────────────────────────────────────────────────────

export default function SecurityDemoWalkthrough() {
  const pathname = usePathname();
  const router = useRouter();
  const { getToken, isLoaded } = useAuth();
  const { role } = useWorkspace();
  const canManage = canManageDemoData(role);

  const [hydrated, setHydrated] = useState(false);
  const [collapsed, setCollapsed] = useState(true);
  const [dismissed, setDismissed] = useState(false);
  const [step, setStep] = useState(0);

  const [status, setStatus] = useState<SecurityDemoDataStatus | null>(null);
  const [sampleFindingId, setSampleFindingId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const visible = isSecurityPath(pathname);

  // Hydrate persisted UI state once on the client.
  useEffect(() => {
    setCollapsed(lsGet(LS_COLLAPSED) !== "0");
    setDismissed(lsGet(LS_DISMISSED) === "1");
    const s = Number.parseInt(lsGet(LS_STEP) ?? "", 10);
    if (Number.isFinite(s)) setStep(s);
    setHydrated(true);
  }, []);

  const steps = useMemo(() => buildWalkthroughSteps(sampleFindingId), [sampleFindingId]);
  const clampedStep = Math.min(Math.max(step, 0), steps.length - 1);
  const current = steps[clampedStep];

  const refreshStatus = useCallback(async () => {
    if (!isLoaded) return;
    try {
      const token = await getToken();
      const s = await getSecurityDemoDataStatus(token);
      setStatus(s);
      if (s.exists) {
        try {
          const res = await getSecurityFindings({ page_size: 1 }, token);
          setSampleFindingId(res.items?.[0]?.id ?? null);
        } catch {
          setSampleFindingId(null);
        }
      } else {
        setSampleFindingId(null);
      }
    } catch {
      setStatus(null);
    }
  }, [getToken, isLoaded]);

  // Load demo status when the widget is actually shown.
  useEffect(() => {
    if (visible && hydrated && isLoaded) void refreshStatus();
  }, [visible, hydrated, isLoaded, refreshStatus]);

  const persistCollapsed = useCallback((v: boolean) => {
    setCollapsed(v);
    lsSet(LS_COLLAPSED, v ? "1" : "0");
  }, []);
  const persistDismissed = useCallback((v: boolean) => {
    setDismissed(v);
    lsSet(LS_DISMISSED, v ? "1" : "0");
  }, []);
  const persistStep = useCallback(
    (v: number, len: number) => {
      const next = Math.min(Math.max(v, 0), len - 1);
      setStep(next);
      lsSet(LS_STEP, String(next));
    },
    [],
  );

  const trackOpts = { getToken, pagePath: normalizeSecurityPath(pathname) ?? undefined };

  const onSeed = useCallback(async () => {
    setBusy(true);
    setNote(null);
    trackSecurityBetaEvent("security_demo_seed_clicked", { action: "walkthrough" }, { getToken, pagePath: normalizeSecurityPath(pathname) ?? undefined });
    try {
      const token = await getToken();
      const s = await seedSecurityDemoData(token);
      setStatus(s);
      await refreshStatus();
      setNote("Demo data loaded. Open Security Overview to view sample findings.");
      trackSecurityBetaEvent("security_demo_seed_completed", { action: "walkthrough", result: "ok" }, { getToken, pagePath: normalizeSecurityPath(pathname) ?? undefined });
      router.refresh();
    } catch {
      setNote("Could not load demo data. Please try again.");
    } finally {
      setBusy(false);
    }
  }, [getToken, refreshStatus, router, pathname]);

  const onClear = useCallback(async () => {
    setBusy(true);
    setNote(null);
    trackSecurityBetaEvent("security_demo_clear_clicked", { action: "walkthrough" }, { getToken, pagePath: normalizeSecurityPath(pathname) ?? undefined });
    try {
      const token = await getToken();
      await clearSecurityDemoData(token);
      setStatus({
        exists: false,
        finding_count: 0,
        active_count: 0,
        resolved_count: 0,
        accepted_count: 0,
        snoozed_count: 0,
      });
      setSampleFindingId(null);
      setNote("Demo data cleared.");
      router.refresh();
    } catch {
      setNote("Could not clear demo data. Please try again.");
    } finally {
      setBusy(false);
    }
  }, [getToken, router, pathname]);

  // Render nothing on the server / non-security pages / before hydration.
  if (!visible || !hydrated) return null;

  const demoLoaded = !!status?.exists;
  const statusLine = demoLoaded ? "Demo data loaded" : "Load demo data to preview";

  // Dismissed → small reopen pill only (not hidden forever).
  if (dismissed) {
    return (
      <button
        type="button"
        onClick={() => {
          persistDismissed(false);
          persistCollapsed(false);
          trackSecurityBetaEvent("security_walkthrough_opened", { action: "reopen" }, trackOpts);
        }}
        style={{ ...pillStyle, cursor: "pointer" }}
        aria-label="Open Security demo walkthrough"
      >
        Demo walkthrough
      </button>
    );
  }

  // Collapsed → compact card.
  if (collapsed) {
    return (
      <div style={cardStyle}>
        <div style={rowBetween}>
          <div style={{ minWidth: 0 }}>
            <div style={titleStyle}>Demo walkthrough</div>
            <div style={subStyle}>{statusLine}</div>
          </div>
          <div style={{ display: "flex", gap: "6px", flexShrink: 0 }}>
            <button
              type="button"
              onClick={() => {
                persistCollapsed(false);
                trackSecurityBetaEvent("security_walkthrough_opened", { action: "expand" }, trackOpts);
              }}
              style={iconBtn}
              aria-label="Expand walkthrough"
            >
              ▢
            </button>
            <button type="button" onClick={() => persistDismissed(true)} style={iconBtn} aria-label="Dismiss walkthrough">
              ✕
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Expanded → full step UI.
  return (
    <div style={{ ...cardStyle, width: "330px" }}>
      <div style={rowBetween}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", minWidth: 0 }}>
          <span style={titleStyle}>Demo walkthrough</span>
          <span style={demoBadge(demoLoaded)}>{demoLoaded ? "Demo loaded" : "No demo data"}</span>
        </div>
        <div style={{ display: "flex", gap: "6px", flexShrink: 0 }}>
          <button type="button" onClick={() => persistCollapsed(true)} style={iconBtn} aria-label="Collapse walkthrough">
            –
          </button>
          <button type="button" onClick={() => persistDismissed(true)} style={iconBtn} aria-label="Dismiss walkthrough">
            ✕
          </button>
        </div>
      </div>

      {/* Progress */}
      <div style={{ marginTop: "12px" }}>
        <div style={{ fontSize: "11px", color: "#565b6e", marginBottom: "6px" }}>
          Step {clampedStep + 1} of {steps.length}
        </div>
        <div style={{ display: "flex", gap: "4px" }}>
          {steps.map((s, i) => (
            <span
              key={s.id}
              style={{
                flex: 1,
                height: "3px",
                borderRadius: "999px",
                background: i <= clampedStep ? "#6b9cf8" : "#2a2d38",
              }}
            />
          ))}
        </div>
      </div>

      {/* Current step */}
      <div style={{ marginTop: "12px" }}>
        <div style={{ fontSize: "13.5px", fontWeight: 700, color: "#e8eaf0" }}>{current.title}</div>
        <p style={{ fontSize: "12.5px", color: "#8b90a0", margin: "6px 0 0", lineHeight: 1.55 }}>{current.copy}</p>
      </div>

      {/* Step CTAs */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "12px" }}>
        <Link
          href={current.href}
          style={primaryLink}
          onClick={() => {
            trackSecurityBetaEvent("security_walkthrough_step_clicked", { action: current.id }, trackOpts);
            persistCollapsed(true);
          }}
        >
          {current.cta} →
        </Link>
        {current.secondaryHref && current.secondaryCta ? (
          <Link
            href={current.secondaryHref}
            style={secondaryLink}
            onClick={() => {
              trackSecurityBetaEvent("security_walkthrough_step_clicked", { action: `${current.id}_secondary` }, trackOpts);
              persistCollapsed(true);
            }}
          >
            {current.secondaryCta} →
          </Link>
        ) : null}
      </div>

      {/* Prev / Next */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px", marginTop: "12px" }}>
        <button
          type="button"
          onClick={() => persistStep(clampedStep - 1, steps.length)}
          disabled={clampedStep === 0}
          style={navBtn(clampedStep === 0)}
        >
          ← Previous
        </button>
        <button
          type="button"
          onClick={() => persistStep(clampedStep + 1, steps.length)}
          disabled={clampedStep === steps.length - 1}
          style={navBtn(clampedStep === steps.length - 1)}
        >
          Next →
        </button>
      </div>

      {/* Demo data controls */}
      <div style={{ marginTop: "12px", paddingTop: "10px", borderTop: "1px solid #1f2229" }}>
        {!canManage ? (
          <span style={{ fontSize: "11.5px", color: "#8b90a0", lineHeight: 1.5 }}>
            {demoLoaded
              ? "Sample findings — not from connected providers. Ask a workspace admin to clear demo data."
              : "Ask a workspace admin to load or clear demo data."}
          </span>
        ) : demoLoaded ? (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px", flexWrap: "wrap" }}>
            <span style={{ fontSize: "11.5px", color: "#8b90a0" }}>
              Sample findings — not from connected providers.
            </span>
            <button type="button" onClick={onClear} disabled={busy} style={ghostBtn(busy)}>
              {busy ? "Working…" : "Clear demo data"}
            </button>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <span style={{ fontSize: "11.5px", color: "#8b90a0", lineHeight: 1.5 }}>
              Load a safe demo dataset to preview the workflow. You can clear it any time.
            </span>
            <button type="button" onClick={onSeed} disabled={busy} style={seedBtn(busy)}>
              {busy ? "Loading…" : "Load demo data"}
            </button>
          </div>
        )}
        {note ? <div style={{ fontSize: "11.5px", color: "#6b9cf8", marginTop: "8px" }}>{note}</div> : null}
      </div>
    </div>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────

const cardStyle: React.CSSProperties = {
  position: "fixed",
  right: "20px",
  bottom: "20px",
  width: "300px",
  maxWidth: "calc(100vw - 32px)",
  zIndex: 50,
  background: "#13151a",
  border: "1px solid #2a2d38",
  borderRadius: "12px",
  padding: "14px 16px",
  boxShadow: "0 10px 30px rgba(0,0,0,0.45)",
};

const pillStyle: React.CSSProperties = {
  position: "fixed",
  right: "20px",
  bottom: "20px",
  zIndex: 50,
  background: "#13151a",
  border: "1px solid #2a2d38",
  borderRadius: "999px",
  padding: "8px 14px",
  fontSize: "12.5px",
  fontWeight: 600,
  color: "#6b9cf8",
  boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
  fontFamily: "inherit",
};

const rowBetween: React.CSSProperties = {
  display: "flex",
  alignItems: "flex-start",
  justifyContent: "space-between",
  gap: "10px",
};

const titleStyle: React.CSSProperties = { fontSize: "13px", fontWeight: 700, color: "#e8eaf0" };
const subStyle: React.CSSProperties = { fontSize: "11.5px", color: "#8b90a0", marginTop: "3px" };

const iconBtn: React.CSSProperties = {
  fontSize: "12px",
  color: "#8b90a0",
  background: "transparent",
  border: "1px solid #2a2d38",
  borderRadius: "6px",
  width: "24px",
  height: "24px",
  lineHeight: 1,
  cursor: "pointer",
  fontFamily: "inherit",
};

function demoBadge(loaded: boolean): React.CSSProperties {
  const color = loaded ? "#6b9cf8" : "#8b90a0";
  return {
    fontSize: "10px",
    fontWeight: 700,
    letterSpacing: "0.03em",
    textTransform: "uppercase",
    color,
    background: `${color}1f`,
    border: `1px solid ${color}55`,
    borderRadius: "6px",
    padding: "2px 7px",
    whiteSpace: "nowrap",
  };
}

const primaryLink: React.CSSProperties = {
  fontSize: "12.5px",
  fontWeight: 600,
  color: "#fff",
  background: "#6b9cf8",
  border: "1px solid #6b9cf8",
  borderRadius: "8px",
  padding: "6px 12px",
  textDecoration: "none",
};
const secondaryLink: React.CSSProperties = {
  fontSize: "12.5px",
  fontWeight: 600,
  color: "#6b9cf8",
  background: "transparent",
  border: "1px solid #2a2d38",
  borderRadius: "8px",
  padding: "6px 12px",
  textDecoration: "none",
};

function navBtn(disabled: boolean): React.CSSProperties {
  return {
    fontSize: "12px",
    fontWeight: 600,
    color: disabled ? "#565b6e" : "#c4c8d4",
    background: "transparent",
    border: "1px solid #2a2d38",
    borderRadius: "8px",
    padding: "5px 10px",
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.6 : 1,
    fontFamily: "inherit",
  };
}

function ghostBtn(busy: boolean): React.CSSProperties {
  return {
    fontSize: "12px",
    fontWeight: 600,
    color: "#8b90a0",
    background: "transparent",
    border: "1px solid #2a2d38",
    borderRadius: "8px",
    padding: "5px 10px",
    cursor: busy ? "wait" : "pointer",
    opacity: busy ? 0.6 : 1,
    fontFamily: "inherit",
  };
}
function seedBtn(busy: boolean): React.CSSProperties {
  return {
    fontSize: "12.5px",
    fontWeight: 600,
    color: "#fff",
    background: "#6b9cf8",
    border: "1px solid #6b9cf8",
    borderRadius: "8px",
    padding: "7px 12px",
    cursor: busy ? "wait" : "pointer",
    opacity: busy ? 0.6 : 1,
    fontFamily: "inherit",
  };
}
