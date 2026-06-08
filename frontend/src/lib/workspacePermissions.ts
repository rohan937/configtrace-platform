/**
 * workspacePermissions.ts — frontend mirror of the M63.2 backend policy (M63.5).
 *
 * Pure helpers that turn a workspace role into Security Exposure UI capability
 * flags, so non-admins see disabled high-impact actions instead of clicking
 * into a backend 403. The backend remains the source of truth — these only
 * drive affordances + helper copy.
 *
 * Policy (M63.2):
 *   member+  → read, acknowledge findings, add review notes
 *   admin/owner → accept risk, snooze, toggle rules, seed/clear demo data,
 *                 view beta analytics
 *
 * Fail-safe: when the role is unknown (null/undefined — still loading or
 * lookup failed), HIGH-IMPACT capabilities return false (disabled), while
 * low-impact read/acknowledge/note stay available (any viewer is a member, and
 * the backend still enforces).
 */

import type { WorkspaceRole } from "@/types";

export type MaybeRole = WorkspaceRole | null | undefined;

export function isWorkspaceAdmin(role: MaybeRole): boolean {
  return role === "admin" || role === "owner";
}

// ── Low-impact (member or above) ──────────────────────────────────────────────
// Anyone who can view a finding is at least a member; keep these usable even
// before the role resolves.
export function canAcknowledgeSecurity(_role: MaybeRole): boolean {
  return true;
}
export function canAddSecurityNote(_role: MaybeRole): boolean {
  return true;
}

// ── High-impact (admin/owner only; fail-safe to false when unknown) ───────────
export function canManageSecurityActions(role: MaybeRole): boolean {
  return isWorkspaceAdmin(role);
}
export function canAcceptRisk(role: MaybeRole): boolean {
  return isWorkspaceAdmin(role);
}
export function canSnooze(role: MaybeRole): boolean {
  return isWorkspaceAdmin(role);
}
export function canManageSecurityRules(role: MaybeRole): boolean {
  return isWorkspaceAdmin(role);
}
export function canManageDemoData(role: MaybeRole): boolean {
  return isWorkspaceAdmin(role);
}
export function canViewBetaAnalytics(role: MaybeRole): boolean {
  return isWorkspaceAdmin(role);
}
