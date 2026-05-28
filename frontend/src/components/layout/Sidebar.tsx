"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { UserButton, useAuth, useUser } from "@clerk/nextjs";
import { getMyProfile } from "@/lib/api";
import WorkspaceSwitcher from "./WorkspaceSwitcher";

interface NavItem {
  label: string;
  href: string;
  /** Render as a sub-item (indented, smaller) under a parent section. */
  sub?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard",    href: "/dashboard" },
  { label: "Needs Review", href: "/needs-review" },
  { label: "Timeline",     href: "/timeline" },
  { label: "Integrations", href: "/integrations" },
  { label: "Resources",    href: "/resources" },
  { label: "Settings",     href: "/settings" },
  { label: "Workspace",    href: "/settings/workspace" },
  { label: "Members",        href: "/settings/workspace/members",       sub: true },
  { label: "Audit Log",      href: "/settings/workspace/audit",         sub: true },
  { label: "Billing",        href: "/settings/workspace/billing",       sub: true },
  { label: "Notifications",  href: "/settings/workspace/notifications", sub: true },
  { label: "Trust Center",   href: "/settings/workspace/data-access",   sub: true },
  { label: "Policies",          href: "/settings/workspace/policies",         sub: true },
  { label: "Expected Changes",  href: "/settings/workspace/expected-changes", sub: true },
];

export default function Sidebar() {
  const pathname = usePathname();
  const { user, isLoaded } = useUser();
  const { getToken, isLoaded: authLoaded } = useAuth();

  // Best available email fallback: primary, then first listed.
  const email =
    user?.primaryEmailAddress?.emailAddress ??
    user?.emailAddresses?.[0]?.emailAddress ??
    null;

  // ── M59.13 — display name from /me/profile ─────────────────────────────────
  // The server resolves the final display name using:
  //   first/last → display_name (non-placeholder) → email
  // so we just trust ``computed_display_name``.  Email remains visible as a
  // secondary line so users always see which account they're signed into.
  const [displayName, setDisplayName] = useState<string | null>(null);

  const loadProfile = useCallback(async () => {
    if (!authLoaded) return;
    try {
      const token = await getToken();
      const p = await getMyProfile(token);
      setDisplayName(p.computed_display_name);
    } catch {
      // Network/auth errors fall back silently to the email line below.
      setDisplayName(null);
    }
  }, [authLoaded, getToken]);

  useEffect(() => {
    if (authLoaded) void loadProfile();
  }, [authLoaded, loadProfile]);

  // Show the user's name (when distinct from email) above the email line.
  // If only email is available, the name slot is hidden to avoid duplication.
  const showNameLine =
    !!displayName && !!email && displayName !== email;

  return (
    <aside
      style={{
        width: "240px",
        minWidth: "240px",
        background: "#13151a",
        borderRight: "1px solid #2a2d38",
      }}
      className="flex flex-col h-screen sticky top-0"
    >
      {/* Logo / wordmark */}
      <div className="px-6 py-5 border-b border-border">
        <span className="text-textPrimary font-semibold text-base tracking-tight">
          ConfigTrace
        </span>
      </div>

      {/* Workspace switcher — M50 */}
      <WorkspaceSwitcher />

      {/* Nav links */}
      <nav className="flex-1 overflow-y-auto py-3">
        <ul className="space-y-0.5">
          {NAV_ITEMS.map((item) => {
            const isActive =
              pathname === item.href ||
              (item.href !== "/dashboard" &&
                item.href !== "/settings" &&
                pathname.startsWith(item.href));

            if (item.sub) {
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      fontSize: "12px",
                      borderLeft: isActive ? "2px solid #4f80f7" : "2px solid transparent",
                      paddingLeft: "32px",
                      paddingRight: "24px",
                      paddingTop: "5px",
                      paddingBottom: "5px",
                      color: isActive ? "#c4c8d4" : "#565b6e",
                      textDecoration: "none",
                      background: isActive ? "rgba(255,255,255,0.03)" : "transparent",
                    }}
                    onMouseOver={(e) => {
                      if (!isActive) (e.currentTarget as HTMLAnchorElement).style.color = "#8b90a0";
                    }}
                    onMouseOut={(e) => {
                      if (!isActive) (e.currentTarget as HTMLAnchorElement).style.color = "#565b6e";
                    }}
                  >
                    {item.label}
                  </Link>
                </li>
              );
            }

            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  style={
                    isActive
                      ? { borderLeft: "2px solid #4f80f7" }
                      : { borderLeft: "2px solid transparent" }
                  }
                  className={[
                    "flex items-center px-6 py-2 text-sm transition-none",
                    isActive
                      ? "text-textPrimary bg-surface2"
                      : "text-textSecondary hover:text-textPrimary hover:bg-surface1",
                  ].join(" ")}
                >
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Footer — avatar + email + sign-out */}
      <div
        className="border-t border-border"
        style={{ padding: "12px 16px" }}
      >
        {/* Avatar row */}
        <div className="flex items-center gap-3" style={{ marginBottom: "10px" }}>
          <UserButton
            afterSignOutUrl="/sign-in"
            appearance={{
              elements: {
                avatarBox: { width: 30, height: 30 },
              },
            }}
          />
          {isLoaded && (email || displayName) && (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                minWidth: 0,
                lineHeight: 1.25,
              }}
            >
              {showNameLine && (
                <span
                  className="truncate"
                  style={{
                    fontSize: "12px",
                    color: "#c4c8d4",
                    fontWeight: 500,
                  }}
                  title={displayName ?? undefined}
                >
                  {displayName}
                </span>
              )}
              {email && (
                <span
                  className="truncate"
                  style={{
                    fontSize: "11px",
                    color: "#8b90a0",
                  }}
                  title={email}
                >
                  {email}
                </span>
              )}
            </div>
          )}
        </div>

        {/* Quick links */}
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "1px",
            borderTop: "1px solid #1e2030",
            paddingTop: "8px",
          }}
        >
          {[
            { label: "Integrations", href: "/integrations" },
            { label: "Resources",    href: "/resources" },
            { label: "Settings",     href: "/settings" },
          ].map((link) => (
            <Link
              key={link.href}
              href={link.href}
              style={{
                fontSize: "11px",
                color: "#565b6e",
                textDecoration: "none",
                padding: "3px 4px",
                borderRadius: "3px",
                display: "block",
              }}
              onMouseOver={(e) => {
                (e.currentTarget as HTMLAnchorElement).style.color = "#c4c8d4";
              }}
              onMouseOut={(e) => {
                (e.currentTarget as HTMLAnchorElement).style.color = "#565b6e";
              }}
            >
              {link.label}
            </Link>
          ))}
        </div>

        {/* Version */}
        <p
          style={{
            margin: "8px 0 0",
            fontSize: "10px",
            color: "#3a3d4a",
            letterSpacing: "0.02em",
          }}
        >
          v0.1.0
        </p>
      </div>
    </aside>
  );
}
