"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { UserButton, useAuth, useUser } from "@clerk/nextjs";
import { getMyProfile } from "@/lib/api";
import {
  DRIFT_HOME,
  SECURITY_HOME,
  ProductMode,
  isNavActive,
  navForMode,
  resolveMode,
} from "@/lib/nav";
import WorkspaceSwitcher from "./WorkspaceSwitcher";
import ModeSwitch from "./ModeSwitch";

/** localStorage key persisting the last active product mode (M60.1). */
const MODE_STORAGE_KEY = "ct.productMode";

export default function Sidebar() {
  const pathname = usePathname();
  const { user, isLoaded } = useUser();
  const { getToken, isLoaded: authLoaded } = useAuth();

  // ── M60.1 — product mode (Drift Detection vs Configuration Risk) ───────────
  // Mode is derived from the URL so deep links / refreshes are preserved. On a
  // SHARED page (Integrations/Settings/…) the URL is mode-agnostic, so we fall
  // back to the last mode the user was in (persisted to localStorage). This
  // keeps you in the Configuration Risk mode when you click a shared item.
  const urlMode = resolveMode(pathname);
  const [mode, setMode] = useState<ProductMode>(urlMode ?? "drift");

  useEffect(() => {
    if (urlMode) {
      setMode(urlMode);
      try {
        window.localStorage.setItem(MODE_STORAGE_KEY, urlMode);
      } catch {
        /* storage may be unavailable (private mode) — non-fatal */
      }
    } else {
      // Shared page: restore the persisted mode if present.
      try {
        const stored = window.localStorage.getItem(
          MODE_STORAGE_KEY,
        ) as ProductMode | null;
        if (stored === "drift" || stored === "security") setMode(stored);
      } catch {
        /* non-fatal */
      }
    }
  }, [urlMode, pathname]);

  const navItems = navForMode(mode);

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

  // Sidebar footer policy: prefer the user's display name; fall back to email
  // only when no real name is set.  We never render both at once — the email
  // remains visible inside Settings → Profile for users who need it.
  const hasRealName = !!displayName && displayName !== email;
  const footerLabel = hasRealName ? displayName : email;

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

      {/* Product mode switch — M60.1 (Drift Detection · Configuration Risk) */}
      <ModeSwitch
        mode={mode}
        driftHref={DRIFT_HOME}
        securityHref={SECURITY_HOME}
      />

      {/* Workspace switcher — M50 */}
      <WorkspaceSwitcher />

      {/* Nav links */}
      <nav className="flex-1 overflow-y-auto py-3">
        <ul className="space-y-0.5">
          {navItems.map((item) => {
            const isActive = isNavActive(item.href, pathname);

            // M66.1: gated future area (Incident Signals) — non-clickable.
            if (item.comingSoon) {
              return (
                <li key={item.href}>
                  <div
                    aria-disabled="true"
                    title="Coming soon — audit/activity-log correlation is not live yet"
                    className="flex items-center justify-between px-6 py-2 text-sm text-textSecondary"
                    style={{
                      borderLeft: "2px solid transparent",
                      opacity: 0.55,
                      cursor: "default",
                    }}
                  >
                    <span>{item.label}</span>
                    <span
                      style={{
                        fontSize: "9px",
                        fontWeight: 700,
                        letterSpacing: "0.05em",
                        textTransform: "uppercase",
                        color: "#8b90a0",
                        border: "1px solid #2a2d38",
                        borderRadius: "5px",
                        padding: "1px 5px",
                      }}
                    >
                      Soon
                    </span>
                  </div>
                </li>
              );
            }

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
                  <span>{item.label}</span>
                  {item.badge && (
                    <span
                      style={{
                        marginLeft: "8px",
                        fontSize: "9px",
                        fontWeight: 700,
                        letterSpacing: "0.05em",
                        textTransform: "uppercase",
                        color: "#6b9cf8",
                        border: "1px solid rgba(107,156,248,0.4)",
                        borderRadius: "5px",
                        padding: "1px 5px",
                      }}
                    >
                      {item.badge}
                    </span>
                  )}
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
          {isLoaded && footerLabel && (
            <span
              className="truncate"
              style={{
                fontSize: hasRealName ? "12px" : "11px",
                color: hasRealName ? "#c4c8d4" : "#8b90a0",
                fontWeight: hasRealName ? 500 : 400,
                lineHeight: 1.3,
                minWidth: 0,
              }}
              title={footerLabel}
            >
              {footerLabel}
            </span>
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
