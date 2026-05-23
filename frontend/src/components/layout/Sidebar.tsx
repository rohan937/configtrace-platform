"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { UserButton, useUser } from "@clerk/nextjs";

interface NavItem {
  label: string;
  href: string;
}

const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard",    href: "/dashboard" },
  { label: "Timeline",     href: "/timeline" },
  { label: "Integrations", href: "/integrations" },
  { label: "Resources",    href: "/resources" },
  { label: "Settings",     href: "/settings" },
];

export default function Sidebar() {
  const pathname = usePathname();
  const { user, isLoaded } = useUser();

  // Best available display: primary email address, then full name, then nothing
  const email =
    user?.primaryEmailAddress?.emailAddress ??
    user?.emailAddresses?.[0]?.emailAddress ??
    null;

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

      {/* Nav links */}
      <nav className="flex-1 overflow-y-auto py-3">
        <ul className="space-y-0.5">
          {NAV_ITEMS.map((item) => {
            const isActive =
              pathname === item.href ||
              (item.href !== "/dashboard" && pathname.startsWith(item.href));

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
          {isLoaded && email && (
            <span
              className="truncate"
              style={{
                fontSize: "11px",
                color: "#8b90a0",
                lineHeight: 1.3,
                minWidth: 0,
              }}
              title={email}
            >
              {email}
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
