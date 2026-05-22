"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { UserButton } from "@clerk/nextjs";

interface NavItem {
  label: string;
  href: string;
}

const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", href: "/dashboard" },
  { label: "Timeline", href: "/timeline" },
  { label: "Integrations", href: "/integrations" },
  { label: "Resources", href: "/resources" },
  { label: "Settings", href: "/settings" },
];

export default function Sidebar() {
  const pathname = usePathname();

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

      {/* Footer — UserButton + version */}
      <div
        className="px-6 py-4 border-t border-border flex items-center justify-between"
        style={{ gap: "12px" }}
      >
        <UserButton
          afterSignOutUrl="/sign-in"
          appearance={{
            elements: {
              avatarBox: { width: 28, height: 28 },
            },
          }}
        />
        <p className="text-textTertiary text-xs">v0.1.0</p>
      </div>
    </aside>
  );
}
