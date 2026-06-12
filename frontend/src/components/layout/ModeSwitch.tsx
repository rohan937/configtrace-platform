"use client";

import Link from "next/link";
import type { ProductMode } from "@/lib/nav";

interface ModeSwitchProps {
  mode: ProductMode;
  driftHref: string;
  securityHref: string;
}

/**
 * ModeSwitch — top-level product mode toggle (M60.1).
 *
 * Two segments: Drift Detection ("what changed") and Configuration Risk
 * ("what is dangerous right now"). Each segment is a real link to that mode's
 * home route, so switching is a normal navigation that preserves deep links
 * and back/forward behavior. The active segment is highlighted from the
 * resolved `mode` (URL-derived, persisted for shared pages).
 */
export default function ModeSwitch({
  mode,
  driftHref,
  securityHref,
}: ModeSwitchProps) {
  return (
    <div
      className="border-b border-border"
      style={{ padding: "12px 16px 14px" }}
    >
      <div
        style={{
          fontSize: "10px",
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          color: "#565b6e",
          marginBottom: "8px",
          paddingLeft: "2px",
        }}
      >
        Product mode
      </div>

      <div
        role="tablist"
        aria-label="Product mode"
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "4px",
          background: "#0e0f11",
          border: "1px solid #2a2d38",
          borderRadius: "8px",
          padding: "4px",
        }}
      >
        <Segment
          href={driftHref}
          active={mode === "drift"}
          label="Drift"
          title="Drift Detection — what changed"
        />
        <Segment
          href={securityHref}
          active={mode === "security"}
          label="Security"
          title="Configuration Risk — what is dangerous right now"
        />
      </div>
    </div>
  );
}

function Segment({
  href,
  active,
  label,
  title,
}: {
  href: string;
  active: boolean;
  label: string;
  title: string;
}) {
  return (
    <Link
      href={href}
      role="tab"
      aria-selected={active}
      title={title}
      style={{
        textAlign: "center",
        fontSize: "12px",
        fontWeight: active ? 600 : 500,
        padding: "6px 4px",
        borderRadius: "6px",
        textDecoration: "none",
        color: active ? "#e8eaf0" : "#8b90a0",
        background: active ? "#1c1e26" : "transparent",
        border: active ? "1px solid #2a2d38" : "1px solid transparent",
        transition: "none",
      }}
      onMouseOver={(e) => {
        if (!active)
          (e.currentTarget as HTMLAnchorElement).style.color = "#c4c8d4";
      }}
      onMouseOut={(e) => {
        if (!active)
          (e.currentTarget as HTMLAnchorElement).style.color = "#8b90a0";
      }}
    >
      {label}
    </Link>
  );
}
