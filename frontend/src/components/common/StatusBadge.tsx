import type { IntegrationStatus } from "@/types";

interface StatusBadgeProps {
  status: IntegrationStatus | string;
}

const STATUS_STYLES: Record<string, { bg: string; text: string; label?: string }> = {
  active:  { bg: "#3ccf7e", text: "#fff" },
  error:   { bg: "#e84040", text: "#fff" },
  paused:  { bg: "#565b6e", text: "#fff" },
  // M59.14: distinct amber for "your credentials are dead, please reconnect".
  // Not red (no system error) and not green (it's not currently working).
  needs_reconnect: { bg: "#f5a623", text: "#1a1d26", label: "Reconnect" },
  // M59.15: backend status is active but the latest sync surfaced a problem.
  //   ``needs_attention`` — resource_missing (404 from the provider).  Amber.
  //                          Less severe than ``degraded`` because retrying
  //                          may help or the user may need to verify the
  //                          target resource exists upstream.
  //   ``degraded``        — any other failed category (5xx, rate_limit,
  //                          network, etc.).  Red, but distinct from
  //                          ``error`` which is reserved for the legacy
  //                          credential-error status.
  needs_attention: { bg: "#f5a623", text: "#1a1d26", label: "Needs attention" },
  degraded:        { bg: "#e84040", text: "#fff",    label: "Degraded" },
  unknown: { bg: "#565b6e", text: "#fff" },
};

export default function StatusBadge({ status }: StatusBadgeProps) {
  const key = (status ?? "unknown").toLowerCase();
  const style = STATUS_STYLES[key] ?? STATUS_STYLES.unknown;
  const label = style.label ?? key;

  return (
    <span
      style={{ backgroundColor: style.bg, color: style.text }}
      className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium capitalize"
    >
      {label}
    </span>
  );
}
