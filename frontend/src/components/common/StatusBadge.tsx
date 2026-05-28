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
