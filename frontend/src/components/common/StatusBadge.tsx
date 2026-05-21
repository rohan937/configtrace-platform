import type { IntegrationStatus } from "@/types";

interface StatusBadgeProps {
  status: IntegrationStatus | string;
}

const STATUS_STYLES: Record<string, { bg: string; text: string }> = {
  active:  { bg: "#3ccf7e", text: "#fff" },
  error:   { bg: "#e84040", text: "#fff" },
  paused:  { bg: "#565b6e", text: "#fff" },
  unknown: { bg: "#565b6e", text: "#fff" },
};

export default function StatusBadge({ status }: StatusBadgeProps) {
  const key = (status ?? "unknown").toLowerCase();
  const style = STATUS_STYLES[key] ?? STATUS_STYLES.unknown;

  return (
    <span
      style={{ backgroundColor: style.bg, color: style.text }}
      className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium capitalize"
    >
      {key}
    </span>
  );
}
