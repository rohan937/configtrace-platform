import type { RiskLevel } from "@/types";

interface RiskBadgeProps {
  level: RiskLevel | string;
}

const RISK_STYLES: Record<string, { bg: string; text: string }> = {
  critical: { bg: "#e84040", text: "#fff" },
  high:     { bg: "#f5632a", text: "#fff" },
  medium:   { bg: "#f5a623", text: "#fff" },
  low:      { bg: "#6b9cf8", text: "#fff" },
  healthy:  { bg: "#3ccf7e", text: "#fff" },
  unknown:  { bg: "#565b6e", text: "#fff" },
};

export default function RiskBadge({ level }: RiskBadgeProps) {
  const key = (level ?? "unknown").toLowerCase();
  const style = RISK_STYLES[key] ?? RISK_STYLES.unknown;

  return (
    <span
      style={{ backgroundColor: style.bg, color: style.text }}
      className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium capitalize"
    >
      {key}
    </span>
  );
}
