interface StatBlockProps {
  value: string | number;
  label: string;
  /** Optional override for the value text color — use for risk-level counts. */
  valueColor?: string;
}

/**
 * A compact stat display: large number above a small secondary label.
 * Used in the dashboard summary bar — no card chrome, no shadows.
 */
export default function StatBlock({ value, label, valueColor }: StatBlockProps) {
  return (
    <div className="flex flex-col gap-1">
      <span
        className="font-semibold leading-none"
        style={{ fontSize: "24px", color: valueColor ?? "#e8eaf0" }}
      >
        {value}
      </span>
      <span
        className="leading-none"
        style={{ fontSize: "12px", color: "#8b90a0" }}
      >
        {label}
      </span>
    </div>
  );
}
