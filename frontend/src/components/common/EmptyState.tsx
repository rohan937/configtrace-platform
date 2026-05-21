interface EmptyStateProps {
  /** Short primary label. */
  title?: string;
  /** Longer secondary text shown below the title. */
  description?: string;
  /**
   * @deprecated Pass `title` instead.  Kept for backward compat with existing callers.
   */
  message?: string;
}

export default function EmptyState({ title, description, message }: EmptyStateProps) {
  const heading = title ?? message ?? "Nothing here yet.";

  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-border bg-surface1 py-16 px-8 gap-2">
      <p className="text-textTertiary text-sm text-center">{heading}</p>
      {description && (
        <p className="text-textTertiary text-xs text-center opacity-70">{description}</p>
      )}
    </div>
  );
}
