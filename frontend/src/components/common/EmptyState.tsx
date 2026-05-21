interface EmptyStateProps {
  message: string;
}

export default function EmptyState({ message }: EmptyStateProps) {
  return (
    <div className="flex items-center justify-center rounded-lg border border-border bg-surface1 py-16 px-8">
      <p className="text-textTertiary text-sm text-center">{message}</p>
    </div>
  );
}
