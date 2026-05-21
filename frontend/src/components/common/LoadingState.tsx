interface LoadingStateProps {
  message?: string;
}

export default function LoadingState({
  message = "Loading…",
}: LoadingStateProps) {
  return (
    <div
      className="flex items-center justify-center py-16 text-sm"
      style={{ color: "#8b90a0" }}
    >
      {message}
    </div>
  );
}
