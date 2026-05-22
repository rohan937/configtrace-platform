interface ErrorStateProps {
  message?: string;
}

export default function ErrorState({
  message = "Something went wrong.",
}: ErrorStateProps) {
  return (
    <div
      className="flex items-center justify-center py-16 text-sm"
      style={{ color: "#e84040" }}
    >
      Error: {message}
    </div>
  );
}
