import AppShell from "@/components/layout/AppShell";
import { WorkspaceProvider } from "@/contexts/WorkspaceContext";

export default function AppLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <WorkspaceProvider>
      <AppShell>{children}</AppShell>
    </WorkspaceProvider>
  );
}
