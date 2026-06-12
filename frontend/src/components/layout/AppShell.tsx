"use client";

import Sidebar from "./Sidebar";
import SecurityDemoWalkthrough from "@/components/security/SecurityDemoWalkthrough";
import SecurityPageViewTracker from "@/components/security/SecurityPageViewTracker";

interface AppShellProps {
  children: React.ReactNode;
}

export default function AppShell({ children }: AppShellProps) {
  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-6xl mx-auto px-8 py-8">{children}</div>
      </main>
      {/* M63.1 — Configuration Risk beta page-view instrumentation (renders nothing). */}
      <SecurityPageViewTracker />
      {/* M62.9 — guided Configuration Risk demo walkthrough.
          Self-gates to /security pages; renders nothing elsewhere. */}
      <SecurityDemoWalkthrough />
    </div>
  );
}
