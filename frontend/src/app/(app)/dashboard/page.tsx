import EmptyState from "@/components/common/EmptyState";
import PageHeader from "@/components/common/PageHeader";

export const metadata = {
  title: "Dashboard — ConfigTrace",
};

export default function DashboardPage() {
  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Overview of recent configuration changes and monitored resources."
      />
      <EmptyState message="Change timeline will appear here after the first sync." />
    </>
  );
}
