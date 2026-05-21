import EmptyState from "@/components/common/EmptyState";
import PageHeader from "@/components/common/PageHeader";

export const metadata = {
  title: "Integrations — ConfigTrace",
};

export default function IntegrationsPage() {
  return (
    <>
      <PageHeader
        title="Integrations"
        description="Manage connected DNS providers and sync schedules."
      />
      <EmptyState message="No integrations configured yet. Add a provider to start tracking changes." />
    </>
  );
}
