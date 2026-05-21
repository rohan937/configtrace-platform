import EmptyState from "@/components/common/EmptyState";
import PageHeader from "@/components/common/PageHeader";

export const metadata = {
  title: "Resources — ConfigTrace",
};

export default function ResourcesPage() {
  return (
    <>
      <PageHeader
        title="Resources"
        description="All monitored DNS zones and records across your integrations."
      />
      <EmptyState message="No resources discovered yet. Trigger a sync from the Integrations page." />
    </>
  );
}
