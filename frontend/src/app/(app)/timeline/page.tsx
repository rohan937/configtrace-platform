import EmptyState from "@/components/common/EmptyState";
import PageHeader from "@/components/common/PageHeader";

export const metadata = {
  title: "Timeline — ConfigTrace",
};

export default function TimelinePage() {
  return (
    <>
      <PageHeader
        title="Timeline"
        description="Full change history across all integrations and resources."
      />
      <EmptyState message="No changes recorded yet. Run a sync to capture your first snapshot." />
    </>
  );
}
