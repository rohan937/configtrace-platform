import EmptyState from "@/components/common/EmptyState";
import PageHeader from "@/components/common/PageHeader";

export const metadata = {
  title: "Settings — ConfigTrace",
};

export default function SettingsPage() {
  return (
    <>
      <PageHeader
        title="Settings"
        description="Account preferences and notification configuration."
      />
      <EmptyState message="Settings will be available in a future release." />
    </>
  );
}
