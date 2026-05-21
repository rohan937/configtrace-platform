interface PageHeaderProps {
  title: string;
  description?: string;
}

export default function PageHeader({ title, description }: PageHeaderProps) {
  return (
    <div className="mb-8">
      <h1 className="text-textPrimary text-2xl font-semibold">{title}</h1>
      {description && (
        <p className="mt-1 text-textSecondary text-sm">{description}</p>
      )}
    </div>
  );
}
