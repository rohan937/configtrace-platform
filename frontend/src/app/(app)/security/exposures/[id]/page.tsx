/**
 * Backward-compatible redirect (M66.1).
 *
 * Old exposure-detail deep links (/security/exposures/[id]) now resolve to the
 * repositioned Configuration Risk detail route (/security/risks/[id]).
 */
import { redirect } from "next/navigation";

export default async function ExposureDetailRedirect({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  redirect(`/security/risks/${id}`);
}
