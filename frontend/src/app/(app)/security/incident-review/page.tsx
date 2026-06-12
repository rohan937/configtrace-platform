/**
 * Backward-compatible redirect (M66.1).
 *
 * "Incident Review" was renamed to "Cases" as part of repositioning toward the
 * future Incident Signals product. The route moved from
 * /security/incident-review → /security/cases. This stub preserves old links.
 */
import { redirect } from "next/navigation";

export default function IncidentReviewRedirect() {
  redirect("/security/cases");
}
