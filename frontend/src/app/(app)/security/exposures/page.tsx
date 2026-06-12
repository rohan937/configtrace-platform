/**
 * Backward-compatible redirect (M66.1).
 *
 * "Security Exposure" was repositioned to "Configuration Risk"; the route
 * moved from /security/exposures → /security/risks. This stub preserves old
 * deep links and bookmarks.
 */
import { redirect } from "next/navigation";

export default function ExposuresRedirect() {
  redirect("/security/risks");
}
