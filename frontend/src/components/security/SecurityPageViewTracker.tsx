"use client";

/**
 * SecurityPageViewTracker (M63.1).
 *
 * Renders nothing. Mounted once in the app shell; fires a single
 * `security_page_viewed` beta event per Security route change (with a coarse
 * route_group and a normalized page_path — never raw query params). Fire-and-
 * forget; failures are invisible.
 */

import { useEffect, useRef } from "react";
import { usePathname } from "next/navigation";
import { useAuth } from "@clerk/nextjs";

import {
  trackSecurityBetaEvent,
  routeGroupFor,
  normalizeSecurityPath,
  exposureIdFromPath,
} from "@/lib/securityBetaEvents";

export default function SecurityPageViewTracker() {
  const pathname = usePathname();
  const { getToken, isLoaded } = useAuth();
  const lastTracked = useRef<string | null>(null);

  useEffect(() => {
    if (!isLoaded) return;
    const group = routeGroupFor(pathname);
    if (!group) return; // not a known Security route — skip
    if (lastTracked.current === pathname) return; // one event per route change
    lastTracked.current = pathname;

    const findingId = exposureIdFromPath(pathname);
    trackSecurityBetaEvent(
      "security_page_viewed",
      { route_group: group, ...(findingId ? { finding_id: findingId } : {}) },
      { getToken, pagePath: normalizeSecurityPath(pathname) ?? undefined },
    );
  }, [pathname, isLoaded, getToken]);

  return null;
}
