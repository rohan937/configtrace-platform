"use client";

/**
 * usePollingRefresh — lightweight polling hook for ConfigTrace pages.
 *
 * Calls `callback` on a fixed interval while the browser tab is visible.
 * Pauses automatically when the tab is hidden (document.visibilityState)
 * and resumes (with an immediate call) when the tab becomes visible again.
 *
 * Design decisions
 * ----------------
 * - `callbackRef` holds the latest callback without resetting the interval;
 *   the interval closure always invokes the ref value so stale-closure bugs
 *   are avoided without adding the callback to the effect dependency array.
 * - `inFlightRef` skips a tick if the previous call hasn't finished, which
 *   prevents request stacking under slow network conditions.
 * - `intervalRef` is never written from two places simultaneously; cleanup
 *   always runs before the next start so there is at most one active interval.
 * - SSR guard: early-returns if `document` is not available (Next.js SSR).
 *
 * Usage
 * -----
 * ```tsx
 * const { refresh, lastUpdatedAt } = usePollingRefresh({
 *   callback: fetchData,
 *   intervalMs: 30_000,
 * });
 * ```
 */

import { useCallback, useEffect, useRef, useState } from "react";

export interface UsePollingRefreshOptions {
  /** Function to call on each tick. May be async. */
  callback: () => void | Promise<void>;
  /** Polling interval in milliseconds. */
  intervalMs: number;
  /**
   * Set to false to suspend polling (e.g. while the initial load is still in
   * flight). Defaults to true.
   */
  enabled?: boolean;
}

export interface UsePollingRefreshResult {
  /** Trigger an immediate out-of-band refresh. */
  refresh: () => void;
  /** Timestamp of the last successful callback invocation, or null before the first. */
  lastUpdatedAt: Date | null;
}

export function usePollingRefresh({
  callback,
  intervalMs,
  enabled = true,
}: UsePollingRefreshOptions): UsePollingRefreshResult {
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);

  // Hold the latest callback without resetting the interval on every render.
  const callbackRef = useRef(callback);
  useEffect(() => {
    callbackRef.current = callback;
  });

  // Stable reference to the interval timer.
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Prevent stacking concurrent requests.
  const inFlightRef = useRef(false);

  // Execute the callback, skipping if already in flight.
  const runCallback = useCallback(async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    try {
      await callbackRef.current();
      setLastUpdatedAt(new Date());
    } finally {
      inFlightRef.current = false;
    }
  }, []);

  // Public manual-refresh trigger.
  const refresh = useCallback(() => {
    void runCallback();
  }, [runCallback]);

  useEffect(() => {
    // SSR guard — document is not available in the server render.
    if (typeof document === "undefined") return;
    if (!enabled) return;

    function startInterval() {
      if (intervalRef.current !== null) return; // already running
      intervalRef.current = setInterval(() => void runCallback(), intervalMs);
    }

    function stopInterval() {
      if (intervalRef.current !== null) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    }

    function handleVisibilityChange() {
      if (document.visibilityState === "hidden") {
        stopInterval();
      } else {
        // Tab became visible — trigger an immediate refresh so the user
        // doesn't have to wait a full interval for fresh data.
        void runCallback();
        startInterval();
      }
    }

    startInterval();
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      stopInterval();
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [enabled, intervalMs, runCallback]);

  return { refresh, lastUpdatedAt };
}
