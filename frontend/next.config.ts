import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /**
   * M58.7: Headers for the service worker script.
   *
   * Service-Worker-Allowed: /   — lets the SW registered at /sw.js control
   *   the entire origin (not just /public/).  Without this, the browser
   *   restricts the SW scope to the directory it is served from.
   *
   * Cache-Control: no-cache     — ensures the browser always re-validates
   *   the SW script so updates are picked up on next page load rather than
   *   being silently served from the HTTP cache.
   */
  async headers() {
    return [
      {
        source: "/sw.js",
        headers: [
          { key: "Service-Worker-Allowed", value: "/" },
          { key: "Cache-Control", value: "public, max-age=0, must-revalidate" },
        ],
      },
    ];
  },
};

export default nextConfig;
