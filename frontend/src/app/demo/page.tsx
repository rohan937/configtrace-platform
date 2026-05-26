/**
 * /demo — Public Demo Risk Timeline — M58.13.
 *
 * Server component wrapper that exports SEO metadata and renders the
 * interactive client component.  No auth required (middleware updated).
 */

import type { Metadata } from "next";
import DemoPage from "./DemoPage";

export const metadata: Metadata = {
  title: "ConfigTrace — Public Demo Risk Timeline",
  description:
    "Explore a synthetic ConfigTrace timeline showing risky configuration drift across AWS, Firebase, Supabase, Stripe, GitHub, Cloudflare, Vercel, and Shopify.",
};

export default function DemoPageRoute() {
  return <DemoPage />;
}
