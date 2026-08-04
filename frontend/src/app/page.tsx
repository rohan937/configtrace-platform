import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { auth } from "@clerk/nextjs/server";
import PublicHomePage from "./PublicHomePage";

/**
 * Root route (`/`).
 *
 * Signed-in visitors are sent straight to /dashboard (unchanged prior
 * behavior). Signed-out visitors get a public, static overview page
 * instead of bouncing through the auth wall — this is what lets external
 * reviewers (e.g. Paddle's domain verification) see the app domain
 * without an account. The auth check below reads the existing Clerk
 * session only; it makes no call to our backend API.
 */

export const metadata: Metadata = {
  title: "ConfigTrace — Configuration drift & security posture monitoring",
  description:
    "ConfigTrace monitors cloud and SaaS configuration drift and security posture with read-only provider access.",
};

export default async function RootPage() {
  const { userId } = await auth();
  if (userId) {
    redirect("/dashboard");
  }
  return <PublicHomePage />;
}
