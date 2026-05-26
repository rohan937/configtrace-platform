/**
 * Clerk authentication middleware.
 *
 * Runs at the edge for every request whose path matches the matcher below.
 * Pages inside the (app) route group are protected: an unauthenticated user
 * is redirected to the sign-in page.  Public routes (sign-in, sign-up, and
 * static assets) are allowed through unauthenticated.
 *
 * Matcher exclusion notes
 * -----------------------
 * - Next.js internals (`_next/*`) are excluded so middleware doesn't run on
 *   asset requests.
 * - The matcher also skips common static file extensions to keep edge
 *   invocations cheap.
 */

import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";

const isPublicRoute = createRouteMatcher([
  "/sign-in(.*)",
  "/sign-up(.*)",
  // Allow direct hits to the root — the root page redirects to /dashboard,
  // which is protected, so signed-out users still bounce to /sign-in via
  // the protect() call below.
  "/",
  // M58.13: Public demo — no auth required.
  "/demo(.*)",
]);

export default clerkMiddleware(async (auth, request) => {
  if (!isPublicRoute(request)) {
    await auth.protect();
  }
});

export const config = {
  matcher: [
    // Run on every request except Next.js internals and static files.
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    // Always run on API routes (none yet, but keeps the matcher future-proof).
    "/(api|trpc)(.*)",
  ],
};
