import type { Metadata } from "next";
import { ClerkProvider } from "@clerk/nextjs";
import Script from "next/script";
import "./globals.css";

export const metadata: Metadata = {
  title: "ConfigTrace",
  description: "Configuration change intelligence for production systems.",
};

/**
 * Root layout — wraps the entire app in <ClerkProvider>.
 *
 * Clerk requires `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` to be set at build/runtime.
 * If it is missing, Clerk throws during initialization and the app fails to
 * boot — this is deliberate.  See README + docs/deployment.md for the local
 * dev setup (a free Clerk development application).
 *
 * The app uses Clerk's dark theme styling via global CSS overrides — no
 * `appearance` prop here, to keep the file lean.
 *
 * M58.7: The root layout also links the PWA manifest and registers the
 * service worker for browser push notifications.  SW registration is
 * deferred to afterInteractive so it does not block hydration.
 */
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ClerkProvider>
      <html lang="en">
        <head>
          {/* M58.7: PWA manifest + theme color */}
          <link rel="manifest" href="/manifest.json" />
          <meta name="theme-color" content="#8b5cf6" />
        </head>
        <body className="bg-background text-textPrimary antialiased">
          {children}
          {/* M58.7: Service worker registration — deferred, non-blocking */}
          <Script id="sw-register" strategy="afterInteractive">{`
            if ('serviceWorker' in navigator) {
              window.addEventListener('load', function () {
                navigator.serviceWorker.register('/sw.js', { scope: '/' })
                  .catch(function (err) {
                    console.warn('[ConfigTrace SW] Registration failed:', err);
                  });
              });
            }
          `}</Script>
        </body>
      </html>
    </ClerkProvider>
  );
}
