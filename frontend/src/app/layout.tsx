import type { Metadata } from "next";
import { ClerkProvider } from "@clerk/nextjs";
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
 */
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ClerkProvider>
      <html lang="en">
        <body className="bg-background text-textPrimary antialiased">
          {children}
        </body>
      </html>
    </ClerkProvider>
  );
}
