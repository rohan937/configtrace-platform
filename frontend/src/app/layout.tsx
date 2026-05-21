import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ConfigTrace",
  description: "Configuration change intelligence for production systems.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-background text-textPrimary antialiased">
        {children}
      </body>
    </html>
  );
}
