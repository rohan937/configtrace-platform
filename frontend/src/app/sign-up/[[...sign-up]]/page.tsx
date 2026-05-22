import { SignUp } from "@clerk/nextjs";

/**
 * Catch-all sign-up route handled by Clerk's hosted UI component.
 *
 * See sign-in/[[...sign-in]]/page.tsx for the rationale on the segment shape.
 */
export default function SignUpPage() {
  return (
    <div
      className="flex min-h-screen items-center justify-center"
      style={{ background: "#0e0f11" }}
    >
      <SignUp />
    </div>
  );
}
