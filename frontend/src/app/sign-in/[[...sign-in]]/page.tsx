import { SignIn } from "@clerk/nextjs";

/**
 * Catch-all sign-in route handled by Clerk's hosted UI component.
 *
 * The `[[...sign-in]]` segment is Clerk's required convention so the same
 * page handles `/sign-in`, `/sign-in/factor-one`, `/sign-in/sso-callback`,
 * etc. without us writing each one.
 */
export default function SignInPage() {
  return (
    <div
      className="flex min-h-screen items-center justify-center"
      style={{ background: "#0e0f11" }}
    >
      <SignIn />
    </div>
  );
}
