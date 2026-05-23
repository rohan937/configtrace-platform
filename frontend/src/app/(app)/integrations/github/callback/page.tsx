"use client";

/**
 * GitHub App installation callback page — M31.
 *
 * GitHub redirects here after the user installs or updates the App:
 *   https://app.configtrace.org/integrations/github/callback
 *     ?installation_id=12345
 *     &setup_action=install|update|delete
 *     &state=<hmac-token>
 *
 * Flow:
 *   1. Read installation_id + state from URL query params.
 *   2. Pass state to the backend for authoritative HMAC + expiry + user validation.
 *   3. Fetch the list of repositories for this installation.
 *   4. If one repo  → skip picker, go straight to confirmation.
 *      If many repos → show GitHubRepoPicker.
 *   5. On repo selection → POST /integrations/github/app/complete.
 *   6. On success → redirect to /integrations.
 *
 * Security model:
 *   The backend is the authoritative validator for the state token:
 *   it verifies the HMAC signature, expiry, and that state.user_id matches
 *   the current Clerk user.  sessionStorage is used as an optional one-time
 *   cleanup hint only — it is NOT a hard security gate on the frontend.
 *
 *   Removing the hard sessionStorage check does not weaken security because:
 *   - A forged state token fails backend HMAC verification.
 *   - A state token for a different user fails the user_id binding check.
 *   - An expired state token is rejected by the backend.
 *   The frontend hard-blocking on sessionStorage was causing legitimate
 *   re-entry (setup_action=update, tab-reuse, retry after network error)
 *   to fail before the backend could even run its checks.
 *
 * Next.js requirement:
 *   useSearchParams() must be inside a <Suspense> boundary during SSG/prerender.
 *   CallbackContent owns useSearchParams(); GitHubAppCallbackPage wraps it.
 */

import { Suspense, useCallback, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@clerk/nextjs";
import type { GitHubInstallationRepo } from "@/types";
import { completeGitHubAppInstall, getInstallationRepositories } from "@/lib/api";
import LoadingState from "@/components/common/LoadingState";
import GitHubRepoPicker from "@/components/integrations/GitHubRepoPicker";

// Key used to store the state token in sessionStorage before the redirect.
// Used for soft one-time-use cleanup only — not a hard security gate.
const STATE_KEY = "github_app_oauth_state";

// ── Shared loading UI ─────────────────────────────────────────────────────────

function LoadingVerifying({ message }: { message?: string }) {
  return (
    <div className="px-6 py-12">
      <LoadingState />
      <p
        style={{
          textAlign: "center",
          fontSize: "13px",
          color: "#8b90a0",
          marginTop: "12px",
        }}
      >
        {message ?? "Verifying GitHub App installation…"}
      </p>
    </div>
  );
}

// ── Inner component — owns useSearchParams() ──────────────────────────────────
// Must be rendered inside a <Suspense> boundary (see default export below).

function CallbackContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { getToken, isLoaded } = useAuth();

  const [phase, setPhase] = useState<
    "loading" | "picker" | "completing" | "error" | "success"
  >("loading");
  const [loadingMessage, setLoadingMessage] = useState<string | undefined>(undefined);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Parsed from URL
  const [installationId, setInstallationId] = useState<number | null>(null);
  const [stateToken, setStateToken] = useState<string | null>(null);

  // Repos returned by the server
  const [repos, setRepos] = useState<GitHubInstallationRepo[]>([]);

  // Auto-selected repo (single-repo installations skip the picker)
  const [autoRepo, setAutoRepo] = useState<GitHubInstallationRepo | null>(null);

  // Display name pre-filled from the repo's full_name
  const [displayName, setDisplayName] = useState("");

  // ── Step 1-3: parse URL, validate state via backend, fetch repos ──────────

  const init = useCallback(async () => {
    const idParam    = searchParams.get("installation_id");
    const stateParam = searchParams.get("state");
    const action     = searchParams.get("setup_action");

    // ── Basic URL param checks ─────────────────────────────────────────────
    if (!idParam || !stateParam) {
      setErrorMsg(
        "Missing installation_id or state in the callback URL. " +
          "Please restart the GitHub App installation from the integrations page.",
      );
      setPhase("error");
      return;
    }

    // Uninstall — nothing to create.
    if (action === "delete") {
      router.replace("/integrations");
      return;
    }

    const parsedId = parseInt(idParam, 10);
    if (isNaN(parsedId)) {
      setErrorMsg("Invalid installation_id in callback URL. Please try again.");
      setPhase("error");
      return;
    }

    // ── sessionStorage: soft cleanup, not a hard gate ─────────────────────
    //
    // We stored the state token before redirecting to GitHub.  We clean it up
    // here as a one-time-use hint.  However, we do NOT block on a mismatch
    // because the backend is the authoritative HMAC validator.
    //
    // sessionStorage may be absent or wrong when:
    //   - GitHub redirects back with setup_action=update (user changed settings)
    //   - The callback opened in a different tab or window
    //   - A previous failed attempt already cleared it
    //   - The user retried by refreshing the callback URL
    //
    // In all those cases, the backend still validates the token cryptographically.
    const storedState = sessionStorage.getItem(STATE_KEY);
    if (storedState && storedState !== stateParam) {
      console.warn(
        "[github-callback] sessionStorage state does not match URL state — " +
          "proceeding; backend will perform authoritative HMAC validation.",
      );
    }
    // Remove regardless — one-time use intent; errors come from the backend.
    sessionStorage.removeItem(STATE_KEY);

    setInstallationId(parsedId);
    setStateToken(stateParam);

    // ── Fetch repos — backend validates state here ─────────────────────────
    //
    // setup_action=install and setup_action=update are treated identically:
    // we show the repo picker and let the user complete the integration.
    setLoadingMessage("Loading repositories…");
    let repoList: GitHubInstallationRepo[];
    try {
      const token = await getToken();
      const data = await getInstallationRepositories(parsedId, stateParam, token);
      repoList = data.repos;
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error.";
      setErrorMsg(`Could not load installation repositories — ${msg}`);
      setPhase("error");
      return;
    }

    setRepos(repoList);

    if (repoList.length === 0) {
      setErrorMsg(
        "No repositories found for this installation. " +
          "Make sure you granted the App access to at least one repository, " +
          "then try again from the integrations page.",
      );
      setPhase("error");
      return;
    }

    if (repoList.length === 1) {
      // Single-repo install — skip the picker, show confirmation step.
      setAutoRepo(repoList[0]);
      setDisplayName(repoList[0].full_name);
      setPhase("picker");
    } else {
      setPhase("picker");
    }
  }, [searchParams, getToken, router]);

  useEffect(() => {
    if (!isLoaded) return;
    void init();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoaded]);

  // ── Step 5: complete the installation ────────────────────────────────────

  async function handleComplete(repo: GitHubInstallationRepo, name: string) {
    if (!installationId || !stateToken) return;
    setPhase("completing");
    try {
      const token = await getToken();
      await completeGitHubAppInstall(
        {
          installation_id: installationId,
          state: stateToken,
          repo_owner: repo.owner,
          repo_name: repo.name,
          display_name: name.trim() || repo.full_name,
        },
        token,
      );
      setPhase("success");
      // Redirect after a short pause so the user sees the success message.
      setTimeout(() => router.replace("/integrations"), 1500);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error.";
      setErrorMsg(`Could not complete installation — ${msg}`);
      setPhase("error");
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  if (phase === "loading") {
    return <LoadingVerifying message={loadingMessage} />;
  }

  if (phase === "success") {
    return (
      <div className="px-6 py-12 flex flex-col items-center gap-4">
        <span style={{ fontSize: "32px" }}>✓</span>
        <p style={{ fontSize: "14px", color: "#3ccf7e", fontWeight: 600 }}>
          GitHub integration connected.
        </p>
        <p style={{ fontSize: "12px", color: "#8b90a0" }}>
          Redirecting to integrations…
        </p>
      </div>
    );
  }

  if (phase === "error") {
    return (
      <div className="px-6 py-12">
        <div
          style={{
            background: "rgba(232,64,64,0.06)",
            border: "1px solid rgba(232,64,64,0.25)",
            borderRadius: "6px",
            padding: "16px 20px",
            marginBottom: "16px",
          }}
        >
          <p style={{ fontSize: "13px", color: "#e84040", margin: 0 }}>
            {errorMsg ?? "An unexpected error occurred."}
          </p>
        </div>
        <button
          onClick={() => router.replace("/integrations")}
          style={{
            background: "transparent",
            border: "1px solid #4f80f7",
            color: "#4f80f7",
            borderRadius: "6px",
            padding: "7px 14px",
            fontSize: "13px",
            cursor: "pointer",
            fontFamily: "inherit",
          }}
        >
          ← Back to Integrations
        </button>
      </div>
    );
  }

  if (phase === "completing") {
    return <LoadingVerifying message="Creating integration…" />;
  }

  // phase === "picker"
  return (
    <div className="px-6 py-8" style={{ maxWidth: "560px" }}>
      <h1
        style={{
          fontSize: "16px",
          color: "#e8eaf0",
          fontWeight: 600,
          marginBottom: "6px",
        }}
      >
        Select a repository
      </h1>
      <p style={{ fontSize: "13px", color: "#8b90a0", marginBottom: "24px" }}>
        Choose one repository to monitor. You can add more integrations later.
      </p>

      <GitHubRepoPicker
        repos={repos}
        autoSelectedRepo={autoRepo}
        initialDisplayName={displayName}
        onComplete={handleComplete}
        onCancel={() => router.replace("/integrations")}
      />
    </div>
  );
}

// ── Page export — wraps CallbackContent in Suspense ───────────────────────────
// Required by Next.js App Router: useSearchParams() in a child component must
// have a Suspense boundary above it in the tree, or the build fails with
// "useSearchParams() should be wrapped in a suspense boundary".

export default function GitHubAppCallbackPage() {
  return (
    <Suspense fallback={<LoadingVerifying />}>
      <CallbackContent />
    </Suspense>
  );
}
