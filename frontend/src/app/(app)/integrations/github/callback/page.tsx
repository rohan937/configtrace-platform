"use client";

/**
 * GitHub App installation callback page — M31.
 *
 * GitHub redirects here after the user installs the App:
 *   https://app.configtrace.org/integrations/github/callback
 *     ?installation_id=12345
 *     &setup_action=install
 *     &state=<hmac-token>
 *
 * Flow:
 *   1. Read installation_id + state from URL query params.
 *   2. Verify state matches what we stored in sessionStorage (CSRF guard).
 *   3. Fetch the list of repositories for this installation.
 *   4. If one repo  → skip picker, go straight to confirmation.
 *      If many repos → show GitHubRepoPicker.
 *   5. On repo selection → POST /integrations/github/app/complete.
 *   6. On success → redirect to /integrations.
 *
 * Security:
 *   - state is never logged or shown in UI.
 *   - installation_id is never stored beyond this session.
 *   - The JWT is fetched fresh for each API call and not held in state.
 */

import { useCallback, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@clerk/nextjs";
import type { GitHubInstallationRepo } from "@/types";
import { completeGitHubAppInstall, getInstallationRepositories } from "@/lib/api";
import LoadingState from "@/components/common/LoadingState";
import GitHubRepoPicker from "@/components/integrations/GitHubRepoPicker";

// Prefix used to store the state token in sessionStorage.
const STATE_KEY = "github_app_oauth_state";

export default function GitHubAppCallbackPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { getToken, isLoaded } = useAuth();

  const [phase, setPhase] = useState<
    "loading" | "picker" | "completing" | "error" | "success"
  >("loading");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Parsed from URL
  const [installationId, setInstallationId] = useState<number | null>(null);
  const [stateToken, setStateToken] = useState<string | null>(null);

  // Repos returned by the server
  const [repos, setRepos] = useState<GitHubInstallationRepo[]>([]);

  // Auto-selected repo (single-repo installations skip the picker)
  const [autoRepo, setAutoRepo] = useState<GitHubInstallationRepo | null>(null);

  // Display name for completing the integration
  const [displayName, setDisplayName] = useState("");

  // ── Step 1-3: parse URL, verify state, fetch repos ───────────────────────

  const init = useCallback(async () => {
    const idParam = searchParams.get("installation_id");
    const stateParam = searchParams.get("state");
    const action = searchParams.get("setup_action");

    if (!idParam || !stateParam) {
      setErrorMsg(
        "Missing installation_id or state in the callback URL. " +
          "Please restart the GitHub App installation."
      );
      setPhase("error");
      return;
    }

    if (action === "delete") {
      // User uninstalled the App — nothing to do.
      router.replace("/integrations");
      return;
    }

    const parsedId = parseInt(idParam, 10);
    if (isNaN(parsedId)) {
      setErrorMsg("Invalid installation_id in callback URL.");
      setPhase("error");
      return;
    }

    // CSRF check: compare with the token we stashed before the redirect.
    const storedState = sessionStorage.getItem(STATE_KEY);
    if (!storedState || storedState !== stateParam) {
      setErrorMsg(
        "State token mismatch — this link may have expired or been tampered with. " +
          "Please start the installation again."
      );
      setPhase("error");
      return;
    }

    // Clear state from storage (one-time use).
    sessionStorage.removeItem(STATE_KEY);

    setInstallationId(parsedId);
    setStateToken(stateParam);

    try {
      const token = await getToken();
      const data = await getInstallationRepositories(parsedId, stateParam, token);
      const repoList = data.repos;
      setRepos(repoList);

      if (repoList.length === 0) {
        setErrorMsg(
          "No repositories found for this installation. " +
            "Make sure you granted the App access to at least one repository."
        );
        setPhase("error");
        return;
      }

      if (repoList.length === 1) {
        // Single-repo install — skip the picker.
        setAutoRepo(repoList[0]);
        setDisplayName(repoList[0].full_name);
        setPhase("picker"); // still show the confirm step
      } else {
        setPhase("picker");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load repositories.";
      setErrorMsg(msg);
      setPhase("error");
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
      const msg =
        err instanceof Error ? err.message : "Failed to complete installation.";
      setErrorMsg(msg);
      setPhase("error");
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  if (phase === "loading") {
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
          Verifying GitHub App installation…
        </p>
      </div>
    );
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
          Creating integration…
        </p>
      </div>
    );
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
